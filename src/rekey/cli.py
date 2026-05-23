"""rekey CLI entry point — Typer commands."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import webbrowser
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load .env into os.environ on import so OP_SERVICE_ACCOUNT_TOKEN, BW_SESSION,
# API keys, etc. work without the user having to `source` them.
load_dotenv()

from rekey.composition import (
    NoVaultsConfigured,
    NoVaultWriter,
    build_audit_dependencies,
    build_rotation_dependencies,
)
from rekey.domain.audit import AuditFinding, Severity
from rekey.domain.rotation import State

app = typer.Typer(
    name="rekey",
    help="rekey — local credential hygiene agent.",
    no_args_is_help=True,
)
console = Console()


# ---------------------------------------------------------------------- audit


@app.command()
def audit(
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write JSON results to file."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print summary."),
) -> None:
    """Audit credentials against breach data, reuse, and weakness (Phase 0)."""
    _setup_logging()
    try:
        deps = build_audit_dependencies()
    except NoVaultsConfigured as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from e

    console.print(
        f"[dim]Auditing across {len(deps.vaults)} vault(s): "
        f"{', '.join(v.name() for v in deps.vaults)}[/]"
    )
    findings = deps.audit_service.run()
    _print_audit(findings, quiet=quiet)

    if output is not None:
        output.write_text(json.dumps(_findings_to_json(findings), indent=2))
        console.print(f"\n[dim]Detailed results: {output}[/]")


# --------------------------------------------------------------------- rotate


@app.command()
def rotate(
    target: str = typer.Argument(..., help="Credential to rotate (composite_id or host)"),
) -> None:
    """Rotate a single credential's password (Phase 1)."""
    _setup_logging()
    asyncio.run(_run_rotation(target))


async def _run_rotation(target: str) -> None:
    try:
        deps = build_rotation_dependencies()
    except (NoVaultsConfigured, NoVaultWriter) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(2) from e

    match = deps.find_credential(target)
    if match is None:
        console.print(f"[red]No credential matching {target!r} found in any vault.[/]")
        raise typer.Exit(1)
    credential, vault = match

    current_password = vault.get_password(credential.id)

    server_task = asyncio.create_task(deps.dashboard.serve())
    # Give the server a moment to bind.
    await asyncio.sleep(0.5)

    console.print(f"\n[cyan]Dashboard:[/] {deps.dashboard.url}")
    console.print(
        f"[cyan]Rotating[/] {credential.host} "
        f"([dim]{credential.username or '<unknown>'}[/])..."
    )
    _try_open_browser(deps.dashboard.url)

    try:
        attempt = await deps.state_machine.run(credential, current_password)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    _print_rotation_outcome(attempt, credential_host=credential.host)
    if attempt.state != State.DONE:
        raise typer.Exit(1)


def _try_open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001  best-effort
        pass


# ----------------------------------------------------------------- rendering


def _print_audit(findings: list[AuditFinding], *, quiet: bool) -> None:
    bad = [f for f in findings if not f.is_clean]
    console.print("\n[bold]Audit summary[/]")
    console.print(f"  Total credentials: {len(findings)}")
    console.print(f"  Issues found:      [yellow]{len(bad)}[/]")
    console.print(f"  Clean:             [green]{len(findings) - len(bad)}[/]\n")

    if quiet or not bad:
        return

    table = Table(show_lines=True, header_style="bold")
    table.add_column("Priority", style="dim", justify="right")
    table.add_column("Host", style="cyan")
    table.add_column("Username")
    table.add_column("Source", style="dim")
    table.add_column("Issues")

    for f in bad:
        issues_str = "\n".join(
            f"[{_severity_color(i.severity)}]{i.kind.value}[/]: {i.detail}"
            for i in f.issues
        )
        table.add_row(
            str(f.priority),
            f.credential.host,
            f.credential.username or "[dim]<unknown>[/]",
            f.credential.source.value,
            issues_str,
        )
    console.print(table)


def _severity_color(severity: Severity) -> str:
    return {
        Severity.LOW: "yellow",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red",
    }[severity]


def _findings_to_json(findings: list[AuditFinding]) -> list[dict]:
    return [
        {
            "credential": {
                "composite_id": f.credential.composite_id,
                "host": f.credential.host,
                "username": f.credential.username,
                "source": f.credential.source.value,
            },
            "priority": f.priority,
            "issues": [
                {
                    "kind": i.kind.value,
                    "severity": int(i.severity),
                    "detail": i.detail,
                    "metric": i.metric,
                    "related_credential_ids": list(i.related_credential_ids),
                }
                for i in f.issues
            ],
        }
        for f in findings
    ]


def _print_rotation_outcome(attempt, *, credential_host: str) -> None:
    if attempt.state == State.DONE:
        console.print(f"\n[green]✓ Rotation complete for {credential_host}[/]")
        console.print(f"  duration: {attempt.duration_seconds:.1f}s")
    else:
        reason = attempt.failure_reason or "(no reason)"
        console.print(f"\n[red]✗ Rotation {attempt.state.value} for {credential_host}[/]")
        console.print(f"  reason: {reason}")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    """Console-script entrypoint."""
    app()


if __name__ == "__main__":
    main()
