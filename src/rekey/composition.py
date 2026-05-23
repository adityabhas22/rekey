"""DI composition root — the only place that knows about concrete adapters.

Builds wired-up dependency bundles for each CLI command. Tests can replace
the factories via keyword arguments without touching adapter modules.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

from rekey.adapters.breach.hibp import HIBPChecker
from rekey.adapters.browser.chrome_cdp import CDPConfig, ChromeCDPSession
from rekey.adapters.browser.rotation_driver import BrowserUseRotationDriver
from rekey.adapters.browser.secret_store import SecretStore
from rekey.adapters.event_bus.in_memory import InMemoryEventBus
from rekey.adapters.handoff.web_dashboard import WebDashboard
from rekey.adapters.llm.factory import BrowserUseLLMFactory
from rekey.adapters.vault.bitwarden import BitwardenError, BitwardenVault
from rekey.adapters.vault.csv_import import CSVImportVault
from rekey.adapters.vault.onepassword import OnePasswordError, OnePasswordVault
from rekey.config import Settings
from rekey.domain.credential import Credential
from rekey.ports.breach_check import BreachChecker
from rekey.ports.vault import VaultReader, VaultWriter
from rekey.services.audit_service import AuditService
from rekey.services.rotation_service import RotationService

logger = logging.getLogger(__name__)


@dataclass
class AuditDependencies:
    audit_service: AuditService
    vaults: list[VaultReader]


@dataclass
class RotationDependencies:
    rotation_service: RotationService
    dashboard: WebDashboard
    vaults: list[VaultReader]
    primary_writer: VaultWriter

    def find_credential(self, target: str) -> tuple[Credential, VaultReader] | None:
        """Find a credential by composite_id or by host across all configured vaults."""
        for vault in self.vaults:
            for cred in vault.list_credentials():
                if cred.composite_id == target or cred.host == target:
                    return cred, vault
        return None


def _make_vaults(settings: Settings) -> list[VaultReader]:
    """Build configured vault readers based on env + settings."""
    vaults: list[VaultReader] = []

    if os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
        try:
            vaults.append(OnePasswordVault())
        except OnePasswordError as e:
            logger.warning("1Password disabled: %s", e)

    if os.environ.get("BW_SESSION"):
        try:
            vaults.append(BitwardenVault())
        except BitwardenError as e:
            logger.warning("Bitwarden disabled: %s", e)

    for path in settings.csv_paths_list:
        vaults.append(CSVImportVault(path))

    return vaults


def _find_writer(vaults: list[VaultReader]) -> VaultWriter | None:
    """Return the first vault that also implements VaultWriter, or None."""
    for v in vaults:
        # Duck-type: VaultWriter requires update_password + append_note
        if callable(getattr(v, "update_password", None)) and callable(
            getattr(v, "append_note", None)
        ):
            return v   # type: ignore[return-value]  duck-typed
    return None


def build_audit_dependencies(
    settings: Settings | None = None,
    *,
    breach_checker: BreachChecker | None = None,
    vaults: list[VaultReader] | None = None,
) -> AuditDependencies:
    settings = settings or Settings()
    resolved_vaults = vaults if vaults is not None else _make_vaults(settings)
    if not resolved_vaults:
        raise NoVaultsConfigured(
            "No vaults configured. Set OP_SERVICE_ACCOUNT_TOKEN or BW_SESSION; "
            "or list CSV exports via REKEY_CSV_PATHS=<path1>,<path2>."
        )
    checker = breach_checker if breach_checker is not None else HIBPChecker()
    service = AuditService(vaults=resolved_vaults, breach_checker=checker)
    return AuditDependencies(audit_service=service, vaults=resolved_vaults)


def build_rotation_dependencies(
    settings: Settings | None = None,
    *,
    vaults: list[VaultReader] | None = None,
    llm_factory_builder: Callable[[], BrowserUseLLMFactory] = BrowserUseLLMFactory,
    chrome_session_builder: Callable[[Settings], ChromeCDPSession] | None = None,
) -> RotationDependencies:
    settings = settings or Settings()
    resolved_vaults = vaults if vaults is not None else _make_vaults(settings)
    if not resolved_vaults:
        raise NoVaultsConfigured("No vaults configured (see SETUP.md).")

    writer = _find_writer(resolved_vaults)
    if writer is None:
        raise NoVaultWriter(
            "Rotation needs a writable vault (1Password or Bitwarden). "
            "CSV imports are read-only."
        )

    event_bus = InMemoryEventBus()
    secrets = SecretStore()
    dashboard = WebDashboard(
        event_bus=event_bus,
        host=settings.web_host,
        port=settings.web_port,
    )

    chrome = (
        chrome_session_builder(settings)
        if chrome_session_builder
        else ChromeCDPSession(CDPConfig(port=settings.cdp_port))
    )
    llm_factory = llm_factory_builder()

    driver = BrowserUseRotationDriver(
        llm_factory=llm_factory,
        chrome_session=chrome,
        secrets=secrets,
        otp_fetcher=None,            # webmail-tab OTP reader is post-v0.1
        handoff=dashboard,
    )

    rotation_service = RotationService(
        driver=driver,
        vault_writer=writer,
        secrets=secrets,
        event_bus=event_bus,
    )

    return RotationDependencies(
        rotation_service=rotation_service,
        dashboard=dashboard,
        vaults=resolved_vaults,
        primary_writer=writer,
    )


class NoVaultsConfigured(RuntimeError):
    """No vault adapters are configured in the environment."""


class NoVaultWriter(RuntimeError):
    """No writable vault is configured (1Password or Bitwarden required for rotation)."""
