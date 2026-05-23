# ARCHITECTURE.md

How rekey is put together, and why.

---

## Layered (Hexagonal / Ports & Adapters)

```
                ┌──────────────────────────────┐
                │            CLI               │  Typer — entry point
                │     (src/rekey/cli.py)       │
                └──────────────┬───────────────┘
                               │
                ┌──────────────▼───────────────┐
                │       Composition root       │  DI wiring
                │   (src/rekey/composition.py) │
                └──────────────┬───────────────┘
                               │ depends only on ports
                ┌──────────────▼───────────────┐
                │           Services           │  Use cases
                │ AuditService, RotationService│
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼─────┐
       │   Domain    │  │    Ports    │  │ Detection  │
       │ Credential, │  │  Protocols  │  │ HIBP rules,│
       │ Audit, etc. │  │             │  │ reuse, etc.│
       └─────────────┘  └─────────────┘  └────────────┘
                               ▲
                               │ adapters implement ports
                ┌──────────────┴───────────────┐
                │           Adapters           │
                │                              │
                │  vault/ ─ 1Password / Bitwarden / CSV
                │  breach/ ─ HIBP
                │  llm/    ─ browser-use multi-provider factory
                │  browser/─ Chrome CDP + custom actions
                │  handoff/─ FastAPI web dashboard
                │  event_bus/ ─ in-memory async pub/sub
                └──────────────────────────────┘
```

## Dependency rule

**Inward only.** Domain knows nothing about ports or adapters. Ports know nothing about adapters. Adapters depend on ports and domain. Services depend on ports + domain. Composition is the only place that knows about concrete adapters.

This means:
- Adding a new vault (KeePass, Proton Pass) = one new file in `adapters/vault/`.
- Swapping the LLM = one config change.
- Replacing the web dashboard with native UI = drop in a new `HandoffUI` implementation.

## SOLID alignment

- **S** (Single Responsibility): each module has one purpose.
  - `audit_service.py` orchestrates audit. Doesn't know about HIBP details.
  - `detection/reuse.py` finds reuse groups. Doesn't know about vaults.
  - `actions.py` types secrets. Doesn't know about CSV.
- **O** (Open/Closed): extension by adding files, not modifying existing ones.
  - New `VaultReader` → new file in `adapters/vault/`.
  - New `LLMProvider` → one new line in `adapters/llm/factory.py`.
- **L** (Liskov Substitution): every adapter is interchangeable behind its port.
  - Tests pass `FakeVault`, `FakeBreachChecker`, `FakeDriver` without modifying service code.
- **I** (Interface Segregation): ports are narrow.
  - `VaultReader` and `VaultWriter` are separate — CSV adapters implement only the former.
  - `HandoffUI` has 2 methods, not 20.
- **D** (Dependency Inversion): services depend on protocols, not concrete classes.
  - `RotationService.__init__` takes `RotationDriver` (Protocol), not `BrowserUseRotationDriver`.

## The security boundary

The single most important architectural property: **the LLM never sees a secret value.**

```
LLM context:
    "credential_id = 1password::abc"
              │
              ▼ tool call: type_current_password(credential_id, element_index)
              │
    rekey custom action:
        secret = SecretStore.get(credential_id).current_password    ◄── value here
        await element.fill(secret)                                  ◄── typed here
        return "filled"                                             ◄── LLM sees this
```

The value never crosses back into the LLM's context window. Prompt injection from a malicious page cannot exfiltrate what isn't there to exfiltrate.

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the full set of invariants.

## State machine

A single rotation traverses an explicit state machine. Every transition emits an `Event` to the `EventBus`, which the web dashboard subscribes to via Server-Sent Events.

```
PENDING
  → FINDING_CHANGE_PAGE      (driver navigates, may try /.well-known/change-password first)
  → FILLING_FORM             (type_current_password, type_new_password)
  → AWAITING_HUMAN_APPROVAL  (web dashboard prompt)
  → SUBMITTING
  → HANDLING_CHALLENGES      (TOTP auto, email-OTP auto; SMS/push/CAPTCHA → handoff)
  → VERIFYING                (success signal + fresh test-login)
  → WRITING_TO_VAULT         (only after verified; preserve old in history)
  → DONE

Any → FAILED (recoverable; safe to skip and continue)
Any → LOCKOUT_DETECTED (abort; never retry — protects against escalating to lockout)
```

## Testing strategy

- **Domain layer** — pure data, exhaustively tested. Constructors validate invariants (canonical origins, frozen, valid policy).
- **Detection rules** — pure functions, table-driven tests.
- **Adapters** — unit-tested with mocks (HIBP via `respx`; vault CLIs via `subprocess` mocks; web dashboard via `httpx.AsyncClient` against the ASGI app).
- **Services** — wired against fakes for every port. The real behavior is verified against the real adapters in a live integration test (see [`SETUP.md`](../SETUP.md) for browser/vault setup).

Live integration tests are marked with `@pytest.mark.integration` and run with `pytest -m integration`.
