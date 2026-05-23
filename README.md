# rekey

**Local-first AI agent for credential hygiene.** Audits your password manager against breach data, and helps you rotate compromised, reused, and weak passwords through your real browser — with a human in the loop for the moments only a human can resolve (CAPTCHA, SMS/push 2FA, anything ambiguous).

> **Status:** v0.1 — early development. Phase 0 (audit) is the first shipping deliverable.

## What it does

- **Audit (Phase 0)** — pulls credentials from 1Password / Bitwarden / CSV exports (Apple Passwords, Chrome), checks each against the [HIBP Pwned Passwords](https://haveibeenpwned.com/Passwords) k-anonymity API, identifies reused and weak passwords, and reports them ranked by priority.
- **Rotate (Phase 1)** — for each flagged credential, a browser agent (model-agnostic: Claude / Gemini / GPT / local Ollama) attaches to your *running Chrome* via CDP, navigates to the site's change-password page, fills in a freshly generated strong password, hands off to you for CAPTCHA / 2FA, verifies the new login works, then writes back to the vault. Old password preserved in history.

## Why this architecture works where Dashlane and Google Duplex didn't

| Prior attempts | rekey |
|---|---|
| Server-side OR cloud crawler | **Local, on your machine, on your home IP** |
| Cold logins → fraud-detection wall | **In-session** changes in your already-authenticated Chrome → most sites skip CAPTCHA entirely |
| Per-site recipes that rotted | **LLM-driven** navigation; cached selectors only as optional accelerators |
| Vendor-locked | **Model-agnostic** (Anthropic / OpenAI / Google / Ollama) and **vault-agnostic** (1Password / Bitwarden / CSV) |

## Architecture — Ports & Adapters

```
src/rekey/
├── domain/      # Pure types — Credential, AuditFinding, RotationAttempt
├── ports/       # Protocols — VaultReader/Writer, BreachChecker, BrowserSession,
│                #             LLMFactory, OTPFetcher, HandoffUI, EventBus
├── adapters/    # Concrete impls of ports
│   ├── vault/   #   OnePassword (op CLI), Bitwarden (bw CLI), CSV
│   ├── breach/  #   HIBP
│   ├── llm/     #   browser-use's multi-provider factory
│   ├── browser/ #   Chrome via CDP + custom Actions (security boundary)
│   ├── mail/    #   Webmail-tab OTP fetcher
│   ├── handoff/ #   FastAPI + SSE local dashboard
│   └── event_bus/
├── services/    # AuditService, RotationService, Orchestrator — depend only on ports
├── detection/   # Pure analysis (reuse, strength)
└── web/         # FastAPI app on localhost:7777
```

Services depend on ports, not adapters. Adding a new vault = drop a file in `adapters/vault/`. Swapping the LLM = one config line.

## Security model (short version)

- **The LLM never sees a password.** All secret-handling actions execute in our handler, type via Playwright, and return `"filled"` to the LLM. Origin-check on every typing action.
- **You approve every submit.** Web dashboard renders a hand-off for the final click; nothing is submitted without your explicit OK.
- **Verify-then-discard.** The new password is only committed to the vault after a fresh test-login succeeds. The old password stays in item history.
- **Localhost-only.** Web dashboard binds `127.0.0.1`. CSRF cookie on every POST.

Full threat model: see [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) (coming).

## Quickstart

```bash
# 1. Install
uv sync

# 2. Configure (see SETUP.md for the full walkthrough)
cp .env.example .env

# 3. Audit
uv run rekey audit

# 4. Rotate a single site (Phase 1)
uv run rekey rotate github.com
```

See [`SETUP.md`](./SETUP.md) for API keys, 1Password service-account token, Bitwarden CLI login, and the Chrome CDP launch flag.

## License

MIT — see [`LICENSE`](./LICENSE).
