# THREAT_MODEL.md

What rekey is designed to protect against, what it deliberately doesn't, and the architectural invariants that uphold those properties.

---

## What rekey IS

- A **local-first** tool. All code runs on the user's machine. No rekey-operated server.
- An **agent** that mediates between the user's password vault, the user's email/2FA, and the change-password forms of websites the user already has accounts on.
- An **open-source** tool whose code is auditable.

## What rekey is NOT

- A cloud service.
- A password manager (it integrates with existing ones).
- A breach intelligence database (it queries HIBP's free k-anonymity API).
- A CAPTCHA solver — rekey hands those to the human.

---

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                  USER'S TRUST ZONE (this machine)                    │
│                                                                       │
│  ┌────────────┐    ┌──────────────┐    ┌────────────────────────┐    │
│  │  rekey     │───►│ 1Password /  │    │ The user's Chrome      │    │
│  │  process   │    │ Bitwarden CLI│    │ (via CDP on localhost) │    │
│  └─────┬──────┘    └──────────────┘    └────────────────────────┘    │
│        │                                                              │
│        │ HTTPS                                                        │
└────────┼──────────────────────────────────────────────────────────────┘
         ▼
    ┌──────────┐   ┌────────────────────┐   ┌──────────────────────┐
    │  HIBP    │   │  LLM API           │   │  Target site         │
    │ (range)  │   │ (Anthropic/Google/ │   │ (github.com,         │
    │ free     │   │  OpenAI/Ollama)    │   │  bank.com, ...)      │
    └──────────┘   └────────────────────┘   └──────────────────────┘
```

The **rekey process** is the trust root. If that's compromised (RCE, supply-chain attack, malicious dependency), the attacker has access to the user's vault + email + ability to change passwords. This is concentrated risk by design — and the same risk a human's password-manager-and-email session already concentrates.

---

## Protections rekey provides

### P1. The LLM never sees password values

**Invariant:** secret values (existing passwords, newly-generated passwords, OTP codes) are never placed in any string that the LLM sees.

**Mechanism:**
- Secrets live in `SecretStore`, keyed by a `composite_id`.
- The LLM driving the browser is given the `composite_id` only.
- Custom browser actions (`type_current_password`, `type_new_password`, `fetch_and_type_email_otp`) read the value from the store and type it via the browser-use Element API. They return `"filled"` — never the value.
- The task prompt never includes a password.

**Consequence:** prompt-injection of the LLM by a target page cannot exfiltrate the password — the password isn't in the LLM's context to leak.

### P2. Origin validation before typing

**Invariant:** the agent will refuse to type a credential's secrets on a page whose origin doesn't match the credential's stored origin.

**Mechanism:** every secret-typing action calls `verify_origin()` first, which compares the current browser page URL's canonical origin to `RotationSecrets.expected_origin`. Mismatch raises `WrongOriginError`.

**Consequence:** a redirect or open-redirect attack to an attacker-controlled domain cannot trick the agent into typing the password there.

### P3. Pre-submit human approval

**Invariant:** the user explicitly approves the final form submission via the web dashboard for every rotation. (The LLM's task prompt instructs it to pause; the dashboard surfaces the prompt.)

**Consequence:** even if the LLM is steered into a bad state, the user has a last-second veto.

### P4. Verify-then-discard

**Invariant:** the new password is not written to the vault until the agent has verified the change succeeded on the site.

**Mechanism:** `RotationDriver.rotate()` returns `True` only on confirmed success. The orchestrator writes to the vault only on `True`. The old password remains in item history for rollback.

**Consequence:** a failed change leaves the user's vault correct (old password still valid for the unchanged site).

### P5. Lockout-detected → abort, never retry

**Invariant:** when the driver raises `LockoutDetected`, the orchestrator marks the attempt `LOCKOUT_DETECTED` and stops. There is no retry path.

**Consequence:** the agent can't escalate a single failure into an account lockout cascade.

### P6. Local-only web dashboard

**Invariant:** the FastAPI dashboard binds to `127.0.0.1` and validates a per-process CSRF cookie on every POST.

**Consequence:** the dashboard cannot be reached by another host on the network, and a malicious page in another tab cannot CSRF the approval endpoints (cookie is `SameSite=strict`, `HttpOnly`).

### P7. K-anonymity breach checking

**Invariant:** rekey never sends a password (or even a full hash) to a remote server for breach checking. It sends the first 5 hex characters of SHA-1, receives all suffixes sharing that prefix, and matches locally.

**Consequence:** HIBP cannot determine which password the user looked up.

---

## What rekey does NOT protect against

- **Compromise of the host machine.** Keyloggers, malicious browser extensions, host-level malware bypass all of the above.
- **Compromise of the rekey process itself** (malicious dependency, RCE). The trust root is the binary; verify dependencies (`uv.lock`) and audit changes.
- **A determined LLM prompt-injection that doesn't need the password** — e.g., one that tricks the agent into clicking a button that changes other account settings. P3 (human approval before submit) is the main defense; for sensitive accounts (banking, primary email) we recommend supervised mode (you watch every step).
- **A user who skips approvals.** rekey hands sensitive steps to the user; if the user clicks "approve" without reading, the safety is lost.
- **Network attackers**, *as long as* the user trusts the HIBP / LLM provider TLS chain.
- **Account takeover prior to rekey use.** rekey rotates passwords *the user already controls*; it does not recover hijacked accounts.

---

## Defenses to add over time

- **Dependency pinning + supply-chain verification** (`uv.lock` checked in; CI to detect drift).
- **Reproducible builds** of release wheels.
- **Per-rotation logging** to an append-only local log for forensic review.
- **Secret broker integration** (1Password Secure Agentic Autofill) — the browser receives credentials over an encrypted channel without rekey ever holding them in process memory.
- **Sandboxing the LLM call** (separate process, drop privileges).
- **Static analysis** (`ruff` + `mypy` --strict) wired into CI to prevent regressions in the security invariants.

If you find a security issue, please open an issue on GitHub.
