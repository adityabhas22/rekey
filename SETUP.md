# SETUP.md

What you need to do on your machine to use rekey. The agent is **local-first** — everything runs on this laptop, talking to APIs and your real Chrome.

---

## 1. Install rekey

You already have it. From the repo root:

```bash
uv sync                 # installs all Python deps into .venv
```

Verify:
```bash
uv run rekey --help
```

> Note: rekey requires **Python 3.13+**. `uv` will pick the right one from the project's `requires-python`.

---

## 2. Pick an LLM provider (for Phase 1 rotation)

You only need **one**. rekey auto-detects in priority order: **Anthropic → Google → OpenAI → local Ollama**.

| Provider | Env var | Default model | Approx cost / rotation |
|---|---|---|---|
| Anthropic (recommended) | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` | $0.10–$0.50 |
| Google Gemini | `GOOGLE_API_KEY` | `gemini-2.5-flash` | $0.005–$0.03 |
| OpenAI | `OPENAI_API_KEY` | `gpt-5.5` | $0.10–$0.50 |
| Local Ollama | `REKEY_LLM_PROVIDER=ollama` (no key) | `qwen2.5:32b` | free |

To force a specific provider, set `REKEY_LLM_PROVIDER=anthropic|openai|google|ollama`.
To override the model, set `REKEY_LLM_MODEL=...`.

You only need an LLM for **rotation**. The **audit** phase needs no LLM.

---

## 3. Connect at least one vault

You need either 1Password, Bitwarden, or a CSV export. Audit works with any source. **Rotation requires a writable vault** (1Password or Bitwarden).

### 3a. 1Password (recommended)

Install the 1Password CLI:
```bash
brew install --cask 1password-cli       # macOS
```

Create a **service-account token** (this is the secure auth — your master password is never used):

1. Visit https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount
2. *Create Service Account* → name it `rekey`
3. Grant **Read & Write** on the vault(s) rekey should manage
4. Copy the token (`ops_eyJ...`) — you only see it once
5. Export it:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_eyJ..."
```

Or put it in your `.env` (see `.env.example`).

Smoke test:
```bash
op item list --categories=Login --format=json | head -c 200
```

### 3b. Bitwarden

```bash
brew install bitwarden-cli              # macOS

bw login                                # interactive login
export BW_SESSION="$(bw unlock --raw)"  # session token expires when shell closes
```

> **Tip:** `BW_SESSION` is per-shell. For longer-lived setup, store it in `.env` (it auto-expires safely since `bw` re-checks).

### 3c. CSV import (Apple Passwords / Chrome / Firefox / generic)

For **detection only** (no rotation). Export from your manager:

- **Apple Passwords (macOS)**: open the Passwords app → `File ▸ Export Passwords…` → CSV.
- **Chrome**: `chrome://password-manager/settings` → *Download passwords*.
- **Firefox**: `about:logins` → `…` menu → *Export logins*.

Then point rekey at it:
```bash
export REKEY_CSV_PATHS="/Users/me/Downloads/Passwords.csv"
# Or multiple, comma-separated:
export REKEY_CSV_PATHS="/path/to/apple.csv,/path/to/chrome.csv"
```

> ⚠️ **CSV files contain plaintext passwords.** Keep them on an encrypted volume and delete after import.

---

## 4. (Phase 1 only) Launch Chrome with remote debugging

For rotation, rekey attaches to your **running Chrome** via CDP so the agent uses your real profile (existing logins, cookies, sessions). Quit Chrome first, then relaunch:

```bash
# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222
```

Chrome should launch and behave normally. You can keep browsing.

Verify rekey can see it:
```bash
curl -s http://127.0.0.1:9222/json/version | head -c 200
```

If you want a different port, set `REKEY_CDP_PORT=...`.

---

## 5. Run

### Audit (Phase 0)

```bash
uv run rekey audit
uv run rekey audit --output ~/.rekey/audit-$(date +%F).json
```

You'll see a ranked table of credentials with compromised / reused / weak issues. No browser, no LLM — just HIBP + local analysis.

### Rotate a single credential (Phase 1)

```bash
uv run rekey rotate github.com
# or by the composite ID printed in the audit JSON:
uv run rekey rotate 1password::abc123
```

What happens:
1. rekey starts the local web dashboard at `http://127.0.0.1:7777` and opens it.
2. A browser agent attaches to your Chrome (CDP) and starts driving the change-password flow.
3. When CAPTCHA / SMS 2FA / push 2FA / anything ambiguous appears, the dashboard shows a hand-off — you click **Approve** / **Skip** / **Abort**.
4. On success, the new password is written to your vault (the old one stays in item history).

---

## (Optional) Enable automatic OTP capture

v0.2 races multiple OTP channels in parallel — first match wins. You can enable any combination of these. Without any of them, you'll just see `pause_for_human` prompts in the dashboard and complete OTP steps by hand.

### TOTP from your password manager (highest priority, zero setup if you have it)

If a credential has a TOTP secret stored in 1Password or Bitwarden, rekey can generate the 6-digit code locally — no email, no SMS, no internet round-trip. Already wired automatically; nothing extra to do.

### SMS / iMessage codes via macOS Continuity (`chat.db`)

If your iPhone forwards SMS to your Mac (Messages app → Settings → "Text Message Forwarding" enabled for this Mac), rekey can read codes from `~/Library/Messages/chat.db` within seconds.

**One-time permission:** System Settings → Privacy & Security → **Full Disk Access** → click **+** → navigate to `/Users/<you>/ideas/rekey/.venv/bin/python` (or your Terminal binary). Restart your shell after granting.

Verify:
```bash
uv run python -c "from rekey.adapters.messages.chat_db import ChatDbReader; print('available:', ChatDbReader().available())"
```

### Apple Mail.app rule (provider-agnostic email push)

Works for iCloud Mail, Gmail, Outlook, Fastmail — whatever you have configured in Mail.app. Sub-2-second push notification of new emails to rekey via `localhost`.

**One-time setup:**

1. Open **Mail.app** → menu **Mail** → **Settings** → **Rules** → **Add Rule**.
2. Description: `rekey OTP forwarder`.
3. **If**: `Every Message`.
4. Add action: **Run AppleScript** → click **Open in Finder…** → choose `docs/scripts/rekey-mail-handler.applescript` from this repo.
5. Save. Mail will install the script at `~/Library/Application Scripts/com.apple.mail/`.
6. When prompted, **Apply to existing messages? → No** (we only want new mail).

The script POSTs each incoming message to `http://127.0.0.1:7777/mail-event`, which rekey's dashboard listens on while a rotation is active. When rekey isn't running, the POST silently fails — Mail keeps the email; nothing else happens.

### Webmail-tab scrape (fallback only)

If none of the above are set up, rekey will open Gmail in a new tab in your Brave/Chrome and try to scrape recent messages. This only works if you're signed into Gmail in that browser, and it's brittle. Use as a last resort.

---

## Summary checklist

You're ready when you have:

- [ ] `uv sync` succeeds
- [ ] `uv run rekey --help` prints the help
- [ ] **One** LLM key set (only needed for rotation)
- [ ] **One** vault configured (`OP_SERVICE_ACCOUNT_TOKEN`, `BW_SESSION`, or `REKEY_CSV_PATHS`)
- [ ] (For rotation only) Chrome launched with `--remote-debugging-port=9222`

Then:
```bash
uv run rekey audit                              # Phase 0
uv run rekey rotate github.com                  # Phase 1
```

See [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) for what rekey does and doesn't protect against.
