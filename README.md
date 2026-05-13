# K.I.R.O Register (English edition)

An automation toolkit for AWS Builder ID accounts — batch registration, token management, subscription automation, and health monitoring. English fork of [GALIAIS/k_i_r_o-register](https://github.com/GALIAIS/k_i_r_o-register).

> **Legal notice.** This project is for educational and research purposes only. Selling, redistributing, or using it for any commercial purpose is strictly prohibited. You use it entirely at your own risk.

---

## Features

- Automated registration flow (headless mode supported)
- Pluggable temp-mail backends (ShiroMail, YYDSMail) — easy to extend
- Automatic token refresh and account state monitoring
- Pro subscription automation (Stripe payment integration)
- Account health checks (ban detection, trial-status detection)
- Automatic retry on registration failure
- Randomized browser fingerprint and anti-detection
- Local SQLite database for account storage

## Requirements

- Python 3.11+ (the prebuilt Windows release targets 3.11)
- Windows, macOS, or Linux (the GUI uses Tkinter — bundled with CPython on Windows/macOS; on Linux you may need `sudo apt install python3-tk`)
- A working network connection (registration hits AWS OIDC endpoints)
- Optional: a [YesCaptcha](https://yescaptcha.com) or [Multibot](https://multibot.cloud) API key if you want automatic hCaptcha solving

## Installation

```bash
# Clone
git clone https://github.com/YOUR_FORK/k_i_r_o-register-en.git
cd k_i_r_o-register-en

# Create and activate a virtualenv (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install the Chromium runtime Playwright drives
python -m playwright install chromium
```

### Key Python dependencies

| Package | Purpose |
|---|---|
| `playwright` | Headless Chromium automation |
| `playwright-stealth` | Anti-bot detection patches |
| `curl_cffi` | TLS fingerprint impersonation |
| `requests` | Plain HTTP calls where TLS impersonation isn't needed |
| `cryptography` | Token encryption at rest |
| `tkinter` | Desktop GUI (bundled with Python; `apt install python3-tk` on Linux) |

## Running the tool

```bash
python main.py
```

A desktop window opens. On first launch the app generates `kiro_config.json` next to `main.py` — that's where your mail-provider settings, YesCaptcha key, and CDK codes live. The file is gitignored and never committed.

### First-run checklist inside the GUI

1. **Mail provider tab.** Pick a provider (ShiroMail or YYDSMail), paste its base URL and API key, choose a domain, click *Test*.
2. **Captcha tab (optional).** Paste an API key for either **YesCaptcha** or **Multibot**, then pick the active provider from the dropdown. Without any key the tool falls back to manual solving and registration will pause for you.
3. **Registration tab.** Set the concurrency, pick headless or headed mode, click *Start*. Progress streams into the log pane.
4. **Accounts tab.** Inspect every account's token, expiry, trial status, and ban state. Refresh or re-subscribe from the toolbar.

## Packaging a Windows .exe

The repo ships a PyInstaller build script and a matching `build.bat`:

```cmd
:: From a Windows shell with Python on PATH
build.bat
```

The output lands in `dist\KiroProManager\KiroProManager.exe`. The `build.py` script bundles the Playwright Chromium runtime, `curl_cffi` native libs, and the `mail_providers` package so the exe is self-contained.

GitHub Actions also builds a release zip on every `v*` tag — see `.github/workflows/build.yml`.

## Project layout

```
main.py              # Tkinter GUI + account manager
kiro_register.py     # Registration state machine
kiro_subscribe.py    # Subscription management API
kiro_login.py        # Manual login helper (OAuth token capture)
stripe_pay.py        # Stripe Checkout automation
captcha_solver.py    # hCaptcha solver (pluggable: YesCaptcha or Multibot)
roxy_register.py     # Registration via RoxyBrowser fingerprint profiles
build.py             # PyInstaller packaging driver
build.bat            # Windows one-shot build entry point
mail_providers/      # Pluggable temp-mail backends
  base.py            # Abstract MailProvider base class
  shiromail.py       # ShiroMail implementation
  yydsmail.py        # YYDSMail implementation
```

## Adding a new mail provider

1. Create `mail_providers/myprovider.py`
2. Subclass `MailProvider` from `base.py`
3. Implement `create_mailbox`, `wait_otp`, `list_domains`
4. Register it in `mail_providers/__init__.py`'s `PROVIDERS` dict
5. It shows up in the GUI's provider dropdown automatically

## Configuration file (`kiro_config.json`)

Auto-generated on first run. Example:

```json
{
  "mail_provider": "shiromail",
  "shiromail": {
    "base_url": "https://example.com",
    "api_key": "...",
    "domain_id": 1
  },
  "yescaptcha_api_key": "",
  "multibot_key": "",
  "captcha_provider": "yescaptcha",
  "cdk_codes": []
}
```

## Captcha providers

The hCaptcha solver is pluggable. Pick one at runtime via either the GUI dropdown or the `CAPTCHA_PROVIDER` env var:

| Provider | Env var for the key | Endpoint | Notes |
|---|---|---|---|
| `yescaptcha` (default) | `YESCAPTCHA_API_KEY` | `https://api.yescaptcha.com` | JSON API; simpler pricing tiers |
| `multibot` | `MULTIBOT_API_KEY` | `https://api.multibot.cloud` | Cheaper per-solve; classic 2captcha-style API |

Both keys can be stored simultaneously — only the provider selected in `CAPTCHA_PROVIDER` / the GUI dropdown is used for the active run.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `playwright._impl._api_types.Error: Executable doesn't exist` | Run `python -m playwright install chromium` |
| GUI opens but crashes immediately on Linux | Missing Tk: `sudo apt install python3-tk` |
| hCaptcha never solves | Open Settings, paste a key for either YesCaptcha or Multibot, then pick the active provider in the dropdown — empty key = manual solve |
| `401` on subscription flow | Token expired or account banned. Inspect the account row in the Accounts tab |
| Registration hangs on email OTP | Mail provider unreachable or API key wrong — test it in the Mail provider tab |

## Credits

Original project by [GALIAIS](https://github.com/GALIAIS) and the [LINUX DO community](https://linux.do). This fork is a straight English translation of strings, comments, and docs — runtime behaviour is intentionally unchanged.
