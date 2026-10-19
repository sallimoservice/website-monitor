# Website Monitor

Free website uptime and security alerts that run on GitHub Actions. Alerts arrive by email (and WhatsApp, coming in the next stage).

> **Work in progress.** Stage 1 is built (uptime checks, email alerts, workflow). The full beginner guide is written in the last stage.

## Quick local test (Stage 1)

1. Install Python 3.11 or newer, then run `pip install -r requirements.txt`.
2. Copy `.env.example` to `.env` and fill in your email settings.
3. Copy `sites.example.json` to `sites.json` and put your real websites in it.
4. Check everything without sending anything: `python -m monitor.main --dry-run`
5. Send a test email: `python -m monitor.main --test-alert`
6. Real run: `python -m monitor.main`

`.env`, `sites.json` and `state.json` are ignored by git, so your real data is never uploaded.
