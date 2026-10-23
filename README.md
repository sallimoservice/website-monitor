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

## How a DOWN alert is decided

The monitor runs on GitHub's servers, which is one single viewpoint. A hosting company can block that address
while the site works fine for everyone else. So a failure seen only from there is never called DOWN.

1. The monitor visits a site 3 times, at least 60 seconds apart. If it ever loads, the site is UP and that is the end of it.
2. A DNS failure needs no second opinion (two public resolvers outside GitHub already agree).
3. Any other would-be DOWN is checked from about 5 locations around the world with [Globalping](https://globalping.io),
   which is free and needs no sign-up. Only the failing site is sent (its host name and path, never a query
   string), healthy sites are never sent.
4. If most of those locations also fail, the monitor waits 5 minutes and repeats both checks. Only when both
   rounds agree is it a DOWN email, with the evidence (each location, its network, its result, both rounds and
   the monitor's own IP address).

| What happened | What you get |
|---|---|
| Outside locations fail in both rounds | DOWN, with evidence |
| The monitor fails but the outside locations load the site | a low priority WARNING, "the monitor may be blocked", at most once a day |
| The failure cleared on the second look | nothing |
| Globalping is rate limited, down, answers oddly, or too few locations answer, or they split evenly | a WARNING, "could not confirm", never a DOWN |
| 8 or more sites fail at the same moment | one WARNING for all of them |

"Back online" is only sent for a site that was confirmed DOWN. At most 5 sites are checked from outside per run.
To switch the whole thing off set the repository variable `CONFIRM_ENABLED` to `false` (DOWN then comes from the
monitor alone again). To see what Globalping really answers, run the workflow with "test_confirm" ticked, or
`python -m monitor.main --test-confirm`.
