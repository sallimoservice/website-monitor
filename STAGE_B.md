# Stage B and later (parked, not forgotten)

Written 21 Oct 2026 after the audit. Nothing here is being worked on. Each item says why it matters, so
it can be judged on its own later.

## Decisions already made (do not reopen without a reason)

- Flap detection: dropped. It needs about 21 samples and this monitor takes 3 a day. Output is already
  capped at one email per run.
- Retries stay fixed-interval (60 seconds apart, random stagger on the first visit). No backoff.
- The User-Agent stays as it is. Revisit only if a host starts blocking the monitor.
- The daily summary must not show an uptime percentage. At 3 samples a day the only possible values
  are 0, 33, 67 and 100, so a percentage would pretend to be precise. Show counts of what was seen.
- Real uptime for important sites belongs to an external monitor (HetrixTools and similar). This
  monitor is an 8-hourly sampler plus a content, certificate and hack watcher.
- Backstop. A commit to `main` must exist before 1 Dec 2026, or GitHub disables the schedule
  around 19 Dec (60 days after the last commit on 20 Oct, if only commits count).
- Heartbeat setup is the owner's job: Healthchecks check at 8 hours period and 2 hours grace, email
  integration confirmed, `HEALTHCHECK_URL` added as a repository secret before the merge. A check stays
  "New", and cannot alarm, until the first real run pings it. Dry runs never ping.

## Parked, in rough priority order

1. **State on an orphan branch** (`monitor-state`), instead of the Actions cache.
   Why. Caches evict after 7 days without access, are branch-scoped, and cannot be inspected. A branch
   gives history, a file you can open at 2am, and `git revert` for a bad state. Consider making the repo
   private at the same time (ends the 60-day rule, hides state). Not verified: free Actions minutes for
   private repos, and whether a commit to a non-default branch counts as repository activity.
2. **State shape validation. DONE** (audit fix): wrong-typed values are reset, a site entry that is not an
   object is dropped, and the run carries on instead of crashing every time.
3. **Wording after a gap.** After a long silence an alert can say "Down for 193 hours" or "Downtime up to
   201 hours" about time the monitor was not running. Add a "the monitor did not run between X and Y"
   line, and stop using the fixed "checked every 8 hours" text, which is wrong after a dropped run.
4. **TLS expiry at 30, 14 and 7 days**, once per threshold, reset on renewal, on the certificate
   actually served. Plus **domain expiry** (RDAP). Both were in the original brief and were never built.
   Today only an already-invalid certificate is reported.
5. **Crash email wording.** After a send failure the "monitor is broken" step still runs, so flaky email
   can produce a "crashed" message next to pending alerts. Separate a real crash from a delivery
   failure (suggested: distinct exit codes, and a different message for a total channel failure). The
   same wrong message now also appears when a Healthchecks ping cannot be delivered.
6. **"Silent but notable" log line.** List every site in UNKNOWN or INSPECTION_BLOCKED with the reason,
   in the run summary only (no email), so a permanent 403 is visible.
7. **Keep-alive** so the 60-day shutdown cannot happen: a weekly workflow that adds an empty commit to
   `main` only if the last commit is older than 30 days. Needs `contents: write`. Not verified: that a
   bot commit counts as repository activity. The Healthchecks alarm is the independent backstop.
8. **Maintenance windows.** A per-site "quiet until" date so planned work does not send reminders
   every 8 hours.
9. **Verification scripts. DONE on 21 Oct 2026**, kept here as a reminder of what they need. They live in
   `verification/` and run with `python verification/run_all.py`. They need the `openssl` command, git
   history (the Stage 1 comparison rebuilds commit 6a5c558) and permission to listen on localhost port 465
   (root on Linux, because the monitor only uses SSL mail on exactly port 465). A suite that cannot run says
   SKIPPED, and a skip is never counted as a pass. One documented known gap is asserted as it is today (the
   wording after a gap), so fixing item 3 above will make those rows fail on purpose and the expectation
   must then be updated.
10. **Smaller ones.** (A second opinion for "connection refused" is now built in: every would-be DOWN is
    confirmed from outside locations, see `monitor/checks/confirm.py`.) A cap on reminder emails for very long outages, SETTINGS HELP wording for `behind_cloudflare` (it only matters before a Cloudflare
    response has been seen, and it hides certificate warnings), daily summary lines for DNS degraded,
    unrecognised Cloudflare codes and a rebuilt state.

11. **A second free confirmation source.** `ConfirmationSource` in `monitor/checks/confirm.py` is a two-member
    interface (`name`, `check(site, runner_result) -> Confirmation`), so a Cloudflare Worker or a GitLab CI job can
    be added to `build_sources` without touching the decision logic. Today only Globalping is asked. Useful if
    Globalping's probes turn out to be blocked by the same hosts as the runner, or if its free limit is too tight.

## Stage C and D (unchanged from the earlier plan)

- Stage C. README for a beginner, and the full test suite (the `tests/` folder is the start of it,
  standard library `unittest`, run with `python -m unittest discover -s tests`).
- Stage D. Content and hack checks (change detection, defacement words, spam, injected scripts,
  robots.txt, sitemap), at most 5 page requests per site per run.

## What the audit could not verify (check these yourself)

- The exact GitHub wording on cache branch scope. See Actions, then Caches in the repository.
- Whether Pingdom confirms failures from a second location. The UptimeRobot claim is its own.
- Cloudflare's official text for 524, 526, 527 and 530. The 520 reading comes from hosting guides and
  from the real Galaxy Town Car incident.
- Whether a restore from a branch counts as an access that resets the 7-day cache clock.
