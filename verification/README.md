# Verification suites

One command runs everything (the unit tests in `tests/` and every suite here) and prints one count:

    python verification/run_all.py

Useful options: `--only round6` (one suite), `--allow-skips`, `--keep` (keep the throw-away work folder).

Everything runs against fake services on localhost: `cf_server.py` (fake sites that behave like
Cloudflare, on ports 8083 and 8443), `fake_smtp.py` (mail server on port 465, writes `.eml` files),
`fake_healthchecks.py` (port 8084). Nothing touches the internet, and DNS-over-HTTPS is replaced by a
stand-in, so the result is the same with or without a network. The fake certificate is made fresh for
every run with `openssl`. All files are written to a temporary folder, never into the repository.

## Needs

- Python 3.11 or newer, the `openssl` command, `git` history for the Stage 1 comparison.
- Permission to listen on localhost port 465 (root on Linux). Without it the suites that need mail say
  SKIPPED and the run does not count as green. This is deliberate: the monitor only uses SSL mail on
  exactly port 465, so the fake has to be there.

## Fixtures and the clock

`fixtures/state_old_v1.json` is a real version 1 state (17 sites) produced by running the Stage 1 code
through a real timeline. Its timestamps are from the day it was made, so every suite ages it with
`_paths.age_state(...)` ("the last run was N seconds ago") before use. A test in `tests/` fails if a suite
reads it without aging it, or hard-codes a date. The regression suite deliberately uses a frozen clock
(seconds from an arbitrary start).

## Suites

| Suite | Covers |
|---|---|
| `suite_stage_a.py` | Cloudflare-aware classification, retries, evidence, labels |
| `suite_round2.py` | labels, per-site flags, history, dry-run table, email text |
| `suite_round3.py` | Cloudflare 1xxx pages, DNS evidence, retry gap, settings help, dry runs and the cache |
| `suite_round4.py` | stagger, rest between visits, load on healthy and failing sites |
| `suite_round5.py` | Cloudflare overload, challenge look-alikes, shared hosting, masking |
| `suite_round6.py` | email failure and heartbeat order, clean start, dry-run report and lock |
| `suite_migration.py` | an old-format state read by today's code, five scenarios |
| `suite_regression.py` | 15 scenarios against the frozen Stage 1 code (rebuilt from git), three approved differences |
| `suite_refused_timeline.py` | `connection_refused_is_warning` over time |
| `suite_request_rules.py` | the request itself and how plain answers are read |
| `suite_corrupt_state.py` | damaged state files, including documented known gaps |
| `suite_stale_state.py` | an 8-day-old state, including documented known gaps |
| `suite_load_and_timing.py` | requests per site per run, and the time a bad run takes |

The "round" names are historical (the order the suites were written in).

Two rows assert a **known gap** as it is today (see `STAGE_B.md`). When that gap is fixed the row fails
on purpose and the expectation must be changed.
