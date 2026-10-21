"""Shared set-up for the verification suites. Import this first.

It puts the repository on sys.path, builds a throw-away work folder (fake certificates, copies of
the fixture files, an empty mail folder) and points the environment variable SP at it. Nothing in
the repository is written to, and nothing leaves this machine: all the fake sites, the fake mail
server and the fake Healthchecks listen on localhost, and DNS-over-HTTPS is replaced by a stand-in
so a run gives the same answers with or without internet.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
# VERIFY_USE_PYTHONPATH=1 keeps whatever copy of the code the caller put on PYTHONPATH (used to run the
# same scenarios against the frozen Stage 1 code). Otherwise the repository in front of this folder is used.
for path in ((str(HERE),) if os.environ.get("VERIFY_USE_PYTHONPATH") else (str(ROOT), str(HERE))):
    if path not in sys.path:
        sys.path.insert(0, path)

SKIP_EXIT_CODE = 77   # "this suite could not run here" (never counted as a pass)


def skip(reason: str):
    print(f"SKIPPED: {reason}", flush=True)
    sys.exit(SKIP_EXIT_CODE)


def _make_certs(folder: pathlib.Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    if (folder / "cert.pem").exists():
        return
    if not shutil.which("openssl"):
        skip("the openssl command is needed to make the fake certificate")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(folder / "key.pem"), "-out", str(folder / "cert.pem")],
        check=True, capture_output=True,
    )


def _prepare_work_folder() -> str:
    work = os.environ.get("SP")
    if not work:
        work = tempfile.mkdtemp(prefix="monitor-verification-")
        os.environ["SP"] = work
    folder = pathlib.Path(work)
    for name in ("sites17", "hc_sites", "ok_sites", "group_sites"):
        shutil.copy(HERE / "fixtures" / f"{name}.json", folder / f"{name}.json")
    for sub in ("mig", "mail_migration", "r6", "audit"):
        (folder / sub).mkdir(exist_ok=True)
    shutil.copy(HERE / "fixtures" / "state_old_v1.json", folder / "mig" / "state_old.json")
    _make_certs(folder / "certs")
    return str(folder)


SP = _prepare_work_folder()


def hermetic_dns() -> None:
    """Replace DNS-over-HTTPS with a stand-in: every name resolves except ".invalid" names."""
    try:
        from monitor.checks import network
    except ImportError:   # the frozen Stage 1 code has no DNS module
        return
    network._doh_query = lambda url, host, rtype: "NXDOMAIN" if host.endswith(".invalid") else "OK"


hermetic_dns()


def age_state(state: dict, seconds_since_last_run: float = 600) -> dict:
    """Move every timestamp in a saved state so that its last run was `seconds_since_last_run` ago.

    The fixtures hold absolute times from the day they were made. Always age them with this, so a
    fixture never goes stale as the calendar moves (an old reminder never becomes "due" by accident).
    """
    shift = (time.time() - seconds_since_last_run) - state["meta"]["last_run"]
    for key in ("last_run", "created", "started_notified"):
        if state["meta"].get(key):
            state["meta"][key] += shift
    for site in state["sites"].values():
        for key in ("down_since", "down_notified_at", "last_slow_alert", "last_refused_alert", "last_up_at", "baseline_learned_at"):
            if site.get(key):
                site[key] += shift
        site["history"] = [[row[0] + shift, row[1], row[2]] for row in site["history"]]
        pending = site.get("pending_recovery")
        if pending:
            site["pending_recovery"] = {k: (v + shift if isinstance(v, (int, float)) else v) for k, v in pending.items()}
    return state


def run_monitor(args, env, timeout=250):
    """Run the real command line (python -m monitor.main) with the stand-in DNS and no mail retry delay."""
    code = (
        "import sys; from monitor.checks import network; "
        "network._doh_query = lambda url, host, rtype: 'NXDOMAIN' if host.endswith('.invalid') else 'OK'; "
        "import monitor.notifiers.email_smtp as e; e.RETRY_DELAY_SECONDS = 0; "
        "from monitor.main import main; sys.exit(main(%r))" % (list(args),)
    )
    env = dict(env)
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        env.pop(name, None)
    return subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=timeout)
