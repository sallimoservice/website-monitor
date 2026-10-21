import _paths
import copy, glob, json, os, shutil, subprocess, sys, email
from email import policy
SP = os.environ["SP"]
OLD = json.load(open(f"{SP}/mig/state_old.json"))
names = {}                                   # state id -> "Limo NN" (only for readable output)
import hashlib, hmac
for n, s in enumerate(json.load(open(f"{SP}/sites17.json")), start=1):
    sid = hmac.new(b"realsalt", s["url"].strip().lower().rstrip("/").encode(), hashlib.sha256).hexdigest()[:16]
    names[sid] = s["name"]
def setmodes(d): json.dump(d, open(f"{SP}/dyn_modes.json", "w"))
def mails(): return sorted(glob.glob(f"{SP}/mail_migration/*.eml"))
import cf_server, fake_smtp
cf_server.start(); fake_smtp.start()
def rejuvenate(st):   # the fixture is absolute-dated, so move its clock to "the old run was 10 minutes ago"
    return _paths.age_state(st, 600)
def run_new(label, mutate, modes):
    state = rejuvenate(copy.deepcopy(OLD)); mutate(state)
    path = f"{SP}/mig/state_{label}.json"; json.dump(state, open(path, "w"))
    setmodes(modes); before = len(mails())
    env = dict(os.environ, SITES_FILE=f"{SP}/sites17.json", STATE_PATH=path, STATE_SALT="realsalt", RETRY_GAP_SECONDS="1",
               TEXT_RECHECK_GAP_SECONDS="1", NO_PROXY="*", no_proxy="*", SMTP_HOST="localhost", SMTP_PORT="465", SMTP_USER="alerts@test.com",
               SMTP_PASSWORD="SuperSecret123", SMTP_FROM="alerts@test.com", EMAIL_TO="me@test.com", SSL_CERT_FILE=f"{SP}/certs/cert.pem")
    env.pop("HTTPS_PROXY", None); env.pop("https_proxy", None)
    p = _paths.run_monitor([], env)
    out = p.stdout + p.stderr
    new = mails()[before:]; alerts = []
    for f in new:
        m = email.message_from_string(open(f, encoding="utf-8").read(), policy=policy.default)
        for b in m.get_body(preferencelist=("plain",)).get_content().split("-" * 40):
            head = b.strip().splitlines()[0] if b.strip() else ""
            if head: alerts.append(head)
    after = json.load(open(path))
    return {"rc": p.returncode, "fresh_start": "STATE WAS MISSING" in out, "crash": "Traceback" in out or "crashed" in out,
            "emails": len(new), "alerts": alerts, "state": after, "before": state, "out": out}
def show(label, r, expect):
    ok = (r["rc"] == 0 and not r["fresh_start"] and not r["crash"] and r["alerts"] == expect)
    print(("PASS  " if ok else "FAIL  ") + label)
    print(f"        exit={r['rc']}  fresh start={r['fresh_start']}  crash={r['crash']}  emails={r['emails']}  alerts={r['alerts'] or 'none'}")
    return ok
allok = True
slow03 = {"03": "slow"}

print("== N1  first run after merge, nothing has changed since the old run")
r = run_new("n1", lambda s: None, slow03); allok &= show("no alert storm: 0 alerts", r, [])
st, before = r["state"], r["before"]
hist_ok = all(st["sites"][k]["history"][:len(v["history"])] == v["history"] for k, v in before["sites"].items())
print(f"        history of all {len(before['sites'])} sites kept (old rows are the first rows of the new ones): {hist_ok}   rows per site now: {sorted({len(v['history']) for v in st['sites'].values()})}")
allok &= hist_ok
down = [names[k] for k, v in st["sites"].items() if v["status"] == "down"]
print(f"        Limo 17 (DOWN in old file) still DOWN, no new email: {down}   down_since unchanged: {st['sites'][[k for k,n in names.items() if n=='Limo 17'][0]]['down_since'] == before['sites'][[k for k,n in names.items() if n=='Limo 17'][0]]['down_since']}")
allok &= down == ["Limo 17"]
newf = ["last_up_at", "last_state", "baseline_hash", "baseline_learned_at", "down_signal", "cloudflare_seen", "inspection_blocked"]
print(f"        new fields filled in on every site silently: {all(all(f in v for f in newf) for v in st['sites'].values())}   baseline_hash all empty (nothing learned yet): {all(v['baseline_hash'] is None for v in st['sites'].values())}")
from collections import Counter
print("        labels now:", dict(Counter(v["last_state"] for v in st["sites"].values())))
print(f"        state version in file: {before['version']} -> {st['version']}")

print("\n== N2  one UP site genuinely fails (Limo 14 returns Cloudflare 522 on all 3 visits)")
r = run_new("n2", lambda s: None, {"03": "slow", "14": "522"}); allok &= show("exactly ONE alert, for the site that changed", r, ["🔴 DOWN - Limo 14"])

print("\n== N3  nine hours later, Limo 17 is still down (8 hour reminder rule)")
def shift(s, secs=9 * 3600):
    s["meta"]["last_run"] -= secs; s["meta"]["created"] -= secs
    for v in s["sites"].values():
        for f in ("down_since", "down_notified_at", "last_slow_alert", "last_refused_alert"):
            if v.get(f): v[f] -= secs
        v["history"] = [[r_[0] - secs, r_[1], r_[2]] for r_ in v["history"]]
r = run_new("n3", shift, slow03); allok &= show("exactly ONE alert, the reminder for the site still down", r, ["🔴 STILL DOWN - Limo 17"])

print("\n== N4  a recovery email from the old run never got delivered (pending_recovery in the old file)")
def pend(s):
    sid = [k for k, n in names.items() if n == "Limo 05"][0]
    import time
    s["sites"][sid]["pending_recovery"] = {"down_since": time.time() - 3600, "recovered_at": time.time() - 600}
r = run_new("n4", pend, slow03); allok &= show("exactly ONE alert, the undelivered RECOVERED", r, ["✅ RECOVERED - Limo 05"])
print("        wording:", [l for l in r["out"].splitlines() if "Email sent" in l][:1])

print("\n== N5  even if the old history held 'up'/'down' words or nulls, nothing breaks")
def weird(s):
    for i, v in enumerate(s["sites"].values()):
        v["history"] = [[row[0], ("up" if i % 3 == 0 else ("down" if i % 3 == 1 else None)), row[2]] for row in v["history"]]
r = run_new("n5", weird, slow03); allok &= show("no crash, no alerts", r, [])
print("\nRESULT:", "ALL PASSED" if allok else "SOMETHING FAILED")
