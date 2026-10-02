#!/usr/bin/env python3
"""
wazuh-alert-summary.py - summarize the last N days of Wazuh alerts for triage.

Read-only. Uses the Sentinel integration config (/etc/sentinel/wazuh.json, root-only):
the read-only indexer account and the pinned certificate fingerprint recorded at setup.
No passwords are printed or written anywhere.

Usage (on the Wazuh server):
    sudo python3 wazuh-alert-summary.py            # last 3 days
    sudo python3 wazuh-alert-summary.py --days 7 --top 40
    sudo python3 wazuh-alert-summary.py --out ~/alert-summary.md

Output is Markdown: totals by severity, alerts per day, per agent, and the top
rule+agent combinations with first/last seen, so repeat noise stands out.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import ssl
import sys
import urllib.parse
from datetime import datetime

CONF_FILE = "/etc/sentinel/wazuh.json"
TUNED_RULES = ("100100", "100101", "100102", "100103", "100104")


def load_conf(path):
    try:
        with open(path) as f:
            conf = json.load(f)
    except PermissionError:
        sys.exit("Can't read %s. Run with sudo." % path)
    except FileNotFoundError:
        sys.exit("%s not found. Run Sentinel's --wazuh-setup first." % path)
    for k in ("indexer", "user", "password"):
        if not conf.get(k):
            sys.exit("%s is missing '%s'." % (path, k))
    return conf


def search(conf, body):
    r = request(conf, "POST", "/wazuh-alerts-*/_search", body)
    sh = r.get("_shards") or {}
    if sh.get("failed"):
        reasons = sorted({((f.get("reason") or {}).get("reason") or str(f.get("reason")))[:300]
                          for f in sh.get("failures") or []})
        sys.exit("Indexer: %s of %s shards failed:\n  - %s" % (sh["failed"], sh.get("total"), "\n  - ".join(reasons)))
    return r


def request(conf, method, path, body=None):
    base = conf["indexer"]
    u = urllib.parse.urlsplit(base)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # self-signed; trust comes from the pinned fingerprint
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=30, context=ctx)
    try:
        conn.connect()
        want = (conf.get("pins") or {}).get(base)
        got = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if not want:
            sys.exit("No pinned certificate for %s. Re-run Sentinel's --wazuh-setup." % base)
        if not hmac.compare_digest(want, got):
            sys.exit("Indexer certificate changed since setup. Refusing to connect.")
        auth = base64.b64encode(("%s:%s" % (conf["user"], conf["password"])).encode()).decode()
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
        r = conn.getresponse()
        raw = r.read()
        if r.status >= 400:
            sys.exit("Indexer answered HTTP %d: %s" % (r.status, raw[:200].decode("utf-8", "replace")))
        return json.loads(raw)
    finally:
        conn.close()


def sev(level):
    return "critical" if level >= 15 else "high" if level >= 12 else "medium" if level >= 7 else "low"


def short_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%m-%d %H:%M")
    except Exception:
        return ts or "?"


def rule_agent_agg(size):
    return {"terms": {"field": "rule.id", "size": size, "order": {"_count": "desc"}},
            "aggs": {"lvl": {"max": {"field": "rule.level"}},
                     "desc": {"terms": {"field": "rule.description", "size": 1}},
                     "mitre": {"terms": {"field": "rule.mitre.id", "size": 3}},
                     "agents": {"terms": {"field": "agent.name", "size": 10},
                                "aggs": {"first": {"min": {"field": "timestamp"}},
                                         "last": {"max": {"field": "timestamp"}}}}}}


def rule_agent_rows(agg):
    rows = []
    for b in agg.get("buckets", []):
        lvl = int(b["lvl"]["value"] or 0)
        desc = ((b["desc"]["buckets"] or [{}])[0].get("key") or "").replace("|", "/").strip()[:80]
        mitre = ",".join(m["key"] for m in b["mitre"]["buckets"]) or "-"
        for ag in b["agents"]["buckets"]:
            rows.append((ag["doc_count"], b["key"], lvl, ag["key"], desc, mitre,
                         ag["first"].get("value_as_string"), ag["last"].get("value_as_string")))
    return rows


def build_aggs(top):
    return {
        "sev": {"range": {"field": "rule.level", "ranges": [
            {"key": "low (0-6)", "to": 7}, {"key": "medium (7-11)", "from": 7, "to": 12},
            {"key": "high (12-14)", "from": 12, "to": 15}, {"key": "critical (15+)", "from": 15}]}},
        "day": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "format": "yyyy-MM-dd"}},
        "agent": {"terms": {"field": "agent.name", "size": 50},
                  "aggs": {"max": {"max": {"field": "rule.level"}}}},
        # rule -> agent nesting with plain terms/min/max only. (multi_terms + top_hits trips an
        # OpenSearch bug: "Scorable.score() because this.scorer is null" on some shards.)
        "combo": rule_agent_agg(max(top, 10) * 2),
        "hi": {"filter": {"range": {"rule.level": {"gte": 10}}}, "aggs": {"r": rule_agent_agg(50)}},
        "tuned": {"filter": {"terms": {"rule.id": list(TUNED_RULES)}},
                  "aggs": {"by": {"terms": {"field": "rule.id", "size": 10}}}}
    }


def check(conf):
    """Print what the read-only account can see. No passwords or document contents are shown."""
    def safe(fn):
        try:
            return fn()
        except SystemExit as ex:
            return {"error": str(ex)}
    who = safe(lambda: request(conf, "GET", "/_plugins/_security/authinfo"))
    print("user:          ", who.get("user_name", who.get("error")))
    print("roles:         ", ", ".join(who.get("roles") or []) or "-")
    print("backend roles: ", ", ".join(who.get("backend_roles") or []) or "-")
    idx = safe(lambda: request(conf, "POST", "/wazuh-alerts-*/_search",
                               {"size": 0, "aggs": {"i": {"terms": {"field": "_index", "size": 500}}}}))
    if "error" in idx:
        print("alert indices: ", idx["error"])
    else:
        b = sorted(idx["aggregations"]["i"]["buckets"], key=lambda x: x["key"])
        print("alert indices visible: %d" % len(b))
        for i in b[-5:]:
            print("   %s  %s docs" % (i["key"], i["doc_count"]))
    for label, q in (("all time", {"match_all": {}}),
                     ("last 3 days", {"range": {"timestamp": {"gte": "now-3d"}}})):
        r = safe(lambda: request(conf, "POST", "/wazuh-alerts-*/_count", {"query": q}))
        print("count %-12s %s" % (label + ":", r.get("count", r.get("error", r))))
    r = safe(lambda: request(conf, "POST", "/wazuh-alerts-*/_search",
                             {"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp", "agent.name"]}))
    hits = ((r.get("hits") or {}).get("hits") or []) if isinstance(r, dict) else []
    print("newest alert:  ", (hits[0].get("_source") if hits else r.get("error", "none visible")))
    print("summary aggregations (each tested alone, last 3 days):")
    for name, agg in build_aggs(5).items():
        r = safe(lambda: search(conf, {"size": 0, "query": {"range": {"timestamp": {"gte": "now-3d"}}},
                                       "aggs": {name: agg}}))
        if "error" in r:
            print("   %-6s FAILED: %s" % (name, r["error"]))
        else:
            print("   %-6s ok (%d buckets)" % (name, len(r["aggregations"][name].get("buckets", [])
                                                     or r["aggregations"][name].get("by", {}).get("buckets", [])
                                                     or r["aggregations"][name].get("r", {}).get("buckets", []))))


DRILL_FIELDS = [
    # Indexed alert documents nest decoded fields under "data." (rules refer to them without it).
    # Windows / Sysmon
    "data.win.eventdata.image", "data.win.eventdata.sourceImage", "data.win.eventdata.targetImage",
    "data.win.eventdata.grantedAccess", "data.win.eventdata.parentImage", "data.win.eventdata.targetFilename",
    "data.win.eventdata.targetObject", "data.win.eventdata.details", "data.win.eventdata.commandLine",
    "data.win.eventdata.user", "data.win.eventdata.sourceUser", "data.win.eventdata.callTrace",
    "data.win.system.eventID",
    # Linux auditd / syslog / FIM
    "data.audit.exe", "data.audit.command", "data.audit.dev", "data.audit.type", "data.audit.auid",
    "data.audit.prom", "data.audit.old_prom", "syscheck.path", "data.title", "data.file",
    "predecoder.program_name", "location",
]


def drill(conf, a):
    rules = [r.strip() for r in a.drill.split(",") if r.strip()]
    flt = [{"range": {"timestamp": {"gte": "now-%dd" % a.days}}}, {"terms": {"rule.id": rules}}]
    if a.agent:
        flt.append({"term": {"agent.name": a.agent}})
    aggs = {"rule": {"terms": {"field": "rule.id", "size": 20}},
            "agent": {"terms": {"field": "agent.name", "size": 20}},
            "hour": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 1,
                                        "format": "MM-dd HH:00"}}}
    for i, f in enumerate(DRILL_FIELDS):
        aggs["f%d" % i] = {"terms": {"field": f, "size": 8}}
    r = search(conf, {"size": a.sample, "track_total_hits": True, "query": {"bool": {"filter": flt}}, "aggs": aggs,
                      "sort": [{"timestamp": "desc"}], "_source": ["timestamp", "agent.name", "full_log"]})
    ag = r.get("aggregations") or {}
    tot = (r.get("hits") or {}).get("total", 0)
    tot = tot.get("value", 0) if isinstance(tot, dict) else tot
    print("Drill-down: rule(s) %s%s, last %d day(s): %d events" % (
        ",".join(rules), " on " + a.agent if a.agent else "", a.days, tot))
    for name, key in (("rule", "rule"), ("agent", "agent")):
        print("  %-6s %s" % (name + ":", ", ".join("%s (%d)" % (b["key"], b["doc_count"]) for b in ag[key]["buckets"])))
    hrs = ag["hour"]["buckets"]
    if hrs:
        busiest = sorted(hrs, key=lambda b: -b["doc_count"])[:6]
        print("  busiest hours (UTC): " + ", ".join("%s=%d" % (b["key_as_string"], b["doc_count"]) for b in busiest))
    for i, f in enumerate(DRILL_FIELDS):
        bs = ag["f%d" % i]["buckets"]
        if not bs:
            continue
        print("\n  %s" % f)
        for b in bs:
            v = str(b["key"]).replace("\\\\", "\\")
            if f.endswith("callTrace"):
                # keep just the module names: C:\\...\\ntdll.dll+9d4f4|... -> ntdll|KERNELBASE|...
                v = " > ".join(m.split("\\")[-1].split("+")[0].rsplit(".", 1)[0] for m in v.split("|"))
            print("    %6d  %s" % (b["doc_count"], v[:220]))
    for h in (r.get("hits") or {}).get("hits") or []:
        src = h.get("_source") or {}
        print("\n  sample %s %s:\n    %s" % (src.get("timestamp"), (src.get("agent") or {}).get("name"),
                                         (src.get("full_log") or "(no full_log)")[:1500]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--top", type=int, default=30, help="rule+agent rows to show")
    ap.add_argument("--min-level", type=int, default=0)
    ap.add_argument("--conf", default=CONF_FILE)
    ap.add_argument("--out", help="also write the report to this file")
    ap.add_argument("--check", action="store_true", help="diagnose access: who am I, what can I see")
    ap.add_argument("--drill", help="rule ID(s), comma-separated: show what's behind them (programs, files, rights)")
    ap.add_argument("--agent", help="limit --drill to one agent name")
    ap.add_argument("--sample", type=int, default=0, help="with --drill: print the raw log of the N newest events")
    a = ap.parse_args()
    conf = load_conf(a.conf)
    if a.check:
        return check(conf)
    if a.drill:
        return drill(conf, a)

    rng = {"range": {"timestamp": {"gte": "now-%dd" % a.days}}}
    flt = [rng] + ([{"range": {"rule.level": {"gte": a.min_level}}}] if a.min_level else [])
    body = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": flt}},
        "aggs": build_aggs(a.top),
    }
    res = search(conf, body)
    aggs = res.get("aggregations") or {}
    total = (res.get("hits") or {}).get("total", 0)
    total = total.get("value", 0) if isinstance(total, dict) else int(total or 0)

    L = []
    L.append("# Wazuh alert summary: last %d day(s)" % a.days)
    L.append("")
    L.append("Generated %s. Total alerts: **%d**%s." % (
        datetime.now().strftime("%Y-%m-%d %H:%M"), total,
        " (level >= %d)" % a.min_level if a.min_level else ""))
    L.append("")
    L.append("## By severity")
    L.append("| Severity | Alerts |")
    L.append("|---|---:|")
    for b in aggs.get("sev", {}).get("buckets", []):
        L.append("| %s | %d |" % (b["key"], b["doc_count"]))
    L.append("")
    L.append("## Per day")
    L.append("| Day | Alerts |")
    L.append("|---|---:|")
    for b in aggs.get("day", {}).get("buckets", []):
        L.append("| %s | %d |" % (b["key_as_string"], b["doc_count"]))
    L.append("")
    L.append("## Per agent")
    L.append("| Agent | Alerts | Highest level |")
    L.append("|---|---:|---:|")
    for b in aggs.get("agent", {}).get("buckets", []):
        L.append("| %s | %d | %d |" % (b["key"], b["doc_count"], int(b["max"]["value"] or 0)))
    L.append("")
    L.append("## Top rule + agent combinations")
    L.append("Repeating rows are tuning candidates; rare high-level rows deserve a closer look.")
    L.append("")
    L.append("| Count | Rule | Lvl | Sev | Agent | Description | MITRE | First | Last |")
    L.append("|---:|---|---:|---|---|---|---|---|---|")
    rows = rule_agent_rows(aggs.get("combo", {}))
    rows.sort(key=lambda r: (-r[0], -r[2]))
    for cnt, rid, lvl, agent, desc, mitre, first, last in rows[:a.top]:
        L.append("| %d | %s | %d | %s | %s | %s | %s | %s | %s |" % (
            cnt, rid, lvl, sev(lvl), agent, desc, mitre, short_ts(first), short_ts(last)))
    L.append("")
    L.append("## Level 10 and above (all of them, highest level first)")
    L.append("High-severity rules can be rare, so they're listed separately and never cut off by the count ranking.")
    L.append("")
    hi = rule_agent_rows((aggs.get("hi") or {}).get("r", {}))
    if hi:
        L.append("| Count | Rule | Lvl | Sev | Agent | Description | MITRE | First | Last |")
        L.append("|---:|---|---:|---|---|---|---|---|---|")
        for cnt, rid, lvl, agent, desc, mitre, first, last in sorted(hi, key=lambda r: (-r[2], r[0])):
            L.append("| %d | %s | %d | %s | %s | %s | %s | %s | %s |" % (
                cnt, rid, lvl, sev(lvl), agent, desc, mitre, short_ts(first), short_ts(last)))
    else:
        L.append("- none")
    L.append("")
    L.append("## Custom tuning rules still matching")
    tb = aggs.get("tuned", {}).get("by", {}).get("buckets", [])
    if tb:
        for b in tb:
            L.append("- rule %s: %d events (downgraded instead of alerting high)" % (b["key"], b["doc_count"]))
    else:
        L.append("- none in this window")
    L.append("")

    report = "\n".join(L)
    print(report)
    if a.out:
        with open(a.out, "w") as f:
            f.write(report + "\n")
        print("\nSaved to %s" % a.out, file=sys.stderr)


if __name__ == "__main__":
    main()
