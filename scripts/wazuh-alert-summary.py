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
TUNED_RULES = ("100100", "100101", "100102", "100103")


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
    return request(conf, "POST", "/wazuh-alerts-*/_search", body)


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
    idx = safe(lambda: request(conf, "GET", "/_cat/indices/wazuh-alerts-*?format=json&h=index,docs.count"))
    if isinstance(idx, list):
        print("alert indices visible: %d" % len(idx))
        for i in sorted(idx, key=lambda x: x["index"])[-5:]:
            print("   %s  %s docs" % (i["index"], i["docs.count"]))
    else:
        print("alert indices: ", idx.get("error", idx))
    for label, q in (("all time", {"match_all": {}}),
                     ("last 3 days", {"range": {"timestamp": {"gte": "now-3d"}}})):
        r = safe(lambda: request(conf, "POST", "/wazuh-alerts-*/_count", {"query": q}))
        print("count %-12s %s" % (label + ":", r.get("count", r.get("error", r))))
    r = safe(lambda: request(conf, "POST", "/wazuh-alerts-*/_search",
                             {"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp", "agent.name"]}))
    hits = ((r.get("hits") or {}).get("hits") or []) if isinstance(r, dict) else []
    print("newest alert:  ", (hits[0].get("_source") if hits else r.get("error", "none visible")))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--top", type=int, default=30, help="rule+agent rows to show")
    ap.add_argument("--min-level", type=int, default=0)
    ap.add_argument("--conf", default=CONF_FILE)
    ap.add_argument("--out", help="also write the report to this file")
    ap.add_argument("--check", action="store_true", help="diagnose access: who am I, what can I see")
    a = ap.parse_args()
    conf = load_conf(a.conf)
    if a.check:
        return check(conf)

    rng = {"range": {"timestamp": {"gte": "now-%dd" % a.days}}}
    flt = [rng] + ([{"range": {"rule.level": {"gte": a.min_level}}}] if a.min_level else [])
    body = {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": flt}},
        "aggs": {
            "sev": {"range": {"field": "rule.level", "ranges": [
                {"key": "low (0-6)", "to": 7}, {"key": "medium (7-11)", "from": 7, "to": 12},
                {"key": "high (12-14)", "from": 12, "to": 15}, {"key": "critical (15+)", "from": 15}]}},
            "day": {"date_histogram": {"field": "timestamp", "calendar_interval": "day", "format": "yyyy-MM-dd"}},
            "agent": {"terms": {"field": "agent.name", "size": 50},
                      "aggs": {"max": {"max": {"field": "rule.level"}}}},
            "combo": {"multi_terms": {"terms": [{"field": "rule.id"}, {"field": "agent.name"}],
                                      "size": a.top, "order": {"_count": "desc"}},
                      "aggs": {"first": {"min": {"field": "timestamp"}},
                               "last": {"max": {"field": "timestamp"}},
                               "info": {"top_hits": {"size": 1, "_source": ["rule.level", "rule.description",
                                                                            "rule.mitre.id"]}}}},
            "tuned": {"filter": {"terms": {"rule.id": list(TUNED_RULES)}},
                      "aggs": {"by": {"terms": {"field": "rule.id", "size": 10}}}},
        },
    }
    res = search(conf, body)
    aggs = res.get("aggregations") or {}
    total = (res.get("hits") or {}).get("total", {}).get("value", 0)

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
    for b in aggs.get("combo", {}).get("buckets", []):
        rid, agent = b["key"][0], b["key"][1]
        src = ((b["info"]["hits"]["hits"] or [{}])[0].get("_source") or {}).get("rule") or {}
        lvl = int(src.get("level") or 0)
        desc = (src.get("description") or "").replace("|", "/").strip()[:80]
        mitre = ",".join((src.get("mitre") or {}).get("id") or []) or "-"
        L.append("| %d | %s | %d | %s | %s | %s | %s | %s | %s |" % (
            b["doc_count"], rid, lvl, sev(lvl), agent, desc, mitre,
            short_ts(b["first"].get("value_as_string")), short_ts(b["last"].get("value_as_string"))))
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
