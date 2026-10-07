# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems.

Report it privately through GitHub instead:
<https://github.com/KevinTechLabs/Homelab-SIEM-Detection-Lab/security/advisories/new>
(**Security → Report a vulnerability**). Include what you found, how to
reproduce it, and what an attacker could do with it. You'll get a reply within
a few days. Please allow up to 90 days for a fix before disclosing the issue
publicly.

If you spot something in this repository that looks like a real credential,
token, address or other private detail, please report it the same way.

## Supported versions

Only the latest commit on `main` is supported.

## What's already in place

- All addresses use a fake `10.20.x.x` plan. No credentials, keys or real IPs are published.
- The Wazuh API, indexer and syslog ports are bound to `127.0.0.1`; agents connect on 1514/1515 only.
- The vulnerable lab target runs on an isolated VLAN and is published only on loopback.
- `scripts/wazuh-alert-summary.py` is read-only.
