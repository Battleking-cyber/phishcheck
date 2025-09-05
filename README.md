# PhishCheck — Phishing Page Detection (Author: Pankaj A)

A small CLI tool to check links for common phishing indicators.

## Features
- Heuristic checks: IP-based URL, suspicious TLDs, '@' character, SSL checks
- CLI & non-interactive mode for automation
- JSON output for machine consumption
- GitHub Actions CI (shellcheck + smoke test)

## Requirements
- bash (Linux / macOS)
- openssl
- (optional) timeout (for quicker SSL checks)

## Install
```bash
git clone https://github.com/<you>/phishcheck.git
cd phishcheck
chmod +x bin/phishcheck.sh
