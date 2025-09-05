# phishcheck
phish-detector,   phishing-url-scanner, phish-guard,  anti-phish
phishcheck/                  # repo root
├─ bin/
│  └─ phishcheck.sh
├─ docs/
│  └─ design.md
├─ .github/
│  └─ workflows/
│     └─ ci.yml
├─ .gitignore
├─ README.md
├─ LICENSE
├─ CHANGELOG.md
├─ CONTRIBUTING.md
└─ logs/                     # runtime logs (gitignored)


Usage

# Interactive
bin/phishcheck.sh

# Non-interactive (suitable for CI)
bin/phishcheck.sh --url "https://example.com" --output json --noninteractive
