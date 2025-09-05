#!/usr/bin/env bash
# ==========================================================
# Phishing Page Detection Tool
# Author: Pankaj A
# Version: 1.0.0
# Description: CLI tool to check a URL for common phishing indicators.
# Usage: bin/phishcheck.sh --url "https://example.com" [--output json|pretty] [--noninteractive]
# ==========================================================
set -euo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
AUTHOR="Pankaj A"
LOGDIR="./logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/phishcheck.log"
TMPCERT="$(mktemp -u)"
CLEANUPS=()

cleanup() {
  for f in "${CLEANUPS[@]}"; do
    [[ -f "$f" ]] && rm -f "$f"
  done
}
trap cleanup EXIT

print_banner() {
  local CYAN="\e[36m" RESET="\e[0m"
  echo -e "=================================================="
  echo -e " 🛡️  Phishing Page Detection Tool"
  echo -e " 👨‍💻 Author: ${CYAN}${AUTHOR}${RESET}    Version: ${VERSION}"
  echo -e "=================================================="
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]
Options:
  -u, --url URL            URL to analyze
  -o, --output FORMAT      Output format: json|pretty  (default: pretty)
      --noninteractive     Do not prompt; fail if URL missing
  -h, --help               Show this help
  -v, --version            Print version
EOF
  exit 2
}

# Default values
output="pretty"
noninteractive=false
url=""

# Parse args (simple)
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) url="$2"; shift 2;;
    --url=*) url="${1#*=}"; shift;;
    -o|--output) output="$2"; shift 2;;
    --output=*) output="${1#*=}"; shift;;
    --noninteractive) noninteractive=true; shift;;
    -h|--help) usage;;
    -v|--version) echo "$VERSION"; exit 0;;
    *) echo "Unknown option: $1"; usage;;
  esac
done

# Interactive prompt if allowed
if [[ -z "$url" ]]; then
  if [[ "$noninteractive" = true ]]; then
    echo "Error: --url is required in noninteractive mode." >&2
    exit 2
  fi
  read -r -p "🔗 Enter the URL to check: " url
fi

# Normalize URL (add https:// if missing)
if ! [[ "$url" =~ ^https?:// ]]; then
  url="https://$url"
fi

print_banner
echo "🔍 Analyzing: $url"
score=0
declare -a issues
declare -a notes

# Extract domain
domain="${url#http://}"
domain="${domain#https://}"
domain="${domain%%/*}"

# Check 1: IP address instead of domain
if [[ "$domain" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  issues+=("Uses IP address instead of hostname")
  ((score+=3))
fi

# Check 2: Suspicious TLDs
suspicious_tlds=(xyz top tk ml ga cf gq)
for t in "${suspicious_tlds[@]}"; do
  if [[ "$domain" == *."$t" ]]; then
    issues+=("Suspicious TLD detected: .$t")
    ((score+=2))
    break
  fi
done

# Check 3: '@' symbol in URL
if [[ "$url" == *"@"* ]]; then
  issues+=("Contains '@' character")
  ((score+=2))
fi

# Check 4: Too many '-' characters in domain
dash_count=$(grep -o "-" <<< "$domain" | wc -l || echo 0)
if (( dash_count > 3 )); then
  issues+=("Excessive '-' characters in domain")
  ((score+=1))
fi

# Check 5: Very long URL
if (( ${#url} > 100 )); then
  issues+=("URL length unusually long (${#url} chars)")
  ((score+=1))
fi

# Check 6: SSL certificate check (attempt)
certfile="$(mktemp)"
CLEANUPS+=("$certfile")
set +e
# Use timeout to avoid hanging (timeout may not exist on macOS by default)
if command -v timeout >/dev/null 2>&1; then
  timeout 8s bash -c "echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null | openssl x509 -noout -dates" > "$certfile" 2>/dev/null
else
  # fallback without timeout
  bash -c "echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null | openssl x509 -noout -dates" > "$certfile" 2>/dev/null
fi
rc=$?
set -e
if [[ $rc -ne 0 ]] || ! grep -q "notAfter=" "$certfile" 2>/dev/null; then
  issues+=("Could not verify SSL certificate or connection failed")
  ((score+=2))
else
  exp_date=$(grep -m1 'notAfter=' "$certfile" | cut -d= -f2)
  notes+=("SSL valid until: $exp_date")
fi

# Optionally: placeholder for reputation APIs (VirusTotal, PhishTank)
if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
  # Note: This is a placeholder. Add proper API call and error handling when you add the key.
  # curl -s -X GET "https://www.virustotal.com/api/v3/urls/..." -H "x-apikey: $VIRUSTOTAL_API_KEY"
  notes+=("VirusTotal key configured (reputation checks available)")
fi

# Compose risk level
risk_text="Low Risk (Likely Safe)"
if (( score >= 7 )); then
  risk_text="High Risk (Phishing Likely)"
elif (( score >= 4 )); then
  risk_text="Medium Risk (Suspicious)"
fi

# Logging
timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf "%s | %s | score=%d | risk=%s | issues=%s\n" \
  "$timestamp" "$url" "$score" "$risk_text" "$(IFS=';'; echo "${issues[*]}")" >> "$LOGFILE"

# Output
if [[ "$output" == "json" ]]; then
  # Build JSON safely (minimal, no jq dependency)
  printf '{\n' 
  printf '  "url": "%s",\n' "$(printf '%s' "$url" | sed 's/"/\\"/g')"
  printf '  "score": %d,\n' "$score"
  printf '  "risk": "%s",\n' "$(printf '%s' "$risk_text" | sed 's/"/\\"/g')"
  printf '  "issues": [' 
  first=true
  for it in "${issues[@]}"; do
    if ! $first; then printf ', '; fi
    printf '"%s"' "$(printf '%s' "$it" | sed 's/"/\\"/g')"
    first=false
  done
  printf '],\n'
  printf '  "notes": [' 
  first=true
  for it in "${notes[@]}"; do
    if ! $first; then printf ', '; fi
    printf '"%s"' "$(printf '%s' "$it" | sed 's/"/\\"/g')"
    first=false
  done
  printf "]\n}\n"
else
  echo -e "\nIssues found:"
  if [[ ${#issues[@]} -eq 0 ]]; then
    echo "  None detected by heuristics."
  else
    for it in "${issues[@]}"; do
      echo "  - $it"
    done
  fi
  if [[ ${#notes[@]} -gt 0 ]]; then
    echo -e "\nNotes:"
    for it in "${notes[@]}"; do
      echo "  - $it"
    done
  fi
  echo -e "\n🔎 Total Risk Score: $score"
  echo -e "📊 Risk Level: $risk_text"
  echo -e "\nLog saved to: $LOGFILE"
fi

# Exit codes (for automation)
# 0 => low risk, 1 => medium risk, 2 => high risk
if (( score >= 7 )); then
  exit 2
elif (( score >= 4 )); then
  exit 1
else
  exit 0
fi
