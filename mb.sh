#!/bin/bash

export PATH="/usr/local/bin:/usr/bin:/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"

TARGET=""
SCOPE=""
MODE="balanced"
POWER="desktop"
DEPTH="everest"
RUSTSCAN_MODE=""
RESTORE_MODE=""
SCREENSHOT_MODE=""
HEADLESS_MODE=""
HISTORICAL_MODE=""
XSS_MODE=""
CUSTOM_TEMPLATES_DIR=""
HEADERS=()
HEADERS_B=()
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/maidbug_logs.XXXXXX")
JS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/maidbug_js.XXXXXX")

cleanup() {
  if [ -n "$OUT_DIR" ] && [ -d "$OUT_DIR" ] && [ -s "$LOG_FILE" ]; then
    cat "$LOG_FILE" >> "$OUT_DIR/run.log" 2>/dev/null
  fi
  rm -f "$LOG_FILE" 2>/dev/null
  rm -rf "$JS_DIR" 2>/dev/null
  if [ -n "$OUT_DIR" ]; then rm -f "$OUT_DIR"/.stage*_stderr 2>/dev/null; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -t 1 ]; then
  C_RED='\033[1;31m'; C_YEL='\033[1;33m'; C_CYN='\033[1;36m'
  C_GRN='\033[1;32m'; C_BLD='\033[1m'; C_RST='\033[0m'
else
  C_RED=''; C_YEL=''; C_CYN=''; C_GRN=''; C_BLD=''; C_RST=''
fi

UAS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
)

get_random_ua() { echo "${UAS[$RANDOM % ${#UAS[@]}]}"; }

touch "$LOG_FILE"
log_msg() { echo "[$(date +'%d-%m-%Y %H:%M:%S')] $1" >> "$LOG_FILE"; }
SUB_C=0
LIVE_C=0
PORT_C=0
PARAM_C=0
INTERESTING_C=0
ACCESS_DIFF_C=0
CRIT_C=0
HIGH_C=0
MED_C=0
LOW_C=0
FFUF_C=0
START_TIME=$(date +%s)

FFUF_MODE=""
# getopts only understands single-character short options, so "-Rs" (two
# chars) can't be a case inside the getopts loop itself. Pre-scan argv for
# the literal "-Rs" token, strip it out, and set the flag directly —
# everything else still goes through getopts normally below.
ARGS=()
for arg in "$@"; do
  if [ "$arg" = "-Rs" ]; then
    RUSTSCAN_MODE="1"
  else
    ARGS+=("$arg")
  fi
done
set -- "${ARGS[@]}"

while getopts ":u:s:m:p:d:H:A:hf:rSLt:gx" opt; do
  case $opt in
    u) TARGET="$OPTARG" ;;
    s) SCOPE="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    p) POWER="$OPTARG" ;;
    d) DEPTH="$OPTARG" ;;
    H) HEADERS+=("$OPTARG") ;;
    A) HEADERS_B+=("$OPTARG") ;;
    f) FFUF_MODE="$OPTARG" ;;
    r) RESTORE_MODE="1" ;;
    S) SCREENSHOT_MODE="1" ;;
    L) HEADLESS_MODE="1" ;;
    t) CUSTOM_TEMPLATES_DIR="$OPTARG" ;;
    g) HISTORICAL_MODE="1" ;;
    x) XSS_MODE="1" ;;
    h)
      clear
      cat << "EOF"
====================================================================================================
           ███╗   ███╗ █████╗ ██╗██████╗ ██████╗ ██╗   ██╗ ██████╗ 
           ████╗ ████║██╔══██╗██║██╔══██╗██╔══██╗██║   ██║██╔════╝ 
           ██╔████╔██║███████║██║██║  ██║██████╔╝██║   ██║██║  ███╗
           ██║╚██╔╝██║██╔══██║██║██║  ██║██╔══██╗██║   ██║██║   ██║
           ██║ ╚═╝ ██║██║  ██║██║██████╔╝██████╔╝╚██████╔╝╚██████╔╝
           ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ 
                 MAIDBUG - RECON ENGINE & OWASP TOP 10 SCANNER
====================================================================================================

USAGE:
  ./mb.sh -u <target> [options]

REQUIRED:
  -u <target>     Target domain, e.g. -u example.com

OPTIONAL:
  -s <scope>      Scope regex anchor if different from target (default: same as -u)
  -m <mode>       Request pacing: stealth | balanced | brawler   (default: balanced)
  -p <power>      Machine profile:  mobile | desktop | vps       (default: desktop)
  -d <depth>      Crawl/scan depth: mariana | everest            (default: everest)
                    mariana = extreme crawl (depth 8 + -jc)
                    everest = deep crawl (depth 5 + -jc)
  -H <header>     Extra HTTP header (Can be used multiple times)
  -A <header>     Second identity's header, e.g. an admin session cookie
                    (Can be used multiple times). Only used by Stage 4.7
                    to diff access control: same URL, -H's identity vs
                    -A's identity. Skipped entirely if -A isn't given.
  -Rs             Use RustScan instead of naabu for port scanning (Stage 2).
                    Naabu needs raw sockets, which commonly fail with a
                    permission/capability error inside Android chroot/Termux
                    environments (no CAP_NET_RAW). RustScan works around
                    this by doing full TCP connect scans instead, at the
                    cost of being noisier/slower than a SYN scan. Requires
                    rustscan on PATH: https://github.com/bee-san/RustScan
  -r              Restore/resume the previous run for this exact
                    target+mode+power+depth combo instead of starting a
                    fresh output folder. If no previous run exists yet,
                    behaves like a normal fresh run. Without -r, re-running
                    the same target+config always gets a NEW folder
                    (suffixed " (1)", " (2)", ...) so you never
                    accidentally resume/mix results from an unrelated
                    earlier run.
  -f <ffuf-mode>  Enable ffuf content discovery (OFF by default). One of:
                    silent  - small wordlist (~5k), low rate. Use on
                              sensitive/fragile targets.
                    vortex  - medium wordlist (~30k), moderate rate.
                              Balanced middle ground.
                    brutal  - large wordlist (~60k+), high rate.
                              Loud. Only for targets/programs that
                              explicitly allow heavy brute-forcing.
                  Wordlist: auto-detects SecLists if installed
                  (common paths under /usr/share/seclists,
                  /opt/SecLists, ~/SecLists); falls back to a small
                  built-in wordlist otherwise. Uses ffuf's -ac
                  auto-calibration to filter soft-404 noise.
  -S              Enable screenshot triage (Stage 3.7, uses gowitness).
                    Screenshots every live host so you can eyeball
                    login pages / API docs / default pages quickly
                    instead of opening each one by hand. Requires
                    gowitness on PATH: https://github.com/sensepost/gowitness
  -L              Enable headless crawling (Stage 4, katana -hl).
                    Use this against SPAs / client-side-rendered apps
                    (React, Vue, Angular routing) — the default crawl
                    only sees what's in the initial HTML/JS-extracted
                    URLs and silently misses routes that only appear
                    after the JS framework renders them. Slower and
                    heavier than the default crawl (spins up a real
                    browser per page), so it's opt-in. Requires a
                    Chromium/Chrome binary on PATH for katana to drive.
  -t <dir>        Load an additional custom nuclei template directory as
                    a SEPARATE extra stage (6.5), run alongside (not
                    instead of) the normal default-template Stage 6/7
                    scans. Kept separate deliberately: passing -t to
                    nuclei directly replaces its default template set
                    rather than adding to it, which would silently gut
                    Stage 6/7's normal CVE/misconfig coverage. Output:
                    06_5_nuclei_custom_*.jsonl.
  -g              Enable historical/archived URL discovery (Stage 4.55,
                    uses gau+uro). Pulls every URL the target has ever
                    had indexed (Wayback Machine, Common Crawl, OTX,
                    urlscan.io) — catches old API versions and debug
                    pages that are gone from navigation but never
                    actually deleted from the server, which the normal
                    live crawl (katana) can never see. Every survivor is
                    re-validated against the Stage 4.5 soft-404 baseline
                    before being trusted; if no stable baseline exists,
                    this stage is skipped entirely rather than flooding
                    the report with dead archive URLs. Requires gau and
                    uro on PATH.
  -x              Enable the reflected-XSS pipeline (Stage 7.5, uses
                    kxss+dalfox). kxss first narrows the endpoint list
                    down to parameters that actually reflect special
                    characters unencoded; only those get fuzzed by
                    dalfox for a confirmed PoC. Narrower and more
                    accurate than relying on nuclei -dast's generic XSS
                    templates alone. Requires kxss and dalfox on PATH.
  -h              Show this help and exit
====================================================================================================
EOF
      exit 0
      ;;
    \?|:)
      echo "[!] Invalid option or missing argument for -$OPTARG."
      exit 1
      ;;
  esac
done

if [ -n "$FFUF_MODE" ] && [ "$FFUF_MODE" != "silent" ] && [ "$FFUF_MODE" != "vortex" ] && [ "$FFUF_MODE" != "brutal" ]; then
  echo "[!] Invalid ffuf mode: '$FFUF_MODE'. Valid values: silent, vortex, brutal."
  exit 1
fi

shift $((OPTIND - 1))

check_dependencies() {
  MISSING=0
  TOOLS=("subfinder" "httpx-toolkit" "katana" "arjun" "nuclei" "trufflehog" "curl" "jq")
  # naabu is only required when -Rs (rustscan) isn't requested — no point
  # forcing it to be installed if it's not going to be used, especially
  # since "naabu doesn't work here" is exactly why -Rs exists.
  if [ "$RUSTSCAN_MODE" != "1" ]; then TOOLS+=("naabu"); fi
  # dnsx is used to validate which crawled subdomains actually resolve and
  # to detect wildcard DNS before anything downstream wastes requests on
  # hosts that don't exist / all resolve to the same catch-all answer.
  echo "[+] Checking required tools/dependencies..."
  for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "  [✓] $tool : Installed"
    else
      echo "  [-] $tool : NOT Installed"
      MISSING=1
    fi
  done
  if command -v dnsx >/dev/null 2>&1; then
    echo "  [✓] dnsx : Installed (DNS validation + wildcard filtering enabled)"
  else
    echo "  [i] dnsx : NOT Installed — subdomains won't be DNS-validated and wildcard DNS won't be filtered. Recommended: https://github.com/projectdiscovery/dnsx"
  fi
  if command -v nmap >/dev/null 2>&1; then
    echo "  [✓] nmap : Installed (non-web open ports get -sV service/version follow-up)"
  else
    echo "  [i] nmap : NOT Installed — non-web open ports (SSH, DBs, etc.) will be listed but not fingerprinted. Optional."
  fi
  if [ "$MISSING" -eq 1 ]; then exit 1; fi
  if [ "$SCREENSHOT_MODE" = "1" ]; then
    if command -v gowitness >/dev/null 2>&1; then
      echo "  [✓] gowitness : Installed (screenshot triage enabled)"
    else
      echo "  [-] gowitness : NOT Installed — -S was requested but gowitness isn't on PATH."
      exit 1
    fi
  fi
  if [ "$HEADLESS_MODE" = "1" ]; then
    if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
      echo "  [✓] chromium/chrome : Installed (headless crawl enabled)"
    else
      echo "  [-] chromium/chrome : NOT found on PATH — -L was requested but katana's headless mode needs a Chromium/Chrome binary to drive."
      exit 1
    fi
  fi
  if [ "$HISTORICAL_MODE" = "1" ]; then
    if command -v gau >/dev/null 2>&1 && command -v uro >/dev/null 2>&1; then
      echo "  [✓] gau + uro : Installed (historical/archived URL discovery enabled)"
    else
      echo "  [-] gau/uro : NOT Installed — -g was requested but gau and/or uro isn't on PATH."
      exit 1
    fi
  fi
  if [ "$XSS_MODE" = "1" ]; then
    if command -v kxss >/dev/null 2>&1 && command -v dalfox >/dev/null 2>&1; then
      echo "  [✓] kxss + dalfox : Installed (reflected XSS pipeline enabled)"
    else
      echo "  [-] kxss/dalfox : NOT Installed — -x was requested but kxss and/or dalfox isn't on PATH."
      exit 1
    fi
  fi
  if [ -n "$CUSTOM_TEMPLATES_DIR" ]; then
    if [ -d "$CUSTOM_TEMPLATES_DIR" ]; then
      echo "  [✓] custom templates : $CUSTOM_TEMPLATES_DIR (found, will run as an additional Stage 6.5 scan)"
    else
      echo "  [-] custom templates : '$CUSTOM_TEMPLATES_DIR' does not exist or is not a directory (-t)."
      exit 1
    fi
  fi
  if [ "$RUSTSCAN_MODE" = "1" ]; then
    if command -v rustscan >/dev/null 2>&1; then
      echo "  [✓] rustscan : Installed"
    else
      echo "  [-] rustscan : NOT Installed — -Rs was requested but rustscan isn't on PATH."
      exit 1
    fi
  fi
  if [ -n "$FFUF_MODE" ]; then
    if command -v ffuf >/dev/null 2>&1; then
      echo "  [✓] ffuf : Installed (content discovery: $FFUF_MODE mode)"
    else
      echo "  [-] ffuf : NOT Installed — -f $FFUF_MODE was requested but ffuf isn't on PATH."
      exit 1
    fi
  fi
  echo "[+] All dependencies met! Initializing MaidBug pipeline..."
  sleep 2
}

if [ -z "$TARGET" ]; then
  echo "Target is required. Use -u <target>"
  exit 1
fi
TARGET=$(echo "$TARGET" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##')

if [ "$DEPTH" != "mariana" ] && [ "$DEPTH" != "everest" ]; then
  echo "[!] Invalid depth: '$DEPTH'. Valid values: mariana, everest."
  exit 1
fi

if [ "$POWER" != "mobile" ] && [ "$POWER" != "vps" ] && [ "$POWER" != "desktop" ]; then
  echo "[!] Invalid power: '$POWER'. Valid values: mobile, vps, desktop."
  exit 1
fi

if [ "$MODE" != "stealth" ] && [ "$MODE" != "brawler" ] && [ "$MODE" != "balanced" ]; then
  echo "[!] Invalid mode: '$MODE'. Valid values: stealth, balanced, brawler."
  exit 1
fi

check_dependencies

if [ -z "$SCOPE" ]; then SCOPE="$TARGET"; fi

ESCAPED_SCOPE=$(echo "$SCOPE" | sed 's/\./[.]/g')
STRICT_REGEX="^([a-zA-Z0-9_-]+[.])*${ESCAPED_SCOPE}$"
SAFE_TARGET=$(echo "$TARGET" | tr -cd 'a-zA-Z0-9._-')

M_TAG=$(echo "$MODE" | cut -c1-3 | tr 'a-z' 'A-Z')
P_TAG=$(echo "$POWER" | cut -c1-3 | tr 'a-z' 'A-Z')
D_TAG=$(echo "$DEPTH" | cut -c1-3 | tr 'a-z' 'A-Z')
BASE_OUT_DIR="output/${SAFE_TARGET}_${M_TAG}-${P_TAG}-${D_TAG}"

# -r: explicitly resume the previous run for this exact target+config —
# reuse the same folder so STATE_FILE / checkpoints carry over.
# No -r (default): never silently resume/mix with a past run. If the
# base folder already exists, keep incrementing " (1)", " (2)", ... until
# a free name is found, same convention as "file (1).txt" — always a
# clean start unless -r was asked for explicitly.
if [ "$RESTORE_MODE" = "1" ]; then
  OUT_DIR="$BASE_OUT_DIR"
  if [ -d "$OUT_DIR" ]; then
    echo "[i] -r: resuming previous run at $OUT_DIR"
  else
    echo "[i] -r: no previous run found for this target+config yet — starting fresh at $OUT_DIR"
  fi
else
  OUT_DIR="$BASE_OUT_DIR"
  if [ -d "$OUT_DIR" ]; then
    N=1
    while [ -d "${BASE_OUT_DIR} (${N})" ]; do
      N=$((N + 1))
    done
    OUT_DIR="${BASE_OUT_DIR} (${N})"
    echo "[i] '${BASE_OUT_DIR}' already exists and -r wasn't given — starting a fresh run at '${OUT_DIR}'. Use -r to resume the existing one instead."
  fi
fi
mkdir -p "$OUT_DIR"
STATE_FILE="$OUT_DIR/.maidbug_state"

H_HTTPX=(); H_KATANA=(); H_ARJUN=(); H_NUCLEI=(); H_CURL=(); H_FFUF=()
for h in "${HEADERS[@]}"; do
  H_HTTPX+=("-H" "$h")
  H_KATANA+=("-H" "$h")
  H_NUCLEI+=("-H" "$h")
  H_CURL+=("-H" "$h")
  H_FFUF+=("-H" "$h")
done
# H_CURL needs to reach xargs subshells, but bash can't export arrays via
# the environment. declare -p produces a properly shell-quoted
# reconstruction string that's safe to eval even if header values contain
# quotes/semicolons/backticks — unlike building a raw "-H '$h'" string by
# hand (which breaks, or worse, executes arbitrary shell, if a header
# value itself contains a single quote).
if [ "${#HEADERS[@]}" -gt 0 ]; then H_ARJUN=("--headers" "$(printf '%s\n' "${HEADERS[@]}")"); fi
CURL_HEADERS_DECL=$(declare -p H_CURL)
export CURL_HEADERS_DECL

# Context B (-A) — a second identity's headers, kept completely separate
# from H_CURL/CURL_HEADERS_DECL above. Only Stage 4.7 (access-control
# diff) uses this; every other stage still only ever sees -H's identity.
H_CURL_B=()
for h in "${HEADERS_B[@]}"; do
  H_CURL_B+=("-H" "$h")
done
CURL_HEADERS_B_DECL=$(declare -p H_CURL_B)
export CURL_HEADERS_B_DECL

# --- Stage 0.5: Auth session freshness check ---
# Runs every invocation (not checkpointed — a token can expire between
# resumes of the same output folder), and only if -H was actually given.
# Without this, an expired cookie/token means Stage 3-7 silently scan as
# an ANONYMOUS user for the entire run, and nothing anywhere would ever
# tell you that happened — the pipeline would just quietly under-report
# everything behind auth. This is a heuristic (401/403/login-redirect
# sniffing), not proof either way, so it only warns, it never blocks.
if [ "${#HEADERS[@]}" -gt 0 ]; then
  AUTH_CHECK_UA=$(get_random_ua)
  AUTH_CHECK_URL="https://${TARGET}"
  AUTH_RESP=$(curl -skL -m 10 -A "$AUTH_CHECK_UA" "${H_HTTPX[@]}" -o /dev/null -w "%{http_code} %{url_effective}" "$AUTH_CHECK_URL" 2>/dev/null)
  AUTH_CODE=$(echo "$AUTH_RESP" | awk '{print $1}')
  AUTH_FINAL_URL=$(echo "$AUTH_RESP" | awk '{print $2}')
  AUTH_LOOKS_DEAD=0
  case "$AUTH_CODE" in
    401|403) AUTH_LOOKS_DEAD=1 ;;
  esac
  if echo "$AUTH_FINAL_URL" | grep -qiE 'login|signin|sso|auth'; then
    AUTH_LOOKS_DEAD=1
  fi
  if [ "$AUTH_LOOKS_DEAD" -eq 1 ]; then
    echo "[!] WARNING: the -H session/token you gave looks like it may be expired or invalid (got ${AUTH_CODE:-no response}, landed on ${AUTH_FINAL_URL:-unknown}). If so, Stages 3-7 will silently scan as an ANONYMOUS user for this entire run. Refresh the token/cookie or press Ctrl+C to abort."
    log_msg "[WARN] Stage 0.5: -H identity looks expired/invalid (code=${AUTH_CODE:-n/a}, landed=${AUTH_FINAL_URL:-n/a}). Proceeding anyway — verify manually if authenticated-only findings matter for this run."
    sleep 3
  else
    log_msg "[INFO] Stage 0.5: -H identity looks alive (code=${AUTH_CODE:-n/a})."
  fi
fi

# Every flag that changes what a stage actually DOES belongs in this
# fingerprint, not just MODE/POWER/DEPTH/HEADERS. Missing one here means
# toggling it between two -r (resume) runs on the SAME output folder
# silently keeps stale checkpoints from the old config instead of
# re-running the affected stage(s) — the single worst case being -A
# (HEADERS_B): Stage 4.7 marks itself done as a no-op when -A is absent,
# so adding -A later on a resumed run would otherwise find that no-op
# already checkpointed and never actually run the access-control diff.
CONFIG_FINGERPRINT="MODE=${MODE}|POWER=${POWER}|DEPTH=${DEPTH}|HEADERS=${HEADERS[*]}|HEADERS_B=${HEADERS_B[*]}|FFUF_MODE=${FFUF_MODE}|RUSTSCAN_MODE=${RUSTSCAN_MODE}|HEADLESS_MODE=${HEADLESS_MODE}|SCREENSHOT_MODE=${SCREENSHOT_MODE}|HISTORICAL_MODE=${HISTORICAL_MODE}|XSS_MODE=${XSS_MODE}|CUSTOM_TEMPLATES_DIR=${CUSTOM_TEMPLATES_DIR}"
FINGERPRINT_FILE="$OUT_DIR/.maidbug_config"

if [ -f "$FINGERPRINT_FILE" ]; then
  OLD_FP=$(cat "$FINGERPRINT_FILE" 2>/dev/null)
  if [ "$OLD_FP" != "$CONFIG_FINGERPRINT" ] && [ -s "$STATE_FILE" ]; then
    : > "$STATE_FILE"
    rm -f "$OUT_DIR/.ffuf_done_hosts"
  fi
fi
echo "$CONFIG_FINGERPRINT" > "$FINGERPRINT_FILE"
touch "$STATE_FILE"

is_done() { grep -q "^$1$" "$STATE_FILE" 2>/dev/null; }
mark_done() { echo "$1" >> "$STATE_FILE"; }

if [ "$POWER" = "mobile" ]; then
  N_C=5; H_T=10; F_T=10
elif [ "$POWER" = "vps" ]; then
  N_C=100; H_T=200; F_T=100
else
  N_C=25; H_T=50; F_T=40
fi

# S_L (-timeout) and S_R (-retries): nuclei's own defaults are timeout=5s,
# retries=0. The previous values here (timeout=1s across stealth/balanced)
# were tighter than nuclei's default even in "balanced" mode — on any
# target with real-world latency (e.g. non-CDN, overseas, campus sites),
# that caused widespread request timeouts, which combined with a low -mhe
# below made nuclei silently abandon scanning the host mid-way with zero
# visible error, producing 0 findings even on a live, vulnerable target.
# NOTE: nuclei has no standalone "-delay" flag — pacing is controlled
# entirely via -rl/-rate-limit (already set above). The old "-delay 2"
# here was an invalid flag: nuclei rejected it and exited immediately on
# every Stage 6/7 call in stealth mode, silently producing 0 findings
# (stderr was suppressed, so this failure was invisible until we compared
# stage durations in run.log). N_EXTRA is kept as an escape hatch for any
# future genuinely-valid extra flags, but stays empty by default now.
if [ "$MODE" = "stealth" ]; then
  N_RL=5; S_L=5; S_R=1; N_EXTRA=""
  D_WORKERS=3; D_DELAY=1000
elif [ "$MODE" = "brawler" ]; then
  N_RL=150; S_L=8; S_R=3; N_EXTRA=""
  D_WORKERS=40; D_DELAY=0
else
  N_RL=50; S_L=5; S_R=2; N_EXTRA=""
  D_WORKERS=15; D_DELAY=200
fi

if [ "$DEPTH" = "mariana" ]; then
  K_D=8; K_JS="-jc"
else
  K_D=5; K_JS="-jc"
fi
# Report severity is intentionally narrower than scan severity: we still
# SCAN low/info-tagged templates (Stage 3.5 keeps cors/config/exposure
# findings regardless of severity, since e.g. a misconfigured CORS policy
# can be "low" severity by template metadata but high impact in context),
# but Stage 6/7's main vuln hunt and the FINAL_SUMMARY only surface
# medium+ by default to keep the report free of low-signal noise.
# info/low are still written to disk for manual follow-up.
N_SEV="low,medium,high,critical"
N_REPORT_SEV="medium,high,critical"
NOISY_TAGS="default-login"

# Stage 4.5 (baseline_check/soft404_check) and Stage 5 (JS download loop)
# are all raw curl loops (no -rl flag to lean on, unlike nuclei/httpx/
# naabu), so they need their own MODE-driven concurrency cap — otherwise
# "-m stealth" still fires N_C (a POWER-only value, e.g. 25 on desktop)
# concurrent unthrottled requests at the target during these stages,
# silently breaking the stealth contract.
case "$MODE" in
  stealth)  CURL_LOOP_CONC=3 ;;
  brawler)  CURL_LOOP_CONC=$N_C ;;
  *)        if [ "$N_C" -lt 15 ]; then CURL_LOOP_CONC=$N_C; else CURL_LOOP_CONC=15; fi ;;
esac

# --- RustScan config (only used when -Rs is passed) ---
# Note: RustScan's exact `--greppable` output wording has changed across
# releases (older versions used `-q`/`--quiet` for the same "no nmap,
# machine-readable" behavior). If Stage 2 errors out with an "unknown
# flag" on your rustscan build, run `rustscan --help` and swap
# --greppable for whatever your version calls it.
# batch-size/ulimit scale with POWER (device capability) — mirrors how
# N_C/H_T are already split for the other tools.
case "$POWER" in
  mobile) RS_ULIMIT=1024; RS_BATCH_BASE=500  ;;
  vps)    RS_ULIMIT=8000; RS_BATCH_BASE=4500 ;;
  *)      RS_ULIMIT=3000; RS_BATCH_BASE=2000 ;;
esac
# port scope/pacing scale with MODE (how loud we're allowed to be) —
# mirrors how N_RL is already split for the other tools. stealth caps to
# the top 1000 ports with a quarter of the batch size and a longer
# timeout instead of hammering all 65535 ports at full batch size.
case "$MODE" in
  stealth)  RS_TOP="--top"; RS_TIMEOUT=3000; RS_BATCH=$(( RS_BATCH_BASE / 4 )) ;;
  brawler)  RS_TOP="";      RS_TIMEOUT=1000; RS_BATCH=$RS_BATCH_BASE ;;
  *)        RS_TOP="";      RS_TIMEOUT=1500; RS_BATCH=$(( RS_BATCH_BASE / 2 )) ;;
esac

# --- ffuf content-discovery config (opt-in via -f) ---
if [ "$FFUF_MODE" = "silent" ]; then
  F_THREADS=10; F_DELAY="0.3-1.0"; F_RATE=5; F_TIMEOUT=10
elif [ "$FFUF_MODE" = "vortex" ]; then
  F_THREADS=40; F_DELAY="0.05-0.2"; F_RATE=40; F_TIMEOUT=8
elif [ "$FFUF_MODE" = "brutal" ]; then
  F_THREADS=100; F_DELAY="0"; F_RATE=0; F_TIMEOUT=6
fi

# Built-in fallback wordlist used only when no SecLists installation is
# found on the machine — small on purpose (real coverage should come from
# installing SecLists: https://github.com/danielmiessler/SecLists).
write_fallback_wordlist() {
  cat > "$OUT_DIR/.ffuf_fallback_wordlist.txt" << 'WORDLIST_EOF'
admin
administrator
login
api
api/v1
api/v2
backup
backups
.git
.git/config
.git/HEAD
.env
.env.local
.env.production
.svn
config
config.php
config.json
config.yml
wp-admin
wp-login.php
wp-content
wp-json
phpmyadmin
robots.txt
sitemap.xml
.well-known/security.txt
uploads
upload
files
file
test
tests
dev
staging
old
tmp
temp
debug
console
actuator
actuator/health
actuator/env
swagger
swagger-ui
swagger-ui.html
swagger.json
openapi.json
graphql
graphiql
.htaccess
.htpasswd
web.config
server-status
server-info
elmah.axd
trace.axd
crossdomain.xml
clientaccesspolicy.xml
info.php
phpinfo.php
readme.md
README.md
CHANGELOG.md
package.json
composer.json
Dockerfile
docker-compose.yml
.DS_Store
error_log
logs
log
db
database
dump.sql
backup.sql
backup.zip
backup.tar.gz
.aws
.aws/credentials
id_rsa
id_rsa.pub
private.key
cgi-bin
admin.php
login.php
register
signup
dashboard
panel
cpanel
webmail
mail
ftp
sftp
vpn
jenkins
gitlab
jira
confluence
grafana
kibana
elasticsearch
solr
redis
metrics
health
status
version
debug.log
error.log
access.log
.well-known
sitemap_index.xml
feed
rss
atom.xml
xmlrpc.php
install
setup
install.php
update.php
upgrade
migration
migrations
seed
seeds
vendor
node_modules
.npmrc
.yarnrc
yarn.lock
package-lock.json
Gemfile
Gemfile.lock
requirements.txt
Pipfile
.env.example
env.example
secrets
secret
keys
key
cert
certs
ssl
tls
private
internal
hidden
WORDLIST_EOF
}

# Looks for a real SecLists install (common paths) matching the requested
# size tier; falls back to the small built-in list above if none found.
# Prints the resolved wordlist path to stdout.
resolve_ffuf_wordlist() {
  local tier="$1" candidates=()
  case "$tier" in
    silent)
      candidates=(
        "/usr/share/seclists/Discovery/Web-Content/common.txt"
        "/opt/SecLists/Discovery/Web-Content/common.txt"
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
        "$HOME/SecLists/Discovery/Web-Content/common.txt"
      ) ;;
    vortex)
      candidates=(
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        "$HOME/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
      ) ;;
    brutal)
      candidates=(
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
        "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt"
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt"
        "$HOME/SecLists/Discovery/Web-Content/raft-large-directories.txt"
      ) ;;
  esac
  local c
  for c in "${candidates[@]}"; do
    if [ -s "$c" ]; then echo "$c"; return 0; fi
  done
  write_fallback_wordlist
  echo "$OUT_DIR/.ffuf_fallback_wordlist.txt"
}
# nuclei's own default is 30 before it gives up on a host. 5 was too
# trigger-happy — a handful of slow/timed-out requests (normal on a
# non-CDN target) was enough to make nuclei quietly stop scanning that
# host for the rest of the templates, with no visible error.
N_MHE=20

draw_ui() {
  clear
  PROG=$1
  TASK=$2
  FULL=30
  FILL=$(( (PROG * FULL) / 100 ))
  EMPTY=$(( FULL - FILL ))
  BAR=$(printf "%${FILL}s" | tr " " "#")$(printf "%${EMPTY}s" | tr " " "-")
  
  if [ -f "$OUT_DIR/01_subfinder_subdomains.txt" ]; then SUB_C=$(wc -l < "$OUT_DIR/01_subfinder_subdomains.txt"); fi
  if [ -f "$OUT_DIR/02_port_scan_results.txt" ]; then PORT_C=$(wc -l < "$OUT_DIR/02_port_scan_results.txt"); fi
  if [ -f "$OUT_DIR/03_httpx_live_hosts.txt" ]; then LIVE_C=$(wc -l < "$OUT_DIR/03_httpx_live_hosts.txt"); fi
  if [ -f "$OUT_DIR/04_katana_endpoints_filtered.txt" ]; then PARAM_C=$(wc -l < "$OUT_DIR/04_katana_endpoints_filtered.txt"); fi
  if [ -f "$OUT_DIR/04_6_interesting_endpoints.txt" ]; then INTERESTING_C=$(wc -l < "$OUT_DIR/04_6_interesting_endpoints.txt"); fi
  if [ -f "$OUT_DIR/04_7_access_control_diff.txt" ]; then ACCESS_DIFF_C=$(wc -l < "$OUT_DIR/04_7_access_control_diff.txt"); fi
  # Severity counters are derived from the *_verified.jsonl files written by
  # Stage 6/7/3.5's re-check pass (see nuclei_jsonl_severity_counts below),
  # not by grepping raw text — jsonl + jq avoids miscounting severity words
  # that happen to appear in a URL or template name rather than the actual
  # "severity" field.
  nuclei_jsonl_severity_counts
  if [ -f "$OUT_DIR/08_ffuf_findings.txt" ]; then FFUF_C=$(wc -l < "$OUT_DIR/08_ffuf_findings.txt"); fi

  echo "================================================================================"
  printf "  ${C_BLD}[ MAIDBUG ENGINE ]${C_RST} :: Target: %s\n" "$TARGET"
  if [ -n "$FFUF_MODE" ]; then
    printf "  [ RUN CONFIG ]     :: Mode: %s | Power: %s | Depth: %s | Ffuf: %s\n" "${MODE^^}" "${POWER^^}" "${DEPTH^^}" "${FFUF_MODE^^}"
  else
    printf "  [ RUN CONFIG ]     :: Mode: %s | Power: %s | Depth: %s\n" "${MODE^^}" "${POWER^^}" "${DEPTH^^}"
  fi
  echo "================================================================================"
  echo " [!] Progress : [$BAR] $PROG% ($TASK)"
  echo "================================================================================"
  echo " STATS & COUNTERS:"
  printf "  • Subdomains Found : %-13s • Vulnerabilities (Nuclei, verified):\n" "$SUB_C"
  printf "  • Live Hosts (HTTP): %-13s    - ${C_RED}Critical${C_RST} : %s\n" "$LIVE_C" "$CRIT_C"
  printf "  • Open Ports       : %-13s    - ${C_YEL}High${C_RST}     : %s\n" "$PORT_C" "$HIGH_C"
  printf "  • Dynamic Endpoints: %-13s    - ${C_CYN}Medium${C_RST}   : %s\n" "$PARAM_C" "$MED_C"
  if [ -n "$FFUF_MODE" ]; then
    printf "  • Ffuf Hits (%-6s): %-13s    - ${C_GRN}Low${C_RST}      : %s\n" "$FFUF_MODE" "$FFUF_C" "$LOW_C"
  else
    printf "  %-20s %-13s    - ${C_GRN}Low${C_RST}      : %s\n" "" "" "$LOW_C"
  fi
  printf "  • Interesting Eps  : %-13s\n" "$INTERESTING_C"
  printf "  • Access-Ctrl Diff : %-13s\n" "$ACCESS_DIFF_C"
  echo "================================================================================"
  echo " LIVE LOGS:"
  tail -n 4 "$LOG_FILE"
  echo "================================================================================"
}

# Several tools (httpx, nuclei, katana, ...) always create their -o file
# even when they find nothing, leaving empty 0-byte .txt files cluttering
# the output dir. Call this right after such a file is written; downstream
# stages already use [ -s file ] to decide list-mode vs single-target
# fallback, so removing empty files changes nothing functionally.
drop_if_empty() { [ -s "$1" ] || rm -f "$1" 2>/dev/null; }

# Centralized severity counting from the *verified* jsonl files (written
# by nuclei_verify_findings below), using jq on the real "severity" field
# instead of grep against template-id/URL text. Replaces the old
# `grep -c -i "\[critical\]"` approach, which could over/under count if a
# template-id or matched URL happened to contain the word "critical" etc.
nuclei_jsonl_severity_counts() {
  CRIT_C=0; HIGH_C=0; MED_C=0; LOW_C=0
  local jf
  for jf in "$OUT_DIR"/*_verified.jsonl; do
    [ -s "$jf" ] || continue
    CRIT_C=$((CRIT_C + $(jq -r '.info.severity // empty' "$jf" 2>/dev/null | grep -c -i '^critical$')))
    HIGH_C=$((HIGH_C + $(jq -r '.info.severity // empty' "$jf" 2>/dev/null | grep -c -i '^high$')))
    MED_C=$((MED_C + $(jq -r '.info.severity // empty' "$jf" 2>/dev/null | grep -c -i '^medium$')))
    LOW_C=$((LOW_C + $(jq -r '.info.severity // empty' "$jf" 2>/dev/null | grep -c -i '^low$')))
  done
}

# Re-checks every finding in a raw nuclei jsonl output by re-running its
# exact template against its exact matched-at URL a second time. Only
# findings that reproduce BOTH times are written to the *_verified.jsonl
# file; everything else (one-off WAF noise, latency flukes, blind/OOB
# templates whose first "match" was a false trigger) goes to
# *_unverified.jsonl for manual review instead of being reported as
# confirmed. This directly targets the single biggest source of nuclei
# false positives in automated pipelines: an unstable match reported once
# and never re-checked.
#   $1 = raw jsonl path from the nuclei run
#   $2 = output basename (without extension) for *_verified.jsonl / *_unverified.jsonl
nuclei_verify_findings() {
  local raw_jsonl="$1" out_base="$2"
  local verified="${out_base}_verified.jsonl" unverified="${out_base}_unverified.jsonl"
  : > "$verified"; : > "$unverified"
  [ -s "$raw_jsonl" ] || return 0

  local total
  total=$(jq -c '.' "$raw_jsonl" 2>/dev/null | wc -l)
  log_msg "[INFO] Re-verifying $total raw nuclei match(es) from $(basename "$raw_jsonl") (each re-run once against its own template+URL)..."

  local line tpl_id matched_at recheck_out
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    tpl_id=$(echo "$line" | jq -r '.["template-id"] // empty' 2>/dev/null)
    matched_at=$(echo "$line" | jq -r '.["matched-at"] // .host // empty' 2>/dev/null)
    if [ -z "$tpl_id" ] || [ -z "$matched_at" ]; then
      # Can't re-target this finding (missing fields) — keep it but mark
      # it as unverified rather than silently dropping or silently trusting it.
      echo "$line" >> "$unverified"
      continue
    fi
    recheck_out=$(mktemp "${TMPDIR:-/tmp}/maidbug_recheck.XXXXXX")
    nuclei -t "$tpl_id" -u "$matched_at" -silent -jsonl -timeout "$S_L" -retries 1 -H "User-Agent: $(get_random_ua)" "${H_NUCLEI[@]}" -o "$recheck_out" >/dev/null 2>&1
    if [ -s "$recheck_out" ]; then
      echo "$line" >> "$verified"
    else
      echo "$line" >> "$unverified"
    fi
    rm -f "$recheck_out"
  done < <(jq -c '.' "$raw_jsonl" 2>/dev/null)

  drop_if_empty "$verified"
  drop_if_empty "$unverified"
  local v_count u_count
  v_count=$([ -s "$verified" ] && wc -l < "$verified" || echo 0)
  u_count=$([ -s "$unverified" ] && wc -l < "$unverified" || echo 0)
  log_msg "[INFO] Verification of $(basename "$raw_jsonl"): $v_count reproduced twice (verified) / $u_count did not reproduce (unverified, see ${unverified})."
}

waf_healthcheck() {
  local sample_file="$OUT_DIR/03_httpx_live_hosts.txt"
  [ -s "$sample_file" ] || return
  local total=0 blocked=0 code check_ua
  check_ua=$(get_random_ua)
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    total=$((total + 1))
    code=$(curl -sk -o /dev/null -m 10 -A "$check_ua" "${H_CURL[@]}" -w "%{http_code}" "$host" 2>/dev/null)
    case "$code" in 403|406|429|503) blocked=$((blocked + 1)) ;; esac
  done < <(shuf "$sample_file" 2>/dev/null | head -n 5)
  if [ "$total" -gt 0 ]; then
    ratio=$(( blocked * 100 / total ))
    if [ "$ratio" -ge 50 ]; then
      log_msg "[WARN] WAF health-check: $blocked/$total sampled hosts show block signatures. Throttling down."
      N_RL=5; [ "$N_C" -gt 10 ] && N_C=10
    fi
  fi
}

log_msg "[INFO] MaidBug initialized. Target: $TARGET"
draw_ui 0 "Initializing Pipeline"

if ! is_done "STAGE_1"; then
  log_msg "[TASK] Running Stage 1: Subfinder"
  draw_ui 10 "Stage 1/7: Subfinder"
  subfinder -d "$TARGET" -silent | grep -iE "$STRICT_REGEX" | sort -u > "$OUT_DIR/01_subfinder_subdomains_raw.txt" 2>/dev/null
  if [ ! -s "$OUT_DIR/01_subfinder_subdomains_raw.txt" ]; then echo "$TARGET" > "$OUT_DIR/01_subfinder_subdomains_raw.txt"; fi

  # --- DNS validation + wildcard filtering (dnsx) ---
  # Two problems this fixes, both of which were previously silent:
  #   1. subfinder/cert-transparency sources routinely return subdomains
  #      that no longer resolve (decommissioned, expired, typo'd in certs).
  #      Every downstream stage would still "scan" them as if live.
  #   2. Wildcard DNS ("*.target.com" resolves to one catch-all IP) makes
  #      EVERY possible subdomain resolve successfully, so naabu/httpx/
  #      nuclei would treat hundreds of nonexistent hosts as real,
  #      multiplying both scan time and false positives identically
  #      across all of them (since they're really all the same host).
  if command -v dnsx >/dev/null 2>&1; then
    dnsx -l "$OUT_DIR/01_subfinder_subdomains_raw.txt" -silent -a -resp -wd "$TARGET" -o "$OUT_DIR/.dnsx_raw.txt" >/dev/null 2>"$OUT_DIR/.stage1_dnsx_stderr"
    # -wd flags wildcard-matched entries; dnsx marks them inline as
    # "host [ip] [wildcard]" so we can drop just those lines rather than
    # guessing a catch-all IP ourselves.
    if [ -s "$OUT_DIR/.dnsx_raw.txt" ]; then
      grep -v '\[wildcard\]' "$OUT_DIR/.dnsx_raw.txt" | awk '{print $1}' | sort -u > "$OUT_DIR/01_subfinder_subdomains.txt"
      WC_COUNT=$(grep -c '\[wildcard\]' "$OUT_DIR/.dnsx_raw.txt" 2>/dev/null || echo 0)
      RAW_COUNT=$(wc -l < "$OUT_DIR/01_subfinder_subdomains_raw.txt")
      RESOLVED_COUNT=$(wc -l < "$OUT_DIR/01_subfinder_subdomains.txt")
      log_msg "[INFO] dnsx: $RAW_COUNT candidate subdomain(s) -> $RESOLVED_COUNT resolved and non-wildcard ($WC_COUNT wildcard-matched entries dropped)."
    else
      log_msg "[WARN] dnsx produced no output — falling back to unvalidated subdomain list. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage1_dnsx_stderr" 2>/dev/null | cut -c1-300)"
      cp "$OUT_DIR/01_subfinder_subdomains_raw.txt" "$OUT_DIR/01_subfinder_subdomains.txt"
    fi
    rm -f "$OUT_DIR/.dnsx_raw.txt" "$OUT_DIR/.stage1_dnsx_stderr"
    if [ ! -s "$OUT_DIR/01_subfinder_subdomains.txt" ]; then
      log_msg "[WARN] DNS validation left zero live hosts — falling back to the raw (unvalidated) list so the pipeline still has something to scan."
      cp "$OUT_DIR/01_subfinder_subdomains_raw.txt" "$OUT_DIR/01_subfinder_subdomains.txt"
    fi
  else
    cp "$OUT_DIR/01_subfinder_subdomains_raw.txt" "$OUT_DIR/01_subfinder_subdomains.txt"
  fi
  mark_done "STAGE_1"
else
  log_msg "[INFO] Stage 1 Checkpoint found. Skipping..."
  draw_ui 10 "Stage 1/7: Subfinder (Skipped)"
fi

if ! is_done "STAGE_1_5"; then
  log_msg "[TASK] Running Stage 1.5: Takeovers"
  draw_ui 15 "Stage 1.5/7: Takeovers"
  if [ -s "$OUT_DIR/01_subfinder_subdomains.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/01_subfinder_subdomains.txt"); else NUC_TGT=("-u" "$TARGET"); fi
  # -t takeovers (path-based) depends on a template directory literally
  # named "takeovers" existing at that exact path — current
  # nuclei-templates lays these out under http/takeovers/, so a bare
  # "-t takeovers" resolves to nothing and nuclei fatals with "no
  # templates provided for scan". -tags takeover (tag-based, same
  # mechanism Stage 3.5 already uses successfully) finds every template
  # carrying that tag regardless of which directory it physically lives
  # in, so it isn't broken by future template-repo reorganizations.
  #
  # CNAME-based takeover templates are a notorious false-positive source:
  # a CNAME pointing at an unclaimed-looking service page doesn't always
  # mean the service name is actually claimable right now. So the raw
  # nuclei hit here is treated as a LEAD, not a confirmed finding — it's
  # written to a "_candidates" file and the CNAME is logged for manual
  # confirmation (dig + check the provider's own "claim this" flow)
  # rather than reported directly in FINAL_SUMMARY as if verified.
  if nuclei "${NUC_TGT[@]}" -tags takeover -silent -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -jsonl -o "$OUT_DIR/01_5_nuclei_subdomain_takeover_candidates.jsonl" >/dev/null 2>"$OUT_DIR/.stage1_5_stderr"; then
    if [ -s "$OUT_DIR/01_5_nuclei_subdomain_takeover_candidates.jsonl" ]; then
      jq -r '"[TAKEOVER-CANDIDATE, NOT CONFIRMED] " + (.host // .["matched-at"] // "unknown") + " via template " + (.["template-id"] // "unknown") + " — verify manually: dig CNAME, check provider claim flow before reporting."' \
        "$OUT_DIR/01_5_nuclei_subdomain_takeover_candidates.jsonl" > "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt" 2>/dev/null
    fi
    drop_if_empty "$OUT_DIR/01_5_nuclei_subdomain_takeover_candidates.jsonl"
    drop_if_empty "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt"
    mark_done "STAGE_1_5"
  else
    log_msg "[ERROR] Stage 1.5 nuclei call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage1_5_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage1_5_stderr"
else
  log_msg "[INFO] Stage 1.5 Checkpoint found. Skipping..."
  draw_ui 15 "Stage 1.5/7: Takeovers (Skipped)"
fi

if ! is_done "STAGE_2"; then
  if [ "$RUSTSCAN_MODE" = "1" ]; then
    # RustScan has no -iL/file-input flag (still an open feature request
    # upstream: github.com/bee-san/RustScan/issues/34) — it only takes
    # -a with a comma-separated address list, so we build that ourselves.
    log_msg "[TASK] Running Stage 2: RustScan"
    draw_ui 25 "Stage 2/7: RustScan Ports"
    if [ -s "$OUT_DIR/01_subfinder_subdomains.txt" ]; then
      RS_ADDR=$(grep -v '^[[:space:]]*$' "$OUT_DIR/01_subfinder_subdomains.txt" | paste -sd,)
    else
      RS_ADDR="$TARGET"
    fi
    if rustscan -a "$RS_ADDR" $RS_TOP -b "$RS_BATCH" -t "$RS_TIMEOUT" --ulimit "$RS_ULIMIT" --scan-order "Random" --greppable --no-config > "$OUT_DIR/.rustscan_raw.txt" 2>"$OUT_DIR/.stage2_stderr"; then
      # IMPORTANT: RustScan's --greppable output resolves each input to
      # its IP before printing (confirmed via upstream RustScan issue
      # #379 — hostnames are NOT preserved in greppable mode, only IPs).
      # So unlike naabu's "host -> [ports]" style output, we cannot
      # directly recover which host owns which port from rustscan's
      # output alone.
      #
      # Fix (replaces the old blind cross-join): instead of pairing EVERY
      # hostname with every port found on ANY scanned IP (which produced
      # mostly-fake host:port pairs), resolve each hostname to its own IP
      # with dnsx/getent first, then only pair a hostname with the ports
      # that were actually open on ITS OWN resolved IP. A hostname that
      # can't be resolved here is paired with nothing rather than guessed.
      : > "$OUT_DIR/02_port_scan_results.txt"
      declare -A IP_TO_PORTS
      while IFS= read -r rs_line; do
        # greppable format: "host_or_ip () -> [port1,port2,...]"
        rs_ip=$(echo "$rs_line" | awk '{print $1}')
        rs_ports=$(echo "$rs_line" | grep -oE '\[[0-9,]+\]' | tr -d '[]')
        [ -n "$rs_ip" ] && [ -n "$rs_ports" ] && IP_TO_PORTS["$rs_ip"]="$rs_ports"
      done < "$OUT_DIR/.rustscan_raw.txt"
      rm -f "$OUT_DIR/.rustscan_raw.txt"
      if [ -s "$OUT_DIR/01_subfinder_subdomains.txt" ] && [ "${#IP_TO_PORTS[@]}" -gt 0 ]; then
        while IFS= read -r rs_host; do
          [ -z "$rs_host" ] && continue
          if command -v dnsx >/dev/null 2>&1; then
            rs_host_ip=$(dnsx -silent -a -resp-only -u "$rs_host" 2>/dev/null | head -n1)
          else
            rs_host_ip=$(getent ahosts "$rs_host" 2>/dev/null | awk '{print $1; exit}')
          fi
          [ -z "$rs_host_ip" ] && continue
          rs_ports_for_host="${IP_TO_PORTS[$rs_host_ip]}"
          [ -z "$rs_ports_for_host" ] && continue
          IFS=',' read -ra RS_PARR <<< "$rs_ports_for_host"
          for rs_port in "${RS_PARR[@]}"; do echo "${rs_host}:${rs_port}"; done
        done < "$OUT_DIR/01_subfinder_subdomains.txt" >> "$OUT_DIR/02_port_scan_results.txt"
        PAIRED_HOSTS=$(cut -d: -f1 "$OUT_DIR/02_port_scan_results.txt" 2>/dev/null | sort -u | wc -l)
        log_msg "[INFO] RustScan: resolved each hostname to its own IP and paired it only with ports found open on that IP ($PAIRED_HOSTS host(s) got a real port match; hostnames with no match or no DNS resolution were skipped, not guessed)."
      fi
      unset IP_TO_PORTS
      if [ ! -s "$OUT_DIR/02_port_scan_results.txt" ]; then cp "$OUT_DIR/01_subfinder_subdomains.txt" "$OUT_DIR/02_port_scan_results.txt"; fi
      mark_done "STAGE_2"
    else
      log_msg "[ERROR] Stage 2 rustscan call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage2_stderr" 2>/dev/null | cut -c1-500)"
    fi
    rm -f "$OUT_DIR/.stage2_stderr" "$OUT_DIR/.rustscan_raw.txt"
  else
    log_msg "[TASK] Running Stage 2: Naabu"
    draw_ui 25 "Stage 2/7: Naabu Ports"
    if [ -s "$OUT_DIR/01_subfinder_subdomains.txt" ]; then NAABU_TGT=("-list" "$OUT_DIR/01_subfinder_subdomains.txt"); else NAABU_TGT=("-host" "$TARGET"); fi
    # -ec (exclude CDN/WAF IP ranges from full port-scan; naabu still
    # reports 80/443 for them) stops CDN-fronted hosts (Cloudflare etc.)
    # from reporting dozens of "open" ports that actually belong to the
    # CDN edge, not the origin — a common source of misleading port lists.
    if naabu "${NAABU_TGT[@]}" -silent -c "$N_C" -rate "$N_RL" -ec -o "$OUT_DIR/02_port_scan_results.txt" > /dev/null 2>"$OUT_DIR/.stage2_stderr"; then
      if [ ! -s "$OUT_DIR/02_port_scan_results.txt" ]; then cp "$OUT_DIR/01_subfinder_subdomains.txt" "$OUT_DIR/02_port_scan_results.txt"; fi
      mark_done "STAGE_2"
    else
      log_msg "[ERROR] Stage 2 naabu call failed/exited non-zero — if this keeps failing on a chroot/Termux environment (raw-socket permission issues are common there), retry with -Rs to use RustScan instead. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage2_stderr" 2>/dev/null | cut -c1-500)"
    fi
    rm -f "$OUT_DIR/.stage2_stderr"
  fi
else
  log_msg "[INFO] Stage 2 Checkpoint found. Skipping..."
  draw_ui 25 "Stage 2/7: Naabu Ports (Skipped)"
fi

# --- Stage 2.5: non-web port service/version follow-up (nmap) ---
# naabu/rustscan only ever answer "is this port open" — they never say
# WHAT is running on it. A bare port number in 02_port_scan_results.txt
# (e.g. host:5432, host:6379, host:22) was previously a dead end with no
# next step. This pulls out every discovered port that isn't a standard
# web port, dedupes host:port pairs, and runs a quick -sV against just
# those so you get "PostgreSQL 13.2", "Redis 6.x, no auth", "OpenSSH
# 7.4" etc. instead of just a number. Skipped entirely if nmap isn't
# installed (checked in check_dependencies, informational only).
if ! is_done "STAGE_2_5"; then
  if command -v nmap >/dev/null 2>&1 && [ -s "$OUT_DIR/02_port_scan_results.txt" ]; then
    log_msg "[TASK] Running Stage 2.5: Non-web port service/version scan (nmap)"
    draw_ui 27 "Stage 2.5/7: Service/Version Scan"
    WEB_PORTS_RE='^(80|443|8080|8443|8000|8888|3000)$'
    : > "$OUT_DIR/02_5_nmap_targets.txt"
    while IFS= read -r hp; do
      [ -z "$hp" ] && continue
      hp_host="${hp%:*}"; hp_port="${hp##*:}"
      # skip lines with no ":port" suffix (plain hostnames from the
      # fallback path, where naabu/rustscan never actually ran)
      [ "$hp_host" = "$hp_port" ] && continue
      echo "$hp_port" | grep -qE '^[0-9]+$' || continue
      echo "$hp_port" | grep -qE "$WEB_PORTS_RE" && continue
      echo "${hp_host} ${hp_port}" >> "$OUT_DIR/02_5_nmap_targets.txt"
    done < "$OUT_DIR/02_port_scan_results.txt"
    sort -u "$OUT_DIR/02_5_nmap_targets.txt" -o "$OUT_DIR/02_5_nmap_targets.txt" 2>/dev/null
    if [ -s "$OUT_DIR/02_5_nmap_targets.txt" ]; then
      : > "$OUT_DIR/02_5_nmap_service_versions.txt"
      NMAP_RAW_TMP=$(mktemp "${TMPDIR:-/tmp}/mb_nmap_raw.XXXXXX")
      while IFS=' ' read -r nh np; do
        [ -z "$nh" ] && continue
        nmap -sV --version-light -Pn -p "$np" "$nh" -oG - 2>/dev/null | grep -v '^#' >> "$NMAP_RAW_TMP"
      done < "$OUT_DIR/02_5_nmap_targets.txt"
      if [ -s "$NMAP_RAW_TMP" ]; then
        grep -oE 'Host: [^ ]+.*Ports: [^/]+/[^/]+/[^/]+/[^/]+/[^/]*/[^/]*/' "$NMAP_RAW_TMP" 2>/dev/null > "$OUT_DIR/02_5_nmap_service_versions.txt"
        if [ ! -s "$OUT_DIR/02_5_nmap_service_versions.txt" ]; then cp "$NMAP_RAW_TMP" "$OUT_DIR/02_5_nmap_service_versions.txt"; fi
      fi
      rm -f "$NMAP_RAW_TMP"
      NMAP_TARGET_COUNT=$(wc -l < "$OUT_DIR/02_5_nmap_targets.txt" 2>/dev/null || echo 0)
      log_msg "[INFO] Stage 2.5: service/version scan completed for $NMAP_TARGET_COUNT non-web host:port pair(s)."
    fi
    drop_if_empty "$OUT_DIR/02_5_nmap_targets.txt"
    drop_if_empty "$OUT_DIR/02_5_nmap_service_versions.txt"
    mark_done "STAGE_2_5"
  else
    mark_done "STAGE_2_5"
  fi
else
  log_msg "[INFO] Stage 2.5 Checkpoint found. Skipping..."
  draw_ui 27 "Stage 2.5/7: Service/Version Scan (Skipped)"
fi

if ! is_done "STAGE_3"; then
  log_msg "[TASK] Running Stage 3: Httpx Toolkit"
  draw_ui 40 "Stage 3/7: Httpx Liveness"
  CUR_UA=$(get_random_ua)
  if [ -s "$OUT_DIR/02_port_scan_results.txt" ]; then HTTPX_TGT=("-l" "$OUT_DIR/02_port_scan_results.txt"); else HTTPX_TGT=("-u" "$TARGET"); fi

  log_msg "[DEBUG] httpx-toolkit target: ${HTTPX_TGT[*]}"
  # -json replaces the previous awk-on-raw-text parsing, so status/line
  # filtering below is against real structured fields, not column
  # position (which silently breaks if httpx's text column layout ever
  # changes). -fhr follows redirects on the final-hop host only, so an
  # http->https redirect on the same host collapses to one liveness
  # result instead of being probed/reported twice.
  if httpx-toolkit "${HTTPX_TGT[@]}" -silent -t "$H_T" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -status-code -tech-detect -title -content-length -fhr -json -H "User-Agent: $CUR_UA" "${H_HTTPX[@]}" -o "$OUT_DIR/03_httpx_raw_responses.jsonl" > /dev/null 2>"$OUT_DIR/.stage3_stderr"; then
    if [ -s "$OUT_DIR/03_httpx_raw_responses.jsonl" ]; then
      jq -r 'select(.status_code == 403 or .status_code == 429 or .status_code == 406 or .status_code == 503) | .url' "$OUT_DIR/03_httpx_raw_responses.jsonl" 2>/dev/null | sort -u > "$OUT_DIR/03_httpx_waf_blocked.txt"
      jq -r 'select(.status_code != 403 and .status_code != 429 and .status_code != 406 and .status_code != 503 and .status_code != 404) | .url' "$OUT_DIR/03_httpx_raw_responses.jsonl" 2>/dev/null | sort -u > "$OUT_DIR/03_httpx_live_hosts.txt"
    fi
    drop_if_empty "$OUT_DIR/03_httpx_waf_blocked.txt"
    drop_if_empty "$OUT_DIR/03_httpx_raw_responses.jsonl"
    if [ ! -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then
      drop_if_empty "$OUT_DIR/03_httpx_live_hosts.txt"
      log_msg "[WARN] No live hosts confirmed by httpx (all blocked/dead/empty list). Downstream stages will fall back to single-target mode against $TARGET (scheme auto-negotiated) instead of a host list."
    fi
    if [ -s "$OUT_DIR/03_httpx_waf_blocked.txt" ]; then
      log_msg "[INFO] $(wc -l < "$OUT_DIR/03_httpx_waf_blocked.txt") host(s) returned 403/406/429/503 and were excluded from the main scan, but kept in 03_httpx_waf_blocked.txt — these are worth a manual look (bypass headers/paths), not necessarily dead."
    fi
    mark_done "STAGE_3"
  else
    log_msg "[ERROR] Stage 3 httpx-toolkit call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage3_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage3_stderr"
else
  log_msg "[INFO] Stage 3 Checkpoint found. Skipping..."
  draw_ui 40 "Stage 3/7: Httpx Liveness (Skipped)"
fi

if ! is_done "STAGE_3_5"; then
  log_msg "[TASK] Running Stage 3.5: CORS & Config"
  draw_ui 50 "Stage 3.5/7: CORS & Config"
  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/03_httpx_live_hosts.txt"); else NUC_TGT=("-u" "$TARGET"); fi
  if nuclei "${NUC_TGT[@]}" -tags cors,config,exposure -silent -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -jsonl "${H_NUCLEI[@]}" -o "$OUT_DIR/03_5_nuclei_quickwins_raw.jsonl" >/dev/null 2>"$OUT_DIR/.stage3_5_stderr"; then
    nuclei_verify_findings "$OUT_DIR/03_5_nuclei_quickwins_raw.jsonl" "$OUT_DIR/03_5_nuclei_quickwins"
    drop_if_empty "$OUT_DIR/03_5_nuclei_quickwins_raw.jsonl"
    mark_done "STAGE_3_5"
  else
    log_msg "[ERROR] Stage 3.5 nuclei call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage3_5_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage3_5_stderr"
else
  log_msg "[INFO] Stage 3.5 Checkpoint found. Skipping..."
  draw_ui 50 "Stage 3.5/7: CORS & Config (Skipped)"
fi

# --- Stage 3.6: GraphQL detection + introspection ---
# katana/nuclei's standard crawl treats a GraphQL endpoint as just one
# flat URL ("/graphql"), so the entire query/mutation surface behind it
# — often the real attack surface on a GraphQL API — was previously
# completely invisible to every later stage. This probes common GraphQL
# paths directly, and if introspection is enabled (itself worth flagging
# — it should usually be disabled in production), dumps the schema and
# extracts every query/mutation name into the endpoint list so Stage 4.6
# triage and nuclei's own -tags graphql templates have something to work
# with instead of a single opaque URL.
if ! is_done "STAGE_3_6"; then
  log_msg "[TASK] Running Stage 3.6: GraphQL Detection"
  draw_ui 55 "Stage 3.6/7: GraphQL Detection"
  : > "$OUT_DIR/03_6_graphql_endpoints.txt"
  GQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/graphql/v1" "/graphiql" "/api/v1/graphql")
  GQL_INTROSPECTION='{"query":"query{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"}'
  CUR_UA=$(get_random_ua)

  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then
    GQL_HOSTS_FILE="$OUT_DIR/03_httpx_live_hosts.txt"
  else
    GQL_HOSTS_FILE="$OUT_DIR/.gql_single_target.txt"
    echo "https://${TARGET}" > "$GQL_HOSTS_FILE"
  fi

  graphql_probe() {
    local host="$1" path="$2" url resp
    eval "$CURL_HEADERS_DECL"
    url="${host%/}${path}"
    resp=$(curl -sk -m 10 -A "$CUR_UA" "${H_CURL[@]}" -H "Content-Type: application/json" -X POST -d "$GQL_INTROSPECTION" "$url" 2>/dev/null)
    if echo "$resp" | grep -q '"__schema"' 2>/dev/null; then
      echo "INTROSPECTION_ON|${url}|${resp}"
    elif echo "$resp" | grep -qiE '"errors"|"data"' 2>/dev/null; then
      echo "GRAPHQL_PRESENT|${url}|"
    fi
  }
  export -f graphql_probe
  export CUR_UA CURL_HEADERS_DECL GQL_INTROSPECTION

  : > "$OUT_DIR/.gql_probe_results.txt"
  while IFS= read -r gh; do
    [ -z "$gh" ] && continue
    for gp in "${GQL_PATHS[@]}"; do
      echo "${gh}|${gp}"
    done
  done < "$GQL_HOSTS_FILE" | xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c '
    pair="$1"; h="${pair%%|*}"; p="${pair##*|}"
    graphql_probe "$h" "$p"
  ' _ {} >> "$OUT_DIR/.gql_probe_results.txt" 2>/dev/null

  GQL_SCHEMA_DIR="$OUT_DIR/03_6_graphql_schemas"
  GQL_ON_COUNT=0; GQL_PRESENT_COUNT=0
  if [ -s "$OUT_DIR/.gql_probe_results.txt" ]; then
    mkdir -p "$GQL_SCHEMA_DIR"
    while IFS='|' read -r gstatus gurl gschema; do
      [ -z "$gstatus" ] && continue
      safe_name=$(echo "$gurl" | tr -cd 'a-zA-Z0-9._-' | tail -c 120)
      if [ "$gstatus" = "INTROSPECTION_ON" ]; then
        GQL_ON_COUNT=$((GQL_ON_COUNT + 1))
        echo "$gschema" > "$GQL_SCHEMA_DIR/${safe_name}.json"
        echo "[GRAPHQL-INTROSPECTION-ENABLED] $gurl — schema dumped to $GQL_SCHEMA_DIR/${safe_name}.json (usually should be disabled in production; review exposed types/mutations)" >> "$OUT_DIR/03_6_graphql_endpoints.txt"
        echo "$gschema" | jq -r '.data.__schema.types[]?.fields[]?.name // empty' 2>/dev/null | sort -u | sed "s#^#${gurl}?query=#" >> "$OUT_DIR/04_katana_endpoints_filtered.txt" 2>/dev/null
      else
        GQL_PRESENT_COUNT=$((GQL_PRESENT_COUNT + 1))
        echo "[GRAPHQL-PRESENT] $gurl — introspection appears disabled; still worth manual query/mutation enumeration" >> "$OUT_DIR/03_6_graphql_endpoints.txt"
      fi
    done < "$OUT_DIR/.gql_probe_results.txt"
  fi
  rm -f "$OUT_DIR/.gql_probe_results.txt"
  [ -f "$OUT_DIR/.gql_single_target.txt" ] && rm -f "$OUT_DIR/.gql_single_target.txt"
  log_msg "[INFO] Stage 3.6: GraphQL probe found $GQL_ON_COUNT endpoint(s) with introspection ON, $GQL_PRESENT_COUNT with GraphQL present but introspection likely OFF."

  # Supplement with nuclei's own graphql-tagged templates for anything
  # the manual probe above missed (different path conventions, etc).
  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/03_httpx_live_hosts.txt"); else NUC_TGT=("-u" "$TARGET"); fi
  if nuclei "${NUC_TGT[@]}" -tags graphql -silent -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -jsonl "${H_NUCLEI[@]}" -o "$OUT_DIR/03_6_nuclei_graphql_raw.jsonl" >/dev/null 2>"$OUT_DIR/.stage3_6_stderr"; then
    nuclei_verify_findings "$OUT_DIR/03_6_nuclei_graphql_raw.jsonl" "$OUT_DIR/03_6_nuclei_graphql"
    drop_if_empty "$OUT_DIR/03_6_nuclei_graphql_raw.jsonl"
  else
    log_msg "[ERROR] Stage 3.6 nuclei graphql call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage3_6_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage3_6_stderr"
  sort -u "$OUT_DIR/04_katana_endpoints_filtered.txt" -o "$OUT_DIR/04_katana_endpoints_filtered.txt" 2>/dev/null
  drop_if_empty "$OUT_DIR/03_6_graphql_endpoints.txt"
  mark_done "STAGE_3_6"
else
  log_msg "[INFO] Stage 3.6 Checkpoint found. Skipping..."
  draw_ui 55 "Stage 3.6/7: GraphQL Detection (Skipped)"
fi

# --- Stage 3.7: Screenshot triage (opt-in via -S) ---
# Pure convenience/triage — not a vuln-finding stage. With hundreds of
# live hosts, deciding where to look first by eye (login pages, API
# docs, default install pages, obviously broken apps) beats opening each
# one by hand. Skipped entirely unless -S was passed.
if [ "$SCREENSHOT_MODE" = "1" ]; then
  if ! is_done "STAGE_3_7"; then
    if command -v gowitness >/dev/null 2>&1 && [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then
      log_msg "[TASK] Running Stage 3.7: Screenshot Triage (gowitness)"
      draw_ui 58 "Stage 3.7/7: Screenshot Triage"
      GOWITNESS_DIR="$OUT_DIR/03_7_screenshots"
      mkdir -p "$GOWITNESS_DIR"
      gowitness scan file -f "$OUT_DIR/03_httpx_live_hosts.txt" --screenshot-path "$GOWITNESS_DIR" --write-db-uri "sqlite://$GOWITNESS_DIR/gowitness.sqlite3" --timeout 10 >/dev/null 2>"$OUT_DIR/.stage3_7_stderr"
      SHOT_COUNT=$(find "$GOWITNESS_DIR" -name '*.png' 2>/dev/null | wc -l)
      log_msg "[INFO] Stage 3.7: $SHOT_COUNT screenshot(s) saved to $GOWITNESS_DIR"
      rm -f "$OUT_DIR/.stage3_7_stderr"
      mark_done "STAGE_3_7"
    else
      mark_done "STAGE_3_7"
    fi
  else
    log_msg "[INFO] Stage 3.7 Checkpoint found. Skipping..."
    draw_ui 58 "Stage 3.7/7: Screenshot Triage (Skipped)"
  fi
fi

if ! is_done "STAGE_4"; then
  log_msg "[TASK] Running Stage 4: Katana & Arjun"
  draw_ui 65 "Stage 4/7: Crawling & Params"
  CUR_UA=$(get_random_ua)
  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then
    KAT_TGT=("-list" "$OUT_DIR/03_httpx_live_hosts.txt")
    ARJ_TGT=("-i" "$OUT_DIR/03_httpx_live_hosts.txt")
  else
    # katana/arjun docs only ever show full URLs (unlike nuclei/httpx,
    # which explicitly document accepting bare hostnames) — give them a
    # scheme so the fallback path doesn't silently misbehave.
    KAT_TGT=("-u" "https://$TARGET")
    ARJ_TGT=("-u" "https://$TARGET")
  fi

  # -hl (headless): spins up a real Chromium tab per page instead of a
  # plain HTTP+JS-extraction crawl. Needed for SPAs (React/Vue/Angular
  # client-side routing) — the default crawl only ever sees URLs present
  # in the raw HTML or statically extractable from JS source, and
  # silently misses any route that only materializes after the framework
  # renders it (common pattern: a near-empty index.html + a JS bundle
  # that builds the whole app client-side). Each headless page load is
  # far more expensive than a plain request, so rate is capped lower than
  # whatever MODE/POWER would otherwise allow, regardless of how high
  # N_RL is — otherwise "-L -m brawler -p vps" would try to run 150
  # concurrent real browser tabs, and the host running this script (not
  # the target) would fall over first.
  K_EFFECTIVE_RL=$N_RL
  K_HEADLESS_ARGS=()
  if [ "$HEADLESS_MODE" = "1" ]; then
    [ "$K_EFFECTIVE_RL" -gt 10 ] && K_EFFECTIVE_RL=10
    K_HEADLESS_ARGS=("-hl" "-system-chrome")
    log_msg "[INFO] Stage 4: headless crawl enabled (-L) — rate capped at $K_EFFECTIVE_RL regardless of -m/-p, since each page is a real browser tab."
  fi

  # -ef excludes purely static asset extensions from the crawl output —
  # without it, "filtered" (the query-string/API endpoint list every
  # later stage treats as the interesting set) was getting diluted with
  # CSS/image/font URLs that can never carry a meaningful parameter.
  if katana "${KAT_TGT[@]}" -silent -d "$K_D" -rl "$K_EFFECTIVE_RL" $K_JS -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ico,ttf,eot,map "${K_HEADLESS_ARGS[@]}" -H "User-Agent: $CUR_UA" "${H_KATANA[@]}" -o "$OUT_DIR/04_katana_endpoints_raw.txt" > /dev/null 2>"$OUT_DIR/.stage4_stderr"; then
    # Arjun's hidden-param discovery is run per discovered endpoint (not
    # only against the bare live-host roots as before), since parameter
    # fuzzing on "/" rarely reflects what a deeper app endpoint accepts.
    # It's still capped to the katana-scoped list (not re-crawled) to
    # avoid redundant requests, and respects the same MODE-driven pacing
    # as the other raw-request stages.
    KATANA_BEFORE=$(wc -l < "$OUT_DIR/04_katana_endpoints_raw.txt" 2>/dev/null || echo 0)
    awk -F/ -v re="$STRICT_REGEX" '{ split($3, h, ":"); host = tolower(h[1]); if (host ~ re) print $0 }' "$OUT_DIR/04_katana_endpoints_raw.txt" > "$OUT_DIR/04_katana_scoped.txt" 2>/dev/null
    mv "$OUT_DIR/04_katana_scoped.txt" "$OUT_DIR/04_katana_endpoints_raw.txt"
    KATANA_AFTER=$(wc -l < "$OUT_DIR/04_katana_endpoints_raw.txt" 2>/dev/null || echo 0)
    log_msg "[INFO] Scope re-check on katana output: $KATANA_BEFORE -> $KATANA_AFTER URLs."

    # Dedup by path (ignore query string) before handing URLs to Arjun.
    # Arjun's job is discovering UNDISCLOSED parameter names on a given
    # endpoint shape — it doesn't care what value an already-visible
    # parameter holds. Without this, a paginated/sorted listing like
    # view.php?id=1&o=1 through &o=10 gets fuzzed as 10 separate targets
    # even though they're the same endpoint with the same hidden-param
    # surface, which is pure wasted request volume (this was the single
    # biggest contributor to a 5+ hour stealth-mode runtime on a page-
    # heavy LMS/CMS). This does NOT reduce coverage of distinct endpoint
    # shapes or distinct IDs for nuclei/DAST purposes — it only limits
    # what Arjun itself is asked to fuzz; 04_katana_endpoints_raw.txt and
    # 04_katana_endpoints_filtered.txt (used by triage and Stage 7 DAST)
    # are untouched. The one real trade-off: if a parameter is only
    # exposed on one specific id/value (e.g. a plugin only active on one
    # course), deduping by path could miss discovering that parameter
    # name, since Arjun would only ever probe the first URL seen for
    # that path. For a quick/stealth run this is an acceptable trade,
    # not a free coverage win — re-run without dedup (or raise -m) if
    # you specifically suspect value-dependent hidden parameters.
    awk -F'?' '!seen[$1]++' "$OUT_DIR/04_katana_endpoints_raw.txt" > "$OUT_DIR/.arjun_dedup.txt" 2>/dev/null
    if [ -s "$OUT_DIR/.arjun_dedup.txt" ]; then
      ARJUN_DEDUP_BEFORE=$(wc -l < "$OUT_DIR/04_katana_endpoints_raw.txt" 2>/dev/null || echo 0)
      ARJUN_DEDUP_AFTER=$(wc -l < "$OUT_DIR/.arjun_dedup.txt" 2>/dev/null || echo 0)
      log_msg "[INFO] Arjun input deduped by path (query string ignored): $ARJUN_DEDUP_BEFORE -> $ARJUN_DEDUP_AFTER URLs. Full URL list (all query variants) is untouched for triage/DAST."
      ARJUN_INPUT="$OUT_DIR/.arjun_dedup.txt"
    else
      ARJUN_INPUT="$OUT_DIR/04_katana_endpoints_raw.txt"
    fi
    if [ -s "$ARJUN_INPUT" ]; then ARJ_TGT=("-i" "$ARJUN_INPUT"); fi
    if [ "$MODE" = "stealth" ]; then ARJ_PACE=("-d" "1" "--stable"); else ARJ_PACE=(); fi
    if ! arjun "${ARJ_TGT[@]}" -t "$H_T" "${ARJ_PACE[@]}" "${H_ARJUN[@]}" -oT "$OUT_DIR/05_arjun_hidden_params.txt" > /dev/null 2>"$OUT_DIR/.stage4_arjun_stderr"; then
      log_msg "[ERROR] Stage 4 arjun call failed/exited non-zero (katana still succeeded). stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage4_arjun_stderr" 2>/dev/null | cut -c1-500)"
    fi
    rm -f "$OUT_DIR/.stage4_arjun_stderr"

    grep -E "\?.*=|/api/v[0-9]+/" "$OUT_DIR/04_katana_endpoints_raw.txt" | sort -u > "$OUT_DIR/04_katana_endpoints_filtered.txt"
    if [ -s "$OUT_DIR/05_arjun_hidden_params.txt" ]; then
      # Sanity-filter arjun's own output before merging it in: -oT output
      # should be lines that look like URLs. Guards against -oT format
      # drift between arjun versions silently poisoning the endpoint list
      # with non-URL text.
      grep -E '^https?://' "$OUT_DIR/05_arjun_hidden_params.txt" >> "$OUT_DIR/04_katana_endpoints_filtered.txt" 2>/dev/null
    fi
    sort -u "$OUT_DIR/04_katana_endpoints_filtered.txt" -o "$OUT_DIR/04_katana_endpoints_filtered.txt"
    drop_if_empty "$OUT_DIR/04_katana_endpoints_raw.txt"
    drop_if_empty "$OUT_DIR/04_katana_endpoints_filtered.txt"
    drop_if_empty "$OUT_DIR/05_arjun_hidden_params.txt"
    rm -f "$OUT_DIR/.arjun_dedup.txt"
    mark_done "STAGE_4"
  else
    log_msg "[ERROR] Stage 4 katana call failed/exited non-zero. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage4_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage4_stderr"
else
  log_msg "[INFO] Stage 4 Checkpoint found. Skipping..."
  draw_ui 65 "Stage 4/7: Crawling & Params (Skipped)"
fi

if ! is_done "STAGE_4_5"; then
  log_msg "[TASK] Running Stage 4.5: Soft-404 Baseline Filter"
  draw_ui 72 "Stage 4.5/7: Soft-404 Filter"
  BASELINE_FILE="$OUT_DIR/04_5_soft404_baseline.txt"
  CUR_UA=$(get_random_ua)

  # Baseline signature is now (status_code|length_bucket|title) instead of
  # a raw MD5 of the body. A raw hash broke on any page that reflects the
  # requested (random) path, a CSRF token, or a timestamp into the 404
  # body — which is common — causing the baseline to never match twice
  # and soft-404s to sail straight through. Length is bucketed to the
  # nearest 50 bytes so trivial per-request variance (a reflected token
  # of different length each time) doesn't break the comparison either.
  # Two baseline probes per host (two different random paths) are taken
  # and must agree with each other, or the baseline for that host is
  # considered unstable and skipped (fail-open: that host's endpoints are
  # kept rather than risk filtering out real content).
  baseline_sig() {
    # mktemp instead of a $$-named path: not because $$ can collide
    # between concurrent xargs workers (it can't — the kernel guarantees
    # distinct PIDs for processes alive at the same time), but because a
    # predictable filename in shared /tmp is a classic symlink-race
    # target on a multi-user box. mktemp's random suffix removes that
    # class of risk entirely, for free.
    local url="$1" token resp status len len_bucket title tmpf
    tmpf=$(mktemp "${TMPDIR:-/tmp}/mb_body.XXXXXX") || return
    token=$(date +%s%N | md5sum | head -c 16)
    resp=$(curl -sk -m 10 -A "$CUR_UA" "${H_CURL[@]}" -D - -o "$tmpf" "${url%/}/maidbug-check-${token}" 2>/dev/null)
    status=$(echo "$resp" | head -n1 | grep -oE '[0-9]{3}' | head -n1)
    len=$(wc -c < "$tmpf" 2>/dev/null || echo 0)
    len_bucket=$(( (len / 50) * 50 ))
    title=$(grep -ioE '<title>[^<]*' "$tmpf" 2>/dev/null | head -n1 | sed 's/<title>//I')
    rm -f "$tmpf"
    echo "${status}|${len_bucket}|${title}"
  }

  baseline_check() {
    local host="$1" sig1 sig2
    eval "$CURL_HEADERS_DECL"
    sig1=$(baseline_sig "$host")
    sig2=$(baseline_sig "$host")
    if [ "$sig1" = "$sig2" ]; then
      echo "${host}|${sig1}"
    fi
    # if sig1 != sig2, baseline is unstable for this host — emit nothing;
    # soft404_check below fails open (keeps the URL) when no baseline exists.
  }
  export -f baseline_check baseline_sig
  export CUR_UA CURL_HEADERS_DECL

  : > "$BASELINE_FILE"
  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then
    xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'baseline_check "$@"' _ {} < "$OUT_DIR/03_httpx_live_hosts.txt" > "$BASELINE_FILE" 2>/dev/null
  fi

  if [ -s "$OUT_DIR/04_katana_endpoints_filtered.txt" ] && [ -s "$BASELINE_FILE" ]; then
    soft404_check() {
      local url="$1" host base_sig cur_status cur_len cur_len_bucket cur_title cur_sig resp tmpf
      eval "$CURL_HEADERS_DECL"
      host=$(echo "$url" | awk -F/ '{print $1"//"$3}')
      base_sig=$(grep -F "${host}|" "$BASELINE_FILE" | head -n1 | cut -d'|' -f2-)
      # No stable baseline for this host (unstable or never probed) —
      # fail open and keep the URL rather than risk dropping real content.
      if [ -z "$base_sig" ]; then echo "$url"; return; fi
      tmpf=$(mktemp "${TMPDIR:-/tmp}/mb_u.XXXXXX") || { echo "$url"; return; }
      resp=$(curl -sk -m 10 -A "$CUR_UA" "${H_CURL[@]}" -D - -o "$tmpf" "$url" 2>/dev/null)
      cur_status=$(echo "$resp" | head -n1 | grep -oE '[0-9]{3}' | head -n1)
      cur_len=$(wc -c < "$tmpf" 2>/dev/null || echo 0)
      cur_len_bucket=$(( (cur_len / 50) * 50 ))
      cur_title=$(grep -ioE '<title>[^<]*' "$tmpf" 2>/dev/null | head -n1 | sed 's/<title>//I')
      rm -f "$tmpf"
      cur_sig="${cur_status}|${cur_len_bucket}|${cur_title}"
      # Explicitly drop hard 404s/5xx/empty-timeout responses regardless of
      # baseline match — these were previously only caught if they happened
      # to also hash-match the baseline.
      case "$cur_status" in
        404|"") return ;;
        5*) return ;;
      esac
      if [ "$cur_sig" != "$base_sig" ]; then echo "$url"; fi
    }
    export -f soft404_check
    export BASELINE_FILE CUR_UA CURL_HEADERS_DECL

    BEFORE_COUNT=$(wc -l < "$OUT_DIR/04_katana_endpoints_filtered.txt")
    xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'soft404_check "$@"' _ {} < "$OUT_DIR/04_katana_endpoints_filtered.txt" > "$OUT_DIR/tmp_filtered.txt" 2>/dev/null
    sort -u "$OUT_DIR/tmp_filtered.txt" -o "$OUT_DIR/04_katana_endpoints_filtered.txt"
    rm -f "$OUT_DIR/tmp_filtered.txt"
    AFTER_COUNT=$(wc -l < "$OUT_DIR/04_katana_endpoints_filtered.txt")
    log_msg "[INFO] Soft-404 filter (status+length-bucket+title signature, 2-probe stable baseline): $BEFORE_COUNT -> $AFTER_COUNT endpoints."
  fi
  drop_if_empty "$BASELINE_FILE"
  drop_if_empty "$OUT_DIR/04_katana_endpoints_filtered.txt"
  mark_done "STAGE_4_5"
else
  log_msg "[INFO] Stage 4.5 Checkpoint found. Skipping..."
  draw_ui 72 "Stage 4.5/7: Soft-404 Filter (Skipped)"
fi

# --- Stage 4.55: Historical/archived URL discovery (gau+uro, opt-in via -g) ---
# katana only ever sees URLs reachable from the CURRENT live site state.
# Old API versions, debug pages, and endpoints removed from navigation
# but never actually deleted from the server are invisible to it. gau
# pulls every URL the domain (and its subdomains) has ever had indexed
# across the Wayback Machine, Common Crawl, OTX and urlscan.io; uro then
# dedupes/normalizes that output, which on its own is typically very
# noisy (near-duplicate query strings, long-dead parked pages, unrelated
# old campaigns). Every surviving URL is re-validated against the Stage
# 4.5 soft-404 baseline before being trusted at all.
#
# Unlike the rest of the pipeline's fail-OPEN default (keep a URL when
# its host has no stable baseline, to avoid dropping real content), this
# stage fails CLOSED: a URL here is dropped when its host has no stable
# baseline to compare against. gau's raw output is noisy enough that
# fail-open would flood 04_6 triage and Stage 7 DAST with dead archive
# junk instead of the "still alive but forgotten" endpoints this stage
# exists to surface.
if [ "$HISTORICAL_MODE" = "1" ]; then
  if ! is_done "STAGE_4_55"; then
    log_msg "[TASK] Running Stage 4.55: Historical URL Discovery (gau+uro)"
    draw_ui 73 "Stage 4.55/7: Historical URLs (gau+uro)"
    : > "$OUT_DIR/04_55_gau_historical_endpoints.txt"
    GAU_SOFT404_BASELINE="$OUT_DIR/04_5_soft404_baseline.txt"
    GAU_RAW="$OUT_DIR/.gau_raw.txt"
    # Run as a plain statement (not "if pipeline; then") so PIPESTATUS is
    # available right after: without pipefail (not set anywhere in this
    # script), "if gau | uro; then" only ever checks uro's exit code.
    # uro happily exits 0 on empty stdin, so a gau failure (network error,
    # Wayback/CommonCrawl/OTX timeout, etc.) would be silently reported as
    # success — 0 URLs found, Stage checkpointed done, never retried.
    # PIPESTATUS[0] is gau's own exit code, checked explicitly below.
    gau --subs "$TARGET" 2>"$OUT_DIR/.stage4_55_stderr" | uro 2>>"$OUT_DIR/.stage4_55_stderr" > "$GAU_RAW"
    GAU_EXIT="${PIPESTATUS[0]}"
    if [ "$GAU_EXIT" -eq 0 ]; then
      GAU_TOTAL=$(wc -l < "$GAU_RAW" 2>/dev/null || echo 0)
      # Re-scope: gau/uro have their own notion of "in scope" that doesn't
      # necessarily match -s/STRICT_REGEX, so re-check every URL the same
      # way Stage 4 re-checks katana's own output.
      awk -F/ -v re="$STRICT_REGEX" '{ split($3, h, ":"); host = tolower(h[1]); if (host ~ re) print $0 }' "$GAU_RAW" > "$OUT_DIR/.gau_scoped.txt" 2>/dev/null
      mv "$OUT_DIR/.gau_scoped.txt" "$GAU_RAW"
      GAU_SCOPED=$(wc -l < "$GAU_RAW" 2>/dev/null || echo 0)
      log_msg "[INFO] Stage 4.55: gau+uro returned $GAU_TOTAL historical URL(s), $GAU_SCOPED in scope. Live-validating against the soft-404 baseline before keeping any."

      if [ -s "$GAU_RAW" ] && [ -s "$GAU_SOFT404_BASELINE" ]; then
        gau_live_check() {
          local url="$1" host base_sig cur_status cur_len cur_len_bucket cur_title cur_sig resp tmpf
          eval "$CURL_HEADERS_DECL"
          tmpf=$(mktemp "${TMPDIR:-/tmp}/mb_gau.XXXXXX") || return
          resp=$(curl -sk -m 10 -A "$CUR_UA" "${H_CURL[@]}" -D - -o "$tmpf" "$url" 2>/dev/null)
          cur_status=$(echo "$resp" | head -n1 | grep -oE '[0-9]{3}' | head -n1)
          cur_len=$(wc -c < "$tmpf" 2>/dev/null || echo 0)
          cur_len_bucket=$(( (cur_len / 50) * 50 ))
          cur_title=$(grep -ioE '<title>[^<]*' "$tmpf" 2>/dev/null | head -n1 | sed 's/<title>//I')
          rm -f "$tmpf"
          case "$cur_status" in
            400|404|410|""|5*) return ;;
          esac
          host=$(echo "$url" | awk -F/ '{print $1"//"$3}')
          base_sig=$(grep -F "${host}|" "$GAU_SOFT404_BASELINE" 2>/dev/null | head -n1 | cut -d'|' -f2-)
          # Fail CLOSED (see comment above this stage) — drop if no
          # stable baseline for this host, rather than risk flooding the
          # output with dead archive URLs.
          if [ -z "$base_sig" ]; then return; fi
          cur_sig="${cur_status}|${cur_len_bucket}|${cur_title}"
          if [ "$cur_sig" != "$base_sig" ]; then echo "$url"; fi
        }
        export -f gau_live_check
        CUR_UA=$(get_random_ua)
        export CUR_UA CURL_HEADERS_DECL GAU_SOFT404_BASELINE
        xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'gau_live_check "$@"' _ {} < "$GAU_RAW" > "$OUT_DIR/04_55_gau_historical_endpoints.txt" 2>/dev/null
        sort -u "$OUT_DIR/04_55_gau_historical_endpoints.txt" -o "$OUT_DIR/04_55_gau_historical_endpoints.txt" 2>/dev/null
        GAU_SURVIVED=$(wc -l < "$OUT_DIR/04_55_gau_historical_endpoints.txt" 2>/dev/null || echo 0)
        log_msg "[INFO] Stage 4.55: $GAU_SURVIVED historical URL(s) still alive and distinguishable from the soft-404 baseline — merged into the endpoint list for triage/DAST."
        # Feed survivors into the same files Stage 4.6/7 already read, so
        # they get triaged and DAST-fuzzed like any other endpoint, not
        # siloed off in a file nothing downstream looks at.
        if [ -s "$OUT_DIR/04_55_gau_historical_endpoints.txt" ]; then
          cat "$OUT_DIR/04_55_gau_historical_endpoints.txt" >> "$OUT_DIR/04_katana_endpoints_raw.txt"
          grep -E "\?.*=|/api/v[0-9]+/" "$OUT_DIR/04_55_gau_historical_endpoints.txt" >> "$OUT_DIR/04_katana_endpoints_filtered.txt" 2>/dev/null
          sort -u "$OUT_DIR/04_katana_endpoints_raw.txt" -o "$OUT_DIR/04_katana_endpoints_raw.txt" 2>/dev/null
          sort -u "$OUT_DIR/04_katana_endpoints_filtered.txt" -o "$OUT_DIR/04_katana_endpoints_filtered.txt" 2>/dev/null
        fi
      elif [ ! -s "$GAU_SOFT404_BASELINE" ]; then
        log_msg "[WARN] Stage 4.55: no soft-404 baseline available (Stage 4.5 found no stable baseline for any host) — skipping historical URLs entirely rather than trusting unvalidated gau/uro output."
      fi
      mark_done "STAGE_4_55"
    else
      log_msg "[ERROR] Stage 4.55: gau exited non-zero (exit $GAU_EXIT) — NOT marked done, will retry next run. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage4_55_stderr" 2>/dev/null | cut -c1-500)"
    fi
    rm -f "$GAU_RAW" "$OUT_DIR/.stage4_55_stderr"
    drop_if_empty "$OUT_DIR/04_55_gau_historical_endpoints.txt"
  else
    log_msg "[INFO] Stage 4.55 Checkpoint found. Skipping..."
    draw_ui 73 "Stage 4.55/7: Historical URLs (Skipped)"
  fi
fi

# Stage 4.6 doesn't change what earlier stages produce — it only reads
# the already-final 04_katana_endpoints_filtered.txt and picks out a
# SUBSET worth a human's attention first. Automated tools can't tell
# "/health-check" from "/api/v1/admin/users/123" — this is a rough,
# regex-based triage to point manual effort at the endpoints that most
# often turn into IDOR / auth-bypass / business-logic findings, not a
# replacement for looking at the full list.
if ! is_done "STAGE_4_6"; then
  log_msg "[TASK] Running Stage 4.6: Endpoint Triage"
  draw_ui 74 "Stage 4.6/7: Endpoint Triage"
  : > "$OUT_DIR/04_6_interesting_endpoints.txt"
  if [ -s "$OUT_DIR/04_katana_endpoints_raw.txt" ]; then
    # Deliberately sourced from the full scope-filtered raw crawl, not
    # 04_katana_endpoints_filtered.txt — that file is already narrowed to
    # query-string/api-path endpoints only, which would silently exclude
    # static-looking but high-value paths like /admin/dashboard or
    # /.git/config before triage ever saw them.
    TRIAGE_SRC="$OUT_DIR/.triage_src.txt"
    # Drop two known noise sources before triage ever sees them:
    #   - "%5c"/literal backslash: katana's JS-bundle extractor occasionally
    #     lifts a relative-path fragment out of minified JS and glues it
    #     onto every directory it visited, producing URLs like
    #     "/admin/gallery%5C/1793716606%5C/" that were never real app
    #     routes to begin with.
    #   - PHP asset-router paths (javascript.php/, requirejs.php/,
    #     image.php/, styles.php/) that embed a cache-busting revision
    #     number in the path itself (Moodle does this) — the HIGH regex
    #     below has no idea that number is a cache revision, not an
    #     object id, and would otherwise flag every static asset as an
    #     IDOR candidate.
    cat "$OUT_DIR/04_katana_endpoints_raw.txt" "$OUT_DIR/05_arjun_hidden_params.txt" 2>/dev/null \
      | grep -viE '%5c|\\|/(javascript|requirejs|image|styles)\.php/' \
      | sed 's/&amp;/\&/g' | sort -u > "$TRIAGE_SRC"
    # HIGH: numeric/UUID object IDs (classic IDOR shape) or admin/
    # privileged-sounding paths — usually the highest payoff to test
    # by hand (access control, IDOR, privilege escalation).
    HIGH_RE='/[0-9]+([/?]|$)|[?&][a-zA-Z_]*id=[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[/_-](admin|administrator|dashboard|internal|staff|backend|manage|superuser)'
    # MEDIUM: auth flows, account/user management, sensitive actions,
    # and debug/config/API-doc exposure — often the doorway INTO a
    # HIGH-shaped endpoint, or config exposure worth a quick manual look.
    # Boundary after each keyword includes -/_ too (not just /, ?, end) —
    # real-world paths are often hyphenated ("/reset-password",
    # "/forgot-password"), and a slash-only boundary silently drops those
    # into the "boring" bucket even though they're squarely auth-related.
    MED_RE='[/_-](login|logout|auth|token|session|password|reset|register|signup|oauth|sso)([/?_-]|$)|[/_-](user|users|account|accounts|profile|member|order|orders|payment|billing|invoice|checkout|transfer)([/?_-]|$)|[/_-](delete|remove|update|edit|upload|import|export)([/?_-]|$)|/(debug|config|env|actuator|metrics|swagger|openapi|graphql|\.git|\.svn|backup|dump)'

    grep -inE "$HIGH_RE" "$TRIAGE_SRC" 2>/dev/null | cut -d: -f2- | sort -u | sed 's/^/[HIGH]   [access-control\/IDOR shape] /' > "$OUT_DIR/04_6_interesting_endpoints.txt"
    grep -inE "$MED_RE" "$TRIAGE_SRC" 2>/dev/null | cut -d: -f2- | sort -u | grep -vFf <(grep -inE "$HIGH_RE" "$TRIAGE_SRC" 2>/dev/null | cut -d: -f2-) | sed 's/^/[MEDIUM] [auth\/sensitive-action\/exposure] /' >> "$OUT_DIR/04_6_interesting_endpoints.txt"

    TRIAGE_TOTAL=$(wc -l < "$OUT_DIR/04_6_interesting_endpoints.txt" 2>/dev/null || echo 0)
    log_msg "[INFO] Endpoint triage: $TRIAGE_TOTAL of $(wc -l < "$TRIAGE_SRC") crawled endpoints flagged as worth a manual look first."
    rm -f "$TRIAGE_SRC"

    # Re-use the status+length-bucket+title baseline from Stage 4.5 to
    # drop triage entries that are indistinguishable from a known-bad
    # path on their host, now against this stage's own (much smaller)
    # candidate list.
    SOFT404_BASELINE="$OUT_DIR/04_5_soft404_baseline.txt"
    if [ -s "$SOFT404_BASELINE" ] && [ -s "$OUT_DIR/04_6_interesting_endpoints.txt" ]; then
      validate_triage_entry() {
        local line="$1" url host base_sig cur_status cur_len cur_len_bucket cur_title cur_sig resp tmpf
        eval "$CURL_HEADERS_DECL"
        url=$(echo "$line" | grep -oE 'https?://\S+')
        [ -z "$url" ] && return
        tmpf=$(mktemp "${TMPDIR:-/tmp}/mb_t.XXXXXX") || { echo "$line"; return; }
        resp=$(curl -sk -m 10 -A "$CUR_UA" "${H_CURL[@]}" -D - -o "$tmpf" "$url" 2>/dev/null)
        cur_status=$(echo "$resp" | head -n1 | grep -oE '[0-9]{3}' | head -n1)
        cur_len=$(wc -c < "$tmpf" 2>/dev/null || echo 0)
        cur_len_bucket=$(( (cur_len / 50) * 50 ))
        cur_title=$(grep -ioE '<title>[^<]*' "$tmpf" 2>/dev/null | head -n1 | sed 's/<title>//I')
        rm -f "$tmpf"
        # Drop hard 400/404/410/5xx/empty responses outright, regardless of
        # whether this host even has a stable baseline. Previously this
        # check only existed in Stage 4.5's soft404_check — Stage 4.6 had
        # no equivalent, so a plain hard-404 on a host whose baseline
        # happened to be unstable (fails open, see below) sailed straight
        # into the [HIGH]/[MEDIUM] triage list as if it were live content.
        case "$cur_status" in
          400|404|410|""|5*) return ;;
        esac
        host=$(echo "$url" | awk -F/ '{print $1"//"$3}')
        base_sig=$(grep -F "${host}|" "$SOFT404_BASELINE" 2>/dev/null | head -n1 | cut -d'|' -f2-)
        if [ -z "$base_sig" ]; then
          echo "$line"; return  # no stable baseline for this host — fail open, keep it
        fi
        cur_sig="${cur_status}|${cur_len_bucket}|${cur_title}"
        if [ "$cur_sig" != "$base_sig" ]; then echo "$line"; fi
      }
      export -f validate_triage_entry
      CUR_UA=$(get_random_ua)
      export CUR_UA CURL_HEADERS_DECL SOFT404_BASELINE
      TRIAGE_BEFORE=$(wc -l < "$OUT_DIR/04_6_interesting_endpoints.txt")
      xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'validate_triage_entry "$@"' _ {} < "$OUT_DIR/04_6_interesting_endpoints.txt" > "$OUT_DIR/.triage_validated.txt" 2>/dev/null
      mv "$OUT_DIR/.triage_validated.txt" "$OUT_DIR/04_6_interesting_endpoints.txt"
      TRIAGE_AFTER=$(wc -l < "$OUT_DIR/04_6_interesting_endpoints.txt")
      log_msg "[INFO] Endpoint triage liveness check: $TRIAGE_BEFORE -> $TRIAGE_AFTER (dropped entries indistinguishable from a known-bad path on their host)."
    fi
  fi
  drop_if_empty "$OUT_DIR/04_6_interesting_endpoints.txt"
  mark_done "STAGE_4_6"
else
  log_msg "[INFO] Stage 4.6 Checkpoint found. Skipping..."
  draw_ui 74 "Stage 4.6/7: Endpoint Triage (Skipped)"
fi

# Stage 4.7 only runs if -A was given — without a second identity there's
# nothing to diff against, so this is opt-in and silent-skipped otherwise.
# It only re-checks Stage 4.6's [HIGH] (IDOR-shaped) candidates, not every
# crawled endpoint — deliberate, since this now makes 3 requests per URL
# (anonymous baseline + identity A + identity B), so it stays scoped to
# the highest-payoff subset rather than tripling the request volume of
# the whole crawl.
#
# REWRITTEN LOGIC: the previous version flagged a *status-code mismatch*
# between -H and -A, which is backwards — an admin session getting 200
# where a normal session gets 403 is the EXPECTED, correct behavior and
# is not a finding. It also could never catch the actual vulnerability
# class this stage exists for: a low-privilege identity getting the SAME
# 200 response an admin identity gets on an admin/IDOR-shaped endpoint.
#
# The fixed check now:
#   1. Adds a third, unauthenticated request as a baseline.
#   2. Flags when the LOWER-privileged identity (assumed to be -H; -A is
#      assumed to be the higher-privileged/admin identity, matching the
#      flag's own documented purpose "-A ... e.g. an admin session
#      cookie") gets a 2xx response, AND that response's status+length
#      is materially similar to identity -A's response, AND it differs
#      from the anonymous baseline (so an endpoint that's simply public
#      for everyone, anonymous included, isn't flagged as broken access
#      control).
#   3. Follows redirects (-L) so a 302-to-login isn't miscounted as "200
#      body" for either identity.
#   4. Uses response length SIMILARITY (within 10%), never a bare status
#      match alone, as the signal that -H is seeing admin-equivalent
#      content — matching status 200 alone is not proof of equivalent
#      access (a generic "your own profile" 200 looks nothing like an
#      admin's 200, and this stage must not flag that as a finding).
if ! is_done "STAGE_4_7"; then
  if [ "${#HEADERS_B[@]}" -gt 0 ] && [ -s "$OUT_DIR/04_6_interesting_endpoints.txt" ]; then
    log_msg "[TASK] Running Stage 4.7: Access Control Diff (broken-access-control direction: does -H's lower-priv identity see -A's admin-equivalent content?)"
    draw_ui 76 "Stage 4.7/7: Access Control Diff"
    : > "$OUT_DIR/04_7_access_control_diff.txt"
    grep '^\[HIGH\]' "$OUT_DIR/04_6_interesting_endpoints.txt" 2>/dev/null | grep -oE 'https?://\S+' > "$OUT_DIR/.diff_candidates.txt"
    if [ -s "$OUT_DIR/.diff_candidates.txt" ]; then
      # Pulls a normalized, sorted list of key-paths out of a JSON body —
      # array indices are collapsed to "N" so two arrays of different
      # LENGTH but identical item SHAPE still compare as structurally
      # equal. Used below to catch cases a byte-size diff alone misses:
      # two JSON payloads can differ meaningfully (one real record vs one
      # empty-but-same-shaped placeholder) while landing within 10% of
      # each other's byte size, or conversely look byte-size-different
      # while actually being the exact same record (extra whitespace,
      # different field ordering).
      json_key_paths() {
        jq -r '[paths(scalars) as $p | ($p | map(if type=="number" then "N" else tostring end) | join("."))] | sort | unique | .[]' "$1" 2>/dev/null
      }
      access_diff_check() {
        local url="$1" resp_anon resp_a resp_b code_anon len_anon code_a len_a code_b len_b diff_pct
        local tmpf_anon tmpf_a tmpf_b key_diff
        eval "$CURL_HEADERS_DECL"
        eval "$CURL_HEADERS_B_DECL"
        tmpf_anon=$(mktemp "${TMPDIR:-/tmp}/mb_diff_anon.XXXXXX") || return
        tmpf_a=$(mktemp "${TMPDIR:-/tmp}/mb_diff_a.XXXXXX") || { rm -f "$tmpf_anon"; return; }
        tmpf_b=$(mktemp "${TMPDIR:-/tmp}/mb_diff_b.XXXXXX") || { rm -f "$tmpf_anon" "$tmpf_a"; return; }
        # anon: no auth headers at all (neither -H nor -A's identity).
        # Bodies are now captured (not just -o /dev/null) so we can
        # compare JSON structure, not only byte count, further down.
        resp_anon=$(curl -skL -m 10 -o "$tmpf_anon" -w "%{http_code} %{size_download}" -A "$CUR_UA" "$url" 2>/dev/null)
        resp_a=$(curl -skL -m 10 -o "$tmpf_a" -w "%{http_code} %{size_download}" -A "$CUR_UA" "${H_CURL[@]}" "$url" 2>/dev/null)
        resp_b=$(curl -skL -m 10 -o "$tmpf_b" -w "%{http_code} %{size_download}" -A "$CUR_UA" "${H_CURL_B[@]}" "$url" 2>/dev/null)
        code_anon=$(echo "$resp_anon" | awk '{print $1}'); len_anon=$(echo "$resp_anon" | awk '{print $2}')
        code_a=$(echo "$resp_a" | awk '{print $1}'); len_a=$(echo "$resp_a" | awk '{print $2}')
        code_b=$(echo "$resp_b" | awk '{print $1}'); len_b=$(echo "$resp_b" | awk '{print $2}')
        # Need identity A (-H, assumed lower-priv) to get a 2xx at all —
        # if A is already blocked (403/401/etc.), access control is
        # working as expected, nothing to flag.
        case "$code_a" in 2??) ;; *) rm -f "$tmpf_anon" "$tmpf_a" "$tmpf_b"; return ;; esac
        # If anonymous (no auth at all) ALSO gets the same 2xx with a
        # similar length to A, this endpoint is just public for everyone
        # — not a broken-access-control finding, skip it.
        if [ "$code_anon" = "$code_a" ] && [ -n "$len_anon" ] && [ -n "$len_a" ] && [ "$len_anon" -gt 0 ] 2>/dev/null; then
          diff_pct=$(( (len_anon > len_a ? len_anon - len_a : len_a - len_anon) * 100 / (len_a > 0 ? len_a : 1) ))
          if [ "$diff_pct" -le 10 ]; then rm -f "$tmpf_anon" "$tmpf_a" "$tmpf_b"; return; fi
        fi
        # Core check: A's response looks admin-equivalent to B's — and B
        # did get a 2xx too (so we know B's response is a legitimate
        # "admin sees this" baseline, not itself an error page).
        case "$code_b" in 2??) ;; *) rm -f "$tmpf_anon" "$tmpf_a" "$tmpf_b"; return ;; esac
        # Prefer a structural JSON-key comparison over byte-size when
        # both bodies actually parse as JSON — this is the common case
        # for API endpoints, and catches what byte-size diffing alone
        # misses (see json_key_paths comment above). Falls back to the
        # byte-size heuristic only for non-JSON (HTML, etc.) responses.
        if jq -e . "$tmpf_a" >/dev/null 2>&1 && jq -e . "$tmpf_b" >/dev/null 2>&1; then
          key_diff=$(diff <(json_key_paths "$tmpf_a") <(json_key_paths "$tmpf_b") 2>/dev/null)
          if [ -z "$key_diff" ]; then
            echo "[POSSIBLE-BROKEN-ACCESS-CONTROL] $url | -H (lower-priv) got $code_a (${len_a}b, JSON) | -A (admin) got $code_b (${len_b}b, JSON) | anon got ${code_anon:-n/a} (${len_anon:-n/a}b) | JSON key structure IDENTICAL between -H and -A — MANUALLY VERIFY actual field VALUES (not just shape) belong to the same record."
          fi
          rm -f "$tmpf_anon" "$tmpf_a" "$tmpf_b"
          return
        fi
        if [ -n "$len_a" ] && [ -n "$len_b" ] && [ "$len_b" -gt 0 ] 2>/dev/null; then
          diff_pct=$(( (len_a > len_b ? len_a - len_b : len_b - len_a) * 100 / len_b ))
          if [ "$diff_pct" -le 10 ]; then
            echo "[POSSIBLE-BROKEN-ACCESS-CONTROL] $url | -H (lower-priv) got $code_a (${len_a}b) | -A (admin) got $code_b (${len_b}b) | anon got ${code_anon:-n/a} (${len_anon:-n/a}b) | body-size diff A-vs-B: ${diff_pct}% — MANUALLY VERIFY response bodies are actually the same record/data, not just similarly-sized pages."
          fi
        fi
        rm -f "$tmpf_anon" "$tmpf_a" "$tmpf_b"
      }
      export -f json_key_paths access_diff_check
      CUR_UA=$(get_random_ua)
      export CUR_UA CURL_HEADERS_DECL CURL_HEADERS_B_DECL
      xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'access_diff_check "$@"' _ {} < "$OUT_DIR/.diff_candidates.txt" >> "$OUT_DIR/04_7_access_control_diff.txt" 2>/dev/null
    fi
    rm -f "$OUT_DIR/.diff_candidates.txt"
    DIFF_TOTAL=$(wc -l < "$OUT_DIR/04_7_access_control_diff.txt" 2>/dev/null || echo 0)
    log_msg "[INFO] Access-control diff: $DIFF_TOTAL possible broken-access-control candidate(s) where -H's identity got admin-equivalent-sized content. These are candidates, not confirmed findings — verify response bodies actually contain the same data before reporting."
    drop_if_empty "$OUT_DIR/04_7_access_control_diff.txt"
    mark_done "STAGE_4_7"
  else
    mark_done "STAGE_4_7"
  fi
else
  log_msg "[INFO] Stage 4.7 Checkpoint found. Skipping..."
  draw_ui 76 "Stage 4.7/7: Access Control Diff (Skipped)"
fi

if ! is_done "STAGE_5"; then
  log_msg "[TASK] Running Stage 5: JS Secrets"
  draw_ui 80 "Stage 5/7: JS Secrets"
  mkdir -p "$JS_DIR"
  # Also pull .map sourcemaps alongside .js — sourcemaps frequently embed
  # the original (pre-minified) source, which is exactly where secrets
  # tend to leak from, and the old regex never grabbed them.
  grep -iE '\.(js|js\.map)(\?|$)' "$OUT_DIR/04_katana_endpoints_raw.txt" > "$OUT_DIR/05_js_urls_list.txt" 2>/dev/null || true
  drop_if_empty "$OUT_DIR/05_js_urls_list.txt"
  : > "$OUT_DIR/05_js_url_map.tsv"
  if [ -s "$OUT_DIR/05_js_urls_list.txt" ]; then
    CUR_UA=$(get_random_ua)
    download_js() {
      local url="$1" out_name
      eval "$CURL_HEADERS_DECL"
      out_name=$(echo -n "$url" | md5sum | awk '{print $1}')
      # Keep a url<->filename mapping so a trufflehog hit can be traced
      # back to the URL it came from — previously the md5-named files on
      # disk gave no way to recover which URL a finding belonged to.
      echo -e "${out_name}\t${url}" >> "$OUT_DIR/05_js_url_map.tsv"
      curl -skL -m 10 -A "$CUR_UA" "${H_CURL[@]}" "$url" -o "$JS_DIR/${out_name}.js" 2>/dev/null
    }
    export -f download_js
    export CUR_UA CURL_HEADERS_DECL JS_DIR OUT_DIR
    xargs -d '\n' -I {} -P "$CURL_LOOP_CONC" bash -c 'download_js "$@"' _ {} < "$OUT_DIR/05_js_urls_list.txt" 2>/dev/null
    if [ "$(ls -A "$JS_DIR" 2>/dev/null)" ]; then
      # Verified secrets: high-confidence, these are live/working creds.
      if trufflehog filesystem "$JS_DIR" --only-verified --json > "$OUT_DIR/.trufflehog_verified_raw.jsonl" 2>/dev/null; then
        if [ -s "$OUT_DIR/.trufflehog_verified_raw.jsonl" ]; then
          jq -r --arg mapfile "$OUT_DIR/05_js_url_map.tsv" '
            (.SourceMetadata.Data.Filesystem.file // "") as $f
            | "[VERIFIED] " + (.DetectorName // "unknown") + " in " + $f
          ' "$OUT_DIR/.trufflehog_verified_raw.jsonl" 2>/dev/null > "$OUT_DIR/05_trufflehog_verified_secrets.txt"
          # Resolve file path back to original URL via the map.
          while IFS=$'\t' read -r md5 url; do
            sed -i "s#${md5}\.js#${url}#g" "$OUT_DIR/05_trufflehog_verified_secrets.txt" 2>/dev/null
          done < "$OUT_DIR/05_js_url_map.tsv"
        fi
        drop_if_empty "$OUT_DIR/05_trufflehog_verified_secrets.txt"
      fi
      # Unverified secrets: lower confidence (no live verifier, or
      # verification failed/network-blocked) — kept SEPARATE from the
      # verified file so they're never conflated as confirmed in the
      # report, but still surfaced since some real secret types (static
      # API keys, internal tokens) have no verifier at all.
      if trufflehog filesystem "$JS_DIR" --json > "$OUT_DIR/.trufflehog_all_raw.jsonl" 2>/dev/null; then
        if [ -s "$OUT_DIR/.trufflehog_all_raw.jsonl" ]; then
          jq -r --slurpfile verified <(jq -s '.' "$OUT_DIR/.trufflehog_verified_raw.jsonl" 2>/dev/null || echo '[]') '
            select(.Verified != true) | (.SourceMetadata.Data.Filesystem.file // "") as $f
            | "[UNVERIFIED] " + (.DetectorName // "unknown") + " in " + $f + " — no live verifier matched; confirm manually before reporting."
          ' "$OUT_DIR/.trufflehog_all_raw.jsonl" 2>/dev/null > "$OUT_DIR/05_trufflehog_unverified_secrets.txt"
          while IFS=$'\t' read -r md5 url; do
            sed -i "s#${md5}\.js#${url}#g" "$OUT_DIR/05_trufflehog_unverified_secrets.txt" 2>/dev/null
          done < "$OUT_DIR/05_js_url_map.tsv"
        fi
        drop_if_empty "$OUT_DIR/05_trufflehog_unverified_secrets.txt"
      fi
      rm -f "$OUT_DIR/.trufflehog_verified_raw.jsonl" "$OUT_DIR/.trufflehog_all_raw.jsonl"
      mark_done "STAGE_5"
    else
      mark_done "STAGE_5"
    fi
  else
    mark_done "STAGE_5"
  fi
  drop_if_empty "$OUT_DIR/05_js_url_map.tsv"
else
  log_msg "[INFO] Stage 5 Checkpoint found. Skipping..."
  draw_ui 80 "Stage 5/7: JS Secrets (Skipped)"
fi

# --- OOB/interactsh connectivity preflight ---
# Blind/OOB templates (blind SSRF, blind RCE, blind XSS) rely entirely on
# nuclei's default interactsh server (oast.pro / oast.live / oast.site)
# calling back. In a sandboxed/chroot/restricted-network environment,
# that callback can silently fail — and "0 OOB findings" then means
# either "target is clean" or "OOB channel is dead," with zero visible
# difference between the two. This runs once before Stage 6 and logs an
# explicit, impossible-to-miss warning so a lack of OOB findings is never
# silently mistaken for a clean result.
if ! is_done "STAGE_OOB_PREFLIGHT"; then
  OOB_REACHABLE=0
  for oast_host in "oast.pro" "oast.live" "oast.site"; do
    if curl -sk -m 6 -o /dev/null -w "%{http_code}" "https://${oast_host}" 2>/dev/null | grep -qE '^[0-9]{3}$'; then
      OOB_REACHABLE=1
      break
    fi
  done
  if [ "$OOB_REACHABLE" -eq 0 ]; then
    log_msg "[WARN] OOB preflight: could not reach any default interactsh server (oast.pro/live/site). Blind SSRF/RCE/XSS templates in Stage 6/7 may silently produce zero findings even on a vulnerable target — this is NOT the same as 'confirmed clean'. Configure a reachable interactsh server (-iserver) or a self-hosted instance if OOB coverage matters for this engagement."
  else
    log_msg "[INFO] OOB preflight: default interactsh server reachable — blind/OOB templates should be able to call back normally."
  fi
  mark_done "STAGE_OOB_PREFLIGHT"
fi

if ! is_done "STAGE_6"; then
  log_msg "[TASK] Running Stage 6: Nuclei Standard Scan"
  draw_ui 88 "Stage 6/7: Nuclei Standard Scan"
  waf_healthcheck

  CUR_UA=$(get_random_ua)
  if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/03_httpx_live_hosts.txt"); else NUC_TGT=("-u" "$TARGET"); fi
  log_msg "[DEBUG] nuclei standard target: ${NUC_TGT[*]} | timeout=$S_L retries=$S_R mhe=$N_MHE rl=$N_RL c=$N_C"
  # -as (automatic scan): nuclei fingerprints each target's tech stack
  # first and only runs templates relevant to what it detects, instead of
  # throwing every template in the repo at every host regardless of
  # stack. Cuts a large share of templates that could never match
  # (wrong CMS/language/server) before they even run, which both speeds
  # the scan up and removes a class of mismatched-template noise.
  # -jsonl + -irr keep the full request/response for every match, which
  # is what verification (nuclei_verify_findings) and manual review both
  # depend on — plain text match lines gave no way to verify or audit.
  if nuclei "${NUC_TGT[@]}" -silent -as -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -etags "$NOISY_TAGS" -severity "$N_SEV" -ept ssl $N_EXTRA -jsonl -irr -H "User-Agent: $CUR_UA" "${H_NUCLEI[@]}" -o "$OUT_DIR/06_nuclei_standard_cve_vulns_raw.jsonl" > /dev/null 2>"$OUT_DIR/.stage6_stderr"; then
    nuclei_verify_findings "$OUT_DIR/06_nuclei_standard_cve_vulns_raw.jsonl" "$OUT_DIR/06_nuclei_standard_cve_vulns"
    drop_if_empty "$OUT_DIR/06_nuclei_standard_cve_vulns_raw.jsonl"
    mark_done "STAGE_6"
  else
    log_msg "[ERROR] Stage 6 nuclei call failed/exited non-zero — NOT marked done, will retry next run. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage6_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage6_stderr"
else
  log_msg "[INFO] Stage 6 Checkpoint found. Skipping..."
  draw_ui 88 "Stage 6/7: Nuclei Standard Scan (Skipped)"
fi

# --- Stage 6.5: Custom nuclei templates (opt-in via -t <dir>) ---
# Deliberately a SEPARATE nuclei invocation rather than folding
# CUSTOM_TEMPLATES_DIR into Stage 6/7's own -t: passing -t explicitly to
# nuclei makes it run ONLY the template path(s) given, not the default
# template set AS WELL — there is no portable way to also re-point it at
# "whatever the default template directory happens to be" across nuclei
# versions/installs. Running custom templates as their own stage avoids
# silently gutting Stage 6/7's normal CVE/misconfig coverage, and keeps
# custom-template hits in their own clearly-labeled output file.
if [ -n "$CUSTOM_TEMPLATES_DIR" ]; then
  if ! is_done "STAGE_6_5"; then
    log_msg "[TASK] Running Stage 6.5: Custom Nuclei Templates ($CUSTOM_TEMPLATES_DIR)"
    draw_ui 89 "Stage 6.5/7: Custom Templates"
    CUR_UA=$(get_random_ua)
    if [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/03_httpx_live_hosts.txt"); else NUC_TGT=("-u" "$TARGET"); fi
    if nuclei "${NUC_TGT[@]}" -t "$CUSTOM_TEMPLATES_DIR" -silent -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -jsonl -irr -H "User-Agent: $CUR_UA" "${H_NUCLEI[@]}" -o "$OUT_DIR/06_5_nuclei_custom_raw.jsonl" > /dev/null 2>"$OUT_DIR/.stage6_5_stderr"; then
      nuclei_verify_findings "$OUT_DIR/06_5_nuclei_custom_raw.jsonl" "$OUT_DIR/06_5_nuclei_custom"
      drop_if_empty "$OUT_DIR/06_5_nuclei_custom_raw.jsonl"
      mark_done "STAGE_6_5"
    else
      log_msg "[ERROR] Stage 6.5 nuclei call failed/exited non-zero — NOT marked done, will retry next run. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage6_5_stderr" 2>/dev/null | cut -c1-500)"
    fi
    rm -f "$OUT_DIR/.stage6_5_stderr"
  else
    log_msg "[INFO] Stage 6.5 Checkpoint found. Skipping..."
    draw_ui 89 "Stage 6.5/7: Custom Templates (Skipped)"
  fi
fi

if ! is_done "STAGE_7"; then
  log_msg "[TASK] Running Stage 7: Nuclei DAST Scan"
  draw_ui 95 "Stage 7/7: Nuclei DAST"
  waf_healthcheck
  
  # Both depths now use the query-string/API-filtered endpoint list for
  # DAST targeting — DAST templates fuzz parameters, so feeding them the
  # raw crawl (which includes parameter-less pages) in "mariana" mode was
  # pure wasted requests against URLs that can never trigger a DAST
  # template in the first place.
  TGT_FILE="$OUT_DIR/04_katana_endpoints_filtered.txt"
  if [ -s "$TGT_FILE" ]; then NUC_TGT=("-l" "$TGT_FILE"); elif [ -s "$OUT_DIR/03_httpx_live_hosts.txt" ]; then NUC_TGT=("-l" "$OUT_DIR/03_httpx_live_hosts.txt"); else NUC_TGT=("-u" "$TARGET"); fi

  CUR_UA=$(get_random_ua)
  if nuclei "${NUC_TGT[@]}" -silent -as -c "$N_C" -rl "$N_RL" -timeout "$S_L" -retries "$S_R" -mhe "$N_MHE" -etags "$NOISY_TAGS" -dast -severity "$N_SEV" -ept ssl $N_EXTRA -jsonl -irr -H "User-Agent: $CUR_UA" "${H_NUCLEI[@]}" -o "$OUT_DIR/07_nuclei_dast_active_fuzz_raw.jsonl" > /dev/null 2>"$OUT_DIR/.stage7_stderr"; then
    nuclei_verify_findings "$OUT_DIR/07_nuclei_dast_active_fuzz_raw.jsonl" "$OUT_DIR/07_nuclei_dast_active_fuzz"
    drop_if_empty "$OUT_DIR/07_nuclei_dast_active_fuzz_raw.jsonl"
    mark_done "STAGE_7"
  else
    log_msg "[ERROR] Stage 7 nuclei call failed/exited non-zero — NOT marked done, will retry next run. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage7_stderr" 2>/dev/null | cut -c1-500)"
  fi
  rm -f "$OUT_DIR/.stage7_stderr"
else
  log_msg "[INFO] Stage 7 Checkpoint found. Skipping..."
  draw_ui 95 "Stage 7/7: Nuclei DAST (Skipped)"
fi

# --- Stage 7.5: Reflected XSS pipeline (opt-in via -x, uses kxss+dalfox) ---
# nuclei -dast (Stage 7) detects XSS only via its own generic templates —
# pattern matching, not a targeted reflection probe. kxss instead checks,
# per parameter, whether special characters (<>"') survive unencoded in
# the response; only parameters that actually do get passed to dalfox,
# which fires real payloads and reports a proof-of-concept. This two-step
# narrowing is both cheaper (dalfox isn't thrown at every parameter blind)
# and more accurate (a kxss hit is a precondition for reflected XSS being
# possible at all — no reflection, no point fuzzing it).
if [ "$XSS_MODE" = "1" ]; then
  if ! is_done "STAGE_7_5"; then
    log_msg "[TASK] Running Stage 7.5: Reflected XSS Pipeline (kxss+dalfox)"
    draw_ui 96 "Stage 7.5/7: Reflected XSS (kxss+dalfox)"
    XSS_SRC="$OUT_DIR/04_katana_endpoints_filtered.txt"
    : > "$OUT_DIR/07_5_kxss_reflected_params.txt"
    : > "$OUT_DIR/07_5_dalfox_confirmed_xss.txt"
    if [ -s "$XSS_SRC" ]; then
      CUR_UA=$(get_random_ua)
      # kxss has no rate-limit flag of its own, and a plain
      # "cat file | kxss" hands it the WHOLE list in one shot with
      # whatever concurrency kxss defaults to internally — in stealth
      # mode that defeats the point of the mode. Split the URL list into
      # small chunks and bound how many chunks run at once to
      # $CURL_LOOP_CONC (the same MODE-driven cap every other curl-based
      # loop in this script respects), so stealth mode genuinely throttles
      # this stage too instead of just saying it does.
      XSS_CHUNK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mb_kxss_chunks.XXXXXX")
      split -l 20 "$XSS_SRC" "$XSS_CHUNK_DIR/chunk_" 2>/dev/null
      find "$XSS_CHUNK_DIR" -type f -name 'chunk_*' 2>/dev/null \
        | xargs -I{} -P "$CURL_LOOP_CONC" bash -c 'kxss < "$1" 2>/dev/null' _ {} > "$OUT_DIR/.kxss_raw.txt"
      rm -rf "$XSS_CHUNK_DIR"
      # Only keep lines where something actually survived unencoded after
      # "Unfiltered:" — a kxss line with an empty Unfiltered field means
      # the parameter reflects but everything dangerous was encoded/
      # stripped, which is not exploitable and would just be noise for
      # dalfox to re-confirm as "not vulnerable" at added request cost.
      grep -E 'Unfiltered: +[^[:space:]]' "$OUT_DIR/.kxss_raw.txt" 2>/dev/null \
        | grep -oE 'URL: *[^[:space:]]+' | sed 's/^URL: *//' | sort -u > "$OUT_DIR/07_5_kxss_reflected_params.txt"
      rm -f "$OUT_DIR/.kxss_raw.txt"
      KXSS_HITS=$(wc -l < "$OUT_DIR/07_5_kxss_reflected_params.txt" 2>/dev/null || echo 0)
      log_msg "[INFO] Stage 7.5: kxss found $KXSS_HITS URL(s) with an unencoded-reflection parameter — handing those to dalfox for PoC confirmation."

      if [ -s "$OUT_DIR/07_5_kxss_reflected_params.txt" ]; then
        if dalfox file "$OUT_DIR/07_5_kxss_reflected_params.txt" --silence --no-color -w "$D_WORKERS" --delay "$D_DELAY" --user-agent "$CUR_UA" "${H_CURL[@]}" -o "$OUT_DIR/.dalfox_raw.txt" >/dev/null 2>"$OUT_DIR/.stage7_5_stderr"; then
          if [ -s "$OUT_DIR/.dalfox_raw.txt" ]; then
            cp "$OUT_DIR/.dalfox_raw.txt" "$OUT_DIR/07_5_dalfox_confirmed_xss.txt"
          fi
        else
          log_msg "[ERROR] Stage 7.5 dalfox call failed/exited non-zero (kxss narrowing still succeeded, see 07_5_kxss_reflected_params.txt). stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage7_5_stderr" 2>/dev/null | cut -c1-500)"
        fi
        rm -f "$OUT_DIR/.dalfox_raw.txt" "$OUT_DIR/.stage7_5_stderr"
      fi
    else
      log_msg "[INFO] Stage 7.5: no endpoints in 04_katana_endpoints_filtered.txt to test — skipping kxss/dalfox."
    fi
    drop_if_empty "$OUT_DIR/07_5_kxss_reflected_params.txt"
    drop_if_empty "$OUT_DIR/07_5_dalfox_confirmed_xss.txt"
    mark_done "STAGE_7_5"
  else
    log_msg "[INFO] Stage 7.5 Checkpoint found. Skipping..."
    draw_ui 96 "Stage 7.5/7: Reflected XSS (Skipped)"
  fi
fi

FFUF_C=0
if [ -n "$FFUF_MODE" ]; then
  if ! is_done "STAGE_FFUF"; then
    log_msg "[TASK] Running ffuf content discovery ($FFUF_MODE mode)"
    draw_ui 97 "Extra: ffuf Content Discovery ($FFUF_MODE)"

    WORDLIST=$(resolve_ffuf_wordlist "$FFUF_MODE")
    WL_LINES=$(wc -l < "$WORDLIST" 2>/dev/null || echo 0)
    if [ "$WORDLIST" = "$OUT_DIR/.ffuf_fallback_wordlist.txt" ]; then
      log_msg "[WARN] No SecLists installation found — using built-in fallback wordlist ($WL_LINES entries). Install SecLists for real coverage: https://github.com/danielmiessler/SecLists"
    else
      log_msg "[INFO] ffuf wordlist: $WORDLIST ($WL_LINES entries)"
    fi

    : > "$OUT_DIR/08_ffuf_findings.txt"
    FFUF_TARGETS_FILE="$OUT_DIR/03_httpx_live_hosts.txt"
    FFUF_TMP_TARGET_FILE=""
    if [ ! -s "$FFUF_TARGETS_FILE" ]; then
      FFUF_TMP_TARGET_FILE="$OUT_DIR/.ffuf_single_target.txt"
      echo "https://${TARGET}" > "$FFUF_TMP_TARGET_FILE"
      FFUF_TARGETS_FILE="$FFUF_TMP_TARGET_FILE"
    fi

    FFUF_DONE_FILE="$OUT_DIR/.ffuf_done_hosts"
    touch "$FFUF_DONE_FILE"
    while IFS= read -r host; do
      [ -z "$host" ] && continue
      # Already succeeded for this host on a previous (partial) run —
      # don't waste time/requests re-scanning it.
      if grep -qxF "$host" "$FFUF_DONE_FILE" 2>/dev/null; then
        continue
      fi
      CUR_UA=$(get_random_ua)
      SAFE_HOST=$(echo "$host" | tr -cd 'a-zA-Z0-9._-' | tail -c 100)
      JSON_OUT="$OUT_DIR/08_ffuf_${SAFE_HOST}.json"
      if ffuf -u "${host%/}/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,403 -ac \
        -t "$F_THREADS" -p "$F_DELAY" -rate "$F_RATE" -timeout "$F_TIMEOUT" \
        -H "User-Agent: $CUR_UA" "${H_FFUF[@]}" \
        -of json -o "$JSON_OUT" -s > /dev/null 2>"$OUT_DIR/.stage_ffuf_stderr" < /dev/null; then
        echo "$host" >> "$FFUF_DONE_FILE"
        if command -v jq >/dev/null 2>&1 && [ -s "$JSON_OUT" ]; then
          jq -r '.results[]? | "[\(.status)] \(.url) (len=\(.length))"' "$JSON_OUT" 2>/dev/null >> "$OUT_DIR/08_ffuf_findings.txt"
        elif [ -s "$JSON_OUT" ]; then
          grep -o '"url":"[^"]*"' "$JSON_OUT" | sed 's/"url":"//;s/"$//' >> "$OUT_DIR/08_ffuf_findings.txt" 2>/dev/null
        fi
      else
        log_msg "[ERROR] ffuf failed for $host — will retry this host (not the whole batch) on next run. stderr: $(tr '\n' ' ' < "$OUT_DIR/.stage_ffuf_stderr" 2>/dev/null | cut -c1-500)"
      fi
    done < "$FFUF_TARGETS_FILE"
    rm -f "$OUT_DIR/.stage_ffuf_stderr"
    [ -n "$FFUF_TMP_TARGET_FILE" ] && rm -f "$FFUF_TMP_TARGET_FILE"

    drop_if_empty "$OUT_DIR/08_ffuf_findings.txt"
    TOTAL_FFUF_HOSTS=$(grep -vc '^[[:space:]]*$' "$FFUF_TARGETS_FILE" 2>/dev/null || echo 0)
    DONE_FFUF_HOSTS=$(wc -l < "$FFUF_DONE_FILE" 2>/dev/null || echo 0)
    if [ "$TOTAL_FFUF_HOSTS" -gt 0 ] && [ "$DONE_FFUF_HOSTS" -ge "$TOTAL_FFUF_HOSTS" ]; then
      mark_done "STAGE_FFUF"
      rm -f "$FFUF_DONE_FILE"
    fi
  else
    log_msg "[INFO] ffuf stage Checkpoint found. Skipping..."
    draw_ui 97 "Extra: ffuf Content Discovery (Skipped)"
  fi
  if [ -f "$OUT_DIR/08_ffuf_findings.txt" ]; then FFUF_C=$(wc -l < "$OUT_DIR/08_ffuf_findings.txt"); fi
fi

log_msg "[SUCCESS] Pipeline execution finished entirely."
draw_ui 100 "Completed successfully"

END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))
TOTAL_MINS=$((TOTAL_ELAPSED / 60))
TOTAL_SECS=$((TOTAL_ELAPSED % 60))
TOTAL_TIME_STR=$(printf "%02d:%02d" $TOTAL_MINS $TOTAL_SECS)

cat <<EOF > "$OUT_DIR/FINAL_SUMMARY.txt"
======================================
MAIDBUG FINAL REPORT - $TARGET
TIMESTAMP: $TIMESTAMP
MODE: ${MODE^^} | POWER: ${POWER^^} | DEPTH: ${DEPTH^^}
SCOPE: $SCOPE
TOTAL RUNTIME: $TOTAL_TIME_STR
======================================
SUBDOMAINS : $SUB_C (DNS-validated, wildcard-filtered)
LIVE HOSTS : $LIVE_C
OPEN PORTS : $PORT_C
DYN API/EP : $PARAM_C
INTERESTING: $INTERESTING_C (heuristic triage — see DETAILS below, not exhaustive)
ACCESS-DIFF: ${ACCESS_DIFF_C}$([ "${#HEADERS_B[@]}" -eq 0 ] && echo " (not run — use -A to enable)") (candidates only — verify response bodies manually)
FFUF HITS  : ${FFUF_C}$([ -n "$FFUF_MODE" ] && echo " (mode: ${FFUF_MODE^^})" || echo " (not run — use -f to enable)")
======================================
VULNERABILITIES (NUCLEI MATCHES, VERIFIED = reproduced on a second independent request; report below is medium+ severity only — see *_verified.jsonl / *_unverified.jsonl for the full severity range incl. low/info):
CRITICAL : $CRIT_C
HIGH     : $HIGH_C
MEDIUM   : $MED_C
LOW      : $LOW_C (not counted toward CRITICAL/HIGH/MEDIUM above unless shown)
======================================
DETAILS (verified findings, medium+ severity only):
EOF

# Build the human-readable DETAILS section from the *_verified.jsonl files
# (medium+ severity only, per N_REPORT_SEV) instead of grepping raw text
# for "[critical]"/"[high]" etc. — this is what nuclei_jsonl_severity_counts
# already counts from, so the report and the counters now agree exactly,
# and a template-id/URL that happens to contain a severity word can no
# longer be mis-sorted into the wrong bucket.
for jf in "$OUT_DIR"/06_nuclei_standard_cve_vulns_verified.jsonl "$OUT_DIR"/07_nuclei_dast_active_fuzz_verified.jsonl "$OUT_DIR"/03_5_nuclei_quickwins_verified.jsonl "$OUT_DIR"/06_5_nuclei_custom_verified.jsonl; do
  [ -s "$jf" ] || continue
  jq -r --arg sevs "$N_REPORT_SEV" '
    ($sevs | split(",")) as $allowed
    | select(.info.severity as $s | $allowed | index($s))
    | "[" + (.info.severity // "unknown" | ascii_upcase) + "] " + (.["template-id"] // "unknown") + " @ " + (.["matched-at"] // .host // "unknown") + " — " + (.info.name // "")
  ' "$jf" 2>/dev/null >> "$OUT_DIR/FINAL_SUMMARY.txt"
done

if [ -s "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt" ]; then
  {
    echo ""
    echo "--- SUBDOMAIN TAKEOVER CANDIDATES (NOT confirmed — verify CNAME + provider claim flow manually) ---"
    cat "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt"
  } >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/04_6_interesting_endpoints.txt" ]; then
  {
    echo ""
    echo "--- ENDPOINTS FLAGGED FOR MANUAL REVIEW (heuristic, not exhaustive) ---"
    cat "$OUT_DIR/04_6_interesting_endpoints.txt"
  } >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/04_7_access_control_diff.txt" ]; then
  {
    echo ""
    echo "--- POSSIBLE BROKEN ACCESS CONTROL: -H (lower-priv) seeing -A (admin)-equivalent content — CANDIDATES, verify response bodies before reporting ---"
    cat "$OUT_DIR/04_7_access_control_diff.txt"
  } >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/08_ffuf_findings.txt" ]; then
  echo "======================================" >> "$OUT_DIR/FINAL_SUMMARY.txt"
  echo "FFUF CONTENT DISCOVERY ($FFUF_C hits, mode: ${FFUF_MODE^^}):" >> "$OUT_DIR/FINAL_SUMMARY.txt"
  head -n 30 "$OUT_DIR/08_ffuf_findings.txt" >> "$OUT_DIR/FINAL_SUMMARY.txt"
  if [ "$FFUF_C" -gt 30 ]; then
    echo "... ($((FFUF_C - 30)) more, see 08_ffuf_findings.txt)" >> "$OUT_DIR/FINAL_SUMMARY.txt"
  fi
fi

echo "======================================" >> "$OUT_DIR/FINAL_SUMMARY.txt"
if [ -s "$OUT_DIR/05_trufflehog_verified_secrets.txt" ]; then
  echo "[!] VERIFIED (live-credential) SECRETS FOUND VIA TRUFFLEHOG. CHECK 05_trufflehog_verified_secrets.txt" >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi
if [ -s "$OUT_DIR/05_trufflehog_unverified_secrets.txt" ]; then
  echo "[i] Unverified possible secrets also found (no live verifier matched) — review 05_trufflehog_unverified_secrets.txt manually before reporting." >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/07_5_dalfox_confirmed_xss.txt" ]; then
  DALFOX_C=$(wc -l < "$OUT_DIR/07_5_dalfox_confirmed_xss.txt")
  echo "[!] $DALFOX_C possible reflected-XSS finding(s) from the kxss+dalfox pipeline — CHECK 07_5_dalfox_confirmed_xss.txt (dalfox's own output, still verify the PoC yourself before reporting)." >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi
if [ -s "$OUT_DIR/04_55_gau_historical_endpoints.txt" ]; then
  GAU_C=$(wc -l < "$OUT_DIR/04_55_gau_historical_endpoints.txt")
  echo "[i] $GAU_C historical/archived URL(s) (gau+uro) survived liveness validation and were merged into the endpoint list — see 04_55_gau_historical_endpoints.txt." >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/03_httpx_waf_blocked.txt" ]; then
  BLOCKED_C=$(wc -l < "$OUT_DIR/03_httpx_waf_blocked.txt")
  echo "[i] $BLOCKED_C hosts returned 403/406/429/503 and were excluded from scanning, but may still be worth manual bypass testing. Review 03_httpx_waf_blocked.txt" >> "$OUT_DIR/FINAL_SUMMARY.txt"
fi

if [ -s "$OUT_DIR/03_6_graphql_endpoints.txt" ]; then
  GQL_INTRO_C=$(grep -c '^\[GRAPHQL-INTROSPECTION-ENABLED\]' "$OUT_DIR/03_6_graphql_endpoints.txt" 2>/dev/null || echo 0)
  if [ "$GQL_INTRO_C" -gt 0 ]; then
    echo "[i] $GQL_INTRO_C GraphQL endpoint(s) have introspection ENABLED — review 03_6_graphql_endpoints.txt and 03_6_graphql_schemas/" >> "$OUT_DIR/FINAL_SUMMARY.txt"
  fi
fi

# --- Consolidated priority-review report ---
# Everything above is spread across many separate files by stage. This
# pulls the highest-signal items from across ALL stages into one file so
# a human reviewing the run doesn't have to read eight files to find out
# what to look at first. Nothing here is "more confirmed" than its source
# file — it's purely a triage index, ranked roughly by how actionable
# each class of finding tends to be.
PRIORITY_FILE="$OUT_DIR/09_PRIORITY_REVIEW.txt"
{
  echo "======================================"
  echo "MAIDBUG PRIORITY REVIEW - $TARGET"
  echo "Everything here is a pointer into another file — none of this"
  echo "replaces manual verification before reporting anything."
  echo "======================================"

  if [ -s "$OUT_DIR/05_trufflehog_verified_secrets.txt" ]; then
    echo ""
    echo "1) VERIFIED LIVE SECRETS (highest confidence — see 05_trufflehog_verified_secrets.txt):"
    cat "$OUT_DIR/05_trufflehog_verified_secrets.txt"
  fi

  if [ -s "$OUT_DIR/04_7_access_control_diff.txt" ]; then
    echo ""
    echo "2) POSSIBLE BROKEN ACCESS CONTROL (verify response bodies — see 04_7_access_control_diff.txt):"
    cat "$OUT_DIR/04_7_access_control_diff.txt"
  fi

  for jf in "$OUT_DIR"/06_nuclei_standard_cve_vulns_verified.jsonl "$OUT_DIR"/07_nuclei_dast_active_fuzz_verified.jsonl "$OUT_DIR"/06_5_nuclei_custom_verified.jsonl; do
    [ -s "$jf" ] || continue
    jq -r 'select(.info.severity == "critical" or .info.severity == "high") | "   [" + (.info.severity | ascii_upcase) + "] " + (.["template-id"] // "unknown") + " @ " + (.["matched-at"] // .host // "unknown")' "$jf" 2>/dev/null
  done | sort -u > "$OUT_DIR/.pr_crit_high.txt"
  if [ -s "$OUT_DIR/.pr_crit_high.txt" ]; then
    echo ""
    echo "3) CRITICAL/HIGH NUCLEI FINDINGS (reproduced twice — see 06/07_*_verified.jsonl for full request/response):"
    cat "$OUT_DIR/.pr_crit_high.txt"
  fi
  rm -f "$OUT_DIR/.pr_crit_high.txt"

  if [ -s "$OUT_DIR/07_5_dalfox_confirmed_xss.txt" ]; then
    echo ""
    echo "3.5) REFLECTED XSS (kxss+dalfox, PoC-confirmed — still verify yourself before reporting — see 07_5_dalfox_confirmed_xss.txt):"
    cat "$OUT_DIR/07_5_dalfox_confirmed_xss.txt"
  fi

  if [ -s "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt" ]; then
    echo ""
    echo "4) SUBDOMAIN TAKEOVER CANDIDATES (confirm CNAME + provider claim flow manually — see 01_5_nuclei_subdomain_takeover.txt):"
    cat "$OUT_DIR/01_5_nuclei_subdomain_takeover.txt"
  fi

  if grep -q '^\[GRAPHQL-INTROSPECTION-ENABLED\]' "$OUT_DIR/03_6_graphql_endpoints.txt" 2>/dev/null; then
    echo ""
    echo "5) GRAPHQL INTROSPECTION ENABLED (review exposed schema — see 03_6_graphql_schemas/):"
    grep '^\[GRAPHQL-INTROSPECTION-ENABLED\]' "$OUT_DIR/03_6_graphql_endpoints.txt"
  fi

  # Dedup against section 2: every URL Stage 4.7 tests comes FROM this
  # same [HIGH] list in the first place, so a URL that already got its
  # own access-control-diff line above is pure duplication if it's also
  # listed again here as "generic, not yet tested" — worse, it reads as
  # LESS scrutinized than it actually was. Pull out just the URLs that
  # appear in the access-diff output and filter them out of this bucket,
  # so each item is reviewed once, in its most specific (most useful)
  # section, instead of being read twice under two different headings.
  if [ -s "$OUT_DIR/04_6_interesting_endpoints.txt" ]; then
    grep -oE 'https?://\S+' "$OUT_DIR/04_7_access_control_diff.txt" 2>/dev/null | sort -u > "$OUT_DIR/.pr_diff_urls.txt"
    if [ -s "$OUT_DIR/.pr_diff_urls.txt" ]; then
      grep '^\[HIGH\]' "$OUT_DIR/04_6_interesting_endpoints.txt" | grep -vFf "$OUT_DIR/.pr_diff_urls.txt" > "$OUT_DIR/.pr_high_dedup.txt" 2>/dev/null
    else
      grep '^\[HIGH\]' "$OUT_DIR/04_6_interesting_endpoints.txt" > "$OUT_DIR/.pr_high_dedup.txt" 2>/dev/null
    fi
    rm -f "$OUT_DIR/.pr_diff_urls.txt"
    if [ -s "$OUT_DIR/.pr_high_dedup.txt" ]; then
      DEDUP_SKIPPED=$(( $(grep -c '^\[HIGH\]' "$OUT_DIR/04_6_interesting_endpoints.txt" 2>/dev/null || echo 0) - $(wc -l < "$OUT_DIR/.pr_high_dedup.txt") ))
      echo ""
      echo "6) [HIGH] ENDPOINT TRIAGE — IDOR/access-control shaped, not yet manually tested (see 04_6_interesting_endpoints.txt)."
      if [ "$DEDUP_SKIPPED" -gt 0 ]; then
        echo "   ($DEDUP_SKIPPED item(s) also flagged in section 2 above are omitted here — see that section instead):"
      else
        echo "   :"
      fi
      head -n 20 "$OUT_DIR/.pr_high_dedup.txt"
    fi
    rm -f "$OUT_DIR/.pr_high_dedup.txt"
  fi
} > "$PRIORITY_FILE"
drop_if_empty "$PRIORITY_FILE"
if [ -s "$PRIORITY_FILE" ]; then
  log_msg "[INFO] Priority review report written to $PRIORITY_FILE"
fi

clear
cat "$OUT_DIR/FINAL_SUMMARY.txt"
if [ -s "$PRIORITY_FILE" ]; then
  echo ""
  echo "[i] A consolidated priority-review index is also available at: $PRIORITY_FILE"
fi
