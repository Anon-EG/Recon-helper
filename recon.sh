#!/usr/bin/env bash
# recon_pipeline.sh (lightweight: no katana, no waybackurls, no fuzzing)
# Usage: ./recon_pipeline.sh
# WARNING: use only on targets you have permission to test.

set -u
LC_ALL=C

# --------- helpers ----------
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

check_tools() {
  local missing=()
  for t in subfinder assetfinder anew httpx gospider mantra grep sed tee; do
    if ! command_exists "$t"; then
      missing+=("$t")
    fi
  done
  if [ ${#missing[@]} -ne 0 ]; then
    echo "Missing suggested tools: ${missing[*]}"
    echo "You can still run parts of the script manually if some tools are missing."
    read -p "Proceed anyway? (y/N): " yn
    case "${yn,,}" in
      y|yes) echo "Proceeding despite missing tools...";;
      *) echo "Aborting."; exit 1;;
    esac
  fi
}

timestamp() { date +"%Y%m%d_%H%M%S"; }

# --------- start ----------
echo "~~~ Recon pipeline script (light) ~~~"
echo "Warning: run these tools only against targets you have permission to test."
echo

check_tools

read -p "Domain (example: example.com): " DOMAIN
DOMAIN="${DOMAIN// /}"  # strip spaces
if [ -z "$DOMAIN" ]; then echo "Domain required. Exiting."; exit 1; fi

read -p "Output folder (default: recon_$DOMAIN_$(timestamp)): " OUTDIR
OUTDIR=${OUTDIR:-"recon_${DOMAIN}_$(timestamp)"}
mkdir -p "$OUTDIR"
echo "Outputs will be saved to: $OUTDIR"
echo

# Options: which stages to run
echo
read -p "Run subdomain discovery? (y/N): " RUN_SUBS
read -p "Run httpx (filter live hosts)? (y/N): " RUN_HTTPX
read -p "Collect URLs with gospider only? (y/N): " RUN_URLS
read -p "Extract and analyze JS/PHP? (y/N): " RUN_EXTRACT

echo
echo "Starting pipeline..."
echo

# --------- subdomain discovery ----------
SUBS_TEMP="$OUTDIR/subs_merged.tmp"
ALLSUBS="$OUTDIR/allsubs.txt"
if [[ "${RUN_SUBS,,}" =~ ^(y|yes)$ ]]; then
  echo "[*] subdomain discovery -> temporary files in $OUTDIR"
  : > "$SUBS_TEMP"
  # run subfinder if available
  if command_exists subfinder; then
    subfinder -d "$DOMAIN" -all -o "$OUTDIR/subfinder.txt" 2>/dev/null || true
    cat "$OUTDIR/subfinder.txt" >> "$SUBS_TEMP" 2>/dev/null || true
  fi
  # run assetfinder if available
  if command_exists assetfinder; then
    echo "$DOMAIN" | assetfinder --subs-only >> "$SUBS_TEMP" 2>/dev/null || true
  fi

  # merge & dedupe
  if command_exists anew; then
    cat "$SUBS_TEMP" | tr -d '\r' | sed '/^\s*$/d' | anew > "$ALLSUBS" 2>/dev/null || true
  else
    cat "$SUBS_TEMP" | tr -d '\r' | sed '/^\s*$/d' | sort -u > "$ALLSUBS" 2>/dev/null || true
  fi
  rm -f "$SUBS_TEMP"
  echo "Saved deduped subdomains -> $ALLSUBS"
else
  echo "[*] Skipping subdomain discovery"
fi

# --------- httpx to find live hosts ----------
HTTPX_OUT="$OUTDIR/httpx_live.txt"
if [[ "${RUN_HTTPX,,}" =~ ^(y|yes)$ ]]; then
  echo "[*] Running httpx to find live hosts -> $HTTPX_OUT"
  if command_exists httpx; then
    if [ -f "$ALLSUBS" ]; then
      cat "$ALLSUBS" | httpx -silent -status-code -mc 200 -o "$HTTPX_OUT" 2>/dev/null || true
    else
      # fallback: test root domain
      echo "https://$DOMAIN" | httpx -silent -status-code -mc 200 -o "$HTTPX_OUT" 2>/dev/null || true
    fi
  else
    echo "httpx not found; skipping."
  fi
else
  echo "[*] Skipping httpx"
fi

# --------- collect URLs: gospider only (lighter) ----------
ALL_URLS="$OUTDIR/allurls.txt"
if [[ "${RUN_URLS,,}" =~ ^(y|yes)$ ]]; then
  echo "[*] Collecting URLs with gospider (lighter) -> $OUTDIR/gospider.txt"
  GOSP_OUT="$OUTDIR/gospider.txt"
  > "$GOSP_OUT"
  if command_exists gospider; then
    # prefer using live hosts list if available, otherwise use the domain
    if [ -f "$HTTPX_OUT" ] && [ -s "$HTTPX_OUT" ]; then
      gospider -S "$HTTPX_OUT" -o "$OUTDIR/gospider_raw" 2>/dev/null || true
    else
      gospider -d 1 -s "https://$DOMAIN" -o "$OUTDIR/gospider_raw" 2>/dev/null || true
    fi

    # extract URLs from raw output (if produced)
    if [ -d "$OUTDIR/gospider_raw" ]; then
      find "$OUTDIR/gospider_raw" -type f -name "*.txt" -exec cat {} + 2>/dev/null | sed -n 's/.*\(http[s]\?:\/\/[^ ]*\).*/\1/p' >> "$GOSP_OUT" 2>/dev/null || true
    fi
  else
    echo "gospider not found; skipping URL collection."
  fi

  # dedupe
  if [ -s "$GOSP_OUT" ]; then
    if command_exists anew; then
      cat "$GOSP_OUT" | tr -d '\r' | sed '/^\s*$/d' | anew > "$ALL_URLS" 2>/dev/null || true
    else
      sort -u "$GOSP_OUT" > "$ALL_URLS" 2>/dev/null || true
    fi
    echo "Collected URLs -> $ALL_URLS"
  else
    echo "No URLs collected by gospider."
  fi
else
  echo "[*] Skipping URL collection"
fi

# --------- extract JS and PHP ----------
JS_OUT="$OUTDIR/js.txt"
PHP_OUT="$OUTDIR/php.txt"
if [[ "${RUN_EXTRACT,,}" =~ ^(y|yes)$ ]]; then
  echo "[*] Extracting .js and .php from $ALL_URLS"
  if [ -f "$ALL_URLS" ]; then
    grep -Ei "\.js($|\?)" "$ALL_URLS" | sed 's/[?#].*$//' | sort -u > "$JS_OUT" || true
    grep -Ei "\.php($|\?)" "$ALL_URLS" | sed 's/[?#].*$//' | sort -u > "$PHP_OUT" || true
    echo "JS files -> $JS_OUT"
    echo "PHP files -> $PHP_OUT"
  else
    echo "No URLs file ($ALL_URLS) found; cannot extract JS/PHP."
  fi

  # optional: run mantra on js list if available
  if command_exists mantra && [ -f "$JS_OUT" ]; then
    echo "[*] Running mantra on JS files..."
    cat "$JS_OUT" | xargs -n1 -P10 mantra >> "$OUTDIR/mantra_results.txt" 2>/dev/null || true
    echo "mantra results -> $OUTDIR/mantra_results.txt"
  fi
else
  echo "[*] Skipping extraction of JS/PHP"
fi

echo
echo "Pipeline finished. Check $OUTDIR for results."

echo
echo "Suggested next steps:"
echo "- Manual review of $JS_OUT and $OUTDIR/mantra_results.txt for endpoints/keys."
echo "- For even lighter runs, skip URL collection and only run subdomain discovery + httpx."
echo
