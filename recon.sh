#!/usr/bin/env bash
# recon_pipeline.sh (lightweight) with installer for tools
# Usage: ./recon_pipeline.sh
# WARNING: run these tools only against targets you have permission to test.

set -euo pipefail
LC_ALL=C

# --------- helpers ----------
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

ask_yes() {
  # ask_yes "Question?" && echo yes || echo no
  local prompt default answer
  prompt="$1"
  default="${2:-n}"
  read -p "$prompt " answer || true
  answer="${answer:-$default}"
  case "${answer,,}" in
    y|yes|بطاطس) return 0 ;;
    *) return 1 ;;
  esac
}

timestamp() { date +"%Y%m%d_%H%M%S"; }

append_path_if_needed() {
  local bin="$1"
  if ! echo "$PATH" | tr ':' '\n' | grep -qx "$bin"; then
    echo "Adding $bin to PATH for current session and to ~/.bashrc..."
    export PATH="$PATH:$bin"
    # persist for bash
    if [ -w "$HOME/.bashrc" ] || touch "$HOME/.bashrc" 2>/dev/null; then
      if ! grep -q "$bin" "$HOME/.bashrc" 2>/dev/null; then
        echo "export PATH=\$PATH:$bin" >> "$HOME/.bashrc"
      fi
    fi
  fi
}

install_golang_if_missing() {
  if command_exists go; then
    echo "Go is already installed: $(go version)"
    return 0
  fi

  echo "Go (golang) is not installed."
  if ask_yes "Install golang via apt (requires sudo/apt)? (y/N):" "n"; then
    if command_exists apt-get || command_exists apt; then
      echo "Installing golang via apt..."
      sudo apt-get update && sudo apt-get install -y golang-go
      echo "golang installed (apt)."
    else
      echo "apt not found. Please install Go manually (https://go.dev/dl/) and re-run this script."
      return 1
    fi
  else
    echo "Skipping Go install. Note: many tools require Go to install via 'go install'."
    return 1
  fi
}

go_install_module() {
  # go_install_module <module@version> <binary-name> [post-cmd]
  local mod bin post
  mod="$1"
  bin="$2"
  post="${3-}"
  if ! command_exists "$bin"; then
    if ! command_exists go; then
      echo "Go is required to install $bin. Skipping."
      return 1
    fi
    echo "Installing $bin via: go install $mod"
    # Use GOPROXY and GOBIN safe defaults
    GOBIN="${GOBIN:-$HOME/go/bin}" \
      GO111MODULE=on \
      go install -v "$mod" 2>/dev/null || {
        echo "go install failed for $mod — try running manually or check internet connection."
        return 1
      }
    append_path_if_needed "$HOME/go/bin"
    if [ -n "$post" ]; then
      eval "$post"
    fi
    echo "$bin installed (or attempted)."
  else
    echo "$bin already exists."
  fi
}

# --------- start ----------
echo "~~~ Recon pipeline script (light) with installer ~~~"
echo "Warning: run these tools only against targets you have permission to test."
echo

# Tools we will consider installing (module path and binary)
# Note: module paths were checked from official/famous repos.
declare -A TOOLS
TOOLS=(
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|subfinder"
  ["assetfinder"]="github.com/tomnomnom/assetfinder@latest|assetfinder"
  ["anew"]="github.com/tomnomnom/anew@latest|anew"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest|httpx"
  ["gospider"]="github.com/jaeles-project/gospider@latest|gospider"
  ["mantra"]="github.com/brosck/mantra@latest|mantra"
)

# Check minimal required commands that are non-go (grep/sed/tee)
for cmd in grep sed tee; do
  if ! command_exists "$cmd"; then
    echo "Required basic command '$cmd' is missing. Please install it (e.g., via apt). Aborting."
    exit 1
  fi
done

# Offer to install missing tools
echo "Checking required recon tools..."
MISSING=()
for k in "${!TOOLS[@]}"; do
  IFS='|' read -r module bin <<< "${TOOLS[$k]}"
  if ! command_exists "$bin"; then
    MISSING+=("$k")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "Missing tools detected: ${MISSING[*]}"
  if ask_yes "Would you like to attempt automatic installation of missing tools? (y/N):" "n"; then
    # ensure Go
    if ! command_exists go; then
      install_golang_if_missing || echo "Proceeding but Go not installed—Go required for many installs."
    fi

    # install each missing via go install
    for k in "${MISSING[@]}"; do
      IFS='|' read -r module bin <<< "${TOOLS[$k]}"
      echo
      echo "=> Tool: $k  (binary: $bin)"
      if ask_yes "Install $bin now? (y/N):" "n"; then
        # special handling for gospider to set GO111MODULE env
        if [ "$k" = "gospider" ]; then
          if ! command_exists go; then
            echo "Go not found; cannot install gospider. Skipping."
            continue
          fi
          echo "Installing gospider..."
          GO111MODULE=on GOBIN="${GOBIN:-$HOME/go/bin}" go install "$module" 2>/dev/null || {
            echo "gospider install failed. Try: GO111MODULE=on go install github.com/jaeles-project/gospider@latest"
            continue
          }
          append_path_if_needed "$HOME/go/bin"
          continue
        fi

        # default: go install
        go_install_module "$module" "$bin" || echo "Failed to install $bin automatically."
      else
        echo "Skipping install of $k."
      fi
    done
  else
    echo "Skipping automatic installation. You can install tools manually and re-run script."
  fi
else
  echo "All tools detected."
fi

echo
# After install attempts, re-check available tools and proceed

# ---- Main pipeline (lightweight, no katana, no wayback, no fuzzing) ----

read -p "Domain (example: example.com): " DOMAIN
DOMAIN="${DOMAIN// /}"  # strip spaces
if [ -z "$DOMAIN" ]; then echo "Domain required. Exiting."; exit 1; fi

read -p "Output folder (default: recon_${DOMAIN}_$(timestamp)): " OUTDIR
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
if [[ "${RUN_SUBS,,}" =~ ^(y|yes|بطاطس)$ ]]; then
  echo "[*] subdomain discovery -> temporary files in $OUTDIR"
  : > "$SUBS_TEMP"
  # run subfinder if available
  if command_exists subfinder; then
    subfinder -d "$DOMAIN" -all -o "$OUTDIR/subfinder.txt" 2>/dev/null || true
    cat "$OUTDIR/subfinder.txt" >> "$SUBS_TEMP" 2>/dev/null || true
  else
    echo "subfinder not found; skipping that step."
  fi
  # run assetfinder if available
  if command_exists assetfinder; then
    echo "$DOMAIN" | assetfinder --subs-only >> "$SUBS_TEMP" 2>/dev/null || true
  else
    echo "assetfinder not found; skipping that step."
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
if [[ "${RUN_HTTPX,,}" =~ ^(y|yes|بطاطس)$ ]]; then
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
if [[ "${RUN_URLS,,}" =~ ^(y|yes|بطاطس)$ ]]; then
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
if [[ "${RUN_EXTRACT,,}" =~ ^(y|yes|بطاطس)$ ]]; then
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
    echo "[*] Running mantra on JS files (this may be CPU intensive)..."
    # limit parallelism by xargs -n1 -P4 (4 concurrent)
    cat "$JS_OUT" | xargs -n1 -P4 -I{} sh -c 'mantra "{}" >> "'"$OUTDIR"'/mantra_results.txt" 2>/dev/null' || true
    echo "mantra results -> $OUTDIR/mantra_results.txt"
  else
    echo "mantra not found or no JS list; skipping JS analysis."
  fi
else
  echo "[*] Skipping extraction of JS/PHP"
fi

echo
echo "Pipeline finished. Check $OUTDIR for results."
echo
echo "Suggested next steps:"
echo "- Manual review of $JS_OUT and $OUTDIR/mantra_results.txt for endpoints/keys."
echo "- If you want even lighter runs, skip URL collection and only run subdomain discovery + httpx."
echo
