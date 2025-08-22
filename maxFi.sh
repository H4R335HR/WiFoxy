#!/usr/bin/env bash
# PublicFi - rotate MACs & try connecting to a Wi‑Fi SSID (for authorized testing only)
# Usage:
#   sudo ./publicfi.sh -i wlan0 -s "FreeWifi" [-p "pass"] [--bssid AA:BB:CC:DD:EE:FF] [-r 5] [-t 20]
#
# Notes:
# - Requires: bash, ip, iw, nmcli (NetworkManager), openssl, ping
# - Works best on systems using NetworkManager. (wpa_supplicant not auto-managed here)
# - Stores successes in ~/.publicfi_macs
# - Log file: /tmp/publicfi.log
#
# LEGAL: Use only on networks you are authorized to test.
set -Eeuo pipefail

# ---------- Config (defaults) ----------
IFACE="wlan0"
SSID=""
PASS=""
BSSID=""
RETRIES=5
TIMEOUT=20
PING_HOST="8.8.8.8"
PING_COUNT=3
LOG_FILE="/tmp/publicfi.log"
STORE_FILE="${HOME}/.publicfi_macs"

# ---------- Colors ----------
RED=$'\e[31m' ; GREEN=$'\e[32m' ; YELLOW=$'\e[33m' ; BLUE=$'\e[34m' ; RESET=$'\e[0m'

log()      { printf "[%(%F %T)T] %s\n" -1 "$*"    | tee -a "$LOG_FILE" >/dev/null; }
info()     { echo "${BLUE}[i]${RESET} $*"         | tee -a "$LOG_FILE" >/dev/null; }
success()  { echo "${GREEN}[+]${RESET} $*"        | tee -a "$LOG_FILE" >/dev/null; }
warn()     { echo "${YELLOW}[!]${RESET} $*"       | tee -a "$LOG_FILE" >/dev/null; }
error()    { echo "${RED}[-] $*${RESET}"          | tee -a "$LOG_FILE" >/dev/null; }

usage() {
  cat <<EOF
PublicFi - rotate MACs & connect (authorized testing only)

Usage:
  sudo $0 -i <iface> -s <ssid> [-p <password>] [--bssid <AP-MAC>] [-r <retries>] [-t <seconds>]

Options:
  -i, --iface     Wireless interface (default: $IFACE)
  -s, --ssid      Target SSID (required)
  -p, --pass      Password (omit for open networks)
      --bssid     Target BSSID (AP MAC) to prefer (optional)
  -r, --retries   Number of MAC attempts (default: $RETRIES)
  -t, --timeout   Seconds to wait per attempt (default: $TIMEOUT)
  -h, --help      Show this help

Examples:
  sudo $0 -i wlan0 -s "Cafe Free WiFi" -r 6
  sudo $0 -i wlan0 -s "MyHome" -p "Sup3rS3cret!" --bssid aa:bb:cc:dd:ee:ff -t 30
EOF
}

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    error "Run as root (sudo).";
    exit 1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  local deps=(ip iw nmcli openssl ping)
  local missing=()
  for d in "${deps[@]}"; do
    if ! have "$d"; then missing+=("$d"); fi
  done
  if ((${#missing[@]})); then
    error "Missing dependencies: ${missing[*]}"
    exit 1
  fi
}

parse_args() {
  while (("$#")); do
    case "$1" in
      -i|--iface)   IFACE="$2"; shift 2;;
      -s|--ssid)    SSID="$2"; shift 2;;
      -p|--pass)    PASS="$2"; shift 2;;
      --bssid)      BSSID="$2"; shift 2;;
      -r|--retries) RETRIES="$2"; shift 2;;
      -t|--timeout) TIMEOUT="$2"; shift 2;;
      -h|--help)    usage; exit 0;;
      *) error "Unknown arg: $1"; usage; exit 1;;
    esac
  done
  if [[ -z "$SSID" ]]; then
    error "SSID is required."; usage; exit 1
  fi
}

# Generate a locally-administered, unicast MAC
rand_mac() {
  local hex b1
  hex="$(openssl rand -hex 6)"
  b1=$(( (0x${hex:0:2} | 0x02) & 0xFE ))  # set LAA bit, clear multicast bit
  printf "%02x:%s:%s:%s:%s:%s\n" \
    "$b1" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}" "${hex:10:2}"
}

orig_mac=""
get_orig_mac() {
  orig_mac="$(cat /sys/class/net/"$IFACE"/address)"
}

set_mac() {
  local newmac="$1"
  info "Setting MAC $IFACE -> $newmac"
  ip link set "$IFACE" down
  ip link set "$IFACE" address "$newmac"
  ip link set "$IFACE" up
}

restore_mac() {
  if [[ -n "$orig_mac" ]]; then
    warn "Restoring original MAC: $orig_mac"
    ip link set "$IFACE" down || true
    ip link set "$IFACE" address "$orig_mac" || true
    ip link set "$IFACE" up || true
  fi
}

nm_disconnect() {
  nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$IFACE" '$2==d{print $1}' | \
    while read -r con; do nmcli con down "$con" || true; done
  nmcli dev disconnect "$IFACE" || true
}

nm_try_connect() {
  local ssid="$1" pass="$2" bssid="${3:-}"
  local args=(dev wifi connect "$ssid" ifname "$IFACE")
  [[ -n "$pass"  ]] && args+=(password "$pass")
  [[ -n "$bssid" ]] && args+=(bssid "$bssid")
  nmcli "${args[@]}"
}

is_connected() {
  nmcli -t -f DEVICE,STATE dev status | grep -q "^${IFACE}:connected$"
}

test_connectivity() {
  ping -c "$PING_COUNT" -W 2 "$PING_HOST" >/dev/null 2>&1
}

store_success() {
  mkdir -p "$(dirname "$STORE_FILE")"
  echo "$(date -Is)  IFACE=$IFACE  SSID=$SSID  MAC=$1" >> "$STORE_FILE"
}

main() {
  : > "$LOG_FILE"
  need_root
  check_deps
  parse_args "$@"
  info "Interface: $IFACE | SSID: $SSID | Retries: $RETRIES | Timeout: ${TIMEOUT}s"
  [[ -n "$PASS"  ]] && info "Password: (provided)"
  [[ -n "$BSSID" ]] && info "BSSID: $BSSID"

  if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    error "Interface $IFACE not found."
    exit 1
  fi
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    error "Interface $IFACE unavailable."
    exit 1
  fi

  get_orig_mac
  trap 'restore_mac' EXIT INT TERM

  if ! nmcli dev status | awk '{print $1,$3}' | grep -q "^${IFACE} .*"; then
    warn "NetworkManager may not manage $IFACE. Continuing anyway."
  fi

  local attempt=1
  while (( attempt <= RETRIES )); do
    echo
    info "Attempt $attempt/$RETRIES"
    nm_disconnect

    local mac
    mac="$(rand_mac)"
    set_mac "$mac"

    nmcli dev wifi rescan ifname "$IFACE" || true

    if nm_try_connect "$SSID" "$PASS" "$BSSID"; then
      local waited=0
      until is_connected; do
        sleep 1
        ((waited++))
        if (( waited >= TIMEOUT )); then
          warn "Timed out waiting for connection."
          break
        fi
      done
      if is_connected; then
        success "Wi‑Fi reports connected with MAC $mac"
        if test_connectivity; then
          success "Internet reachable (ping $PING_HOST ok)."
          store_success "$mac"
          echo
          success "Done. Leaving spoofed MAC active. (Original: $orig_mac)"
          exit 0
        else
          warn "Connected to Wi‑Fi but no internet reachability."
          store_success "$mac"
          exit 0
        fi
      fi
    else
      warn "nmcli connect command failed."
    fi

    ((attempt++))
  done

  error "Failed to connect after $RETRIES attempts."
  exit 2
}

main "$@"
