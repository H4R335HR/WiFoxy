#!/usr/bin/env bash
#
# WiFoxy - MAC rotation & Wi-Fi connection tool for AUTHORIZED security testing.
#
# A single, self-contained consolidation of the older pubFi/maxFi scripts.
# It rotates the wireless MAC address and attempts to associate with a target
# SSID, verifies connectivity, and (optionally) performs light recon and
# produces an HTML assessment report.
#
# It supports two connection backends and auto-detects which to use:
#   * NetworkManager  (nmcli)                  - preferred when available
#   * wpa_supplicant  (wpa_supplicant + iw + a DHCP client)
#
# MAC rotation strategies:
#   random   - locally-administered random MACs (default)
#   vendor   - MACs built from real vendor OUIs (better for filter evasion)
#   clients  - harvest MACs of clients already on the SSID via airodump-ng
#              (requires monitor-mode capable card + aircrack-ng)
#
# LEGAL: Use ONLY on networks you own or are explicitly authorized to test.
#
# Usage:
#   sudo ./wifoxy.sh -s "SSID" [options]
#
set -Eeuo pipefail

# ----------------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------------
IFACE=""
SSID=""
PASS=""
BSSID=""
RETRIES=5
TIMEOUT=25
STRATEGY="random"          # random | vendor | clients
PING_HOST="8.8.8.8"
PING_COUNT=3
BACKEND="auto"             # auto | nm | wpa
GENERATE_REPORT=false
SCAN_NETWORK=false
KEEP_MAC=false             # keep spoofed MAC on exit instead of restoring
VERBOSE=false

LOG_FILE="${TMPDIR:-/tmp}/wifoxy.log"
STORE_FILE="${HOME:-/root}/.wifoxy_macs"
REPORT_FILE="${TMPDIR:-/tmp}/wifoxy_report.html"
VENDOR_DB="/usr/share/ieee-data/oui.txt"

SCRIPT_NAME="$(basename "$0")"

# Runtime state (populated later)
ORIG_MAC=""
ORIG_NM_MANAGED=""         # yes|no|"" (unknown) - NM managed state to restore
RESOLVED_BACKEND=""        # nm|wpa after detection
WPA_PID=""                 # wpa_supplicant pid we started (for cleanup)
DHCP_PID=""                # background dhcp client pid (for cleanup)
MONITOR_ACTIVE=false       # whether we switched the card to monitor mode
TMP_WORK=""                # scratch dir
SUCCESS_MAC=""
CONNECT_SECONDS=0
USED_ATTEMPT=0

# ----------------------------------------------------------------------------
# Output helpers (color only when attached to a terminal)
# ----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'
  BLUE=$'\e[34m'; CYAN=$'\e[36m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; RESET=""
fi

_ts() { date '+%F %T'; }
_logline() { printf '[%s] %s\n' "$(_ts)" "$*" >>"$LOG_FILE" 2>/dev/null || true; }

info()      { echo "${BLUE}[i]${RESET} $*"; _logline "[i] $*"; }
success()   { echo "${GREEN}[+]${RESET} $*"; _logline "[+] $*"; }
warn()      { echo "${YELLOW}[!]${RESET} $*"; _logline "[!] $*"; }
error()     { echo "${RED}[-]${RESET} $*" >&2; _logline "[-] $*"; }
highlight() { echo "${CYAN}${BOLD}[*] $*${RESET}"; _logline "[*] $*"; }
debug()     { $VERBOSE && echo "${CYAN}[d]${RESET} $*" || true; _logline "[d] $*"; }

die() { error "$*"; exit 1; }

# ----------------------------------------------------------------------------
# Usage
# ----------------------------------------------------------------------------
usage() {
  cat <<EOF
${BOLD}WiFoxy${RESET} - MAC rotation & Wi-Fi connection tool (authorized testing only)

${BOLD}Usage:${RESET}
  sudo $SCRIPT_NAME -s <ssid> [options]

${BOLD}Required:${RESET}
  -s, --ssid <ssid>       Target SSID

${BOLD}Options:${RESET}
  -i, --iface <iface>     Wireless interface (auto-detected if omitted)
  -p, --pass <password>   WPA/WPA2 passphrase (omit for open networks)
      --bssid <mac>       Prefer a specific AP BSSID
  -r, --retries <n>       MAC attempts before giving up (default: $RETRIES)
  -t, --timeout <sec>     Seconds to wait per association (default: $TIMEOUT)
  -m, --strategy <mode>   MAC strategy: random | vendor | clients (default: $STRATEGY)
  -b, --backend <mode>    Connection backend: auto | nm | wpa (default: $BACKEND)
      --ping-host <host>  Connectivity check target (default: $PING_HOST)
      --scan              Light nmap recon of the subnet after connecting
      --report            Write an HTML assessment report
      --keep-mac          Leave the spoofed MAC active on exit (default: restore)
  -v, --verbose           Verbose/debug output
  -h, --help              Show this help

${BOLD}Examples:${RESET}
  sudo $SCRIPT_NAME -s "Cafe Free WiFi" -r 6 --report
  sudo $SCRIPT_NAME -s "Guest" -m vendor --scan
  sudo $SCRIPT_NAME -s "MyHome" -p "secret" --bssid aa:bb:cc:dd:ee:ff
  sudo $SCRIPT_NAME -s "OpenNet" -m clients -i wlan0

Logs:     $LOG_FILE
Successes:$STORE_FILE
EOF
}

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
parse_args() {
  while (($#)); do
    case "$1" in
      -i|--iface)     IFACE="${2:?}"; shift 2;;
      -s|--ssid)      SSID="${2:?}"; shift 2;;
      -p|--pass)      PASS="${2:?}"; shift 2;;
      --bssid)        BSSID="${2:?}"; shift 2;;
      -r|--retries)   RETRIES="${2:?}"; shift 2;;
      -t|--timeout)   TIMEOUT="${2:?}"; shift 2;;
      -m|--strategy)  STRATEGY="${2:?}"; shift 2;;
      -b|--backend)   BACKEND="${2:?}"; shift 2;;
      --ping-host)    PING_HOST="${2:?}"; shift 2;;
      --scan)         SCAN_NETWORK=true; shift;;
      --report)       GENERATE_REPORT=true; shift;;
      --keep-mac)     KEEP_MAC=true; shift;;
      -v|--verbose)   VERBOSE=true; shift;;
      -h|--help)      usage; exit 0;;
      *) usage >&2; die "Unknown argument: $1";;
    esac
  done

  [[ -n "$SSID" ]] || { usage >&2; die "SSID is required (-s)."; }

  case "$STRATEGY" in random|vendor|clients) ;; *) die "Invalid --strategy: $STRATEGY";; esac
  case "$BACKEND"  in auto|nm|wpa) ;;          *) die "Invalid --backend: $BACKEND";; esac

  [[ "$RETRIES" =~ ^[0-9]+$ && "$RETRIES" -ge 1 ]] || die "--retries must be a positive integer"
  [[ "$TIMEOUT" =~ ^[0-9]+$ && "$TIMEOUT" -ge 1 ]] || die "--timeout must be a positive integer"
}

# ----------------------------------------------------------------------------
# Preconditions / environment
# ----------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Root privileges required. Re-run with sudo."
  fi
}

# Detect a wireless interface if the user did not specify one.
detect_iface() {
  [[ -n "$IFACE" ]] && return 0

  local cand=""
  if have iw; then
    cand="$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')"
  fi
  if [[ -z "$cand" ]]; then
    # Fall back to scanning sysfs for a device with a wireless phy.
    local d
    for d in /sys/class/net/*; do
      [[ -e "$d/wireless" || -e "$d/phy80211" ]] && { cand="$(basename "$d")"; break; }
    done
  fi

  [[ -n "$cand" ]] || die "No wireless interface found. Specify one with -i."
  IFACE="$cand"
  info "Auto-detected wireless interface: $IFACE"
}

check_iface() {
  [[ -d "/sys/class/net/$IFACE" ]] || die "Interface '$IFACE' not found."
  ip link show "$IFACE" >/dev/null 2>&1 || die "Interface '$IFACE' is unavailable."
}

# Resolve which backend to use based on request + what's installed/managing.
resolve_backend() {
  local nm_ok=false wpa_ok=false
  if have nmcli && (have systemctl && systemctl is-active --quiet NetworkManager 2>/dev/null || pgrep -x NetworkManager >/dev/null 2>&1); then
    nm_ok=true
  elif have nmcli && nmcli -t -f RUNNING general 2>/dev/null | grep -q running; then
    nm_ok=true
  fi
  if have wpa_supplicant && have iw; then
    wpa_ok=true
  fi

  case "$BACKEND" in
    nm)  $nm_ok  || die "NetworkManager backend requested but nmcli/NetworkManager is not available."
         RESOLVED_BACKEND="nm";;
    wpa) $wpa_ok || die "wpa_supplicant backend requested but wpa_supplicant/iw are not available."
         RESOLVED_BACKEND="wpa";;
    auto)
         if $nm_ok; then RESOLVED_BACKEND="nm"
         elif $wpa_ok; then RESOLVED_BACKEND="wpa"
         else die "No usable backend found. Install NetworkManager (nmcli) or wpa_supplicant + iw."
         fi;;
  esac
  info "Connection backend: $RESOLVED_BACKEND"
}

check_deps() {
  # Core deps needed by every path.
  local core=(ip ping)
  local missing=()
  local d
  for d in "${core[@]}"; do have "$d" || missing+=("$d"); done

  # A source of randomness for MACs.
  if ! have openssl && [[ ! -r /dev/urandom ]]; then
    missing+=("openssl-or-/dev/urandom")
  fi
  ((${#missing[@]})) && die "Missing required dependencies: ${missing[*]}"

  # Strategy-specific.
  if [[ "$STRATEGY" == "clients" ]]; then
    have airodump-ng || die "--strategy clients needs aircrack-ng (airodump-ng)."
    have iw          || die "--strategy clients needs iw for monitor mode."
  fi

  # Optional niceties.
  if $SCAN_NETWORK && ! have nmap; then
    warn "nmap not found - --scan will be skipped."
    SCAN_NETWORK=false
  fi
}

# ----------------------------------------------------------------------------
# MAC address helpers
# ----------------------------------------------------------------------------
_rand_hex() {
  # Print N random bytes as hex (N = $1). Prefer openssl, fall back to urandom.
  local n="$1"
  if have openssl; then
    openssl rand -hex "$n"
  else
    head -c "$n" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# Random locally-administered unicast MAC.
rand_mac_random() {
  local hex b1
  hex="$(_rand_hex 6)"
  b1=$(( (0x${hex:0:2} | 0x02) & 0xFE ))   # set LAA bit, clear multicast bit
  printf '%02x:%s:%s:%s:%s:%s\n' \
    "$b1" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}" "${hex:10:2}"
}

# MAC built from a real vendor OUI (globally-administered - looks like a real NIC).
rand_mac_vendor() {
  local prefixes=(
    "00:1B:44"  # Cisco
    "00:26:BB"  # Apple
    "AC:BC:32"  # Apple
    "00:50:56"  # VMware
    "08:00:27"  # VirtualBox
    "B8:27:EB"  # Raspberry Pi
    "DC:A6:32"  # Raspberry Pi
    "00:1A:11"  # Google
  )
  local prefix suffix
  prefix="${prefixes[$((RANDOM % ${#prefixes[@]}))]}"
  suffix="$(_rand_hex 3)"
  printf '%s:%s:%s:%s\n' "$prefix" "${suffix:0:2}" "${suffix:2:2}" "${suffix:4:2}"
}

# Look up a vendor for a MAC (best effort).
mac_vendor() {
  local mac="$1" oui
  oui="${mac:0:8}"
  if [[ -r "$VENDOR_DB" ]]; then
    grep -i "^${oui//:/-}" "$VENDOR_DB" 2>/dev/null | head -1 | cut -d$'\t' -f3 || true
  fi
}

# ----------------------------------------------------------------------------
# Client MAC harvesting (strategy=clients) - requires monitor mode
# ----------------------------------------------------------------------------
HARVESTED_MACS=()

enter_monitor() {
  info "Switching $IFACE to monitor mode for client discovery..."
  if have nmcli; then nmcli dev set "$IFACE" managed no >/dev/null 2>&1 || true; fi
  ip link set "$IFACE" down
  iw "$IFACE" set type monitor 2>/dev/null || die "Failed to set monitor mode on $IFACE."
  ip link set "$IFACE" up
  MONITOR_ACTIVE=true
}

leave_monitor() {
  $MONITOR_ACTIVE || return 0
  debug "Returning $IFACE to managed mode."
  ip link set "$IFACE" down 2>/dev/null || true
  iw "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null || true
  if have nmcli; then nmcli dev set "$IFACE" managed yes >/dev/null 2>&1 || true; fi
  MONITOR_ACTIVE=false
}

harvest_client_macs() {
  enter_monitor
  local prefix="$TMP_WORK/scan"
  info "Capturing clients on '$SSID' (15s)..."
  airodump-ng "$IFACE" --essid "$SSID" --output-format csv -w "$prefix" >/dev/null 2>&1 &
  local pid=$!
  sleep 15
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  local csv
  csv="$(ls -1 "${prefix}"-*.csv 2>/dev/null | head -1 || true)"
  [[ -n "$csv" && -r "$csv" ]] || { warn "No capture file produced."; leave_monitor; return 1; }

  # The station section starts after the "Station MAC" header line. Take the
  # first field of each subsequent non-empty row that looks like a MAC.
  mapfile -t HARVESTED_MACS < <(
    awk '
      /Station MAC/ { instations=1; next }
      instations {
        gsub(/^[ \t]+|[ \t]+$/, "", $0)
        split($0, f, ",")
        m=f[1]; gsub(/^[ \t]+|[ \t]+$/, "", m)
        if (m ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/) print m
      }
    ' "$csv" | sort -u
  )

  leave_monitor

  if ((${#HARVESTED_MACS[@]} == 0)); then
    warn "No client MACs harvested; falling back to random MACs."
    return 1
  fi
  success "Harvested ${#HARVESTED_MACS[@]} client MAC(s)."
  return 0
}

# Pick the MAC for a given attempt number based on strategy.
next_mac() {
  local attempt="$1"
  case "$STRATEGY" in
    vendor)  rand_mac_vendor;;
    clients)
      if ((${#HARVESTED_MACS[@]} > 0)); then
        printf '%s\n' "${HARVESTED_MACS[$(((attempt - 1) % ${#HARVESTED_MACS[@]}))]}"
      else
        rand_mac_random
      fi;;
    *)       rand_mac_random;;
  esac
}

# ----------------------------------------------------------------------------
# Interface / MAC manipulation
# ----------------------------------------------------------------------------
get_orig_mac() {
  ORIG_MAC="$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || true)"
  [[ -n "$ORIG_MAC" ]] && debug "Original MAC: $ORIG_MAC"
  # Remember NM managed state so we can restore it.
  if have nmcli; then
    if nmcli -t -f GENERAL.STATE dev show "$IFACE" 2>/dev/null | grep -qi 'unmanaged'; then
      ORIG_NM_MANAGED="no"
    else
      ORIG_NM_MANAGED="yes"
    fi
  fi
}

# Set a MAC with graceful fallbacks: ip link -> macchanger -> ifconfig.
set_mac() {
  local newmac="$1" vendor
  vendor="$(mac_vendor "$newmac")"
  info "Setting MAC: $newmac${vendor:+ ($vendor)}"
  ip link set "$IFACE" down 2>/dev/null || true
  if ip link set "$IFACE" address "$newmac" 2>/dev/null; then
    :
  elif have macchanger && macchanger --mac="$newmac" "$IFACE" >/dev/null 2>&1; then
    :
  elif have ifconfig && ifconfig "$IFACE" hw ether "$newmac" >/dev/null 2>&1; then
    :
  else
    ip link set "$IFACE" up 2>/dev/null || true
    warn "Could not change MAC to $newmac (driver may not allow it)."
    return 1
  fi
  ip link set "$IFACE" up 2>/dev/null || true
  sleep 1
  local cur
  cur="$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || true)"
  if [[ "${cur,,}" != "${newmac,,}" ]]; then
    warn "MAC did not stick (now: ${cur:-unknown}). Driver may reset it."
    return 1
  fi
  return 0
}

restore_mac() {
  [[ -n "$ORIG_MAC" ]] || return 0
  if $KEEP_MAC && [[ -n "$SUCCESS_MAC" ]]; then
    info "Keeping spoofed MAC active ($SUCCESS_MAC). Original was $ORIG_MAC."
    return 0
  fi
  warn "Restoring original MAC: $ORIG_MAC"
  ip link set "$IFACE" down 2>/dev/null || true
  ip link set "$IFACE" address "$ORIG_MAC" 2>/dev/null \
    || { have macchanger && macchanger --mac="$ORIG_MAC" "$IFACE" >/dev/null 2>&1; } \
    || { have ifconfig && ifconfig "$IFACE" hw ether "$ORIG_MAC" >/dev/null 2>&1; } \
    || true
  ip link set "$IFACE" up 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# Backend: NetworkManager
# ----------------------------------------------------------------------------
nm_disconnect() {
  nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
    | awk -F: -v d="$IFACE" '$2==d{print $1}' \
    | while read -r con; do nmcli con down "$con" >/dev/null 2>&1 || true; done
  nmcli dev disconnect "$IFACE" >/dev/null 2>&1 || true
}

nm_connect() {
  # NM needs to manage the device to connect.
  nmcli dev set "$IFACE" managed yes >/dev/null 2>&1 || true
  nmcli dev wifi rescan ifname "$IFACE" >/dev/null 2>&1 || true
  sleep 2
  local args=(dev wifi connect "$SSID" ifname "$IFACE")
  [[ -n "$PASS"  ]] && args+=(password "$PASS")
  [[ -n "$BSSID" ]] && args+=(bssid "$BSSID")
  nmcli "${args[@]}" >>"$LOG_FILE" 2>&1
}

nm_is_connected() {
  nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep -q "^${IFACE}:connected$"
}

# ----------------------------------------------------------------------------
# Backend: wpa_supplicant
# ----------------------------------------------------------------------------
wpa_cleanup() {
  [[ -n "$DHCP_PID" ]] && kill "$DHCP_PID" 2>/dev/null || true
  [[ -n "$WPA_PID"  ]] && kill "$WPA_PID"  2>/dev/null || true
  DHCP_PID=""; WPA_PID=""
}

wpa_disconnect() {
  wpa_cleanup
  # Release any DHCP leases we may hold.
  if have dhclient; then dhclient -r "$IFACE" >/dev/null 2>&1 || true; fi
  ip addr flush dev "$IFACE" 2>/dev/null || true
}

wpa_build_conf() {
  local conf="$TMP_WORK/wpa.conf"
  {
    echo "ctrl_interface=${TMP_WORK}/wpa_ctrl"
    echo "network={"
    echo "    ssid=\"$SSID\""
    [[ -n "$BSSID" ]] && echo "    bssid=$BSSID"
    if [[ -n "$PASS" ]]; then
      # psk line (quoted passphrase is accepted by wpa_supplicant).
      echo "    psk=\"$PASS\""
    else
      echo "    key_mgmt=NONE"
    fi
    echo "}"
  } >"$conf"
  chmod 600 "$conf"
  echo "$conf"
}

wpa_start_dhcp() {
  if have dhclient; then
    dhclient -1 "$IFACE" >>"$LOG_FILE" 2>&1 &
    DHCP_PID=$!
  elif have dhcpcd; then
    dhcpcd -w "$IFACE" >>"$LOG_FILE" 2>&1 &
    DHCP_PID=$!
  elif have udhcpc; then
    udhcpc -i "$IFACE" -q >>"$LOG_FILE" 2>&1 &
    DHCP_PID=$!
  else
    warn "No DHCP client (dhclient/dhcpcd/udhcpc) found; connectivity may fail."
  fi
}

wpa_connect() {
  # Make sure NM is not fighting us for the device.
  if have nmcli; then nmcli dev set "$IFACE" managed no >/dev/null 2>&1 || true; fi
  ip link set "$IFACE" up 2>/dev/null || true

  local conf; conf="$(wpa_build_conf)"
  rm -rf "$TMP_WORK/wpa_ctrl" 2>/dev/null || true

  wpa_supplicant -B -i "$IFACE" -c "$conf" -P "$TMP_WORK/wpa.pid" >>"$LOG_FILE" 2>&1 \
    || return 1
  WPA_PID="$(cat "$TMP_WORK/wpa.pid" 2>/dev/null || true)"
  return 0
}

wpa_is_connected() {
  # Associated at L2?
  if have iw; then
    iw dev "$IFACE" link 2>/dev/null | grep -qi "Connected to" || return 1
  fi
  return 0
}

# ----------------------------------------------------------------------------
# Backend dispatch
# ----------------------------------------------------------------------------
backend_disconnect() {
  case "$RESOLVED_BACKEND" in
    nm)  nm_disconnect;;
    wpa) wpa_disconnect;;
  esac
}

backend_connect() {
  case "$RESOLVED_BACKEND" in
    nm)  nm_connect;;
    wpa) wpa_connect && { wpa_is_connected; } ;;
  esac
}

backend_is_connected() {
  case "$RESOLVED_BACKEND" in
    nm)  nm_is_connected;;
    wpa) wpa_is_connected;;
  esac
}

# ----------------------------------------------------------------------------
# Connectivity / recon
# ----------------------------------------------------------------------------
wait_for_link() {
  local waited=0
  until backend_is_connected; do
    sleep 1; ((waited++))
    printf '\r  associating... %ds/%ds' "$waited" "$TIMEOUT"
    if ((waited >= TIMEOUT)); then printf '\r'; return 1; fi
  done
  printf '\r'
  return 0
}

ensure_ip() {
  # For the wpa backend we must bring up DHCP ourselves.
  if [[ "$RESOLVED_BACKEND" == "wpa" ]]; then
    wpa_start_dhcp
    local waited=0
    until ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet "; do
      sleep 1; ((waited++))
      ((waited >= 15)) && break
    done
  fi
}

test_connectivity() {
  ping -c "$PING_COUNT" -W 2 "$PING_HOST" >/dev/null 2>&1
}

network_info() {
  local ip gw dns
  ip="$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' || true)"
  gw="$(ip route 2>/dev/null | awk -v d="$IFACE" '/^default/ && $0 ~ d {print $3; exit}' || true)"
  dns="$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, - || true)"
  echo "IP=${ip:-?} GW=${gw:-?} DNS=${dns:-?}"
}

do_scan() {
  $SCAN_NETWORK || return 0
  have nmap || return 0
  highlight "Running light network recon (nmap -sn)..."
  local net
  net="$(ip -4 route 2>/dev/null | awk -v d="$IFACE" '$0 ~ d && $1 ~ /\// && $1 !~ /default/ {print $1; exit}' || true)"
  if [[ -n "$net" ]]; then
    info "Host discovery on $net"
    nmap -sn "$net" 2>/dev/null | grep -E "Nmap scan report|MAC Address" | tee -a "$LOG_FILE" || true
  else
    warn "Could not determine local subnet for scan."
  fi
}

store_success() {
  local mac="$1"
  mkdir -p "$(dirname "$STORE_FILE")" 2>/dev/null || true
  printf '%s  IFACE=%s  SSID=%s  MAC=%s  [%s]\n' \
    "$(date -Is 2>/dev/null || date)" "$IFACE" "$SSID" "$mac" "$(network_info)" \
    >>"$STORE_FILE" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------------
html_escape() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

generate_report() {
  $GENERATE_REPORT || return 0
  local when outcome_block
  when="$(date 2>/dev/null || true)"

  if [[ -n "$SUCCESS_MAC" ]]; then
    outcome_block="<div class='vuln'><strong>&#9888; MAC-based access control bypassed.</strong>
      The target network was reached using a spoofed MAC, so MAC filtering (if any)
      is not an effective control.</div>"
  else
    outcome_block="<div class='ok'><strong>&#10004; No unauthorized access.</strong>
      MAC rotation did not yield a connection within the configured attempts.</div>"
  fi

  {
    cat <<HEAD
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFoxy Assessment Report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, Arial, sans-serif; margin: 0; background: #f4f5f7; color: #1a1a1a; }
  .wrap { max-width: 900px; margin: 24px auto; background: #fff; border-radius: 10px;
          box-shadow: 0 2px 16px rgba(0,0,0,.08); overflow: hidden; }
  header { background: #1f2d3d; color: #fff; padding: 24px; }
  header h1 { margin: 0 0 6px; font-size: 1.4rem; }
  .pad { padding: 20px 24px; }
  .vuln { background: #fdecea; border-left: 4px solid #e74c3c; padding: 14px; border-radius: 4px; margin: 12px 0; }
  .ok   { background: #eafaf1; border-left: 4px solid #27ae60; padding: 14px; border-radius: 4px; margin: 12px 0; }
  .rec  { background: #eaf2fb; border-left: 4px solid #3498db; padding: 14px; border-radius: 4px; margin: 10px 0; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th, td { border: 1px solid #ddd; padding: 9px 10px; text-align: left; font-size: .95rem; }
  th { background: #f0f2f5; width: 34%; }
  code { background: #eef0f3; padding: 1px 5px; border-radius: 3px; }
  footer { padding: 16px 24px; font-size: .85rem; color: #666; border-top: 1px solid #eee; }
  @media (prefers-color-scheme: dark) {
    body { background: #14181d; color: #e6e6e6; }
    .wrap { background: #1c2127; box-shadow: none; }
    th { background: #262c33; } td, th { border-color: #333; } code { background: #262c33; }
    footer { color: #9aa; border-color: #2a2f36; }
  }
</style></head><body><div class="wrap">
<header><h1>&#128272; WiFoxy Wi-Fi Assessment</h1><div>Generated: ${when}</div></header>
<div class="pad">
<h2>Summary</h2>
${outcome_block}
<h2>Parameters</h2>
<table>
  <tr><th>Target SSID</th><td><code>$(printf '%s' "$SSID" | html_escape)</code></td></tr>
  <tr><th>Interface</th><td><code>$(printf '%s' "$IFACE" | html_escape)</code></td></tr>
  <tr><th>Backend</th><td>${RESOLVED_BACKEND}</td></tr>
  <tr><th>MAC strategy</th><td>${STRATEGY}</td></tr>
  <tr><th>Original MAC</th><td><code>$(printf '%s' "$ORIG_MAC" | html_escape)</code></td></tr>
  <tr><th>Authentication</th><td>$([[ -n "$PASS" ]] && echo "Password-protected" || echo "Open network")</td></tr>
  <tr><th>Attempts configured</th><td>${RETRIES}</td></tr>
HEAD
    if [[ -n "$SUCCESS_MAC" ]]; then
      cat <<ROW
  <tr><th>Spoofed MAC used</th><td><code>$(printf '%s' "$SUCCESS_MAC" | html_escape)</code></td></tr>
  <tr><th>Winning attempt</th><td>${USED_ATTEMPT} of ${RETRIES}</td></tr>
  <tr><th>Time to connect</th><td>${CONNECT_SECONDS}s</td></tr>
  <tr><th>Network</th><td><code>$(network_info | html_escape)</code></td></tr>
ROW
    fi
    cat <<TAIL
</table>
<h2>Recommendations</h2>
<div class="rec"><strong>Do not rely on MAC filtering.</strong> It is trivially bypassed; treat it as inventory, not security.</div>
<div class="rec"><strong>Use 802.1X / WPA2-Enterprise</strong> (EAP-TLS or PEAP) so access depends on credentials, not hardware addresses.</div>
<div class="rec"><strong>Segment the network</strong> with VLANs so a connected device cannot reach sensitive resources.</div>
<div class="rec"><strong>Monitor</strong> for rapid MAC changes and duplicate-MAC association anomalies.</div>
</div>
<footer>WiFoxy &middot; for authorized testing only &middot; log: <code>$(printf '%s' "$LOG_FILE" | html_escape)</code></footer>
</div></body></html>
TAIL
  } >"$REPORT_FILE" 2>/dev/null \
    && success "Report written: $REPORT_FILE" \
    || warn "Could not write report to $REPORT_FILE"
}

# ----------------------------------------------------------------------------
# Cleanup / signal handling
# ----------------------------------------------------------------------------
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  [[ "$RESOLVED_BACKEND" == "wpa" ]] && wpa_cleanup
  leave_monitor
  restore_mac
  # Hand the device back to NetworkManager if that's how we found it.
  if have nmcli && [[ "$ORIG_NM_MANAGED" == "yes" ]]; then
    nmcli dev set "$IFACE" managed yes >/dev/null 2>&1 || true
  fi
  generate_report
  [[ -n "$TMP_WORK" && -d "$TMP_WORK" ]] && rm -rf "$TMP_WORK" 2>/dev/null || true
  exit "$rc"
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  parse_args "$@"
  : >"$LOG_FILE" 2>/dev/null || true

  need_root
  detect_iface
  check_iface
  resolve_backend
  check_deps

  TMP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/wifoxy.XXXXXX")"
  get_orig_mac
  trap cleanup EXIT INT TERM

  highlight "WiFoxy - target '$SSID' on $IFACE via $RESOLVED_BACKEND (strategy: $STRATEGY)"
  [[ -n "$PASS"  ]] && info "Auth: password-protected" || warn "Auth: open network"
  [[ -n "$BSSID" ]] && info "Preferred BSSID: $BSSID"

  # Harvest client MACs up front if requested.
  if [[ "$STRATEGY" == "clients" ]]; then
    harvest_client_macs || true
  fi

  local attempt=1
  while ((attempt <= RETRIES)); do
    echo
    highlight "Attempt $attempt/$RETRIES"
    backend_disconnect

    local mac; mac="$(next_mac "$attempt")"
    if ! set_mac "$mac"; then
      warn "Skipping attempt (MAC change failed)."
      ((attempt++)); continue
    fi

    local start; start="$(date +%s)"
    if backend_connect && wait_for_link; then
      ensure_ip
      if backend_is_connected; then
        CONNECT_SECONDS=$(( $(date +%s) - start ))
        USED_ATTEMPT=$attempt
        success "Associated with '$SSID' using $mac (${CONNECT_SECONDS}s)"
        info "$(network_info)"
        if test_connectivity; then
          success "Internet reachable (ping $PING_HOST OK)."
          SUCCESS_MAC="$mac"
          store_success "$mac"
          do_scan
          highlight "Connected. ${KEEP_MAC:+Spoofed MAC will stay active.}"
          exit 0
        else
          warn "Associated but no internet (captive portal or isolation?)."
          SUCCESS_MAC="$mac"
          store_success "$mac"
          exit 0
        fi
      fi
    fi

    warn "Attempt $attempt failed."
    ((attempt++))
    sleep 1
  done

  error "No connection after $RETRIES attempts. Network may have working access controls."
  exit 2
}

main "$@"
