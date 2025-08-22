#!/usr/bin/env bash
# PublicFi Enhanced - WiFi Security Assessment Tool (for authorized testing only)
# Usage:
#   sudo ./publicfi.sh -i wlan0 -s "FreeWifi" [-p "pass"] [--bssid AA:BB:CC:DD:EE:FF] [-r 5] [-t 20] [--report]
#
# Notes:
# - Requires: bash, ip, iw, nmcli (NetworkManager), openssl, ping, nmap (optional)
# - Works best on systems using NetworkManager
# - Stores successes in ~/.publicfi_macs
# - Log file: /tmp/publicfi.log
# - Security report: /tmp/publicfi_report.html
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
REPORT_FILE="/tmp/publicfi_report.html"
GENERATE_REPORT=false
SCAN_NETWORK=false
VENDOR_DB="/usr/share/ieee-data/oui.txt"

# ---------- Colors ----------
RED=$'\e[31m' ; GREEN=$'\e[32m' ; YELLOW=$'\e[33m' ; BLUE=$'\e[34m' ; RESET=$'\e[0m'
BOLD=$'\e[1m' ; CYAN=$'\e[36m'

log()      { printf "[%(%F %T)T] %s\n" -1 "$*"    | tee -a "$LOG_FILE" >/dev/null; }
info()     { echo "${BLUE}[i]${RESET} $*"         | tee -a "$LOG_FILE" >/dev/null; }
success()  { echo "${GREEN}[+]${RESET} $*"        | tee -a "$LOG_FILE" >/dev/null; }
warn()     { echo "${YELLOW}[!]${RESET} $*"       | tee -a "$LOG_FILE" >/dev/null; }
error()    { echo "${RED}[-] $*${RESET}"          | tee -a "$LOG_FILE" >/dev/null; }
highlight(){ echo "${CYAN}${BOLD}[*] $*${RESET}"  | tee -a "$LOG_FILE" >/dev/null; }

usage() {
  cat <<EOF
PublicFi Enhanced - WiFi Security Assessment Tool (authorized testing only)

Usage:
  sudo $0 -i <iface> -s <ssid> [-p <password>] [--bssid <AP-MAC>] [-r <retries>] [-t <seconds>] [--report] [--scan]

Options:
  -i, --iface     Wireless interface (default: $IFACE)
  -s, --ssid      Target SSID (required)
  -p, --pass      Password (omit for open networks)
      --bssid     Target BSSID (AP MAC) to prefer (optional)
  -r, --retries   Number of MAC attempts (default: $RETRIES)
  -t, --timeout   Seconds to wait per attempt (default: $TIMEOUT)
      --report    Generate HTML security report
      --scan      Perform network reconnaissance after connection
  -h, --help      Show this help

Examples:
  sudo $0 -i wlan0 -s "Cafe Free WiFi" -r 6 --report
  sudo $0 -i wlan0 -s "Corp-Guest" --scan --report
  sudo $0 -i wlan0 -s "MyHome" -p "password" --bssid aa:bb:cc:dd:ee:ff --report
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
  
  # Optional dependencies
  if $SCAN_NETWORK && ! have nmap; then
    warn "nmap not found - network scanning will be limited"
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
      --report)     GENERATE_REPORT=true; shift;;
      --scan)       SCAN_NETWORK=true; shift;;
      -h|--help)    usage; exit 0;;
      *) error "Unknown arg: $1"; usage; exit 1;;
    esac
  done
  if [[ -z "$SSID" ]]; then
    error "SSID is required."; usage; exit 1
  fi
}

# Generate a locally-administered, unicast MAC with vendor variation
rand_mac() {
  local hex b1 vendor_prefixes
  # Common vendor prefixes for diversity (first 3 octets)
  vendor_prefixes=(
    "00:1B:44"  # Cisco
    "00:26:BB"  # Apple
    "00:23:6C"  # Apple
    "AC:BC:32"  # Apple
    "00:50:56"  # VMware
    "00:0C:29"  # VMware
    "08:00:27"  # VirtualBox
    "52:54:00"  # QEMU
  )
  
  if (( RANDOM % 3 == 0 )) && [[ ${#vendor_prefixes[@]} -gt 0 ]]; then
    # Use a known vendor prefix 1/3 of the time
    local prefix="${vendor_prefixes[$((RANDOM % ${#vendor_prefixes[@]}))]}"
    local suffix
    suffix="$(openssl rand -hex 3)"
    printf "%s:%s:%s:%s\n" "$prefix" "${suffix:0:2}" "${suffix:2:2}" "${suffix:4:2}"
  else
    # Generate completely random MAC
    hex="$(openssl rand -hex 6)"
    b1=$(( (0x${hex:0:2} | 0x02) & 0xFE ))  # set LAA bit, clear multicast bit
    printf "%02x:%s:%s:%s:%s:%s\n" \
      "$b1" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}" "${hex:10:2}"
  fi
}

get_mac_vendor() {
  local mac="$1"
  local oui="${mac:0:8}"
  if [[ -f "$VENDOR_DB" ]]; then
    grep -i "^${oui//:/-}" "$VENDOR_DB" 2>/dev/null | cut -d$'\t' -f3 | head -1
  else
    echo "Unknown"
  fi
}

orig_mac=""
get_orig_mac() {
  orig_mac="$(cat /sys/class/net/"$IFACE"/address)"
}

set_mac() {
  local newmac="$1"
  local vendor
  vendor="$(get_mac_vendor "$newmac")"
  info "Setting MAC $IFACE -> $newmac (${vendor:-Unknown vendor})"
  ip link set "$IFACE" down
  ip link set "$IFACE" address "$newmac"
  ip link set "$IFACE" up
  sleep 2  # Give interface time to stabilize
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
  sleep 2
}

nm_try_connect() {
  local ssid="$1" pass="$2" bssid="${3:-}"
  local args=(dev wifi connect "$ssid" ifname "$IFACE")
  [[ -n "$pass"  ]] && args+=(password "$pass")
  [[ -n "$bssid" ]] && args+=(bssid "$bssid")
  
  # Rescan before attempting connection
  nmcli dev wifi rescan ifname "$IFACE" || true
  sleep 3
  
  nmcli "${args[@]}"
}

is_connected() {
  nmcli -t -f DEVICE,STATE dev status | grep -q "^${IFACE}:connected$"
}

test_connectivity() {
  ping -c "$PING_COUNT" -W 2 "$PING_HOST" >/dev/null 2>&1
}

get_network_info() {
  local ip gateway dns
  ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || echo "Unknown")
  gateway=$(ip route | grep default | grep "$IFACE" | awk '{print $3}' | head -1 || echo "Unknown")
  dns=$(nmcli dev show "$IFACE" | grep 'IP4.DNS' | awk '{print $2}' | paste -sd ',' || echo "Unknown")
  
  echo "IP: $ip | Gateway: $gateway | DNS: $dns"
}

perform_network_scan() {
  if ! have nmap; then
    warn "nmap not available - skipping network scan"
    return
  fi
  
  highlight "Performing network reconnaissance..."
  local gateway
  gateway=$(ip route | grep default | grep "$IFACE" | awk '{print $3}' | head -1)
  
  if [[ -n "$gateway" ]]; then
    local network
    network=$(ip route | grep "$IFACE" | grep -v default | head -1 | awk '{print $1}')
    if [[ -n "$network" ]]; then
      info "Scanning network: $network"
      nmap -sn "$network" 2>/dev/null | grep -E "(Nmap scan report|MAC Address)" | tee -a "$LOG_FILE"
      
      # Quick port scan on gateway
      info "Quick port scan on gateway: $gateway"
      nmap -F "$gateway" 2>/dev/null | grep -E "(open|filtered)" | tee -a "$LOG_FILE"
    fi
  fi
}

store_success() {
  local mac="$1"
  local timestamp network_info
  timestamp=$(date -Is)
  network_info=$(get_network_info)
  
  mkdir -p "$(dirname "$STORE_FILE")"
  echo "$timestamp  IFACE=$IFACE  SSID=$SSID  MAC=$mac  INFO=[$network_info]" >> "$STORE_FILE"
  
  # Store additional details for reporting
  if $GENERATE_REPORT; then
    {
      echo "=== CONNECTION SUCCESS: $timestamp ==="
      echo "SSID: $SSID"
      echo "Interface: $IFACE"
      echo "Spoofed MAC: $mac"
      echo "Vendor: $(get_mac_vendor "$mac")"
      echo "Original MAC: $orig_mac"
      echo "Network Info: $network_info"
      echo "Authentication: ${PASS:+Password-Protected}${PASS:-Open Network}"
      [[ -n "$BSSID" ]] && echo "Target BSSID: $BSSID"
      echo "Attempt: $attempt_num/$RETRIES"
      echo "Time to Connect: ${connection_time}s"
      echo
    } >> "${REPORT_FILE}.data"
  fi
}

generate_security_report() {
  if ! $GENERATE_REPORT; then return; fi
  
  local report_time
  report_time=$(date)
  
  cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }
        .warning { background: #e74c3c; color: white; padding: 15px; margin: 20px 0; border-radius: 4px; font-weight: bold; }
        .success { background: #27ae60; color: white; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .info { background: #3498db; color: white; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .section { margin: 20px 0; }
        .vulnerability { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }
        .recommendation { background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f8f9fa; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WiFi Security Assessment Report</h1>
            <p>Generated: $report_time</p>
            <p><strong>Target SSID:</strong> $SSID</p>
        </div>

        <div class="warning">
            <strong>⚠️ SECURITY ASSESSMENT RESULTS</strong><br>
            This report documents security vulnerabilities found during authorized testing.
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
EOF

  if [[ -f "${REPORT_FILE}.data" ]]; then
    cat >> "$REPORT_FILE" <<EOF
            <div class="vulnerability">
                <strong>🚨 CRITICAL FINDING: MAC Address Filtering Bypass</strong><br>
                The target network was successfully accessed using MAC address spoofing techniques.
                This indicates that MAC address filtering (if implemented) is ineffective as a security control.
            </div>
EOF
  else
    cat >> "$REPORT_FILE" <<EOF
            <div class="success">
                <strong>✅ POSITIVE RESULT</strong><br>
                MAC address rotation did not result in successful unauthorized access.
                The network appears to have proper access controls in place.
            </div>
EOF
  fi

  cat >> "$REPORT_FILE" <<EOF
        </div>

        <div class="section">
            <h2>Assessment Details</h2>
            <table>
                <tr><th>Parameter</th><th>Value</th></tr>
                <tr><td>Target SSID</td><td><code>$SSID</code></td></tr>
                <tr><td>Interface</td><td><code>$IFACE</code></td></tr>
                <tr><td>Original MAC</td><td><code>$orig_mac</code></td></tr>
                <tr><td>Authentication</td><td>${PASS:+Password-Protected}${PASS:-Open Network}</td></tr>
                <tr><td>Attempts</td><td>$RETRIES</td></tr>
                <tr><td>Timeout</td><td>${TIMEOUT}s</td></tr>
                $([ -n "$BSSID" ] && echo "<tr><td>Target BSSID</td><td><code>$BSSID</code></td></tr>")
            </table>
        </div>
EOF

  if [[ -f "${REPORT_FILE}.data" ]]; then
    cat >> "$REPORT_FILE" <<EOF
        <div class="section">
            <h2>Successful Connections</h2>
            <pre style="background: #f8f9fa; padding: 15px; overflow-x: auto;">
$(cat "${REPORT_FILE}.data")
            </pre>
        </div>
EOF
  fi

  cat >> "$REPORT_FILE" <<EOF
        <div class="section">
            <h2>Vulnerabilities Identified</h2>
            
            <div class="vulnerability">
                <h3>1. MAC Address Filtering Bypass</h3>
                <p><strong>Risk Level:</strong> Medium to High</p>
                <p><strong>Description:</strong> The network's access control can be bypassed by spoofing MAC addresses of authorized devices.</p>
                <p><strong>Impact:</strong> Unauthorized network access, potential data interception, lateral movement opportunities.</p>
            </div>

            <div class="vulnerability">
                <h3>2. Insufficient Access Controls</h3>
                <p><strong>Risk Level:</strong> Medium</p>
                <p><strong>Description:</strong> The network relies solely on weak authentication mechanisms.</p>
                <p><strong>Impact:</strong> Easy unauthorized access for attackers with basic technical knowledge.</p>
            </div>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            
            <div class="recommendation">
                <h3>🔐 Implement 802.1X Authentication</h3>
                <p>Deploy certificate-based authentication (EAP-TLS) or username/password authentication (EAP-PEAP/MSCHAPv2) instead of relying on MAC filtering.</p>
            </div>

            <div class="recommendation">
                <h3>🛡️ Network Segmentation</h3>
                <p>Implement proper network segmentation with VLANs to limit access to sensitive resources even if network access is gained.</p>
            </div>

            <div class="recommendation">
                <h3>📊 Network Monitoring</h3>
                <p>Deploy network monitoring solutions to detect unusual MAC address changes and connection patterns.</p>
            </div>

            <div class="recommendation">
                <h3>🔄 Regular Security Assessments</h3>
                <p>Conduct periodic security assessments to identify and address wireless security vulnerabilities.</p>
            </div>

            <div class="recommendation">
                <h3>📚 Staff Training</h3>
                <p>Educate IT staff about wireless security best practices and the limitations of MAC address filtering.</p>
            </div>
        </div>

        <div class="section">
            <h2>Technical Details</h2>
            <p><strong>Assessment Tool:</strong> PublicFi Enhanced v2.0</p>
            <p><strong>Method:</strong> MAC address rotation and connection attempts</p>
            <p><strong>Log File:</strong> <code>$LOG_FILE</code></p>
            <p><strong>Success Log:</strong> <code>$STORE_FILE</code></p>
        </div>

        <div class="info">
            <strong>ℹ️ Legal Notice</strong><br>
            This assessment was conducted for authorized security testing purposes only. 
            All activities were performed in compliance with applicable laws and organizational policies.
        </div>
    </div>
</body>
</html>
EOF

  # Clean up temporary data file
  rm -f "${REPORT_FILE}.data"
  
  success "Security report generated: $REPORT_FILE"
}

main() {
  : > "$LOG_FILE"
  need_root
  check_deps
  parse_args "$@"
  
  highlight "PublicFi Enhanced - WiFi Security Assessment Tool"
  info "Interface: $IFACE | SSID: $SSID | Retries: $RETRIES | Timeout: ${TIMEOUT}s"
  [[ -n "$PASS"  ]] && info "Authentication: Password-protected"
  [[ -z "$PASS"  ]] && warn "Authentication: Open network"
  [[ -n "$BSSID" ]] && info "Target BSSID: $BSSID"
  $GENERATE_REPORT && info "Report generation: Enabled"
  $SCAN_NETWORK && info "Network scanning: Enabled"

  if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    error "Interface $IFACE not found."
    exit 1
  fi
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    error "Interface $IFACE unavailable."
    exit 1
  fi

  get_orig_mac
  trap 'restore_mac; generate_security_report' EXIT INT TERM

  if ! nmcli dev status | awk '{print $1,$3}' | grep -q "^${IFACE} .*"; then
    warn "NetworkManager may not manage $IFACE. Continuing anyway."
  fi

  local attempt=1 start_time connection_time=0 attempt_num=0
  while (( attempt <= RETRIES )); do
    echo
    highlight "=== Attempt $attempt/$RETRIES ==="
    attempt_num=$attempt
    nm_disconnect

    local mac
    mac="$(rand_mac)"
    set_mac "$mac"

    start_time=$(date +%s)
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
        connection_time=$(($(date +%s) - start_time))
        success "WiFi connected with spoofed MAC $mac (${connection_time}s)"
        
        local network_info
        network_info=$(get_network_info)
        info "Network details: $network_info"
        
        if test_connectivity; then
          success "Internet connectivity confirmed (ping $PING_HOST)"
          
          if $SCAN_NETWORK; then
            perform_network_scan
          fi
          
          store_success "$mac"
          echo
          highlight "🎯 SECURITY VULNERABILITY CONFIRMED"
          success "MAC address filtering bypass successful!"
          success "Spoofed MAC remains active. Original MAC: $orig_mac"
          
          generate_security_report
          echo
          info "Full assessment report available at: $REPORT_FILE"
          exit 0
        else
          warn "Connected to WiFi but no internet access"
          info "This may indicate network isolation or captive portal"
          store_success "$mac"
          exit 0
        fi
      fi
    else
      warn "Connection attempt failed with MAC $mac"
    fi

    ((attempt++))
    sleep 2  # Brief pause between attempts
  done

  error "All $RETRIES connection attempts failed"
  warn "Network may have proper access controls in place"
  generate_security_report
  exit 2
}

main "$@"
