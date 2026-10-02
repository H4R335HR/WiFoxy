# WiFoxy

A single, self-contained Bash tool for **MAC-address rotation and Wi-Fi
association testing**, intended for **authorized security assessments** of
networks you own or have explicit permission to test.

It replaces the earlier `pubFi.sh` / `maxFi.sh` / `maxFi2.sh` scripts with one
robust, portable script.

> ⚠️ **Legal:** Use only on networks you own or are authorized to test.
> Spoofing MACs or connecting to networks without authorization may be illegal.

## What it does

- Rotates the wireless MAC address and tries to associate with a target SSID.
- Verifies real connectivity with a ping check.
- Restores your original MAC and interface state on exit (even on Ctrl-C).
- Optionally runs light `nmap` recon and writes an HTML assessment report.

It does **not** crack WPA/WPA2/WPA3 — for protected networks you must supply the
passphrase. Its purpose is demonstrating that **MAC filtering and MAC-keyed
captive portals are weak controls**.

## Compatibility

- **Backends (auto-detected):** NetworkManager (`nmcli`), or
  `wpa_supplicant` + `iw` + a DHCP client (`dhclient`/`dhcpcd`/`udhcpc`).
- **MAC changing:** `ip link` → `macchanger` → `ifconfig` (first that works).
- **Randomness:** `openssl` or `/dev/urandom`.
- Degrades gracefully when optional tools are missing.

## Requirements

Core: `bash` (4+), `ip`, `ping`, and either `openssl` or `/dev/urandom`.
Plus one backend (NetworkManager **or** wpa_supplicant + iw + a DHCP client).

Optional: `nmap` (`--scan`), `aircrack-ng` (`--strategy clients`),
`macchanger`, `ieee-data` (vendor lookups).

## Usage

```bash
chmod +x wifoxy.sh
sudo ./wifoxy.sh -s "SSID" [options]
```

### Common examples

```bash
# Open network, random MACs, 6 tries, write a report
sudo ./wifoxy.sh -s "Cafe Free WiFi" -r 6 --report

# Use vendor-looking MACs and scan the subnet after connecting
sudo ./wifoxy.sh -s "Guest" -m vendor --scan

# WPA network with a known passphrase and preferred AP
sudo ./wifoxy.sh -s "MyHome" -p "secret" --bssid aa:bb:cc:dd:ee:ff

# Harvest MACs of clients already on the SSID (needs monitor-mode card)
sudo ./wifoxy.sh -s "OpenNet" -m clients -i wlan0
```

### Options

| Option | Description |
|---|---|
| `-s, --ssid` | Target SSID (required) |
| `-i, --iface` | Wireless interface (auto-detected if omitted) |
| `-p, --pass` | WPA/WPA2 passphrase (omit for open networks) |
| `--bssid` | Prefer a specific AP BSSID |
| `-r, --retries` | MAC attempts before giving up (default 5) |
| `-t, --timeout` | Seconds to wait per association (default 25) |
| `-m, --strategy` | `random` \| `vendor` \| `clients` (default `random`) |
| `-b, --backend` | `auto` \| `nm` \| `wpa` (default `auto`) |
| `--ping-host` | Connectivity check target (default `8.8.8.8`) |
| `--scan` | Light `nmap -sn` recon of the subnet |
| `--report` | Write an HTML assessment report |
| `--keep-mac` | Leave the spoofed MAC active on exit |
| `-v, --verbose` | Verbose output |
| `-h, --help` | Help |

## Output

- Log: `/tmp/wifoxy.log`
- Successful connections: `~/.wifoxy_macs`
- HTML report (with `--report`): `/tmp/wifoxy_report.html`
