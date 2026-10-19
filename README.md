
# Python Nmap Network Reconnaissance Tool

A beginner-friendly cybersecurity project that uses Python
to run Nmap service detection scans and export results to XML
and CSV reports.

## Features

- Accepts IP addresses and resolvable hostnames
- Validates target input before scanning
- Uses Nmap service detection (`-sV`)
- Scans TCP ports 22, 80, 443, 3306, and 8080
- Parses Nmap XML output with Python
- Exports timestamped XML and CSV reports
- Handles common scanning and file errors
- Includes automated tests for target validation

## Requirements

- Python 3
- Nmap
- Git (for cloning the repository)

## Installation

Install Nmap on Kali Linux if it is not already installed:

```bash
sudo apt update
sudo apt install nmap
```

Clone the repository:

```bash
git clone https://github.com/rishiknarayana22/python-nmap-recon-tool.git
cd python-nmap-recon-tool
```

## Usage

Run the scanner:

```bash
python3 scanner.py
```

Enter an IP address or hostname when prompted.

The scanner checks TCP ports 22, 80, 443, 3306, and 8080
and attempts to identify services and versions.

## Reports

Each successful scan creates timestamped files similar to:

- `scan_report_YYYYMMDD_HHMMSS.xml`
- `scan_report_YYYYMMDD_HHMMSS.csv`

The reports contain the scan timestamp, target, protocol,
port, state, service name, product, and version where available.

Generated reports are excluded from Git using `.gitignore`.

## Running Tests

Run the automated target-validation tests:

```bash
python3 -m unittest -v test_scanner.py
```

## Limitations

- Only the five configured TCP ports are scanned.
- Service and version detection may be incomplete.
- DNS resolution does not guarantee that a host is reachable.
- A scan may return no port records without indicating a
  programming error.
- This tool is intended for learning and authorized testing.

## Disclaimer

Only scan systems you own or have explicit permission to test.
The user is responsible for complying with applicable laws and
organizational policies.

## Technologies

- Python
- Nmap
- XML parsing
- CSV reporting
- Git and GitHub
- Python unittest
