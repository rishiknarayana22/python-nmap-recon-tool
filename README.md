# Python + Nmap Network Reconnaissance Tool

A beginner-friendly cybersecurity project that automates Nmap scans using Python and generates structured XML and CSV reports.

## Features

- Runs Nmap through Python's subprocess module
- Scans selected TCP ports
- Detects port states and service information
- Parses Nmap XML output using Python's ElementTree
- Generates XML and CSV reports
- Records scan timestamps

## Technologies Used

- Python 3
- Nmap
- Kali Linux
- XML
- CSV
- Git

## Requirements

- Python 3
- Nmap installed and available in PATH
- Linux terminal or another compatible environment

## Project Structure

```text
network-recon-tool/
├── scanner.py
├── README.md
├── scan_report.xml
└── scan_report.csv
```

## How to Run

1. Install Python 3 and Nmap.
2. Open a terminal in the project directory.
3. Run:

   ```bash
   python3 scanner.py
   ```

4. Enter an IP address or hostname for a system you own or are authorized to test.
5. Review the generated XML and CSV reports.

## How It Works

1. Python starts Nmap using subprocess.
2. Nmap scans the configured TCP ports.
3. Nmap returns XML output.
4. Python parses the XML and extracts port and service information.
5. The program saves the results in XML and CSV formats.

## Learning Outcomes

- Basic network reconnaissance
- TCP port scanning concepts
- Python subprocess automation
- XML parsing
- CSV report generation
- Linux command-line usage

## Disclaimer

This project is intended for educational purposes and authorized security testing only. Scan only systems you own or have explicit permission to test.
