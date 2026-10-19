
import argparse
import subprocess
import xml.etree.ElementTree as ET
import csv
import ipaddress
import socket
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path


DEFAULT_PORTS = [22, 80, 443, 3306, 8080]


def is_valid_target(host):
    """Accept IP addresses and hostnames that resolve successfully."""
    host = host.strip()

    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    hostname = host[:-1] if host.endswith(".") else host

    if not hostname or len(hostname) > 253:
        return False

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or not all(
                character.isalnum() or character == "-"
                for character in label
            )
        ):
            return False

    try:
        socket.getaddrinfo(hostname, None)
        return True
    except (socket.gaierror, OSError):
        return False


def parse_ports(port_text):
    """Parse and validate comma-separated TCP port numbers."""
    try:
        parts = port_text.split(",")

        if not parts or any(not part.strip() for part in parts):
            raise ValueError

        ports = [int(part.strip()) for part in parts]

        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError

        if len(ports) != len(set(ports)):
            raise ValueError

        return ports

    except (ValueError, AttributeError):
        raise ValueError(
            "Ports must be unique integers between 1 and 65535, "
            "separated by commas, e.g. 22,80,443."
        )


def parse_nmap_xml(xml_text, host, timestamp):
    """Extract port and service information from Nmap XML."""
    root = ET.fromstring(xml_text)
    rows = []

    for port in root.findall(".//port"):
        state_element = port.find("state")
        service_element = port.find("service")

        state = (
            state_element.get("state", "unknown")
            if state_element is not None
            else "unknown"
        )

        service_name = (
            service_element.get("name", "unknown")
            if service_element is not None
            else "unknown"
        )

        product = ""
        version = ""

        if service_element is not None:
            product = service_element.get("product", "")
            version = service_element.get("version", "")

        rows.append({
            "timestamp": timestamp,
            "target": host,
            "protocol": port.get("protocol", ""),
            "port": port.get("portid", ""),
            "state": state,
            "service": service_name,
            "product": product,
            "version": version
        })

    return rows


def print_scan_summary(host, ports, rows):
    """Display counts of port states from the scan results."""
    counts = Counter(
        row["state"].lower()
        for row in rows
    )

    open_count = counts["open"]
    closed_count = counts["closed"]
    filtered_count = counts["filtered"]
    other_count = len(rows) - open_count - closed_count - filtered_count

    print("\nSCAN SUMMARY")
    print("-" * 65)
    print(f"Target: {host}")
    print(f"Ports requested: {len(ports)}")
    print(f"Port results returned: {len(rows)}")
    print(f"Open ports: {open_count}")
    print(f"Closed ports: {closed_count}")
    print(f"Filtered ports: {filtered_count}")
    print(f"Other states: {other_count}")


def scan_host(host, ports):
    """Run Nmap and save XML and CSV reports."""
    now = datetime.now().astimezone()
    timestamp = now.isoformat(timespec="seconds")
    file_timestamp = now.strftime("%Y%m%d_%H%M%S")

    xml_file = Path(f"scan_report_{file_timestamp}.xml")
    csv_file = Path(f"scan_report_{file_timestamp}.csv")

    print(f"\nScanning {host} with Nmap...")
    print(f"Ports: {','.join(str(port) for port in ports)}")
    print(f"Started at: {timestamp}\n")

    command = [
        "nmap",
        "-sV",
        "-p", ",".join(str(port) for port in ports),
        "-oX", "-",
        host
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )
    except FileNotFoundError:
        print("Nmap executable was not found.")
        print("Install Nmap or check that it is in PATH.")
        return
    except subprocess.TimeoutExpired:
        print("Scan timed out after 60 seconds.")
        return
    except OSError as error:
        print(f"Could not start Nmap: {error}")
        return

    if result.returncode != 0:
        print("Nmap scan failed:")
        print(result.stderr.strip() or "No error details provided.")
        return

    try:
        rows = parse_nmap_xml(result.stdout, host, timestamp)
    except ET.ParseError as error:
        print(f"Could not parse Nmap XML output: {error}")
        return

    fieldnames = [
        "timestamp",
        "target",
        "protocol",
        "port",
        "state",
        "service",
        "product",
        "version"
    ]

    temp_xml = None
    temp_csv = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=".",
            prefix=".scan_xml_",
            suffix=".tmp",
            delete=False
        ) as report:
            temp_xml = Path(report.name)
            report.write(result.stdout)

        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=".",
            prefix=".scan_csv_",
            suffix=".tmp",
            delete=False
        ) as report:
            temp_csv = Path(report.name)
            writer = csv.DictWriter(report, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        temp_xml.replace(xml_file)
        temp_xml = None

        temp_csv.replace(csv_file)
        temp_csv = None

    except (OSError, csv.Error) as error:
        print(f"Could not save scan reports: {error}")
        return

    finally:
        for temp_file in (temp_xml, temp_csv):
            if temp_file is not None:
                try:
                    temp_file.unlink(missing_ok=True)
                except OSError:
                    pass

    print("PORT SCAN RESULTS")
    print("-" * 65)

    if not rows:
        print("No port information was returned.")

    for row in rows:
        print(
            f"{row['protocol']}/{row['port']}: "
            f"{row['state']} | "
            f"Service: {row['service']} | "
            f"Product: {row['product']} | "
            f"Version: {row['version']}"
        )

    print_scan_summary(host, ports, rows)

    print("\nScan complete.")
    print(f"XML report: {xml_file}")
    print(f"CSV report: {csv_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan authorized targets using Nmap."
    )

    parser.add_argument(
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help="Comma-separated TCP ports (default: 22,80,443,3306,8080)"
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    host = input(
        "Enter an IP address or authorized hostname: "
    ).strip()

    if not is_valid_target(host):
        print("Invalid target or hostname could not be resolved.")
        return

    scan_host(host, ports)


if __name__ == "__main__":
    main()
