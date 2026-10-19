
import argparse
import subprocess
import xml.etree.ElementTree as ET
import csv
import ipaddress
import socket
import tempfile
from datetime import datetime
from pathlib import Path


DEFAULT_PORTS = [22, 80, 443, 3306, 8080]


def is_valid_target(host):
    """Accept IP addresses and hostnames that resolve successfully."""
    host = host.strip()

    if not host:
        return False

    # Accept valid IPv4 and IPv6 addresses.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Remove an optional trailing dot from a hostname.
    hostname = host[:-1] if host.endswith(".") else host

    if not hostname or len(hostname) > 253:
        return False

    # Validate hostname labels.
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

    # Accept only if the hostname resolves.
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

    # Run Nmap and handle process execution errors.
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

    # Parse Nmap XML independently so it can be unit-tested.
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

    # Prepare both reports in temporary files first.
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

        # Publish reports after both temporary files are ready.
        temp_xml.replace(xml_file)
        temp_xml = None

        temp_csv.replace(csv_file)
        temp_csv = None

    except (OSError, csv.Error) as error:
        print(f"Could not save scan reports: {error}")
        return

    finally:
        # Clean up temporary files that were not published.
        for temp_file in (temp_xml, temp_csv):
            if temp_file is not None:
                try:
                    temp_file.unlink(missing_ok=True)
                except OSError:
                    pass

    # Display results after reports are saved.
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

    print("\nScan complete.")
    print(f"Ports recorded: {len(rows)}")
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
