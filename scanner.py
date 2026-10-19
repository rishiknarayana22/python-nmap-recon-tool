
import subprocess
import xml.etree.ElementTree as ET
import csv
import ipaddress
import socket
from datetime import datetime
from pathlib import Path


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

    # Validate the hostname format.
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

    # Check whether the hostname resolves to an IP address.
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except (socket.gaierror, OSError):
        return False


def scan_host(host):
    """Run Nmap and save XML and CSV reports."""
    now = datetime.now().astimezone()
    timestamp = now.isoformat(timespec="seconds")
    file_timestamp = now.strftime("%Y%m%d_%H%M%S")

    xml_file = Path(f"scan_report_{file_timestamp}.xml")
    csv_file = Path(f"scan_report_{file_timestamp}.csv")

    print(f"\nScanning {host} with Nmap...")
    print(f"Started at: {timestamp}\n")

    command = [
        "nmap",
        "-sV",
        "-p", "22,80,443,3306,8080",
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

        if result.returncode != 0:
            print("Nmap scan failed:")
            print(
                result.stderr.strip()
                or "No error details provided."
            )
            return

        # Parse Nmap's XML output.
        root = ET.fromstring(result.stdout)

        # Save the original XML report.
        xml_file.write_text(result.stdout, encoding="utf-8")

        rows = []

        # Extract information about the scanned ports.
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

        # Define the CSV columns.
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

        # Save the CSV report.
        with csv_file.open(
            "w",
            newline="",
            encoding="utf-8"
        ) as report:
            writer = csv.DictWriter(
                report,
                fieldnames=fieldnames
            )
            writer.writeheader()
            writer.writerows(rows)

        # Display the results.
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

    except FileNotFoundError:
        print("Nmap is not installed or not in PATH.")

    except subprocess.TimeoutExpired:
        print("Scan timed out after 60 seconds.")

    except ET.ParseError:
        print("Could not parse Nmap XML output.")

    except (OSError, csv.Error) as error:
        print(f"File or system error: {error}")


def main():
    host = input(
        "Enter an IP address or authorized hostname: "
    ).strip()

    if not is_valid_target(host):
        print(
            "Invalid target or hostname could not be resolved."
        )
        return

    scan_host(host)


if __name__ == "__main__":
    main()
