
import subprocess
import xml.etree.ElementTree as ET
import csv
import ipaddress
import re
from datetime import datetime
from pathlib import Path


def is_valid_target(host):
    """Validate an IPv4 address, IPv6 address, or hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if not host or len(host) > 253:
        return False

    # Remove a trailing dot used in fully qualified hostnames.
    if host.endswith("."):
        host = host[:-1]

    if not host:
        return False

    labels = host.split(".")

    # Validate each hostname label.
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(
            character.isalnum() or character == "-"
            for character in label
        )
        for label in labels
    )


def scan_host(host):
    # Create a timestamp for this scan and its report filenames.
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
            print(result.stderr.strip() or "No error details provided.")
            return

        # Parse Nmap's XML output.
        root = ET.fromstring(result.stdout)

        # Save the original XML report.
        xml_file.write_text(result.stdout, encoding="utf-8")

        # Extract port and service information.
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

        # Display the scan results.
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
        "Enter your own lab IP or authorized target: "
    ).strip()

    if not is_valid_target(host):
        print("Invalid IP address or hostname.")
        return

    scan_host(host)


if __name__ == "__main__":
    main()

