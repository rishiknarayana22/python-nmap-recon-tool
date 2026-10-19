
import subprocess
import xml.etree.ElementTree as ET
import csv
from datetime import datetime


def scan_host(host):
    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

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
            timeout=60
        )

        if result.returncode != 0:
            print("Nmap scan failed:")
            print(result.stderr)
            return

        # Step 1: Parse Nmap's XML output
        root = ET.fromstring(result.stdout)

        # Step 2: Save the original XML report
        with open(
            "scan_report.xml", "w", encoding="utf-8"
        ) as report:
            report.write(result.stdout)

        # Step 3: Extract port information
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

        # Step 4: Save the CSV report
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

        with open(
            "scan_report.csv",
            "w",
            newline="",
            encoding="utf-8"
        ) as report:
            writer = csv.DictWriter(
                report, fieldnames=fieldnames
            )
            writer.writeheader()
            writer.writerows(rows)

        # Step 5: Display the results
        print("PORT SCAN RESULTS")
        print("-" * 65)

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
        print("XML report: scan_report.xml")
        print("CSV report: scan_report.csv")

    except FileNotFoundError:
        print("Nmap is not installed or not in PATH.")

    except subprocess.TimeoutExpired:
        print("Scan timed out after 60 seconds.")

    except ET.ParseError:
        print("Could not parse Nmap XML output.")

    except OSError as error:
        print(f"File or system error: {error}")


def main():
    host = input(
        "Enter your own lab IP or authorized target: "
    ).strip()

    if not host:
        print("Target cannot be empty.")
        return

    scan_host(host)


if __name__ == "__main__":
    main()

