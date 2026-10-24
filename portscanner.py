"""Multithreaded TCP port scanner with banner grabbing and JSON/CSV export."""

import argparse
import csv
import ipaddress
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from tqdm import tqdm

MAX_PORT = 65535

# Lookup table: port number -> usual service name.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# Names the likely service for a port number.
def guess_service(port):
    return COMMON_PORTS.get(port, "Unknown")

# Cleans text from the network so it can't mess with your terminal.
def sanitize(text):
    """Keep printable ASCII only. A hostile service can send terminal escape codes."""
    return re.sub(r"[^\x20-\x7E]", "", text)[:200]

# Turns '80' or '1-1000' into a start and end port, and rejects bad input.
def parse_ports(spec):
    """Turn '80' or '1-1000' into (start, end), or raise ValueError."""
    try:
        if "-" in spec:
            start_text, end_text = spec.split("-")
        else:
            start_text = end_text = spec
        start, end = int(start_text), int(end_text)
    except ValueError:
        raise ValueError(f"Invalid port range '{spec}'. Use a single port (80) or a range (1-1000).")
    if not (1 <= start <= end <= MAX_PORT):
        raise ValueError(f"Ports must satisfy 1 <= start <= end <= {MAX_PORT} (got {start}-{end}).")
    return start, end

# Turns a hostname into an IP address.
def resolve_target(target):
    """Accept an IP address or a hostname and return an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve '{target}'. Check the spelling or your DNS.")


# Checks the target is on your own network.
def is_private_target(ip):
    """True for private, loopback and link-local addresses (your own network)."""
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local

# Checks the output filename is .json or .csv before the scan starts.
def check_output_name(filename):
    """Return 'json' or 'csv', or raise ValueError. Called BEFORE scanning so a typo fails fast."""
    lower = filename.lower()
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".csv"):
        return "csv"
    raise ValueError(f"Unsupported output file '{filename}'. Use a name ending in .json or .csv.")

# Checks ONE port: connects, and reads the banner if it's open.
def scan_port(target_ip, port, timeout=1):
    """Return (port, banner) if the port is open, otherwise None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((target_ip, port)) != 0:
            return None
        try:
            banner = sanitize(sock.recv(1024).decode(errors="ignore")).strip()
        except OSError:
            banner = ""
    if not banner:
        banner = f"No banner (likely {guess_service(port)})"
    return port, banner

# Runs scan_port on every port at once using a thread pool, and collects the open ones.
def scan_ports(target_ip, ports, max_workers=100, timeout=1):
    """Scan every port in `ports` and return {port: banner} for the open ones."""
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout) for port in ports]
        try:
            for future in tqdm(futures, desc="Scanning", unit="port"):
                hit = future.result()
                if hit:
                    results[hit[0]] = hit[1]
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise
    return dict(sorted(results.items()))

# Writes the results to a JSON or CSV file.
def save_results(results, meta, filename):
    """Write results plus target and timestamp, so the file describes itself."""
    fmt = check_output_name(filename)
    if fmt == "json":
        data = {**meta, "open_ports": {str(port): banner for port, banner in results.items()}}
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "scanned_at", "port", "banner"])
            # Print the output for every open port.
            for port, banner in results.items():
                writer.writerow([meta["target"], meta["scanned_at"], port, banner])

# Runs the whole program: read options, validate, scan, print, save.
def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner with banner grabbing.")
    parser.add_argument("target", help="IP address or hostname to scan")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", help="Port or range, e.g. 80 or 1-1000 (default: 1-1000)")
    group.add_argument("--top-ports", action="store_true", help="Scan only the common ports in COMMON_PORTS")
    parser.add_argument("-o", "--output", help="Save results to a .json or .csv file")
    parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
    parser.add_argument("--allow-public", action="store_true",
                        help="Allow non-private targets. Only use on systems you own or have written permission to scan.")
    args = parser.parse_args()

    # Validate everything BEFORE scanning, so mistakes fail in milliseconds, not minutes.
    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        target_ip = resolve_target(args.target)
        if args.top_ports:
            ports, label = sorted(COMMON_PORTS), "common ports"
        else:
            start, end = parse_ports(args.ports or "1-1000")
            ports, label = range(start, end + 1), f"{start}-{end}"
        # Check the output filename now, before scanning.
        if args.output:
            check_output_name(args.output)
        if not args.allow_public and not is_private_target(target_ip):
            raise ValueError(
                f"{target_ip} is not a private or loopback address. Only scan systems you own or have "
                "written permission to scan. If that is you, add --allow-public."
            )
    except ValueError as err:
        parser.error(str(err))

    print(f"Scanning {target_ip} ({args.target}) ports {label}...")
    started = time.perf_counter()
    try:
        # Run the scan.
        results = scan_ports(target_ip, ports, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nScan interrupted. Nothing was saved.")
        return 130
    elapsed = time.perf_counter() - started

    # Print the output for every open port.
    for port, banner in results.items():
        print(f"Port {port}: OPEN \u2014 {banner}")
    if not results:
        print("No open ports found.")
    print(f"\nScanned {len(ports)} ports in {elapsed:.1f}s, {len(results)} open.")

    # Save to a file if asked.
    if args.output:
        meta = {
            "target": args.target,
            "resolved_ip": target_ip,
            "ports": label,
            "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "duration_seconds": round(elapsed, 1),
        }
        try:
            save_results(results, meta, args.output)
        except OSError as err:
            print(f"Could not save results: {err}")
            return 1
        print(f"Results saved to {args.output}")
    return 0


# Starts the program only when this file is run directly.
if __name__ == "__main__":
    # Run main() and hand its exit code to the operating system.
    raise SystemExit(main())