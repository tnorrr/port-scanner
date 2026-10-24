"""Multithreaded TCP port scanner with banner grabbing and JSON/CSV export."""

import argparse
import csv
import errno
import ipaddress
import json
import re
import select
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

MAX_PORT = 65535
MAX_WORKERS = 1000

# Where the disclaimer acceptance is saved (your user folder, e.g. C:\Users\<you>\.portscanner.json).
CONFIG_PATH = Path.home() / ".portscanner.json"

DISCLAIMER = (
    "Port scanning can be illegal or disruptive if done without permission.\n"
    "Only scan systems you own or have written permission to test.\n"
    "You are responsible for how you use this tool."
)

# Lookup table: port number -> usual service name.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# Ports ordered from most to least commonly open. --top-ports N scans the first N.
TOP_PORTS = [
    80, 443, 22, 21, 23, 25, 53, 110, 143, 445, 139, 135, 3389, 8080, 3306,
    5432, 1433, 1723, 111, 995, 993, 587, 8443, 8000, 8888, 5900, 1025, 990,
    88, 389, 636, 1521, 2049, 5060, 5061, 6379, 27017, 9200, 9000, 8008, 548,
    631, 1900, 5000, 5353, 161, 162, 69, 514, 515, 3000, 4443, 1883, 8883,
    11211, 5672, 50000,
]

# Ports that get an HTTP request sent to them when they stay silent.
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n"

# Error codes meaning "no answer" (filtered), as opposed to an active refusal (closed).
FILTERED_ERRORS = {
    errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK,
    errno.EHOSTUNREACH, errno.ENETUNREACH,
    # Winsock codes, used on Windows. Python's errno names do not match these.
    10035,  # WSAEWOULDBLOCK: connect is still pending when the timeout expires
    10051,  # WSAENETUNREACH
    10060,  # WSAETIMEDOUT
    10065,  # WSAEHOSTUNREACH
}

# Codes meaning "connection still in progress" (Linux and Windows). The real result comes later.
PENDING_ERRORS = {errno.EINPROGRESS, errno.EAGAIN, errno.EWOULDBLOCK, 10035, 10036}

# Matches ANSI terminal escape sequences such as colour codes (ESC [ 31 m).
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Names the likely service for a port number.
def guess_service(port):
    return COMMON_PORTS.get(port, "Unknown")

# Cleans text from the network so it can't mess with your terminal.
def sanitize(text):
    """Remove terminal escape sequences, then keep printable ASCII only."""
    text = ANSI_ESCAPE.sub("", text)
    return re.sub(r"[^\x20-\x7E]", "", text)[:200]

# Turns '80', '1-1000' or '22,80,8000-8100' into a sorted list of ports, and rejects bad input.
def parse_ports(spec):
    """Turn '80', '1-1000' or '22,80,8000-8100' into a sorted list of ports, or raise ValueError."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        try:
            if "-" in part:
                start_text, end_text = part.split("-")
            else:
                start_text = end_text = part
            start, end = int(start_text), int(end_text)
        except ValueError:
            raise ValueError(
                f"Invalid port spec '{spec}'. Use ports like 80, ranges like 1-1000, "
                "or a comma-separated mix such as 22,80,8000-8100."
            )
        if not (1 <= start <= end <= MAX_PORT):
            raise ValueError(f"Ports must satisfy 1 <= start <= end <= {MAX_PORT} (got {start}-{end}).")
        ports.update(range(start, end + 1))
    return sorted(ports)

# Turns a hostname into an IP address.
def resolve_target(target):
    """Accept an IP address or hostname and return the first address found (IPv4 or IPv6)."""
    try:
        info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve '{target}'. Check the spelling or your DNS.")
    return info[0][4][0]


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

# Checks ONE port: connects, and records whether it is open, closed or filtered.
def scan_port(target_ip, port, timeout=1, delay=0):
    """Return a dict with the port's state ('open', 'closed' or 'filtered') and, if open, its service and banner."""
    if delay:
        time.sleep(delay)
    family = socket.AF_INET6 if ipaddress.ip_address(target_ip).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        err = sock.connect_ex((target_ip, port))
        if err in PENDING_ERRORS:
            # Still connecting. Wait for the outcome, then read the real result from the socket.
            _, writable, failed = select.select([], [sock], [sock], timeout)
            if writable or failed:
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            else:
                err = errno.ETIMEDOUT  # nothing came back before the timeout
        if err != 0:
            state = "filtered" if err in FILTERED_ERRORS else "closed"
            return {"port": port, "state": state, "service": None, "banner": None}
        try:
            banner = sanitize(sock.recv(1024).decode(errors="ignore")).strip()
        except OSError:
            banner = ""
        if not banner and port in HTTP_PORTS:
            # Web servers wait for the client to speak first, so send a small request.
            try:
                sock.sendall(HTTP_PROBE)
                reply = sock.recv(2048).decode(errors="ignore")
                server = re.search(r"^Server:\s*(.+)$", reply, re.MULTILINE | re.IGNORECASE)
                if server:
                    banner = f"HTTP Server: {sanitize(server.group(1)).strip()}"
                else:
                    banner = sanitize(reply.split("\r\n")[0]).strip()
            except OSError:
                banner = ""
    return {"port": port, "state": "open", "service": guess_service(port), "banner": banner or None}

# Runs scan_port on every port at once using a thread pool, and collects the results.
def scan_ports(target_ip, ports, max_workers=100, timeout=1, delay=0):
    """Scan every port in `ports`. Returns (results, interrupted), where results are dicts sorted by port."""
    interrupted = False
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout, delay) for port in ports]
        try:
            for future in tqdm(futures, desc="Scanning", unit="port"):
                future.result()
        except KeyboardInterrupt:
            interrupted = True
            for future in futures:
                future.cancel()
    # The executor has finished its running tasks by now. Keep everything that completed.
    results = [f.result() for f in futures if f.done() and not f.cancelled()]
    return sorted(results, key=lambda r: r["port"]), interrupted

# Writes the results to a JSON or CSV file.
def save_results(results, meta, filename):
    """Write open-port results plus target and timestamp, so the file describes itself."""
    fmt = check_output_name(filename)
    if fmt == "json":
        data = {**meta, "open_ports": {
            str(r["port"]): {"service": r["service"], "banner": r["banner"]} for r in results
        }}
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "scanned_at", "port", "service", "banner"])
            # Write one row for every open port.
            for r in results:
                writer.writerow([meta["target"], meta["scanned_at"], r["port"],
                                 r["service"], r["banner"] or ""])

# Shows the usage disclaimer once and saves that the user accepted it.
def disclaimer_accepted():
    """True if the user has accepted the disclaimer before."""
    try:
        return json.loads(CONFIG_PATH.read_text()).get("disclaimer_accepted") is True
    except (OSError, ValueError):
        return False

# Asks the user to accept the disclaimer before the first scan, or exits.
def require_disclaimer(accept_flag):
    """Show the disclaimer and record acceptance. Exits if the user declines."""
    if accept_flag or disclaimer_accepted():
        return
    if not sys.stdin.isatty():
        raise SystemExit("Disclaimer not accepted. Run once in a terminal, or pass --accept-disclaimer.")
    print(DISCLAIMER)
    try:
        answer = input("Type 'yes' to accept and continue: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "yes":
        raise SystemExit("Disclaimer not accepted. Nothing was scanned.")
    CONFIG_PATH.write_text(json.dumps({"disclaimer_accepted": True}))

# Runs the whole program: read options, validate, scan, print, save.
def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner with banner grabbing.")
    parser.add_argument("target", help="IP address or hostname to scan")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports",
                       help="Ports to scan, e.g. 80, 1-1000 or 22,80,8000-8100 (default: 1-1000)")
    group.add_argument("--top-ports", type=int, metavar="N",
                       help=f"Scan the N most common ports (1-{len(TOP_PORTS)})")
    parser.add_argument("-o", "--output", help="Save results to a .json or .csv file")
    parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help=f"Number of parallel connections (1-{MAX_WORKERS}, default: 100)")
    parser.add_argument("-d", "--delay", type=float, default=0,
                        help="Seconds to wait before each connection (default: 0)")
    parser.add_argument("--allow-public", action="store_true",
                        help="Allow non-private targets. Only use on systems you own or have written permission to scan.")
    parser.add_argument("--accept-disclaimer", action="store_true",
                        help="Accept the usage disclaimer without prompting (for scripts)")
    args = parser.parse_args()

    # Show the disclaimer first time, or skip it when the flag is given.
    require_disclaimer(args.accept_disclaimer)

    # Validate everything BEFORE scanning, so mistakes fail in milliseconds, not minutes.
    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than 0.")
        if not 1 <= args.workers <= MAX_WORKERS:
            raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}.")
        if args.delay < 0:
            raise ValueError("Delay cannot be negative.")
        target_ip = resolve_target(args.target)
        if args.top_ports is not None:
            if not 1 <= args.top_ports <= len(TOP_PORTS):
                raise ValueError(f"--top-ports must be between 1 and {len(TOP_PORTS)}.")
            ports, label = sorted(TOP_PORTS[:args.top_ports]), f"top {args.top_ports} ports"
        else:
            spec = args.ports or "1-1000"
            ports, label = parse_ports(spec), spec
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
    # Run the scan. Ctrl+C stops it early but keeps the results found so far.
    results, interrupted = scan_ports(target_ip, ports, max_workers=args.workers,
                                      timeout=args.timeout, delay=args.delay)
    elapsed = time.perf_counter() - started

    open_results = [r for r in results if r["state"] == "open"]
    closed = sum(r["state"] == "closed" for r in results)
    filtered = sum(r["state"] == "filtered" for r in results)

    # Print the output for every open port.
    for r in open_results:
        print(f"Port {r['port']}: OPEN ({r['service']}) \u2014 {r['banner'] or 'no banner'}")
    if not open_results:
        print("No open ports found.")
    if interrupted:
        print(f"\nScan interrupted after {len(results)} ports. Saving partial results.")
    print(f"\nScanned {len(results)} ports in {elapsed:.1f}s: "
          f"{len(open_results)} open, {closed} closed, {filtered} filtered.")

    # Save to a file if asked.
    if args.output:
        meta = {
            "target": args.target,
            "resolved_ip": target_ip,
            "ports": label,
            "scanned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "duration_seconds": round(elapsed, 1),
            "interrupted": interrupted,
        }
        try:
            save_results(open_results, meta, args.output)
        except OSError as err:
            print(f"Could not save results: {err}")
            return 1
        print(f"Results saved to {args.output}")
    return 130 if interrupted else 0


# Starts the program only when this file is run directly.
if __name__ == "__main__":
    # Run main() and hand its exit code to the operating system.
    raise SystemExit(main())