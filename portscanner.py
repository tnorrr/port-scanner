import socket
import threading
import argparse
import json
import csv
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

open_ports = {}
lock = threading.Lock()

def grab_banner(target_ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else "No banner"
    except Exception:
        return "No banner"
    
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

def guess_service(port):
    return COMMON_PORTS.get(port, "Unknown")

def scan_port(target_ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target_ip, port))
    sock.close()
    if result == 0:
        banner = grab_banner(target_ip, port)
        if banner == "No banner":
            banner = f"No banner (likely {guess_service(port)})"
        with lock:
            open_ports[port] = banner

def scan_range_threaded(target_ip, start_port, end_port, max_workers=100, timeout=1):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port, timeout)
            for port in range(start_port, end_port + 1)
        ]
        for future in tqdm(futures, desc="Scanning", unit="port"):
            future.result()
    return dict(sorted(open_ports.items()))

def save_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def save_csv(results, filename):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Banner"])
        for port, banner in results.items():
            writer.writerow([port, banner])
def main():
    parser = argparse.ArgumentParser(description="A simple Python port scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range, e.g. 1-1000")
    parser.add_argument("-o", "--output", help="Save results to a file (json or csv)")
    parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    print(f"Scanning {args.target} ports {start_port}-{end_port}...")

    results = scan_range_threaded(args.target, start_port, end_port)
    results = scan_range_threaded(args.target, start_port, end_port, timeout=args.timeout)

    for port, banner in results.items():
        print(f"Port {port}: OPEN — {banner}")
        
    print(f"\nFound {len(results)} open ports.")
    if args.output:
        if args.output.endswith(".json"):
         save_json(results, args.output)
        elif args.output.endswith(".csv"):
            save_csv(results, args.output)
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()