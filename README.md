# Python Port Scanner

A multithreaded TCP port scanner I built from scratch in Python, with banner grabbing and JSON/CSV export. No third-party scanning libraries. Just the standard library's `socket` and `threading` modules doing the real work, plus `tqdm` for a progress bar.

## What This Is

I built this to actually understand how tools like `nmap` work under the hood, instead of just using them as a black box. It attempts a real TCP connection to each port in a range, times how that goes, and reads whatever the service on the other end says about itself once connected.

## Features

- Multithreaded scanning with a capped worker pool, so it won't spawn thousands of raw threads at once
- Banner grabbing on open ports, with a fallback guess based on common port numbers when a service doesn't respond with anything
- Configurable connection timeout
- A real command-line interface built with `argparse`, so I'm not editing the script every time I want to scan something different
- A progress bar so a long scan doesn't look frozen
- JSON and CSV export
- Installable as an actual CLI tool (`pip install -e .`), so it runs from anywhere as `portscan`

## Usage

Run directly:
```bash
python portscanner.py <target> -p <port-range> -o <output-file>
```

Or, once installed with `pip install -e .`:
```bash
portscan <target> -p <port-range> -o <output-file>
```

**Examples:**
```bash
# Scan the first 1000 ports on localhost
portscan 127.0.0.1 -p 1-1000

# Scan a wider range, save results as JSON, and use a shorter timeout
portscan 192.168.1.10 -p 1-9000 -o results.json -t 0.5

# Save as CSV instead
portscan 192.168.1.10 -p 1-1000 -o results.csv
```

## Sample Output

I ran this against my own hardened home server (see my [Linux Server Lab](https://github.com/yourusername/linux-server-lab) project). Every open port matched a service I set up on purpose, and everything else came back closed, which was a good confirmation that the server's firewall was doing exactly what I configured it to do:

```
Scanning [target-ip] ports 1-9000...
Port 53: OPEN — No banner (likely DNS)
Port 2222: OPEN — SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.6
Port 80: OPEN — No banner (likely HTTP)
Port 3000: OPEN — No banner (likely Unknown)
Port 3001: OPEN — No banner (likely Unknown)
Port 8090: OPEN — No banner (likely Unknown)
Port 8080: OPEN — No banner (likely HTTP-alt)
Port 8096: OPEN — No banner (likely Unknown)
Port 8181: OPEN — No banner (likely Unknown)
Port 8443: OPEN — No banner (likely HTTPS-alt)

Found 10 open ports.
Results saved to laptop_scan.json
```

SSH's banner came through right away since OpenSSH announces itself the moment you connect. Most of the web-facing ports show a guessed service instead of a real banner, since HTTP and HTTPS services generally wait for an actual request before they say anything. That gap is exactly what the service-guessing fallback was built to soften.

## What This Demonstrates

- Socket programming, using `socket.connect_ex` to check ports without raising exceptions on every failed connection
- Real concurrency, using a `ThreadPoolExecutor` with a capped worker count instead of spawning an unbounded number of raw threads
- CLI design with `argparse`
- Structured data export in both JSON and CSV
- Packaging a script as an actual installable command-line tool
- Real-world validation against a server I personally hardened, which confirmed the firewall rules were behaving exactly as intended

## Stretch Goals

I started with a working scanner and pushed it further with five improvements. Here's what changed and why, roughly in the order I built them.

### 1. A capped thread pool instead of raw threads

The first version of this scanner spawned one raw thread per port. That's fine for a small range, but scanning the full 65535-port range would have spawned 65,535 threads all at once. That's rude network behavior that can look like a denial-of-service attempt, and it can also crash a machine's own thread limits.

I replaced the raw threading with `concurrent.futures.ThreadPoolExecutor`, capped at 100 workers:
```python
from concurrent.futures import ThreadPoolExecutor

def scan_range_threaded(target_ip, start_port, end_port, max_workers=100, timeout=1):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port, timeout)
            for port in range(start_port, end_port + 1)
        ]
        for future in tqdm(futures, desc="Scanning", unit="port"):
            future.result()
    return dict(sorted(open_ports.items()))
```
No matter how big the port range is, at most 100 connections happen at once.

### 2. A configurable timeout

The connection timeout used to be hardcoded at one second per port. That's overly cautious on a fast local network and slows scans down for no reason, so I exposed it as a CLI flag instead:
```python
parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
```
Now `-t 0.5` runs a noticeably faster scan against something on the same network, while the default stays safe for less predictable targets.

### 3. Service-name guessing as a banner fallback

Web services usually don't send anything the moment you connect, they wait for an actual HTTP request first. That meant a lot of my open ports were coming back with an unhelpful "No banner." I added a lookup table of common ports so the scanner at least makes a reasonable guess when the real banner comes back empty:
```python
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

def guess_service(port):
    return COMMON_PORTS.get(port, "Unknown")
```
You can see this working in the sample output above, where port 80 now shows `No banner (likely HTTP)` instead of a bare, uninformative "No banner."

### 4. A progress bar

A scan across a large port range with no output for a while looks frozen even when it's working fine, so I added `tqdm` around the scan loop. One tradeoff worth mentioning: printing each port as it's found used to interrupt the progress bar's live updates, so I moved the results printing out of the scanning function entirely and into `main()`, after the scan finishes:
```python
for port, banner in results.items():
    print(f"Port {port}: OPEN — {banner}")
```
The bar now stays clean while scanning, and all the results print at once right after.

### 5. Packaged as an installable CLI tool

Running this used to mean `cd`-ing into the project folder and typing `python portscanner.py` every time. I added a `setup.py` so it installs like a real command instead:
```python
from setuptools import setup

setup(
    name="portscanner",
    version="1.0.0",
    py_modules=["portscanner"],
    entry_points={
        "console_scripts": [
            "portscan=portscanner:main",
        ],
    },
    python_requires=">=3.8",
)
```
Installed in editable mode with `pip install -e .`, so any changes I make to the code take effect immediately without reinstalling. Now I can run `portscan` from anywhere on my machine instead of needing to be inside the project folder.

## Requirements

Python 3.8 or newer.

```bash
pip install -r requirements.txt
```
This installs `tqdm` for the progress bar. Everything else the scanner uses ships with the standard library.

## Legal Note

Only scan systems you own or have explicit written permission to scan. Scanning networks without authorization is illegal in most places. I built and tested this exclusively against my own home lab server.

## License

MIT, see [LICENSE](./LICENSE).
