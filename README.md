# Python Port Scanner

A multithreaded TCP port scanner I built from scratch in Python, with banner grabbing, input validation, a built-in safety guard, and JSON/CSV export. No third-party scanning libraries. Just the standard library's `socket` module doing the real work, plus `tqdm` for a progress bar.

## What This Is

I built this to actually understand how tools like `nmap` work under the hood, instead of just using them as a black box. It attempts a real TCP connection to each port in a range, times how that goes, and reads whatever the service on the other end says about itself once connected.

The first version worked, but it had real problems: a global results dictionary that never reset, banners that went straight to the terminal without any cleaning, and almost no input checking. I rebuilt it from an empty file, one piece at a time, and fixed all of that along the way. The sections below cover what it does now and why.

## Features

- Multithreaded scanning with a capped worker pool, so it won't spawn thousands of raw threads at once
- Banner grabbing on open ports, with a fallback guess based on common port numbers when a service doesn't say anything
- Banner cleaning, so a hostile service can't send terminal escape codes to my screen
- Input validation before any scanning starts: bad port ranges, bad timeouts, unknown hostnames and bad filenames all fail fast with a clear message
- A safety guard that refuses non-private targets unless I pass `--allow-public`
- Hostnames as well as IP addresses
- `--top-ports` to scan only the most common ports
- A real command-line interface built with `argparse`
- A progress bar so a long scan doesn't look frozen
- Clean Ctrl+C handling
- JSON and CSV export that includes the target and a timestamp, so a saved file explains itself
- 19 automated tests that run against a fake local service
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

**Options:**

| Option | What it does |
|---|---|
| `-p`, `--ports` | A single port (`80`) or a range (`1-1000`). Defaults to `1-1000` |
| `--top-ports` | Scan only the common ports instead. Can't be combined with `-p` |
| `-t`, `--timeout` | Connection timeout in seconds. Defaults to `1` |
| `-o`, `--output` | Save results to a `.json` or `.csv` file |
| `--allow-public` | Allow targets outside private networks. Only use on systems you own or have written permission to scan |

**Examples:**
```bash
# Scan the first 1000 ports on localhost
portscan 127.0.0.1 -p 1-1000

# Scan only the common ports on a machine on my network
portscan 192.168.1.10 --top-ports

# Scan a wider range, save results as JSON, and use a shorter timeout
portscan 192.168.1.10 -p 1-9000 -o results.json -t 0.5

# Save as CSV instead
portscan 192.168.1.10 -p 1-1000 -o results.csv
```

## Sample Output

To test it safely, I wrote a tiny fake service that listens on my own computer and sends a banner containing a terminal escape code, the kind of thing a hostile service could send. Then I scanned it:

```
Scanning 127.0.0.1 (localhost) ports 8990-9010...
Port 9000: OPEN — HELLO from fake service [31m

Scanned 21 ports in 0.0s, 1 open.
```

The escape code in the banner (which would normally turn the text red) was stripped out, and only harmless printable characters came through. When a service doesn't say anything, the scanner falls back to a guess based on the port number, like `No banner (likely HTTP)`. HTTP and HTTPS services generally wait for an actual request before they say anything, and that gap is exactly what the service-guessing fallback was built to soften.

A saved JSON file describes the scan it came from:

```json
{
  "target": "localhost",
  "resolved_ip": "127.0.0.1",
  "ports": "8990-9010",
  "scanned_at": "2026-10-24T13:10:53-04:00",
  "duration_seconds": 0.0,
  "open_ports": {
    "9000": "HELLO from fake service [31m"
  }
}
```

I also ran this against my own hardened home server (see my [Linux Server Lab](https://github.com/tnorrr/linux-server-lab) project). Every open port matched a service I set up on purpose, and everything else came back closed, which was a good confirmation that the server's firewall was doing exactly what I configured it to do.

## What This Demonstrates

- Socket programming, using `socket.connect_ex` to check ports without raising an exception on every failed connection
- Real concurrency, using a `ThreadPoolExecutor` with a capped worker count instead of spawning an unbounded number of raw threads
- Treating network data as untrusted input, by stripping banners down to printable characters before they reach the terminal
- Input validation and failing fast, so mistakes show up in milliseconds instead of after a long scan
- Responsible-use design, with a guard against scanning anything that isn't on a private network
- CLI design with `argparse`
- Structured data export in both JSON and CSV
- Writing tests with `pytest`, including a fake local service so nothing real gets scanned
- Packaging a script as an actual installable command-line tool
- Testing against a fake local service, so the scanner can be checked without touching anything real
- Real-world validation against a server I personally hardened, which confirmed the firewall rules were behaving exactly as intended

## Stretch Goals

I started with a working scanner and kept pushing it further. Here's what changed and why, roughly in the order I built them.

### 1. A capped thread pool instead of raw threads

The first version of this scanner spawned one raw thread per port. That's fine for a small range, but scanning the full 65535-port range would have spawned 65,535 threads all at once. That's rude network behavior that can look like a denial-of-service attempt, and it can also crash a machine's own thread limits.

I replaced the raw threading with `concurrent.futures.ThreadPoolExecutor`, capped at 100 workers:
```python
def scan_ports(target_ip, ports, max_workers=100, timeout=1):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, target_ip, port, timeout) for port in ports]
        for future in tqdm(futures, desc="Scanning", unit="port"):
            hit = future.result()
            if hit:
                results[hit[0]] = hit[1]
    return dict(sorted(results.items()))
```
No matter how big the port range is, at most 100 connections happen at once. Port scanning spends almost all its time waiting on the network, and Python releases its global lock while a thread waits, so the threads really do run in parallel where it counts.

### 2. No more global state

The original kept its results in a global dictionary that was never cleared. Scanning twice in one run would have mixed the old results into the new ones. Now `scan_ports` builds a fresh dictionary on every call, and `scan_port` just returns its result instead of writing to something shared. That also made the code much easier to test, and there's a test that proves a second scan doesn't remember the first.

### 3. Cleaning what comes back from the network

A banner is text that the other machine chooses to send me. A hostile service could include terminal escape codes that change colors, move the cursor, or hide text. So every banner is stripped down to printable ASCII and capped at 200 characters before it's shown or saved:
```python
def sanitize(text):
    return re.sub(r"[^\x20-\x7E]", "", text)[:200]
```

### 4. Service-name guessing as a banner fallback

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
The same table powers `--top-ports`, which scans only these ports. You can see the fallback working in the sample output above, where port 80 shows `No banner (likely HTTP)` instead of a bare "No banner."

### 5. Validation and a safety guard

Everything the user types is checked before the first connection is made. Port ranges like `100-50`, `0-99999` or `abc` get a clear error, a timeout of zero is rejected, an unknown hostname is reported, and an output file that doesn't end in `.json` or `.csv` is refused up front, so a typo can't waste a long scan.

The scanner also refuses to scan anything that isn't a private, loopback or link-local address unless I add `--allow-public`:
```python
def is_private_target(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local
```
That won't stop someone determined, but it does stop accidents, like a typo in an IP address, and it's a reminder that I should only scan things I own.

### 6. A configurable timeout

The connection timeout used to be hardcoded at one second per port. That's overly cautious on a fast local network and slows scans down for no reason, so I exposed it as a CLI flag instead:
```python
parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
```
Now `-t 0.5` runs a noticeably faster scan against something on the same network, while the default stays safe for less predictable targets.

### 7. A progress bar

A scan across a large port range with no output for a while looks frozen even when it's working fine, so I added `tqdm` around the scan loop. One tradeoff worth mentioning: printing each port as it's found used to interrupt the progress bar's live updates, so the scanning functions only return data, and `main()` prints the results after the scan finishes:
```python
for port, banner in results.items():
    print(f"Port {port}: OPEN — {banner}")
```
The bar now stays clean while scanning, and all the results print at once right after. Pressing Ctrl+C cancels the queued ports and exits with a short message instead of a wall of errors.

### 8. Self-describing exports

Saved results used to be just a list of ports and banners. A file with no context isn't much use three weeks later, so JSON exports now include the target, the resolved IP, the port range, a timestamp and how long the scan took. CSV exports include the target and timestamp on every row. A failed save reports the error instead of claiming success.

### 9. Automated tests

I wrote 19 tests with `pytest`. They cover port parsing, the private-address check, banner cleaning, the output filename check, and file output. The scan tests start a tiny fake service on a free localhost port, so I can check banner capture and escape-code stripping without touching anything real.

### 10. Packaged as an installable CLI tool

Running this used to mean `cd`-ing into the project folder and typing `python portscanner.py` every time. I added a `setup.py` so it installs like a real command instead:
```python
from setuptools import setup

setup(
    name="portscanner",
    version="1.1.0",
    py_modules=["portscanner"],
    install_requires=["tqdm"],
    entry_points={
        "console_scripts": [
            "portscan=portscanner:main",
        ],
    },
    python_requires=">=3.8",
)
```
Installed in editable mode with `pip install -e .`, so any changes I make to the code take effect immediately without reinstalling. Now I can run `portscan` from anywhere on my machine instead of needing to be inside the project folder.

## Limitations

- It's a full-connect scanner, so it's louder than a SYN scan like nmap's default, and the target's logs will show the connections
- TCP and IPv4 only
- It reports open ports only, so it can't tell a closed port from one a firewall is silently dropping
- Banner grabbing only works for services that speak first, so web servers show a guess instead

## Requirements

Python 3.8 or newer.

```bash
pip install -r requirements.txt
```
This installs `tqdm` for the progress bar. Everything else the scanner uses ships with the standard library.

To run the tests:
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Legal Note

Only scan systems you own or have explicit written permission to scan. Scanning networks without authorization is illegal in most places. I built and tested this exclusively against my own computer and home lab server.

## License

MIT, see [LICENSE](./LICENSE).