# Python Port Scanner

A multithreaded TCP port scanner I built from scratch in Python, with banner grabbing, closed and filtered port detection, input validation, a built-in safety guard, and JSON/CSV export. No third-party scanning libraries. Just the standard library's `socket` module doing the real work, plus `tqdm` for a progress bar.

## What This Is

I built this to actually understand how tools like `nmap` work under the hood, instead of just using them as a black box. It attempts a real TCP connection to each port in a range, times how that goes, and reads whatever the service on the other end says about itself once connected.

The first version worked, but it had real problems: a global results dictionary that never reset, banners that went straight to the terminal without any cleaning, and almost no input checking. I rebuilt it from an empty file, one piece at a time, and fixed all of that along the way. The sections below cover what it does now and why.

## Features

- Multithreaded scanning with a capped worker pool, so it won't spawn thousands of raw threads at once
- Closed and filtered port detection, so a silent firewall is reported differently from a closed port
- Port lists and ranges together, like `22,80,8000-8100`
- Banner grabbing on open ports, with a fallback service name based on common port numbers
- Extra HTTP probe on common web ports, so a web server reports its `Server:` header instead of nothing
- Banner cleaning, so a hostile service can't send terminal escape codes to my screen
- Input validation before any scanning starts: bad port ranges, bad timeouts, unknown hostnames and bad filenames all fail fast with a clear message
- A safety guard that refuses non-private targets unless I pass `--allow-public`
- A one-time disclaimer on first run, saved to my user folder, that I have to accept before scanning
- Hostnames and IPv6 addresses as well as IPv4
- `--top-ports N` to scan the N most common ports
- Adjustable parallelism and an optional delay between connections, for networks that don't like bursts
- A real command-line interface built with `argparse`
- A progress bar so a long scan doesn't look frozen
- Clean Ctrl+C handling that saves the results found so far
- JSON and CSV export that includes the target, a timestamp and each port's service name, so a saved file explains itself
- 25 automated tests that run against a fake local service
- Installable as an actual CLI tool (`pip install -e .`), so it runs from anywhere as `portscan`

## Usage

Run directly:
```bash
python portscanner.py <target> -p <ports> -o <output-file>
```

Or, once installed with `pip install -e .`:
```bash
portscan <target> -p <ports> -o <output-file>
```

The first time you run it, the scanner shows a short usage disclaimer and asks you to type `yes`. Your answer is saved to `.portscanner.json` in your home folder, so you're only asked once. Scripts can skip the prompt with `--accept-disclaimer`, which doesn't save anything.

**Options:**

| Option | What it does |
|---|---|
| `-p`, `--ports` | Ports to scan: a single port (`80`), a range (`1-1000`), or a mix (`22,80,8000-8100`). Defaults to `1-1000` |
| `--top-ports N` | Scan the N most common ports instead (1 to 57). Can't be combined with `-p` |
| `-t`, `--timeout` | Connection timeout in seconds. Defaults to `1` |
| `-w`, `--workers` | Number of parallel connections, 1 to 1000. Defaults to `100` |
| `-d`, `--delay` | Seconds to wait before each connection. Defaults to `0` |
| `-o`, `--output` | Save results to a `.json` or `.csv` file |
| `--allow-public` | Allow targets outside private networks. Only use on systems you own or have written permission to scan |
| `--accept-disclaimer` | Accept the usage disclaimer without the prompt. Useful for scripts |

**Examples:**
```bash
# Scan the first 1000 ports on localhost
portscan 127.0.0.1 -p 1-1000

# Scan only the 20 most common ports on a machine on my network
portscan 192.168.1.10 --top-ports 20

# Scan specific ports and a range, save results as JSON, and use a shorter timeout
portscan 192.168.1.10 -p 22,80,443,8000-9000 -o results.json -t 0.5

# Be gentle with a fragile device: fewer connections, with a pause before each one
portscan 192.168.1.10 -p 1-1000 -w 10 -d 0.05

# Save as CSV instead
portscan 192.168.1.10 -p 1-1000 -o results.csv
```

## Sample Output

To test it safely, I wrote a tiny fake service that listens on my own computer and sends a banner containing a terminal escape code, the kind of thing a hostile service could send. Then I scanned it:

```
Scanning 127.0.0.1 (localhost) ports 8990-9010...
Port 9000: OPEN (Unknown) — HELLO from fake service

Scanned 21 ports in 0.1s: 1 open, 20 closed, 0 filtered.
```

The escape code in the banner (which would normally turn the text red) was stripped out, and only harmless printable characters came through. Each open port shows a service name and a banner. When a web server stays silent until it gets a request, the scanner sends a small HTTP request and shows the server's name, for example `HTTP Server: nginx`.

Closed ports refuse the connection straight away, while filtered ports are the ones where nothing comes back before the timeout. That second group is usually a firewall quietly dropping packets, and it's reported separately so the two don't look the same.

A saved JSON file describes the scan it came from:

```json
{
  "target": "localhost",
  "resolved_ip": "127.0.0.1",
  "ports": "8990-9010",
  "scanned_at": "2026-10-24T13:10:53-04:00",
  "duration_seconds": 0.1,
  "interrupted": false,
  "open_ports": {
    "9000": {
      "service": "Unknown",
      "banner": "HELLO from fake service"
    }
  }
}
```

If you press Ctrl+C during a scan, the results found so far are still saved, and the file is marked with `"interrupted": true`.

I also ran this against my own hardened home server (see my [Linux Server Lab](https://github.com/tnorrr/linux-server-lab) project). Every open port matched a service I set up on purpose, and everything else came back closed, which was a good confirmation that the server's firewall was doing exactly what I configured it to do.

## What This Demonstrates

- Socket programming, using `socket.connect_ex` to check ports without raising an exception on every failed connection, and reading the real outcome of a non-blocking connection with `select`
- Real concurrency, using a `ThreadPoolExecutor` with a capped worker count instead of spawning an unbounded number of raw threads
- Treating network data as untrusted input, by stripping banners down to printable characters before they reach the terminal
- Input validation and failing fast, so mistakes show up in milliseconds instead of after a long scan
- Responsible-use design, with a guard against scanning anything that isn't on a private network and a disclaimer the user has to accept
- CLI design with `argparse`
- Structured data export in both JSON and CSV
- Writing tests with `pytest`, including a fake local service so nothing real gets scanned
- Packaging a script as an actual installable command-line tool
- Real-world validation against a server I personally hardened, which confirmed the firewall rules were behaving exactly as intended

## Stretch Goals

I started with a working scanner and kept pushing it further. Here's what changed and why, roughly in the order I built them.

### 1. A capped thread pool instead of raw threads

The first version of this scanner spawned one raw thread per port. That's fine for a small range, but scanning the full 65535-port range would have spawned 65,535 threads all at once. That's rude network behavior that can look like a denial-of-service attempt, and it can also crash a machine's own thread limits.

I replaced the raw threading with `concurrent.futures.ThreadPoolExecutor`, capped at 100 workers by default. No matter how big the port range is, at most that many connections happen at once. Port scanning spends almost all its time waiting on the network, and Python releases its global lock while a thread waits, so the threads really do run in parallel where it counts. Later I exposed the cap as `--workers`, so it can be lowered for a fragile device.

### 2. No more global state

The original kept its results in a global dictionary that was never cleared. Scanning twice in one run would have mixed the old results into the new ones. Now `scan_ports` builds a fresh list on every call, and `scan_port` just returns its result instead of writing to something shared. That also made the code much easier to test, and there's a test that proves a second scan doesn't remember the first.

### 3. Cleaning what comes back from the network

A banner is text that the other machine chooses to send me. A hostile service could include terminal escape codes that change colors, move the cursor, or hide text. So every banner has its escape codes removed, is stripped down to printable ASCII, and is capped at 200 characters before it's shown or saved:
```python
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

def sanitize(text):
    text = ANSI_ESCAPE.sub("", text)
    return re.sub(r"[^\x20-\x7E]", "", text)[:200]
```
My first version only removed the escape character itself, which left stray text like `[31m` behind. Removing the whole sequence fixed that.

### 4. Service-name guessing

A lot of open ports don't say anything the moment you connect. I added a lookup table of common ports, so the scanner can still name the likely service, and it shows that name separately from the banner:
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
Originally the guess was mixed into the banner text, which made saved files harder to trust. Now it has its own `service` field.

### 5. Validation and a safety guard

Everything the user types is checked before the first connection is made. Port specs like `100-50`, `0-99999` or `abc` get a clear error, a timeout of zero is rejected, an unknown hostname is reported, and an output file that doesn't end in `.json` or `.csv` is refused up front, so a typo can't waste a long scan.

The scanner also refuses to scan anything that isn't a private, loopback or link-local address unless I add `--allow-public`:
```python
def is_private_target(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local
```
That won't stop someone determined, but it does stop accidents, like a typo in an IP address, and it's a reminder that I should only scan things I own. A first-run disclaimer adds one more reminder, and it's saved so it doesn't nag on every run.

### 6. A configurable timeout

The connection timeout used to be hardcoded at one second per port. That's overly cautious on a fast local network and slows scans down for no reason, so I exposed it as a CLI flag instead:
```python
parser.add_argument("-t", "--timeout", type=float, default=1, help="Connection timeout in seconds (default: 1)")
```
Now `-t 0.5` runs a noticeably faster scan against something on the same network, while the default stays safe for less predictable targets.

### 7. A progress bar and partial results

A scan across a large port range with no output for a while looks frozen even when it's working fine, so I added `tqdm` around the scan loop. Pressing Ctrl+C now stops the scan but keeps everything found so far, prints a short message, and saves the partial results if you asked for a file.

### 8. Self-describing exports

Saved results used to be just a list of ports and banners. A file with no context isn't much use three weeks later, so JSON exports include the target, the resolved IP, the port range, a timestamp, how long the scan took, and whether it was interrupted. CSV exports include the target and timestamp on every row. A failed save reports the error instead of claiming success.

### 9. Automated tests

I wrote 25 tests with `pytest`. They cover port parsing, the private-address check, banner cleaning, the output filename check, closed and open port detection, and file output. The scan tests start a tiny fake service on a free localhost port, so I can check banner capture and escape-code stripping without touching anything real.

### 10. Packaged as an installable CLI tool

Running this used to mean `cd`-ing into the project folder and typing `python portscanner.py` every time. I added a `setup.py` so it installs like a real command instead:
```python
from setuptools import setup

setup(
    name="portscanner",
    version="2.0.0",
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

### 11. Closed vs filtered ports

The first version only reported open ports, so a closed port and a port behind a firewall looked the same. Now the scanner tells them apart. A refused connection is closed. A connection that never gets an answer before the timeout is filtered.

Windows reports connections that are still in progress with its own error codes, which the first version didn't handle. The scanner now waits for the connection to finish and reads the real result from the socket. On a Windows machine, a closed port can take a couple of seconds to refuse, so the timeout needs to be long enough for that.

### 12. Port lists, web probes and workers

- `-p` accepts comma-separated lists, so `22,80,443,8000-8100` works in one go.
- Web servers that stay silent get a small HTTP request, so the scanner can report the `Server:` header instead of nothing.
- `--workers` and `--delay` let the scanner be gentler with a fragile device.
- `--top-ports N` scans a larger ordered list of common ports, so you choose how deep to go.

### 13. IPv6

The first version only understood IPv4. Hostnames are now resolved with `getaddrinfo`, and the socket type is chosen from the address, so an IPv6 address can be scanned too.

## Limitations

- It's a full-connect scanner, so it's louder than a SYN scan like nmap's default, and the target's logs will show the connections
- It can't scan IPv6 link-local addresses such as `fe80::...`, because those need an interface name added to the address
- Banner grabbing only works well for services that speak first or answer a simple HTTP request
- On some Windows machines, closed ports take a couple of seconds to refuse, so a short timeout can report them as filtered

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