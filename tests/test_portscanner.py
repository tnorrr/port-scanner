import socket
import threading

import pytest

from portscanner import (
    check_output_name, is_private_target, parse_ports, sanitize,
    save_results, scan_port, scan_ports,
)


@pytest.mark.parametrize("spec, expected", [
    ("80", [80]),
    ("1-100", list(range(1, 101))),
    ("65535", [65535]),
    ("22,80,8000-8002", [22, 80, 8000, 8001, 8002]),
])
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["0-10", "100-50", "1-70000", "abc", "1-2-3", "-5", "", "22,,80", "80,70000", "22,abc"])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_sanitize_removes_escape_codes():
    assert "\x1b" not in sanitize("\x1b[31mred\x1b[0m")


def test_sanitize_removes_whole_colour_code():
    assert sanitize("\x1b[31mred\x1b[0m") == "red"


@pytest.mark.parametrize("ip, expected", [("127.0.0.1", True), ("192.168.1.10", True), ("8.8.8.8", False)])
def test_is_private_target(ip, expected):
    assert is_private_target(ip) is expected


def test_unknown_output_extension_is_rejected():
    with pytest.raises(ValueError):
        check_output_name("results.txt")


def free_port():
    """Find a port that is currently closed on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_scan_finds_open_port_and_banner():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"HELLO\x1b[31m")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        result = scan_port("127.0.0.1", port, timeout=1)
        assert result["port"] == port
        assert result["state"] == "open"
        assert result["banner"].startswith("HELLO")
        assert "\x1b" not in result["banner"]
    finally:
        server.close()


def test_closed_port_reports_closed():
    result = scan_port("127.0.0.1", free_port(), timeout=3)
    assert result["state"] == "closed"


def test_results_do_not_leak_between_scans():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        open_port = server.getsockname()[1]
        results, interrupted = scan_ports("127.0.0.1", [open_port], timeout=0.5)
        assert not interrupted
        assert any(r["port"] == open_port and r["state"] == "open" for r in results)
    # Server is closed now. A fresh scan must not remember the old result.
    results, _ = scan_ports("127.0.0.1", [open_port], timeout=0.5)
    assert not any(r["state"] == "open" for r in results)


def test_save_json_includes_target_and_timestamp(tmp_path):
    out = tmp_path / "out.json"
    meta = {"target": "localhost", "scanned_at": "2026-10-24T13:00:00-04:00"}
    rows = [{"port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-test"}]
    save_results(rows, meta, str(out))
    text = out.read_text()
    assert "localhost" in text and "2026-10-24" in text and "SSH-2.0-test" in text


def test_save_csv_has_service_column(tmp_path):
    out = tmp_path / "out.csv"
    meta = {"target": "localhost", "scanned_at": "2026-10-24T13:00:00-04:00"}
    rows = [{"port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-test"}]
    save_results(rows, meta, str(out))
    assert out.read_text().splitlines()[0] == "target,scanned_at,port,service,banner"