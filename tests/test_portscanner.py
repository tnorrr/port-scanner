import socket
import threading

import pytest

from portscanner import (
    check_output_name, is_private_target, parse_ports, sanitize,
    save_results, scan_port, scan_ports,
)


@pytest.mark.parametrize("spec, expected", [("80", (80, 80)), ("1-100", (1, 100)), ("65535", (65535, 65535))])
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["0-10", "100-50", "1-70000", "abc", "1-2-3", "-5", ""])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_sanitize_removes_escape_codes():
    assert "\x1b" not in sanitize("\x1b[31mred\x1b[0m")


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
        found_port, banner = scan_port("127.0.0.1", port, timeout=1)
        assert found_port == port
        assert banner.startswith("HELLO")
        assert "\x1b" not in banner
    finally:
        server.close()


def test_closed_port_returns_none():
    assert scan_port("127.0.0.1", free_port(), timeout=0.5) is None


def test_results_do_not_leak_between_scans():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        open_port = server.getsockname()[1]
        assert open_port in scan_ports("127.0.0.1", [open_port], timeout=0.5)
    # Server is closed now. A fresh scan must not remember the old result.
    assert scan_ports("127.0.0.1", [open_port], timeout=0.5) == {}


def test_save_json_includes_target_and_timestamp(tmp_path):
    out = tmp_path / "out.json"
    meta = {"target": "localhost", "scanned_at": "2026-10-24T13:00:00-04:00"}
    save_results({22: "SSH-2.0-test"}, meta, str(out))
    text = out.read_text()
    assert "localhost" in text and "2026-10-24" in text and "SSH-2.0-test" in text