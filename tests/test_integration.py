"""End-to-end tests against real local HTTP/HTTPS servers (no internet needed)."""

from __future__ import annotations

import http.server
import json
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from safescope.cli import main
from safescope.http import FetchError, HttpClient
from safescope.tls import inspect_tls


class Handler(http.server.BaseHTTPRequestHandler):
    http_port: int = 0
    https_port: int = 0

    def log_message(self, *args):  # keep test output clean
        pass

    def do_GET(self):
        if self.path == "/relative/start":
            self.send_response(302)
            self.send_header("Location", "next")
            self.end_headers()
            return

        if self.path == "/chain/start":
            self.send_response(302)
            self.send_header(
                "Location",
                f"https://127.0.0.1:{self.https_port}/chain/secure",
            )
            self.end_headers()
            return

        if self.path == "/chain/secure":
            self.send_response(301)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{self.http_port}/chain/again",
            )
            self.end_headers()
            return

        if self.path == "/chain/again":
            self.send_response(307)
            self.send_header(
                "Location",
                f"https://127.0.0.1:{self.https_port}/chain/final",
            )
            self.end_headers()
            return
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        body = b"<h1>hello</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessionid=abc; Path=/")
        self.send_header("Set-Cookie", "theme=dark; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(server: http.server.HTTPServer) -> Iterator[int]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def http_port() -> Iterator[int]:
    yield from _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler))


@pytest.fixture
def https_port(tmp_path: Path) -> Iterator[int]:
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    yield from _serve(server)


def test_client_follows_and_records_redirects(http_port):
    resp = HttpClient(timeout=5).get(f"http://127.0.0.1:{http_port}/redirect")
    assert resp.url.endswith("/final")
    assert resp.redirect_chain == [(301, f"http://127.0.0.1:{http_port}/redirect")]
    assert len(resp.headers.get_all("Set-Cookie")) == 2


def test_client_resolves_relative_redirect_location(http_port):
    start_url = f"http://127.0.0.1:{http_port}/relative/start"

    resp = HttpClient(timeout=5).get(start_url)

    assert resp.status == 200
    assert resp.url == f"http://127.0.0.1:{http_port}/relative/next"
    assert resp.redirect_chain == [(302, start_url)]


def test_client_follows_http_https_redirect_chain(http_port, https_port):
    Handler.http_port = http_port
    Handler.https_port = https_port

    start_url = f"http://127.0.0.1:{http_port}/chain/start"
    secure_url = f"https://127.0.0.1:{https_port}/chain/secure"
    again_url = f"http://127.0.0.1:{http_port}/chain/again"
    final_url = f"https://127.0.0.1:{https_port}/chain/final"

    resp = HttpClient(timeout=5, verify_tls=False).get(start_url)

    assert resp.status == 200
    assert resp.url == final_url
    assert resp.redirect_chain == [
        (302, start_url),
        (301, secure_url),
        (307, again_url),
    ]


def test_client_detects_redirect_loops(http_port):
    with pytest.raises(FetchError, match="too many redirects"):
        HttpClient(timeout=5).get(f"http://127.0.0.1:{http_port}/loop")


def test_client_reports_unreachable_host():
    with pytest.raises(FetchError):
        HttpClient(timeout=2).get("http://127.0.0.1:9/")


def test_inspect_tls_on_self_signed_server(https_port):
    info = inspect_tls("127.0.0.1", https_port, timeout=5)
    assert info.connected
    assert not info.verified
    assert info.verify_error
    assert info.protocol in ("TLSv1.2", "TLSv1.3")


def test_cli_json_against_local_server(http_port, tmp_path, capsys):
    out = tmp_path / "report.json"
    code = main(
        [
            "scan",
            f"http://127.0.0.1:{http_port}/",
            "-f",
            "json",
            "-o",
            str(out),
            "--skip",
            "tls",
            "--fail-on",
            "medium",
            "-q",
        ]
    )
    data = json.loads(out.read_text())
    ids = {f["id"] for f in data["findings"]}
    assert "transport.https.unavailable" in ids
    assert "disclosure.versions" in ids
    assert "cookies.sessionid.flags" in ids
    assert code == 1  # --fail-on medium triggered by HTTPS being unavailable (high)


def test_cli_exit_codes(capsys):
    assert main(["scan", "ftp://nope"]) == 2
    assert main(["scan", "example.com", "--only", "nope"]) == 2
    assert main(["scan", "http://127.0.0.1:9/", "--timeout", "2", "-q"]) == 3
    assert main(["checks"]) == 0
    assert "headers" in capsys.readouterr().out


class HostEcho(http.server.BaseHTTPRequestHandler):
    """Answers with the Host header it received and the TLS SNI it saw."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = (self.headers.get("Host") or "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_pinned_connection_keeps_host_header_and_sni(tmp_path):
    """DNS pinning connects to the validated IP but the server must still see
    the original host name in the Host header and in TLS SNI."""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=pinned.test",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    seen_sni: list[str | None] = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HostEcho)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.sni_callback = lambda sock, name, _ctx: seen_sni.append(name)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # "pinned.test" does not exist in DNS: only the pin makes this work.
        client = HttpClient(timeout=5, verify_tls=False, url_guard=lambda url: "127.0.0.1")
        resp = client.get(f"https://pinned.test:{port}/")
        assert resp.status == 200
        assert resp.text == f"pinned.test:{port}"
        assert seen_sni == ["pinned.test"]
    finally:
        server.shutdown()
        server.server_close()
