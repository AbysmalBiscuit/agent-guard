#!/usr/bin/env python3
"""The plugin install of a `github:` tool fails without a GitHub attestation."""

import functools
import hashlib
import http.server
import io
import json
import os
import platform
import shutil
import socketserver
import ssl
import subprocess
import tarfile
import tempfile
import threading
import tomllib
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from hook_support import PLUGIN_ROOT

GITHUB_HOSTS = ("github.com", "api.github.com", "mise-versions.jdx.dev")
TARGETS = {
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("Darwin", "x86_64"): "x86_64-apple-darwin",
    ("Darwin", "arm64"): "aarch64-apple-darwin",
}


def github_tool():
    """The `github:` tool and the version `mise.toml` pins for it."""
    tools = tomllib.loads((PLUGIN_ROOT / "mise.toml").read_text(encoding="utf-8"))["tools"]
    return next((name, version) for name, version in tools.items() if name.startswith("github:"))


def fixture_asset():
    """A release archive holding a `fallow` that only prints `fixture`."""
    script = b'#!/bin/sh\nprintf "fixture\\n"\n'
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo("fallow")
        member.size = len(script)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(script))
    return buffer.getvalue()


def make_certificates(directory):
    """A test CA, and a certificate it signs for the GitHub hosts."""

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=directory, check=True, capture_output=True)

    key = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes")
    openssl(
        "req",
        "-x509",
        *key,
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "1",
        "-subj",
        "/CN=test CA",
    )
    openssl("req", *key, "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=github.com")
    names = ",".join(f"DNS:{host}" for host in GITHUB_HOSTS)
    (directory / "leaf.ext").write_text(f"subjectAltName={names}\n", encoding="utf-8")
    openssl(
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        "leaf.ext",
        "-out",
        "leaf.pem",
    )
    return directory / "ca.pem", directory / "leaf.pem", directory / "leaf.key"


@dataclass
class Release:
    """One release of `tool` with one asset, and the requests GitHub got."""

    tool: str
    version: str
    asset: bytes
    requests: list[str] = field(default_factory=list)

    def listing(self):
        repo = self.tool.removeprefix("github:")
        name = f"{repo.split('/')[1]}-{TARGETS[(platform.system(), platform.machine())]}.tar.gz"
        return {
            "tag_name": f"v{self.version}",
            "name": f"v{self.version}",
            "draft": False,
            "prerelease": False,
            "created_at": "2026-01-01T00:00:00Z",
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "id": 1,
                    "name": name,
                    "size": len(self.asset),
                    "digest": f"sha256:{hashlib.sha256(self.asset).hexdigest()}",
                    "url": f"https://api.github.com/repos/{repo}/releases/assets/1",
                    "browser_download_url": (
                        f"https://github.com/{repo}/releases/download/v{self.version}/{name}"
                    ),
                }
            ],
        }


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    """GitHub with one release and no attestations for any digest."""

    protocol_version = "HTTP/1.1"

    def __init__(self, request, client_address, server, *, release):
        self.release = release
        super().__init__(request, client_address, server)

    def do_GET(self):
        self.release.requests.append(f"{self.headers.get('Host')}{self.path}")
        path = self.path.split("?")[0]
        if "/attestations" in path:
            self.reply(200, json.dumps({"attestations": []}).encode(), "application/json")
        elif "/releases/download/" in path or "/releases/assets/" in path:
            self.reply(200, self.release.asset, "application/octet-stream")
        elif path.startswith("/repos/") and path.endswith("/releases"):
            self.reply(200, json.dumps([self.release.listing()]).encode(), "application/json")
        elif path.startswith("/repos/") and path.endswith(
            f"/releases/tags/v{self.release.version}"
        ):
            self.reply(200, json.dumps(self.release.listing()).encode(), "application/json")
        else:
            self.reply(404, b'{"message": "Not Found"}', "application/json")

    def do_HEAD(self):
        self.do_GET()

    def reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


class Tunnel(socketserver.StreamRequestHandler):
    """Accepts a CONNECT, ends its TLS with the test certificate, and serves
    the requests inside it as FakeGitHub."""

    def __init__(self, request, client_address, server, *, context, release):
        self.context = context
        self.release = release
        super().__init__(request, client_address, server)

    def handle(self):
        if not self.rfile.readline().startswith(b"CONNECT "):
            return
        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
            pass
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        try:
            tls = self.context.wrap_socket(self.connection, server_side=True)
        except OSError:
            return
        with tls:
            FakeGitHub(tls, self.client_address, self.server, release=self.release)


def start_proxy(test, release, certificate, key):
    """A proxy on 127.0.0.1 that answers as GitHub, stopped at test cleanup."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    handler = functools.partial(Tunnel, context=context, release=release)
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return f"http://127.0.0.1:{server.server_address[1]}"


def copy_plugin(destination, asset, *, backend="github:", locked=True):
    """The plugin's install files, with only its `backend` tools pinned. The
    lockfile, when the plugin has one, records the fixture's checksum, as a
    release whose asset matches its pin but carries no attestation. With
    `locked` false, the lockfile has no entry for the `backend` tools."""
    for relative in ("scripts/install.sh", "hooks/bootstrap-tools", ".claude-plugin/plugin.json"):
        (destination / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PLUGIN_ROOT / relative, destination / relative)
    lines, section = [], ""
    for line in (PLUGIN_ROOT / "mise.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("["):
            section = line.strip()
        if section == "[tools]" and "=" in line and not line.startswith(f'"{backend}'):
            continue
        lines.append(line)
    (destination / "mise.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    lock = PLUGIN_ROOT / "mise.lock"
    if lock.is_file():
        text = lock.read_text(encoding="utf-8")
        fixture = f"sha256:{hashlib.sha256(asset).hexdigest()}"
        for name, entries in tomllib.loads(text)["tools"].items():
            if name.startswith("github:"):
                for entry in entries:
                    for key, value in entry.items():
                        if key.startswith("platforms.") and "checksum" in value:
                            text = text.replace(value["checksum"], fixture)
        if not locked:
            kept, section = [], ""
            for line in text.splitlines():
                if line.startswith("["):
                    section = line.lstrip("[")
                if not section.startswith(f'tools."{backend}'):
                    kept.append(line)
            text = "\n".join(kept) + "\n"
        (destination / "mise.lock").write_text(text, encoding="utf-8")


class AttestationTests(unittest.TestCase):
    """The real mise installs through a proxy that answers as GitHub: it ends
    TLS with a test CA, serves a fixture release, and lists no attestations."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        certs = self.root / "certs"
        certs.mkdir()
        ca, certificate, key = make_certificates(certs)
        self.release = Release(*github_tool(), fixture_asset())
        proxy = start_proxy(self, self.release, certificate, key)
        self.plugin = self.root / "plugin"
        copy_plugin(self.plugin, self.release.asset)
        home = self.root / "home"
        (home / ".config" / "mise").mkdir(parents=True)
        self.machine_config = home / ".config" / "mise" / "config.toml"
        self.machine_config.write_text("", encoding="utf-8")
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("MISE_", "AGENT_GUARD_"))
            and key not in ("GITHUB_TOKEN", "GH_TOKEN", "NO_PROXY", "no_proxy")
        }
        self.env.update(
            HOME=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_STATE_HOME=str(self.root / "state"),
            HTTPS_PROXY=proxy,
            https_proxy=proxy,
            SSL_CERT_FILE=str(ca),
        )

    def bootstrap(self):
        return subprocess.run(
            ["bash", str(self.plugin / "hooks" / "bootstrap-tools")],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=120,
        )

    def assert_install_refused(self, result):
        report = f"{result.stderr}\nrequests: {self.release.requests}"
        self.assertEqual(result.returncode, 0, report)
        self.assertIn("install.sh exited", result.stderr, report)
        self.assertIn("requires github-attestations provenance", result.stderr, report)
        self.assertTrue(any("/attestations" in r for r in self.release.requests), report)
        failed = self.root / "state" / "agent-guard" / "bootstrap-failed"
        self.assertTrue(failed.is_file(), report)

    def assert_unlocked_pin_refused(self):
        self.env.update(MISE_LOCKED="false", MISE_LOCKED_SCOPES="global")
        result = self.bootstrap()
        report = f"{result.stderr}\nrequests: {self.release.requests}"
        self.assertEqual(result.returncode, 0, report)
        self.assertIn("install.sh exited", result.stderr, report)
        self.assertIn("not in the lockfile", result.stderr, report)
        failed = self.root / "state" / "agent-guard" / "bootstrap-failed"
        self.assertTrue(failed.is_file(), report)

    def test_an_install_without_an_attestation_fails_and_the_bootstrap_reports_it(self):
        self.assert_install_refused(self.bootstrap())

    def test_a_pin_with_no_lock_entry_fails_and_the_bootstrap_reports_it(self):
        copy_plugin(self.plugin, self.release.asset, locked=False)
        self.assert_unlocked_pin_refused()

    def test_a_pipx_pin_with_no_lock_entry_fails_and_the_bootstrap_reports_it(self):
        copy_plugin(self.plugin, self.release.asset, backend="pipx:", locked=False)
        self.assert_unlocked_pin_refused()

    def test_a_machine_setting_does_not_turn_off_the_attestation_check(self):
        self.machine_config.write_text(
            "[settings]\n"
            "github_attestations = false\n"
            "github.github_attestations = false\n"
            "aqua.github_attestations = false\n"
            "lockfile = false\n"
            "locked_verify_provenance = false\n",
            encoding="utf-8",
        )
        for setting in (
            "github_attestations",
            "github.github_attestations",
            "aqua.github_attestations",
        ):
            pinned = subprocess.run(
                ["mise", "-C", str(self.plugin), "settings", "get", setting],
                capture_output=True,
                text=True,
                env={**self.env, "MISE_TRUSTED_CONFIG_PATHS": str(self.plugin)},
                check=True,
            )
            self.assertEqual(pinned.stdout.strip(), "true", setting)
        self.assert_install_refused(self.bootstrap())

    def test_a_machine_variable_does_not_turn_off_the_attestation_check(self):
        self.env.update(
            MISE_GITHUB_ATTESTATIONS="false",
            MISE_GITHUB_GITHUB_ATTESTATIONS="false",
            MISE_LOCKFILE="false",
            MISE_LOCKED_VERIFY_PROVENANCE="false",
        )
        self.assert_install_refused(self.bootstrap())


if __name__ == "__main__":
    unittest.main()
