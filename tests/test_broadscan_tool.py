"""brain.broadscan_tool: scope gate, argv parsing, and a live loopback scan.

Run: python -m pytest tests/test_broadscan_tool.py -q
The live test skips when tools/broadscan/bin/broadscan is not built.
"""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

from brain.broadscan_tool import (
    BroadscanError,
    BroadscanScopeError,
    BroadscanTool,
)
from brain.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("BROADSCAN_BIN") or REPO_ROOT / "tools" / "broadscan" / "bin" / "broadscan")


@pytest.fixture()
def settings(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"allow": ["127.0.0.0/8"], "max_rate": 5000}))
    monkeypatch.setenv("BROADSCAN_SCOPE", str(scope_file))
    monkeypatch.delenv("BROADSCAN_SCOPE_INLINE", raising=False)
    monkeypatch.delenv("BROADSCAN_ALLOW_OPEN", raising=False)
    return Settings(BROADSCAN_SCOPE=str(scope_file), BROADSCAN_MAX_RATE=100_000)


class TestScope:
    def test_missing_scope_fails_closed(self, monkeypatch):
        monkeypatch.delenv("BROADSCAN_SCOPE", raising=False)
        monkeypatch.delenv("BROADSCAN_SCOPE_INLINE", raising=False)
        monkeypatch.delenv("BROADSCAN_ALLOW_OPEN", raising=False)
        tool = BroadscanTool(Settings(BROADSCAN_SCOPE=None))
        with pytest.raises(BroadscanScopeError, match="no scope configured"):
            tool.plan(["127.0.0.1"])

    def test_allow_open_opt_in(self, monkeypatch):
        monkeypatch.delenv("BROADSCAN_SCOPE", raising=False)
        monkeypatch.delenv("BROADSCAN_SCOPE_INLINE", raising=False)
        monkeypatch.setenv("BROADSCAN_ALLOW_OPEN", "1")
        plan = BroadscanTool(Settings(BROADSCAN_SCOPE=None)).plan(["203.0.113.5"])
        assert plan["enforced"] is False
        assert plan["targets"] == ["203.0.113.5"]

    def test_in_scope_passes(self, settings):
        plan = BroadscanTool(settings).plan(["127.0.0.1"], ports=[25])
        assert plan["targets"] == ["127.0.0.1"]
        assert plan["scope"]["allow"] == ["127.0.0.0/8"]

    def test_out_of_scope_rejected(self, settings):
        with pytest.raises(BroadscanScopeError, match="outside scope"):
            BroadscanTool(settings).plan(["10.0.0.0/24"])

    def test_deny_overlap_rejected(self, settings, tmp_path, monkeypatch):
        scope_file = tmp_path / "deny.json"
        scope_file.write_text(
            json.dumps({"allow": ["127.0.0.0/8"], "deny": ["127.0.0.2/31"]})
        )
        monkeypatch.setenv("BROADSCAN_SCOPE", str(scope_file))
        tool = BroadscanTool(Settings(BROADSCAN_SCOPE=str(scope_file)))
        with pytest.raises(BroadscanScopeError, match="overlaps denied"):
            tool.plan(["127.0.0.2/31"])
        assert tool.plan(["127.0.0.5"])["targets"] == ["127.0.0.5"]

    def test_rate_capped_by_scope_doc(self, settings):
        plan = BroadscanTool(settings).plan(["127.0.0.1"], rate=99_000)
        assert plan["rate"] == 5000

    def test_bad_port_rejected(self, settings):
        with pytest.raises(BroadscanScopeError, match="bad port"):
            BroadscanTool(settings).plan(["127.0.0.1"], ports=["ssh"])


class TestArgs:
    def test_opsec_flags_parsed(self, settings):
        opts = BroadscanTool(settings).parse_args(
            ["-targets", "127.0.0.1", "-ports", "443", "-syn", "-opsec",
             "-decoys", "127.0.0.40/29", "-jitter", "10ms", "-frag", "8",
             "-ttl", "50-60", "-tcp-ts", "-sport", "fixed"]
        )
        assert opts["opsec"] is True
        assert opts["decoys"] == ["127.0.0.40/29"]
        assert opts["jitter_ms"] == 10
        assert opts["frag"] == 8
        assert opts["ttl"] == "50-60"
        assert opts["tcp_ts"] is True
        assert opts["sport"] == "fixed"

    def test_opsec_plan_requires_syn(self, settings):
        with pytest.raises(BroadscanScopeError, match="opsec requires syn"):
            BroadscanTool(settings).plan(["127.0.0.1"], opsec=True)

    def test_opsec_plan_forces_no_banners(self, settings):
        plan = BroadscanTool(settings).plan(["127.0.0.1"], syn=True, opsec=True)
        assert plan["banners"] is False

    def test_decoys_outside_scope_rejected(self, settings):
        with pytest.raises(BroadscanScopeError, match="outside scope"):
            BroadscanTool(settings).plan(
                ["127.0.0.1"], syn=True, opsec=True, decoys=["10.0.0.0/24"]
            )

    def test_flags_parsed(self, settings):
        opts = BroadscanTool(settings).parse_args(
            ["-targets", "127.0.0.1,127.0.0.2", "-ports", "22,80", "-rate", "10",
             "-syn", "-no-banners"]
        )
        assert opts["targets"] == ["127.0.0.1", "127.0.0.2"]
        assert opts["ports"] == "22,80"
        assert opts["rate"] == 10
        assert opts["syn"] is True
        assert opts["banners"] is False

    def test_target_field_used_when_args_empty(self, settings):
        opts = BroadscanTool(settings).parse_args([], target="127.0.0.1")
        assert opts["targets"] == ["127.0.0.1"]

    def test_unknown_flag_rejected(self, settings):
        with pytest.raises(BroadscanScopeError, match="unknown flag"):
            BroadscanTool(settings).parse_args(["-nmap", "127.0.0.1"])


@pytest.mark.skipif(not BIN.is_file(), reason="broadscan binary not built")
class TestLive:
    def test_loopback_hit(self, settings, monkeypatch):
        monkeypatch.setenv("BROADSCAN_BIN", str(BIN))
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]

        stop = threading.Event()

        def accept_loop():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                conn.sendall(b"SSH-2.0-loopback-test\r\n")
                conn.close()

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()
        try:
            tool = BroadscanTool(settings)
            result = __import__("asyncio").run(
                tool.run(["127.0.0.1"], ports=[port], timeout=20)
            )
        finally:
            stop.set()
            t.join(timeout=2)
            srv.close()

        assert result["exit_code"] == 0, result["stderr"]
        assert result["probed"] == 1
        assert result["open"] == 1
        hit = result["hits"][0]
        assert hit["ip"] == "127.0.0.1"
        assert hit["port"] == port
        assert "SSH-2.0" in hit["banner"]

    def test_out_of_scope_never_executes(self, settings, monkeypatch):
        monkeypatch.setenv("BROADSCAN_BIN", str(BIN))
        tool = BroadscanTool(settings)
        with pytest.raises(BroadscanScopeError):
            __import__("asyncio").run(tool.run(["10.0.0.0/24"], ports=[80]))
