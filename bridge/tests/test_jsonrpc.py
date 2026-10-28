"""JSON-RPC wire tests against the real stdio server (subprocess).

Mirrors acceptance criteria:
  * python -m bridge.raphael_bridge emits JSON lines
  * system.health answers status ok with all 7 components
  * fail-closed errors are explicit and non-fatal (process survives)
  * malformed input produces -32700 without killing the server
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


class BridgeProc:
    """Line-delimited JSON-RPC client around a live bridge subprocess."""

    def __init__(self, proc):
        self.proc = proc

    def send(self, obj, timeout=30.0):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()
        return self.read_response(timeout)

    def notify(self, obj):
        """Write a notification (no id) without waiting for a response."""
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def send_raw(self, line, timeout=30.0):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self.read_response(timeout)

    def read_response(self, timeout=30.0):
        # readline in a poll loop so a hung server fails fast
        deadline = time.time() + timeout
        import select
        fd = self.proc.stdout.fileno()
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                line = self.proc.stdout.readline()
                if line.strip():
                    return json.loads(line)
        raise TimeoutError("bridge did not answer in time")

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


@pytest.fixture()
def bridge_proc(tmp_path):
    env = {
        **{k: v for k, v in os.environ.items()
           if not k.startswith(("EGRESS", "TOR_", "KALI_", "VPN_", "BRIDGE_",
                                "OUTBOUND", "DNS_", "SLIVER_", "NEO4J"))},
        "EGRESS_STRATEGY": "tor",
        "TOR_SOCKS": "127.0.0.1:19050",   # unreachable on purpose
        "PYTHONPATH": str(REPO_ROOT),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "bridge.raphael_bridge",
         "--audit-dir", str(tmp_path / "projects")],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    client = BridgeProc(proc)
    try:
        yield client
    finally:
        client.close()
        if proc.poll() is None:
            proc.kill()


class TestHealthAndVersion:
    def test_health_ok_with_all_components(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "1",
                                  "method": "system.health", "params": {}})
        assert resp["id"] == "1"
        res = resp["result"]
        assert res["status"] in ("ok", "degraded")
        comps = res["components"]
        for key in ("tor", "sliver", "neo4j", "kali", "vpn_provider",
                    "ovpn_profile_loaded", "dns"):
            assert key in comps, f"missing component {key}"
        # configured-but-unreachable tor must degrade honestly
        assert comps["tor"]["configured"] is True
        assert comps["tor"]["reachable"] is False
        assert "tor" in res["degraded"]

    def test_bridge_version(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": 2,
                                  "method": "bridge.version", "params": {}})
        res = resp["result"]
        assert res["bridge"] == "raphael-external-bridge"
        assert res["version"] == "2.0.0"
        assert Path(res["repo_root"]).is_dir()
        assert "kali.run" in res["methods"]

    def test_ping(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": 3,
                                  "method": "ping", "params": {}})
        assert resp["result"]["pong"] is True


class TestFailClosedBehavior:
    def test_vpn_connect_without_scope_refused(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "vc",
                                 "method": "vpn.connect", "params": {}})
        err = resp["error"]
        assert err["code"] == -32002
        assert "fail closed" in err["message"].lower()

    def test_process_survives_errors(self, bridge_proc):
        """Errors must be non-fatal: the bridge keeps answering."""
        for i in range(3):
            resp = bridge_proc.send({"jsonrpc": "2.0", "id": i,
                                     "method": "vpn.connect", "params": {}})
            assert "error" in resp
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "alive",
                                 "method": "bridge.version", "params": {}})
        assert resp["id"] == "alive"

    def test_vpn_status_explicit_never_crashes(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "vs",
                                 "method": "vpn.status", "params": {}})
        res = resp["result"]
        assert res["connected"] is False
        assert "openvpn_installed" in res

    def test_targets_set_without_cidrs_error(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "ts",
                                 "method": "targets.set",
                                 "params": {"engagement_id": "x", "urls": ["a.b"]}})
        assert resp["error"]["code"] == -32602

    def test_kali_run_before_scope_refused(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "kr",
                                 "method": "kali.run",
                                 "params": {"tool": "nmap", "target": "10.0.0.1"}})
        assert resp["error"]["code"] == -32002


class TestSessionFlow:
    def test_targets_set_then_get_policy_then_logs(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "s1",
                                 "method": "targets.set",
                                 "params": {"engagement_id": "eng-live-1",
                                            "cidrs": ["203.0.113.0/24"],
                                            "urls": ["demo.example"],
                                            "egress": "tor"}})
        assert resp["result"]["engagement_id"] == "eng-live-1"

        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "s2",
                                 "method": "targets.get_policy",
                                 "params": {"engagement_id": "eng-live-1"}})
        res = resp["result"]
        assert res["scope_cidrs"] == ["203.0.113.0/24"]
        assert res["egress_policy"] == "proxy_tor"
        assert "max_rate" in res and "allowed_ports" in res

        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "s3",
                                 "method": "bridge.logs",
                                 "params": {"last_n": 3}})
        assert resp["result"]["count"] >= 1
        assert resp["result"]["lines"][-1]["engagement"] == "eng-live-1"

    def test_out_of_scope_kali_run_rejected_after_set(self, bridge_proc):
        bridge_proc.send({"jsonrpc": "2.0", "id": "p",
                          "method": "targets.set",
                          "params": {"engagement_id": "eng-live-2",
                                     "cidrs": ["203.0.113.0/24"],
                                     "egress": "direct"}})
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "q",
                                 "method": "kali.run",
                                 "params": {"tool": "nmap", "target": "8.8.8.8"}})
        assert resp["error"]["code"] == -32001
        assert "outside engagement scope" in resp["error"]["message"]

    def test_dns_canary_allowed_without_scope(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "d",
                                 "method": "dns.resolve",
                                 "params": {"host": "example.com"}})
        res = resp["result"]
        assert res["addresses"]  # DNS works in this environment

    def test_proxy_test_unreachable_explicit_error(self, bridge_proc):
        """Tor not running: explicit non-fatal ComponentError (-32003)."""
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "pt",
                                 "method": "proxy.test", "params": {}})
        assert resp["error"]["code"] == -32003
        assert "tor" in resp["error"]["message"].lower()


class TestWireProtocolRobustness:
    def test_malformed_json_parse_error(self, bridge_proc):
        resp = bridge_proc.send_raw("this is not json{{{")
        assert resp["error"]["code"] == -32700
        assert resp["id"] is None

    def test_unknown_method(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": 42,
                                 "method": "nope.nope", "params": {}})
        assert resp["error"]["code"] == -32601
        assert "kali.run" in resp["error"]["data"]["known"]

    def test_notification_no_response(self, bridge_proc):
        """No id -> no response line at all (next request still answered)."""
        bridge_proc.notify({"jsonrpc": "2.0", "method": "ping"})
        time.sleep(0.3)  # give the bridge a moment to (wrongly) emit nothing
        # nothing should be pending; a fresh request must map to its own id
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "after-note",
                                 "method": "ping", "params": {}})
        assert resp["id"] == "after-note"

    def test_params_not_object(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": 7,
                                 "method": "system.health", "params": [1]})
        assert resp["error"]["code"] == -32602


class TestMcpShim:
    def test_initialize(self, bridge_proc):
        resp = bridge_proc.send({
            "jsonrpc": "2.0", "id": "init", "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}})
        assert resp["result"]["serverInfo"]["name"] == "raphael-external-bridge"

    def test_tools_list_and_call(self, bridge_proc):
        resp = bridge_proc.send({"jsonrpc": "2.0", "id": "tl",
                                 "method": "tools/list", "params": {}})
        names = [t["name"] for t in resp["result"]["tools"]]
        assert "targets.set" in names and "kali.run" in names

        resp = bridge_proc.send({
            "jsonrpc": "2.0", "id": "tc", "method": "tools/call",
            "params": {"name": "bridge.version", "arguments": {}}})
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["version"] == "2.0.0"
