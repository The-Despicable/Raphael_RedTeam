# Raphael External-Target Bridge — package layout

Unzip at the repo root (/home/yaser/raphael-redteam) — paths are repo-relative:

```
.env.bridge.example          -> merge the block into your gitignored .env
bridge/raphael_bridge.py     -> JSON-RPC 2.0 stdio server (python -m bridge.raphael_bridge)
bridge/README.md             -> full integration + security + WSL2 network docs
bridge/tests/                -> pytest suite (77 tests; python -m pytest bridge/tests -q)
bridge/pytest.ini
src/bridge/external_target_manager.py  -> policy engine + VPN/Tor/DNS/tools + audit
configs/docker-compose.override.yml    -> sliver config copy, tor/kali env, opt-in vpn-gateway
scripts/install_vpn_deps.sh            -> host openvpn/TUN prerequisites (sudo -n, idempotent)
scripts/test_external_bridge.py        -> live non-destructive smoke (PASS/FAIL/SKIP)
scripts/fake_kali_server.py            -> stub kali-tools endpoint for offline routing tests
```

Quick verification after unzip:

    python -m pytest bridge/tests -q
    echo '{"id":"1","method":"system.health","params":{}}' | python -m bridge.raphael_bridge
    python scripts/test_external_bridge.py

OpenCode mounting (MCP stdio) snippet: see bridge/README.md.
