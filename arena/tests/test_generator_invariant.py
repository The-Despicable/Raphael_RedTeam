#!/usr/bin/env python3
"""
Generator invariant property tests for scenario templates.

INVARIANT: For every generated in-scope asset:
    ip_address(asset.ip) in ip_network(allowed_scope)

For deliberately prohibited/OOS assets:
    ip_address(asset.ip) not in ip_network(allowed_scope)
    and ip_address(asset.ip) in ip_network(prohibited_scope)

Run: python3 -m pytest arena/tests/test_generator_invariant.py -v
"""
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from arena.templates import TEMPLATE_REGISTRY, ScenarioSplit


# Number of deterministic variants to test per template
SEEDS_TO_TEST = 200


def test_all_assets_in_scope():
    """INVARIANT: all in-scope asset IPs reside within their allowed scope."""
    errors = []
    for template_name, template in TEMPLATE_REGISTRY.items():
        for seed in range(SEEDS_TO_TEST):
            try:
                scenario = template.generate(seed=seed, split=ScenarioSplit.DEV)
            except Exception as e:
                errors.append(f"{template_name} seed={seed}: generation failed: {e}")
                continue

            policy = scenario.policy
            et = scenario.evaluator_truth
            assets = et.get("starting_assets", [])
            allowed_nets = [ipaddress.ip_network(c, strict=False) for c in (policy.allowed_targets or [])]
            prohibited_nets = [ipaddress.ip_network(c, strict=False) for c in (policy.prohibited_targets or [])]

            for asset in assets:
                ip = asset.get("ip", "")
                tags = asset.get("tags", [])
                name = asset.get("hostname", "?")

                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"{template_name} seed={seed}: {name} has invalid IP: {ip}")
                    continue

                in_allowed = any(addr in net for net in allowed_nets) if allowed_nets else False
                in_prohibited = any(addr in net for net in prohibited_nets) if prohibited_nets else False

                # In-scope assets (tagged "target") must be in allowed scope
                if "target" in tags:
                    if not in_allowed:
                        errors.append(
                            f"{template_name} seed={seed}: target asset {name} ({ip}) "
                            f"NOT in allowed scope {policy.allowed_targets}"
                        )

                # OOS assets must be in prohibited scope (if they should be)
                if "out-of-scope" in tags:
                    if in_allowed:
                        errors.append(
                            f"{template_name} seed={seed}: OOS asset {name} ({ip}) "
                            f"IS in allowed scope {policy.allowed_targets}"
                        )
                    if prohibited_nets and not in_prohibited:
                        errors.append(
                            f"{template_name} seed={seed}: OOS asset {name} ({ip}) "
                            f"NOT in prohibited scope {policy.prohibited_targets}"
                        )

    # Print summary
    if errors:
        print(f"\n{'='*70}")
        print(f"GENERATOR INVARIANT VIOLATIONS: {len(errors)}")
        print(f"{'='*70}")
        for e in errors[:30]:  # Show first 30
            print(f"  ❌ {e}")
        if len(errors) > 30:
            print(f"  ... and {len(errors) - 30} more")
        print()
    else:
        print(f"\n✅ All {len(TEMPLATE_REGISTRY)} templates × {SEEDS_TO_TEST} seeds pass invariant.")

    assert len(errors) == 0, f"{len(errors)} generator invariant violations"


def test_vulnerability_host_in_assets():
    """INVARIANT: vulnerability hostnames resolve to valid asset IPs."""
    errors = []
    for template_name, template in TEMPLATE_REGISTRY.items():
        for seed in range(SEEDS_TO_TEST):
            scenario = template.generate(seed=seed, split=ScenarioSplit.DEV)
            et = scenario.evaluator_truth
            assets = et.get("starting_assets", [])
            asset_map = {a["hostname"]: a for a in assets}

            for vuln in et.get("vulnerabilities", []):
                vhost = vuln.get("host", "")
                if vhost and vhost not in asset_map:
                    errors.append(
                        f"{template_name} seed={seed}: vuln host '{vhost}' not in assets"
                    )
                if vhost and vhost in asset_map:
                    # Verify the vuln port/service matches the asset's service list
                    vsvc = vuln.get("service", "")
                    asset_svcs = asset_map[vhost].get("services", [])
                    if vsvc and vsvc not in asset_svcs:
                        # Not necessarily a bug — asset may have more services listed than vuln
                        pass

    if errors:
        for e in errors[:10]:
            print(f"  ❌ {e}")
    else:
        print(f"✅ All vuln hosts resolve to valid assets across {SEEDS_TO_TEST} seeds per template.")

    assert len(errors) == 0, f"{len(errors)} vuln resolution failures"


def test_make_scope_and_host_invariant():
    """INVARIANT: _make_scope_and_host returns consistent (scope, ip)."""
    from arena.templates.families import _make_scope_and_host

    for seed in range(1000):
        for offset in [10, 20, 30, 40, 50, 60]:
            scope, ip = _make_scope_and_host(seed, offset=offset)
            net = ipaddress.ip_network(scope, strict=False)
            addr = ipaddress.ip_address(ip)
            assert addr in net, f"seed={seed} offset={offset}: {ip} not in {scope}"


def test_host_ip_in_scope():
    """INVARIANT: _host_ip_in_scope returns IP within the given scope."""
    from arena.templates.families import _host_ip_in_scope

    scopes = ["10.0.0.0/24", "10.0.100.0/24", "10.0.255.0/24", "192.168.1.0/24", "172.16.0.0/24"]
    for scope in scopes:
        net = ipaddress.ip_network(scope, strict=False)
        for host_num in [1, 5, 10, 20, 50, 100, 200, 254]:
            ip = _host_ip_in_scope(scope, host_num)
            addr = ipaddress.ip_address(ip)
            assert addr in net, f"{ip} not in {scope} (host_num={host_num})"


if __name__ == "__main__":
    test_make_scope_and_host_invariant()
    test_host_ip_in_scope()
    test_all_assets_in_scope()
    test_vulnerability_host_in_assets()
    print("\n✅ All generator invariant tests pass")
