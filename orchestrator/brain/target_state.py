from enum import IntEnum


class CompromiseLevel(IntEnum):
    NONE = 0
    LOW_PRIVILEGE = 1
    HIGH_PRIVILEGE = 2
    DOMAIN_ADMIN = 3


class AttackGraph:
    def __init__(self, target: str) -> None:
        self.target = target
        self.hosts: dict[str, dict] = {}
        self.compromised_hosts: dict[str, CompromiseLevel] = {}

    def add_host(self, host: str, criticality: float = 5.0) -> None:
        self.hosts[host] = {"host": host, "criticality": criticality}

    def compromise(self, target: str, level: CompromiseLevel) -> None:
        self.compromised_hosts[target] = level


def build_target_state(target: str) -> dict:
    return {
        "target": target,
        "compromise_level": CompromiseLevel.NONE,
        "hosts_discovered": [],
        "credentials": [],
        "flags": [],
    }


def summarize_target_state(state: dict) -> str:
    level = state.get("compromise_level", 0)
    hosts = len(state.get("hosts_discovered", []))
    creds = len(state.get("credentials", []))
    return f"Target: {state.get('target', '?')} | Level: {level} | Hosts: {hosts} | Creds: {creds}"


def build_vulnu_state(target: str) -> dict:
    return {
        "target": target,
        "vulnerabilities": [],
        "services": [],
        "compromise_level": CompromiseLevel.NONE,
    }


def list_vulnu_services(state: dict) -> list[dict]:
    return state.get("services", [])
