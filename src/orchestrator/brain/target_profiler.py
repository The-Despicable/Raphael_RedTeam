import json
import logging
import os
import re
import socket
import subprocess

logger = logging.getLogger("target_profiler")

_profile_cache: dict[str, dict] = {}


def _nmap_scan(target: str) -> dict:
    ports = []
    services = []
    os_guess = "unknown"
    try:
        result = subprocess.run(
            ["nmap", "-T4", "-F", "-O", "--osscan-guess", target],
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout + result.stderr
        for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", output, re.MULTILINE):
            ports.append(int(m.group(1)))
            services.append(m.group(3))
        os_match = re.search(r"OS details: (.+)", output)
        if os_match:
            os_guess = os_match.group(1).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"nmap scan failed for {target}: {e}")
    return {"ports": ports, "services": services, "os_guess": os_guess}


def _classify_target(ports: list[int], services: list[str], os_guess: str) -> dict:
    type_label = "unknown"
    risk_label = "unknown"
    critical_ports = {22, 3389, 5985, 5986, 445, 139, 135, 389, 636, 88, 464}
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 9090}
    domain_ports = {88, 389, 636, 464, 3268, 3269}
    db_ports = {1433, 1521, 3306, 5432, 27017, 6379, 11211}

    port_set = set(ports)
    if port_set & domain_ports:
        type_label = "domain-controller"
        risk_label = "critical"
    elif port_set & critical_ports:
        type_label = "infrastructure"
        risk_label = "high"
    elif port_set & web_ports:
        type_label = "web-server"
        risk_label = "medium"
    elif port_set & db_ports:
        type_label = "database"
        risk_label = "high"
    elif ports:
        type_label = "generic-host"
        risk_label = "low"

    os_lower = os_guess.lower()
    if "windows" in os_lower:
        risk_label = max(risk_label, "high", key=lambda x: ["unknown", "low", "medium", "high", "critical"].index(x))
    return {"type": type_label, "risk": risk_label}


def profile_target(target: str) -> dict:
    if target in _profile_cache:
        return _profile_cache[target]

    ip = target
    hostname = target
    if not target.replace(".", "").isdigit():
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = target
    else:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ip

    nmap_data = _nmap_scan(ip)
    classification = _classify_target(
        nmap_data["ports"], nmap_data["services"], nmap_data["os_guess"]
    )

    profile = {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "ports": nmap_data["ports"],
        "services": nmap_data["services"],
        "os_guess": nmap_data["os_guess"],
        "classification": classification,
        "tags": [],
    }
    _profile_cache[target] = profile
    return profile
