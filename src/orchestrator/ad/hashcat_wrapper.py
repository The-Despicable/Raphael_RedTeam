import os, re
from typing import Optional
from orchestrator.kali_tools_client import kali

HASHCAT_MODES = {
    "ntlm": 1000, "krb5tgs": 13100, "krb5asrep": 18200,
    "sha512crypt": 1800, "bcrypt": 3200, "sha1": 100,
}


class HashcatWrapper:
    def __init__(self, wordlist: str = ""):
        self._wordlist = wordlist or "/usr/share/wordlists/rockyou.txt"
        self._available = True

    @property
    def available(self) -> bool:
        return self._available

    async def crack(self, hash_str: str, hash_type: str = "ntlm",
                    timeout: int = 600) -> dict:
        mode = HASHCAT_MODES.get(hash_type, 1000)
        with open("/tmp/hashcat_input.txt", "w") as f:
            f.write(hash_str)
        result = await kali.run_hashcat(
            f"-m {mode} /tmp/hashcat_input.txt {self._wordlist} --show --quiet",
            timeout=timeout
        )
        out = result.get("stdout", "")
        cracked = re.search(r"^[^:]+:([^:]+):(.+)$", out, re.MULTILINE)
        return {
            "success": bool(cracked),
            "plaintext": cracked.group(2) if cracked else None,
            "user": cracked.group(1).split(":")[-1] if cracked else None,
            "output": out[:2000],
        }

    async def crack_file(self, hash_file: str, hash_type: str = "ntlm",
                         timeout: int = 600) -> list[dict]:
        mode = HASHCAT_MODES.get(hash_type, 1000)
        result = await kali.run_hashcat(
            f"-m {mode} {hash_file} {self._wordlist} --show --quiet",
            timeout=timeout
        )
        out = result.get("stdout", "")
        results = []
        for line in out.strip().split("\n"):
            m = re.search(r"^([^:]+):([^:]+):(.+)$", line)
            if m:
                results.append({"user": m.group(2), "hash": m.group(1), "plaintext": m.group(3)})
        return results

    async def bruteforce(self, hash_str: str, hash_type: str = "ntlm",
                         mask: str = "?l?l?l?l?l", timeout: int = 600) -> dict:
        mode = HASHCAT_MODES.get(hash_type, 1000)
        with open("/tmp/hashcat_input.txt", "w") as f:
            f.write(hash_str)
        result = await kali.run_hashcat(
            f"-m {mode} -a 3 /tmp/hashcat_input.txt {mask} --show --quiet",
            timeout=timeout
        )
        out = result.get("stdout", "")
        cracked = re.search(r"^[^:]+:([^:]+):(.+)$", out, re.MULTILINE)
        return {
            "success": bool(cracked),
            "plaintext": cracked.group(2) if cracked else None,
        }
