"""KaliBridge — HTTP client for the Kali tools execution API at localhost:3800."""
import asyncio
import json
import logging
import os
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger("raphael.kali_bridge")


class KaliBridge:
    """
    Wraps HTTP calls to the orchestrator's Kali tools bridge and raw /run endpoint.
    Falls back to subprocess if the API is unavailable.
    """

    def __init__(self, api_url: str = "http://localhost:3800"):
        self._api_url = api_url
        self._available: Optional[bool] = None
        self._session = None

    async def _ensure_session(self):
        if self._session is None or self._session.is_closed:
            import httpx
            self._session = httpx.AsyncClient(
                timeout=httpx.Timeout(600.0),
                limits=httpx.Limits(max_keepalive_connections=5),
            )

    async def check_health(self) -> bool:
        """Check if the API is reachable."""
        try:
            await self._ensure_session()
            resp = await self._session.get(f"{self._api_url}/health", timeout=5)
            if resp.status_code == 200:
                self._available = True
                return True
        except Exception:
            pass
        self._available = False
        return False

    async def run(self, tool: str, args: str, timeout: int = 120) -> dict:
        """
        Run a tool via the Kali bridge.
        Tries /run endpoint first, falls back to subprocess.
        """
        await self._ensure_session()

        # Try API first
        if self._available is None:
            self._available = await self.check_health()

        if self._available:
            try:
                result = await self._api_run(tool, args, timeout)
                if result and result.get("returncode") is not None:
                    if result.get("returncode") >= 0:
                        return result
                    if result.get("error"):
                        logger.debug(f"API returned error ({result['error']}), falling back to subprocess")
                        self._available = False
            except Exception as e:
                logger.debug(f"Kali bridge API call failed: {e}, falling back to subprocess")
                self._available = False

        # Fallback to subprocess
        return await self._subprocess_run(tool, args, timeout)

    async def _api_run(self, tool: str, args: str, timeout: int) -> dict:
        """Call the /run endpoint on the orchestrator."""
        import httpx
        try:
            resp = await self._session.post(
                f"{self._api_url}/run",
                params={"tool": tool, "args": args, "timeout": timeout},
                timeout=httpx.Timeout(timeout + 10),
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"API returned {resp.status_code}: {resp.text[:200]}")
                return {"error": f"HTTP {resp.status_code}", "returncode": -1, "stdout": "", "stderr": resp.text[:500]}
        except httpx.TimeoutException:
            return {"error": f"API timeout ({timeout}s)", "returncode": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
            return {"error": str(e), "returncode": -1, "stdout": "", "stderr": str(e)}

    async def run_nmap(self, target: str, scan_type: str = "quick",
                        ports: Optional[str] = None, timeout: int = 300) -> dict:
        """Use the structured /api/tools/nmap endpoint."""
        await self._ensure_session()
        payload = {
            "target": target,
            "scan_type": scan_type,
            "timeout": timeout,
        }
        if ports:
            payload["ports"] = ports
        try:
            resp = await self._session.post(
                f"{self._api_url}/api/tools/nmap",
                json=payload,
                timeout=httpx.Timeout(timeout + 10),
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "returncode": data.get("returncode", 0),
                    "stdout": data.get("raw_stdout", ""),
                    "stderr": data.get("raw_stderr", ""),
                    "open_ports": data.get("open_ports", []),
                }
        except Exception as e:
            logger.debug(f"Structured nmap API failed: {e}")
            # Fall through to generic run
        return await self.run("nmap",
            f"{target} -Pn -sV" if ports else f"{target} -Pn -T4 -F",
            timeout=timeout)

    async def run_recon(self, target: str, depth: str = "normal",
                         port_scan: bool = True, tech_detect: bool = True,
                         timeout: int = 300) -> dict:
        """Use the structured /api/tools/recon endpoint."""
        await self._ensure_session()
        payload = {
            "target": target,
            "depth": depth,
            "port_scan": port_scan,
            "technology_detect": tech_detect,
            "timeout": timeout,
        }
        try:
            resp = await self._session.post(
                f"{self._api_url}/api/tools/recon",
                json=payload,
                timeout=httpx.Timeout(timeout + 10),
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Structured recon API failed: {e}")
        return {"error": "structured recon unavailable", "returncode": -1}

    async def _subprocess_run(self, tool: str, args: str, timeout: int) -> dict:
        """Fallback: run command via subprocess."""
        import shlex, asyncio
        cmd = f"{tool} {args}"
        logger.debug(f"Subprocess fallback: {cmd[:150]}")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except asyncio.TimeoutError:
            return {"error": "timeout", "returncode": -1, "stdout": "", "stderr": "timeout"}
        except FileNotFoundError:
            return {"error": f"tool not found: {tool}", "returncode": -127, "stdout": "", "stderr": ""}
        except Exception as e:
            return {"error": str(e), "returncode": -1, "stdout": "", "stderr": str(e)}

    async def close(self):
        if self._session and not self._session.is_closed:
            await self._session.aclose()
