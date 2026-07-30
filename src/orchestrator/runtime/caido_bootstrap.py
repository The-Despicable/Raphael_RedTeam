import asyncio, json, logging
from typing import Optional

logger = logging.getLogger("runtime.caido")

CAIDO_CONTAINER_PORT = 48080
CAIDO_CONTAINER_URL = f"http://127.0.0.1:{CAIDO_CONTAINER_PORT}"

_LOGIN_MUTATION = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


class CaidoProxy:
    def __init__(self):
        self._client = None
        self._project_id = None
        self._access_token = None

    def bootstrap(self, sandbox, attempts: int = 10) -> bool:
        for i in range(1, attempts + 1):
            result = sandbox.exec_command([
                "curl", "-fsS", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", _LOGIN_MUTATION,
                f"{CAIDO_CONTAINER_URL}/graphql",
            ], timeout=15)
            if result["success"]:
                try:
                    payload = json.loads(result["stdout"])
                    token = (payload.get("data", {}).get("loginAsGuest", {}).get("token", {}).get("accessToken"))
                    if token:
                        self._access_token = str(token)
                        logger.info(f"Caido guest token acquired (attempt {i})")
                        return self._create_project(sandbox)
                except json.JSONDecodeError as e:
                    logger.debug(f"Caido response parse error: {e}")
            else:
                logger.debug(f"Caido not ready (attempt {i}/{attempts}): {result.get('stderr', '')[:100]}")
            import time
            time.sleep(min(2.0 * i, 8.0))
        logger.warning("Caido bootstrap failed after %d attempts", attempts)
        return False

    def _create_project(self, sandbox) -> bool:
        try:
            from caido_sdk_client import Client, TokenAuthOptions
            from caido_sdk_client.types import CreateProjectOptions
        except ImportError:
            logger.warning("caido_sdk_client not installed — skipping project creation")
            return True

        host_url = sandbox.get_container_url(CAIDO_CONTAINER_PORT)
        self._client = Client(host_url, auth=TokenAuthOptions(token=self._access_token))

        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._client.connect())
            project = loop.run_until_complete(
                self._client.project.create(CreateProjectOptions(name="raphael-sandbox", temporary=True))
            )
            loop.run_until_complete(self._client.project.select(project.id))
            self._project_id = project.id
            loop.close()
            logger.info(f"Caido project created: {project.id}")
            return True
        except Exception as e:
            logger.warning(f"Caido project creation failed: {e}")
            return False

    def set_container_proxy(self, sandbox):
        sandbox.exec_command([
            "bash", "-c",
            "cat >> /etc/environment <<'EOF'\n"
            "http_proxy=http://127.0.0.1:48080\n"
            "https_proxy=http://127.0.0.1:48080\n"
            "HTTP_PROXY=http://127.0.0.1:48080\n"
            "HTTPS_PROXY=http://127.0.0.1:48080\n"
            "EOF"
        ])
        sandbox.exec_command([
            "bash", "-c",
            "mkdir -p /etc/systemd/system/docker.service.d && "
            "cat > /etc/systemd/system/docker.service.d/proxy.conf <<'EOF'\n"
            "[Service]\n"
            "Environment=HTTP_PROXY=http://127.0.0.1:48080\n"
            "Environment=HTTPS_PROXY=http://127.0.0.1:48080\n"
            "Environment=NO_PROXY=localhost,127.0.0.1\n"
            "EOF"
        ])
        logger.info("Container proxy configured through Caido")

    def capture_enabled(self) -> bool:
        if self._client is not None:
            return True
        return self._access_token is not None

    def get_requests(self, limit: int = 50, sandbox=None, full: bool = False) -> list:
        if self._client:
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    self._client.request.list()
                )
                loop.close()
                if result:
                    return list(result)[:limit]
            except Exception:
                logger.debug("Non-critical error", exc_info=True)
        if sandbox and self._access_token:
            fields = "id,host,method,path,port,isTls,length" if not full else "id,host,method,path,query,port,isTls,sni,length"
            q = json.dumps({
                "query": f"{{requests(first:{limit}){{edges{{node{{{fields}}}}}}}}}"
            })
            result = sandbox.exec_command([
                "curl", "-fsS",
                "-H", f"Authorization: Bearer {self._access_token}",
                f"{CAIDO_CONTAINER_URL}/graphql",
                "-d", q,
            ], timeout=10)
            if result["success"]:
                try:
                    return json.loads(result["stdout"]).get("data", {}).get("requests", {}).get("edges", [])
                except Exception:
                    logger.debug("Non-critical error", exc_info=True)
        return []
