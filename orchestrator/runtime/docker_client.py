import json, logging, os, time, uuid
from typing import Optional

logger = logging.getLogger("runtime.docker")


class DockerSandbox:
    def __init__(self, image: str = None):
        self.image = image or os.getenv("STRIX_IMAGE", "ghcr.io/usestrix/strix-sandbox:1.0.0")
        self._client = None
        self._container = None
        self._caido_client = None
        self._session_id = None

    def _get_client(self):
        if self._client is None:
            try:
                import docker
            except ImportError:
                raise RuntimeError("docker Python package is not installed")
            self._client = docker.from_env()
        return self._client

    def image_exists(self) -> bool:
        try:
            self._get_client().images.get(self.image)
            return True
        except Exception:
            return False

    def pull_image(self):
        if not self.image_exists():
            logger.info(f"Pulling sandbox image: {self.image}")
            self._get_client().images.pull(self.image)
            logger.info("Image pulled")

    def create_container(self, mounts: list[dict] = None, exposed_ports: tuple = (),
                         cap_add: list[str] = None) -> str:
        client = self._get_client()
        self.pull_image()
        self._session_id = uuid.uuid4().hex[:12]

        cap_add = cap_add or ["NET_ADMIN", "NET_RAW"]
        create_kwargs = {
            "image": self.image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "cap_add": cap_add,
            "extra_hosts": {"host.docker.internal": "host-gateway"},
            "auto_remove": False,
        }
        if mounts:
            create_kwargs["mounts"] = [
                docker.types.Mount(
                    target=m["target"],
                    source=m["source"],
                    type="bind",
                    read_only=m.get("read_only", True),
                ) for m in mounts
            ]
        if exposed_ports:
            create_kwargs["ports"] = {f"{p}/tcp": ("127.0.0.1", None) for p in exposed_ports}

        container = client.containers.create(**create_kwargs)
        container.start()
        self._container = container
        logger.info(f"Sandbox container created: {container.short_id}")
        return container.id

    def exec_command(self, cmd: list[str], timeout: int = 30, workdir: str = None) -> dict:
        if not self._container:
            return {"error": "no container", "exit_code": -1, "stdout": "", "stderr": "no container"}
        exec_kwargs = {"cmd": cmd, "stdout": True, "stderr": True}
        if workdir:
            exec_kwargs["workdir"] = workdir
        try:
            exit_code, output = self._container.exec_run(**exec_kwargs)
            stdout = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
            return {
                "exit_code": exit_code,
                "stdout": stdout if exit_code == 0 else "",
                "stderr": stdout if exit_code != 0 else "",
                "success": exit_code == 0,
            }
        except Exception as e:
            return {"error": str(e), "exit_code": -1, "stdout": "", "stderr": str(e)}

    def copy_to_container(self, src: str, dst: str):
        if not self._container:
            return
        import tarfile, io
        archive = io.BytesIO()
        arcname = os.path.basename(dst)
        with tarfile.open(fileobj=archive, mode="w") as tar:
            tar.add(src, arcname=arcname)
        archive.seek(0)
        self._container.put_archive(os.path.dirname(dst), archive)

    def get_container_url(self, port: int) -> str:
        if not self._container:
            return f"http://127.0.0.1:{port}"
        try:
            self._container.reload()
            port_info = self._container.attrs["NetworkSettings"]["Ports"].get(f"{port}/tcp")
            if port_info:
                return f"http://{port_info[0]['HostIp']}:{port_info[0]['HostPort']}"
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return f"http://127.0.0.1:{port}"

    def stop(self):
        if self._container:
            try:
                self._container.kill()
            except Exception:
                logger.debug("Non-critical error", exc_info=True)
            try:
                self._container.remove(force=True)
            except Exception:
                logger.debug("Non-critical error", exc_info=True)
            self._container = None
            logger.info("Sandbox container stopped and removed")

    @property
    def running(self) -> bool:
        if not self._container:
            return False
        try:
            self._container.reload()
            return self._container.status == "running"
        except Exception:
            return False
