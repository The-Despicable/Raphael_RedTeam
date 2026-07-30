import os, subprocess, json

class RedcloudDeploy:
    def __init__(self, source_dir: str = "/tmp/Redcloud"):
        self.source_dir = source_dir
        self.available = os.path.isdir(source_dir)

    def deploy(self, profile: str = "default") -> dict:
        if not self.available:
            return {
                "status": "unavailable",
                "note": f"Clone Redcloud: git clone https://github.com/khast3x/Redcloud {self.source_dir}",
                "profile": profile,
            }

        compose_path = os.path.join(self.source_dir, "docker-compose.yml")
        if not os.path.isfile(compose_path):
            return {
                "status": "missing_compose",
                "note": "docker-compose.yml not found in source dir",
                "source_dir": self.source_dir,
            }

        try:
            r = subprocess.run(
                ["docker-compose", "-f", compose_path, "up", "-d"],
                capture_output=True, text=True, timeout=60,
                cwd=self.source_dir,
            )
            return {
                "status": "deployed",
                "profile": profile,
                "stdout": r.stdout[-500:],
                "stderr": r.stderr[-500:],
                "returncode": r.returncode,
            }
        except FileNotFoundError:
            return {
                "status": "no_docker",
                "note": "docker-compose not found. Install docker + docker-compose.",
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "note": "docker-compose up timed out after 60s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def status(self) -> dict:
        if not self.available:
            return {"available": False, "source_dir": self.source_dir}
        try:
            r = subprocess.run(
                ["docker-compose", "-f", os.path.join(self.source_dir, "docker-compose.yml"), "ps"],
                capture_output=True, text=True, timeout=15,
                cwd=self.source_dir,
            )
            return {
                "available": True,
                "containers": r.stdout,
                "returncode": r.returncode,
            }
        except Exception as e:
            return {"available": True, "error": str(e)}

    def teardown(self) -> dict:
        if not self.available:
            return {"stopped": False, "note": "source dir not found"}
        try:
            r = subprocess.run(
                ["docker-compose", "-f", os.path.join(self.source_dir, "docker-compose.yml"), "down"],
                capture_output=True, text=True, timeout=30,
                cwd=self.source_dir,
            )
            return {"stopped": True, "stdout": r.stdout[-500:], "returncode": r.returncode}
        except Exception as e:
            return {"stopped": False, "error": str(e)}
