import os, subprocess, json

class BounceBack:
    def __init__(self, source_dir: str = "/tmp/BounceBack"):
        self.source_dir = source_dir
        self.available = os.path.isdir(source_dir)

    def deploy(self, listen_port: int, forward_host: str, forward_port: int, protocol: str = "https") -> dict:
        if not self.available:
            return {
                "status": "unavailable",
                "note": f"Clone BounceBack: git clone https://github.com/D00Movenok/BounceBack {self.source_dir}",
                "config": {
                    "listen_port": listen_port,
                    "forward_host": forward_host,
                    "forward_port": forward_port,
                    "protocol": protocol,
                },
            }

        config = {
            "listen": f"0.0.0.0:{listen_port}",
            "forward": f"{forward_host}:{forward_port}",
            "protocol": protocol,
            "headers": {
                "X-Forwarded-For": "{remote_addr}",
                "X-Real-IP": "{remote_addr}",
            },
        }
        config_path = os.path.join(self.source_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        return {
            "status": "configured",
            "config_file": config_path,
            "listen_port": listen_port,
            "forward": f"{forward_host}:{forward_port}",
            "start_command": f"cd {self.source_dir} && python3 bounceback.py --config config.json",
        }

    def status(self) -> dict:
        if not self.available:
            return {"available": False, "source_dir": self.source_dir}
        try:
            running = subprocess.run(["pgrep", "-f", "bounceback"], capture_output=True, text=True)
            return {
                "available": True,
                "source_dir": self.source_dir,
                "running": bool(running.stdout.strip()),
                "pid": running.stdout.strip() or None,
            }
        except Exception:
            return {"available": True, "source_dir": self.source_dir, "running": False}

    def stop(self) -> dict:
        try:
            subprocess.run(["pkill", "-f", "bounceback"], capture_output=True)
            return {"stopped": True}
        except Exception as e:
            return {"stopped": False, "error": str(e)}
