import json
import logging
import socket
import threading
from typing import Any

logger = logging.getLogger("mesh_engine")


class MeshEngine:
    def __init__(self, listen_port: int = 0) -> None:
        self.peers: dict[str, dict] = {}
        self.listen_port = listen_port
        self._server: socket.socket | None = None

    def discover_peers(self, seed_nodes: list[str]) -> list[dict]:
        discovered = []
        for node in seed_nodes:
            host, port = node.split(":") if ":" in node else (node, "3502")
            try:
                s = socket.create_connection((host, int(port)), timeout=5)
                s.sendall(json.dumps({"type": "ping"}).encode())
                data = s.recv(1024)
                resp = json.loads(data.decode())
                self.peers[node] = {"host": host, "port": int(port), "info": resp}
                s.close()
                discovered.append(self.peers[node])
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                logger.debug(f"Peer {node} unreachable: {e}")
        return discovered

    def gossip_send(self, message: dict) -> None:
        for peer_id, peer_info in self.peers.items():
            try:
                s = socket.create_connection(
                    (peer_info["host"], peer_info["port"]), timeout=5
                )
                s.sendall(json.dumps({"type": "gossip", "data": message}).encode())
                s.close()
            except (socket.timeout, OSError):
                pass
