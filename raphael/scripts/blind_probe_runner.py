#!/usr/bin/env python3
"""Blind probe runner - fires ChaosMatrix vectors blindly at a TCP port."""
import sys
import json
import socket
from raphael.techniques.payloads.chaos_matrix import ChaosMatrix


def run_blind_probe(target_ip: str, port: int, timeout: float = 2.0) -> dict:
    """Fire all ChaosMatrix vectors at a raw TCP socket."""
    vectors = ChaosMatrix.generate_vectors()
    results = {}

    for vec_name, payload in vectors.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target_ip, int(port)))
            s.send(payload)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            s.close()

            if resp:
                results[vec_name] = resp.decode("utf-8", "ignore")[:500]
            else:
                results[vec_name] = "EMPTY_ACK"

        except ConnectionRefusedError:
            results[vec_name] = "CONN_REFUSED"
        except socket.timeout:
            results[vec_name] = "CONN_TIMEOUT"
        except OSError as e:
            results[vec_name] = f"SOCKET_ERR:{e}"
        except Exception as e:
            results[vec_name] = f"EXCEPTION:{e}"

    return results


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: blind_probe_runner.py <target_ip> <port> [timeout]"}))
        sys.exit(1)

    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0

    results = run_blind_probe(target_ip, port, timeout)
    print(json.dumps(results))


if __name__ == "__main__":
    main()
