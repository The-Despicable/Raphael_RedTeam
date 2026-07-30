import os, base64, hashlib

class Uploader:
    @staticmethod
    def read_file(path: str) -> dict:
        try:
            with open(path, "rb") as f:
                data = f.read()
            return {
                "path": path,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode(),
            }
        except Exception as e:
            return {"error": str(e)}
