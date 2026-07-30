import json
import sys
import asyncio
from typing import Callable


class StdioTransport:
    def __init__(self, handler: Callable):
        self.handler = handler

    async def serve(self):
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = await self.handler(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                error = {"error": "Invalid JSON", "id": None}
                sys.stdout.write(json.dumps(error) + "\n")
                sys.stdout.flush()
            except Exception as e:
                error = {"error": str(e), "id": request.get("id") if isinstance(request, dict) else None}
                sys.stdout.write(json.dumps(error) + "\n")
                sys.stdout.flush()
