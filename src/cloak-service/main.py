import sys
import os
import logging
import shutil

sys.path.insert(0, "/app")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

import cloakbrowser as cb

logger = logging.getLogger("cloak-service")

app = FastAPI(title="Cloak Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class LaunchRequest(BaseModel):
    url: str
    viewport: Optional[dict] = None
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    wait: int = 3


def _browser_available() -> bool:
    return shutil.which("cloakbrowser") is not None


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "cloak-service",
        "version": "1.0.0",
        "tor_proxy": os.getenv("TOR_PROXY"),
        "browser_available": _browser_available(),
        "cloakbrowser_binary": shutil.which("cloakbrowser"),
    }


async def _launch(req: LaunchRequest) -> dict:
    try:
        result = await cb.launch_async(
            url=req.url,
            viewport=req.viewport,
            user_agent=req.user_agent,
            proxy=req.proxy or os.getenv("TOR_PROXY"),
            wait=req.wait,
        )
        return {"status": "ok", "broker": "cloakbrowser", "result": result}
    except Exception as e:
        logger.exception("cloakbrowser launch failed")
        raise HTTPException(status_code=502, detail=f"cloakbrowser launch failed: {e}")


@app.post("/launch")
async def launch(req: LaunchRequest):
    return await _launch(req)


@app.post("/cloak")
async def cloak(req: LaunchRequest):
    return await _launch(req)


@app.post("/broker")
async def broker(req: LaunchRequest):
    return await _launch(req)


@app.post("/broker/launch")
async def broker_launch(req: LaunchRequest):
    return await _launch(req)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=3400)
