"""tests/dummy/service.py — minimal FastAPI app used by the integration test.

Serves GET /health -> {"status": "ok"} — the project health contract.
The integration test generates copies of this file parameterized by port.
"""
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
