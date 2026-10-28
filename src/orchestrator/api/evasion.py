"""orchestrator.api.evasion — read-only anti-forensics planning endpoints.

No endpoint here executes anything. `execute` requires RAPHAEL_AF_EXECUTE=1 and
an explicit confirmation token supplied out-of-band, not over HTTP.
"""
from __future__ import annotations

from fastapi import APIRouter, Query

from orchestrator.evasion import phase as phase_mod
from orchestrator.evasion.antiforensics import PROFILES, plan, render_script

router = APIRouter(prefix="/api/evasion", tags=["evasion"])


@router.get("/profiles")
async def list_profiles() -> dict:
    return {
        "profiles": {name: list(cats) for name, cats in PROFILES.items()},
        "phase": phase_mod.COVERING_TRACKS,
        "after": phase_mod.AFTER_PHASE,
        "execute_enabled": False,
    }


@router.get("/plan")
async def get_plan(
    profile: str = Query("standard", description="minimal|standard|full"),
    platform: str = Query("linux", description="linux|windows"),
) -> dict:
    if profile not in PROFILES:
        profile = "standard"
    steps = plan(profile=profile, platform=platform)
    return {
        "profile": profile,
        "platform": platform,
        "count": len(steps),
        "dry_run": True,
        "steps": [s.to_dict() for s in steps],
        "script": render_script(steps, platform=platform),
    }
