import subprocess, shlex, os, shutil
from fastapi import FastAPI, Query, HTTPException

app = FastAPI()

TOOLS_CACHE = {}

@app.on_event("startup")
async def cache_tools():
    paths = os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    for d in paths.split(":"):
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    TOOLS_CACHE[f] = fp
    TOOLS_CACHE["nuclei"] = shutil.which("nuclei")

@app.post("/run")
def run_tool(tool: str = Query(...), args: str = "", timeout: int = 300):
    cmd = shlex.split(f"{tool} {args}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "tool": tool,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' not found")
    except subprocess.TimeoutExpired:
        return {"tool": tool, "returncode": -1, "stdout": "", "stderr": "timed out"}

@app.get("/tools")
def list_tools():
    return {"tools": sorted(TOOLS_CACHE.keys()), "total": len(TOOLS_CACHE)}

@app.get("/health")
def health():
    return {"status": "ok", "tools": len(TOOLS_CACHE)}
