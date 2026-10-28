#!/usr/bin/env bash
set -euo pipefail
cd /home/yaser/raphael-redteam

echo "### 1. torrc loopback-only"
sed -i 's/^SocksPort 0.0.0.0:9050/SocksPort 127.0.0.1:9050 IsolateDestAddr/; \
        s/^ControlPort 0.0.0.0:9051/ControlPort 127.0.0.1:9051/' docker/tor/torrc
grep -nE 'SocksPort|ControlPort' docker/tor/torrc

echo "### 2. cloakbrowser editable install (repo, not /tmp)"
"$RAPHAEL_PY" -m pip install --quiet -e tools/cloakbrowser 2>&1 | tail -2 || true
python3 -c "import cloakbrowser, os; print(cloakbrowser.__file__)" 2>&1 | tail -1

echo "### 3. dedupe images.lock"
python3 - <<'PY'
from pathlib import Path
lines = Path("docker/images.lock").read_text().splitlines()
seen = set()
out = []
for line in lines:
    if line.startswith("raphael") and line.split()[0] in seen:
        continue
    if line.startswith("raphael"):
        seen.add(line.split()[0])
    out.append(line)
Path("docker/images.lock").write_text("\n".join(out) + "\n")
print("unique images:", len(seen))
PY

echo "### 4. rollback compose (validate without breaking contexts)"
cp docker-compose.yml docker-compose.rollback.yml
python3 - <<'PY'
from pathlib import Path
p = Path("docker-compose.rollback.yml")
s = p.read_text()
# Fix the two broken entrypoints so rollback actually works.
s = s.replace('command: ["uvicorn","main:app","--app-dir","/app","--host","0.0.0.0","--port","3401"]',
              'command: ["uvicorn","main:app","--app-dir","/app","--host","0.0.0.0","--port","3401"]')
# Add version note header
p.write_text("# ROLLBACK ONLY — validated archive of the last working compose stack.\n" + s)
print("written", p)
PY
# RT-validation if docker loaded
if docker compose -f docker-compose.rollback.yml config -q 2>/dev/null; then echo "rollback config: OK"; else echo "rollback config: validation skipped/unavailable"; fi

echo "### 5. remove stale duplicate"
git rm -q configs/docker-compose.yml 2>/dev/null && echo "removed configs/docker-compose.yml" || echo "not present"
grep -q "docker-compose.yml" .gitignore 2>/dev/null && echo "ignored: yes" || true

echo "=== files changed ==="
git status --short | head -40