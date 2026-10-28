#!/usr/bin/env bash
set -euo pipefail
cd /home/yaser/raphael-redteam

# remove any stray temp files from prior runs
rm -f .*.sh tmp_run .mv.sh .mv2.sh .t.sh .q.sh .d.sh .tlast.sh check.sh tmp_run
find . -maxdepth 1 -name ".*.sh" -delete 2>/dev/null || true

echo "=== status ==="
git status --short

git add -A
git -c user.name="The-Despicable" -c user.email="raphael-redteam@users.noreply.github.com" commit -q -F - <<'MSG'
feat(intel): passive OSINT reputation from Mullvad DNS blocklists

- src/orchestrator/intel/dns_reputation.py: domain classifier using Mullvad's
  curated feeds (malware/tracker/ad/adult/social). Cached JSON (~7d TTL),
  suffix + wildcard matching, reputation_score, enrich(). Offline-first: no
  network access during classification.
- scripts/sync_mullvad_dns.py: pulls the lists into data/intel/, CLI.
- tests/test_dns_reputation.py: 4 offline tests.
- RUNTIME.md / README: (TODO) mention integration point.

License: feeds fetched at runtime only; content is GPL-3.0 upstream list
aggregation and is not redistributed.
MSG

echo "=== push ==="
git push origin native-migration 2>&1
echo "=== result ==="
git rev-parse HEAD
git ls-remote --heads origin native-migration
git status --porcelain | wc -l
python3 scripts/check_consistency.py 2>&1 | tail -2
