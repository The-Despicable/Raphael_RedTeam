import asyncio, time, logging, re, json
from urllib.parse import urlparse
from ..conductor import conductor_call, conductor_call_parallel, get_research_route

logger = logging.getLogger("deep_research")

_PHASE_GATES = """
### PHASE 1 — Landscape mapping (do not skip to depth yet)
Run broad, short queries (1–3 words) to map what exists: who are the major
players/authors/organizations, what are the competing terms or framings for
this topic, what time periods or sub-debates exist. Do not go deep on any
single source yet. List at least 8 distinct threads/angles you've identified
before moving to Phase 2.

### PHASE 2 — Depth per thread
For EACH thread identified in Phase 1, run at least 2 additional targeted
searches and read/fetch full source content (not just snippets) for the most
authoritative-looking result. Note what each thread's strongest source
actually claims, in your own words, with the source cited.

### PHASE 3 — Adversarial cross-check
For every non-trivial factual claim you've gathered, explicitly search for
the strongest counter-evidence or disagreement. Search terms like
"[claim] criticism," "[claim] debunked," "[claim] vs," or "[claim]
limitations." If you find none after 2 genuine attempts, note that
explicitly rather than skipping this phase.

### PHASE 4 — Recency check
Run at least 2 searches specifically for the most recent developments,
using the actual current date, not a relative term. If your topic could
plausibly have changed in the last 3 months, you must find and cite
something from that window or explicitly state you searched and found
nothing newer.

### PHASE 5 — Gap audit (mandatory before writing anything)
Before producing any output, answer these and only proceed if all are true:
- [ ] I ran at least the minimum number of searches specified above
- [ ] I have sources from at least the minimum number of distinct domains
- [ ] I actively searched for disagreement, not just confirmation
- [ ] I checked for recent developments, not just historical consensus
- [ ] I can name at least one thing I'm still uncertain about, or explain
     why I'm confident there isn't one
"""


async def _web_search(query: str, max_results: int = 5) -> list:
    results = []
    try:
        from ddgs import DDGS
        def _ddgs():
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))
        raw = await asyncio.wait_for(asyncio.to_thread(_ddgs), timeout=20)
        for r in raw:
            results.append({
                "title": r.get("title", ""),
                "url": r.get("href", ""),
                "snippet": r.get("body", ""),
            })
    except ImportError:
        results = await _bing_search(query, max_results)
    except Exception as e:
        logger.warning(f"ddgs failed: {e}")
        results = await _bing_search(query, max_results)
    return results


async def _bing_search(query: str, max_results: int = 5) -> list:
    import httpx
    results = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            resp = await c.get(
                "https://lite.duckduckgo.com/lite/?q=" + query.replace(" ", "+"),
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            html = resp.text
            if "challenge" not in html.lower():
                rows = re.findall(r'<tr class="(?:result|webresult)".*?>(.*?)</tr>', html, re.DOTALL)
                for row in rows[:max_results]:
                    href_m = re.search(r'href="(https?://[^"]+)"', row)
                    txt_m = re.search(r'>([^<]+)</a>', row)
                    if href_m:
                        results.append({
                            "title": txt_m.group(1).strip() if txt_m else "",
                            "url": href_m.group(1),
                            "snippet": "",
                        })
    except Exception as e:
        logger.warning(f"Bing search failed: {e}")
    return results


async def _fetch_url(url: str) -> str:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
            resp = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
            text = re.sub(r'<script[^>]*>.*?</script>', '', resp.text, flags=re.DOTALL)
            text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
            text = re.sub(r'<[^>]+>', ' ', text)
            return re.sub(r'\s+', ' ', text).strip()[:8000]
    except Exception as e:
        logger.warning(f"Fetch failed: {e}")
        return ""


async def _call(alias, prompt, temperature=0.7, timeout=90, category="default"):
    return await conductor_call(
        alias, prompt, category=category,
        max_tokens=4096, temperature=temperature, timeout=timeout,
        fallback_model="oc-deepseek-free",
    )


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def _format_sources(all_results: list, researched: list) -> str:
    lines = [f"Total search results collected: {len(all_results)}"]
    lines.append(f"Sources fetched and analyzed: {len(researched)}")
    domains = set()
    for r in researched:
        d = _extract_domain(r.get("url", ""))
        if d:
            domains.add(d)
    lines.append(f"Distinct domains: {len(domains)}")
    if researched:
        for m in researched:
            lines.append(f"- {m.get('title', '?')} ({m.get('url', '?')})")
    return "\n".join(lines)


async def handle(question, rounds=2, temperature=0.7):
    config = {}
    if isinstance(question, dict):
        config = question.get("mode_config", {})
        question = question.get("messages", [{}])[-1].get("content", "")

    if not question:
        question = "latest cybersecurity tools, AI red-team techniques"

    min_searches = int(config.get("min_searches", 15))
    min_sources = int(config.get("min_sources", 10))
    min_domains = int(config.get("min_domains", 5))
    total_time = int(config.get("research_time", 600))
    deadline = time.time() + total_time

    logger.info(f"Deep Research — {total_time}s on '{question[:60]}...'")
    logger.info(f"  Minimum: {min_searches} searches, {min_sources} sources, {min_domains} domains")

    all_results = []
    all_queries = []
    researched = []

    def _time_left() -> float:
        return max(0, deadline - time.time())

    # ── Phase 1: Landscape mapping ──
    logger.info("PHASE 1: Landscape mapping")
    phase1_question = f"""You are in PHASE 1 (Landscape Mapping) of an exhaustive research investigation.

Topic: {question}

Generate 8-12 broad, short (1-3 word) search queries that map the landscape.
Cover: major players/authors, competing terms/framings, sub-debates, time periods.
Output ONLY a JSON array of strings: ["query1", "query2", ...]
Do NOT produce analysis yet."""
    pq1 = await _call("oc-deepseek-free", phase1_question, temperature=0.5, timeout=60)
    try:
        queries = json.loads(pq1.strip().strip("```json").strip("```").strip())
    except Exception:
        queries = [question, f"{question} tools", f"{question} research", f"{question} analysis",
                   f"{question} frameworks", f"{question} techniques", f"{question} 2024", f"{question} overview"]
    if not isinstance(queries, list):
        queries = [question]

    for q in queries:
        if _time_left() < 30:
            break
        logger.info(f"  Phase 1 search: {q}")
        all_queries.append(q)
        r = await _web_search(q, 5)
        all_results.extend(r)
        await asyncio.sleep(0.3)

    # Fetch Phase 1 top results
    seen_urls = set()
    for r in all_results[:8]:
        if _time_left() < 30:
            break
        url = r.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            content = await _fetch_url(url)
            if content:
                researched.append({"title": r.get("title", ""), "url": url, "content": content[:5000]})

    # ── Phase 2: Depth per thread ──
    logger.info("PHASE 2: Depth per thread")
    depth_prompt = f"""You are in PHASE 2 (Depth per Thread) of an exhaustive research investigation.

Topic: {question}

Phase 1 identified these threads/queries:
{json.dumps(queries, indent=2)}

Phase 1 returned these sources:
{_format_sources(all_results, researched)}

For the 4-6 most promising threads above, generate 2-3 targeted search queries each
that go deeper. Prioritize sources that are authoritative (papers, official docs, expert analysis).
Output ONLY a JSON array of strings: ["query1", "query2", ...] — at least 8 queries."""

    pq2 = await _call("oc-deepseek-free", depth_prompt, temperature=0.5, timeout=60)
    try:
        depth_queries = json.loads(pq2.strip().strip("```json").strip("```").strip())
    except Exception:
        depth_queries = [f"{question} implementation", f"{question} best practices",
                         f"{question} case study", f"{question} comparison",
                         f"{question} pros and cons", f"{question} limitations",
                         f"{question} roadmap", f"{question} future"]
    if not isinstance(depth_queries, list):
        depth_queries = []

    for q in depth_queries:
        if _time_left() < 60:
            break
        if q not in all_queries:
            logger.info(f"  Phase 2 search: {q}")
            all_queries.append(q)
            r = await _web_search(q, 5)
            all_results.extend(r)
            await asyncio.sleep(0.3)

    # Fetch new results
    for r in all_results:
        if _time_left() < 30:
            break
        url = r.get("url", "")
        if url and url not in seen_urls and len([x for x in researched if x["url"] == url]) == 0:
            if len(researched) >= min_sources:
                break
            seen_urls.add(url)
            content = await _fetch_url(url)
            if content:
                researched.append({"title": r.get("title", ""), "url": url, "content": content[:5000]})

    # ── Phase 3: Adversarial cross-check ──
    logger.info("PHASE 3: Adversarial cross-check")
    research_summary = "\n".join(f"- {m['title']}: {m['content'][:300]}" for m in researched[:10])

    adversarial_prompt = f"""You are in PHASE 3 (Adversarial Cross-Check) of an exhaustive research investigation.

Topic: {question}

Research gathered so far:
{research_summary}

Generate 4-6 search queries specifically designed to find counter-evidence,
disagreement, criticism, or limitations. Use patterns like:
"[claim] criticism", "[claim] debunked", "[claim] vs", "[claim] limitations",
"[claim] alternatives", "[claim] controversy"

Output ONLY a JSON array of strings. These must be adversarial — not confirmatory."""

    pq3 = await _call("oc-deepseek-free", adversarial_prompt, temperature=0.6, timeout=60)
    try:
        adv_queries = json.loads(pq3.strip().strip("```json").strip("```").strip())
    except Exception:
        adv_queries = [f"{question} criticism", f"{question} limitations",
                       f"{question} problems", f"{question} disadvantages",
                       f"{question} alternatives"]
    if not isinstance(adv_queries, list):
        adv_queries = []

    for q in adv_queries:
        if _time_left() < 60:
            break
        if q not in all_queries:
            logger.info(f"  Phase 3 search: {q}")
            all_queries.append(q)
            r = await _web_search(q, 5)
            all_results.extend(r)
            await asyncio.sleep(0.3)

    for r in all_results:
        if _time_left() < 30:
            break
        url = r.get("url", "")
        if url and url not in seen_urls and len([x for x in researched if x["url"] == url]) == 0:
            if len(researched) >= min_sources + 3:
                break
            seen_urls.add(url)
            content = await _fetch_url(url)
            if content:
                researched.append({"title": r.get("title", ""), "url": url, "content": content[:5000]})

    # ── Phase 4: Recency check ──
    logger.info("PHASE 4: Recency check")
    from datetime import datetime
    current_date = datetime.utcnow().strftime("%Y-%m-%d")
    current_year = datetime.utcnow().strftime("%Y")
    recency_queries = [
        f"{question} {current_year}",
        f"{question} {current_date[:7]}",
        f"{question} latest developments {current_year}",
    ]
    for q in recency_queries:
        if _time_left() < 30:
            break
        if q not in all_queries:
            logger.info(f"  Phase 4 search: {q}")
            all_queries.append(q)
            r = await _web_search(q, 5)
            all_results.extend(r)

    for r in all_results:
        if _time_left() < 20:
            break
        url = r.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            content = await _fetch_url(url)
            if content:
                researched.append({"title": r.get("title", ""), "url": url, "content": content[:5000]})
                break

    # ── Phase 5: Audit + synthesis ──
    logger.info("PHASE 5: Audit + synthesis")

    # Count distinct domains
    domains = set()
    for m in researched:
        d = _extract_domain(m.get("url", ""))
        if d:
            domains.add(d)

    audit_note = (f"Audit: {len(all_queries)} searches >= {min_searches} minimum? {len(all_queries) >= min_searches}\n"
                  f"{len(researched)} sources >= {min_sources} minimum? {len(researched) >= min_sources}\n"
                  f"{len(domains)} domains >= {min_domains} minimum? {len(domains) >= min_domains}\n")

    synthesis_prompt = f"""You are producing the final output for an exhaustive research investigation.

TOPIC: {question}

PHASE GATES COMPLETED:
1. Landscape mapping: {len(queries)} broad queries
2. Depth per thread: {len(depth_queries)} targeted queries
3. Adversarial cross-check: {len(adv_queries)} adversarial queries
4. Recency check: searched for {current_date} developments
5. AUDIT: {audit_note}

SOURCES ({len(researched)} from {len(domains)} domains):
{json.dumps([{"title": m["title"], "url": m["url"]} for m in researched], indent=2)}

DETAILED CONTENT:
{json.dumps([{"title": m["title"], "content": m["content"][:2000]} for m in researched], indent=2)}

Output format (ONLY after passing the audit):
1. A short note confirming how many searches you ran and how many distinct domains you cited (the actual audit trail)
2. The synthesized findings, organized by thread/theme, not by search order
3. Explicit callouts of any disagreement or unresolved uncertainty found in the adversarial cross-check — do not smooth this over into a single confident narrative
4. A final "open questions" section listing anything still uncertain from Phase 5"""
    synthesis = await _call("oc-deepseek-free", synthesis_prompt, temperature=0.3, timeout=120, category="strategic")
    if not synthesis or synthesis.startswith("[TIMEOUT") or synthesis.startswith("[ERROR") or synthesis.startswith("[REFUSAL"):
        synthesis = await _call("oc-deepseek-free", synthesis_prompt, temperature=0.3, timeout=120, category="strategic")

    sources_text = "\n".join(f"- {m['title']} ({m['url']})" for m in researched) or "No external sources"

    full = f"""## Deep Research Report — {question}
**Audit trail:** {len(all_queries)} searches, {len(researched)} sources, {len(domains)} distinct domains
**Time budget:** {total_time}s | **Queries:** {len(all_queries)}

### Sources
{sources_text}

### Synthesis
{synthesis or 'No synthesis produced.'}
---
Raphael 2.0 Deep Research (enforced multi-phase)"""

    return {
        "final": full,
        "sources_found": len(all_results),
        "sources_analyzed": len(researched),
        "queries_run": len(all_queries),
        "domains": len(domains),
        "audit_passed": len(all_queries) >= min_searches and len(researched) >= min_sources and len(domains) >= min_domains,
    }
