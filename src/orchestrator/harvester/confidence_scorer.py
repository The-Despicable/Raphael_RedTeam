import math
import time


class ConfidenceScorer:
    def score_cve(self, cve: dict) -> float:
        base = 0.0
        if cve.get("cvss_score", 0) >= 9.0:
            base += 0.3
        elif cve.get("cvss_score", 0) >= 7.0:
            base += 0.2
        elif cve.get("cvss_score", 0) >= 4.0:
            base += 0.1

        if cve.get("exploit_available"):
            base += 0.3

        if cve.get("source") == "cisa_kev":
            base += 0.2
        elif cve.get("source") == "exploit_db":
            base += 0.15

        refs = cve.get("exploit_references", [])
        if isinstance(refs, list):
            github_refs = sum(1 for r in refs if "github.com" in r.lower())
            base += min(0.2, github_refs * 0.05)

        return min(1.0, base)

    def score_repo(self, repo: dict) -> float:
        base = 0.0
        stars = repo.get("stars", 0)
        if stars >= 100:
            base += 0.3
        elif stars >= 30:
            base += 0.2
        elif stars >= 10:
            base += 0.1

        lang = repo.get("language", "").lower()
        if lang in ("python", "go", "rust", "c", "c++", "csharp", "java"):
            base += 0.2
        elif lang in ("ruby", "perl", "php", "powershell"):
            base += 0.1

        cve_refs = repo.get("cve_refs", [])
        if isinstance(cve_refs, list) and len(cve_refs) > 0:
            base += 0.15

        last_commit = repo.get("last_commit", "")
        if last_commit:
            try:
                parsed = time.strptime(last_commit[:10], "%Y-%m-%d")
                days_old = (time.time() - time.mktime(parsed)) / 86400
                if days_old < 30:
                    base += 0.15
                elif days_old < 90:
                    base += 0.1
            except (ValueError, OSError):
                pass

        desc = repo.get("description", "").lower()
        exploit_keywords = ["rce", "remote code", "exploit", "poc", "proof of concept",
                            "buffer overflow", "privilege escalation", "bypass"]
        for kw in exploit_keywords:
            if kw in desc:
                base += 0.05

        return min(1.0, base)

    def score_technique(self, technique: dict) -> float:
        score = 0.0
        source = technique.get("source", "")
        if source == "extracted_repo":
            score += 0.2
        elif source == "cve_feed":
            score += 0.15
        elif source == "web_feed":
            score += 0.1

        if technique.get("verified"):
            score += 0.3
        if technique.get("tested_against_target"):
            score += 0.25
        if technique.get("has_code"):
            score += 0.15

        freq = technique.get("observed_frequency", 0)
        score += min(0.15, freq * 0.03)

        return min(1.0, score)

    def combine(self, scores: list[float], weights: list[float] = None) -> float:
        if not scores:
            return 0.0
        if weights is None:
            weights = [1.0 / len(scores)] * len(scores)
        weighted = sum(s * w for s, w in zip(scores, weights))
        n = len(scores)
        penalty = 1.0 - (0.1 * (n - 1)) if n > 1 else 1.0
        return min(1.0, weighted * max(0.5, penalty))
