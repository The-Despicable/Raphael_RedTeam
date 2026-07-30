import random
import re
import unicodedata
from typing import Optional, List, Tuple

_ATTRIBUTION_STARTS = (
    "as an ai",
    "as an ai language model",
    "as a language model",
    "i'd be happy to",
    "i'd be delighted to",
    "i'd love to",
    "certainly",
    "of course",
    "great question",
    "excellent question",
    "that's a great question",
    "it's worth noting",
    "it's important to note",
    "it's also worth noting",
)

_BOILERPLATE = (
    "delve", "robust", "navigate the complexities", "navigate the complexity",
    "in today's world", "in today's digital", "landscape", "realm",
    "tapestry", "unleash", "unlock", "harness", "leverage", "synergy",
    "paradigm", "holistic", "comprehensive", "multifaceted", "intricate",
    "nuanced", "pivotal", "crucial", "paramount", "instrumental",
    "foster", "cultivate", "empower", "transformative", "revolutionize",
    "seamless", "effortless", "unparalleled", "unprecedented", "remarkable",
    "extraordinary", "exceptional", "outstanding", "exemplary", "optimal",
    "deep dive", "circle back", "touch base", "moving forward",
    "going forward", "at this point in time", "in the digital age",
    "in an ever-changing world", "in an increasingly", "fast-paced",
    "rapidly evolving", "dynamic environment", "paradigm shift",
    "game changer", "think outside the box", "low-hanging fruit",
    "moving the needle", "take this offline", "boil the ocean",
    "run it up the flagpole", "bandwidth", "optics", "stakeholders",
    "deliverables", "actionable insights", "core competency",
    "best practice", "value add", "double-click on", "drill down",
    "pivot", "scalable", "streamline", "optimize", "maximize",
    "prioritize", "strategize", "monetize", "operationalize",
    "productize", "solutionize", "incentivize", "actualize",
    "materialize", "crystalize", "galvanize", "catalyze", "synthesize",
    "contextualize", "deconstruct", "extrapolate", "extricate", "elucidate",
)

_TRANSITION_STARTS = (
    "additionally", "moreover", "furthermore", "however", "nevertheless",
    "nonetheless", "conversely", "alternatively", "similarly", "likewise",
    "consequently", "subsequently", "accordingly", "therefore", "thus",
    "hence", "as a result", "for example", "for instance", "specifically",
    "in particular", "notably", "importantly", "interestingly", "surprisingly",
    "obviously", "clearly", "admittedly", "undoubtedly", "fortunately",
    "unfortunately", "firstly", "secondly", "thirdly", "finally", "lastly",
    "in conclusion", "to conclude", "to summarize", "in summary", "overall",
    "all in all", "by and large", "on the whole", "in general",
    "generally speaking", "broadly speaking", "as mentioned earlier",
    "as noted above", "as discussed", "as previously stated",
)

_ATTR_START_RE = [
    re.compile(rf"^\s*{re.escape(p)}\b[,:\s]*", re.IGNORECASE)
    for p in _ATTRIBUTION_STARTS
]
_BOILERPLATE_RE = [
    re.compile(rf"\b{re.escape(p)}\b", re.IGNORECASE)
    for p in _BOILERPLATE
]
_TRANSITION_RE = [
    re.compile(rf"^\s*{re.escape(p)}\b[,:\s]*", re.IGNORECASE)
    for p in _TRANSITION_STARTS
]

_EMDASH_RE = re.compile(r"\s*[\u2013\u2014\u2015]\s*")
_EXCLAMATION_RE = re.compile(r"!{2,}")
_QUESTION_RE = re.compile(r"\?{2,}")
_ELLIPSIS_RE = re.compile(r"\.{4,}")
_MULTI_SPACE_RE = re.compile(r" {2,}")
_SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([.,;!?])")
_MISSING_SPACE_RE = re.compile(r"([.!?])([A-Z])")

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")

_ABBREV = frozenset({
    "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "vs", "etc", "e.g", "i.e",
    "u.s", "u.k", "u.n", "e.u", "a.m", "p.m", "ph.d", "b.a", "m.a", "phd",
    "md", "ceo", "cto", "cfo", "coo", "vp", "svp", "evp", "dba", "llc", "inc",
})

_FILLER_WORDS = (
    "actually", "basically", "essentially", "really", "quite",
    "fairly", "pretty", "somewhat", "rather", "kind of", "sort of",
    "i mean", "you know", "like", "so", "anyway", "though",
)

_TARGET_MEAN = 18.0
_TARGET_CV = 0.45


class _ProtectedRegions:
    _PAT = re.compile(r"\x00\d+\x00")

    def __init__(self):
        self._regions: List[Tuple[int, int, str]] = []

    def _store(self, match: re.Match) -> str:
        self._regions.append((0, 0, match.group(0)))
        return f"\x00{len(self._regions) - 1}\x00"

    def protect(self, text: str) -> str:
        self._regions = []
        patterns = [
            re.compile(r"```[\s\S]*?```"),
            re.compile(r"`[^`\n]+`"),
            re.compile(r"https?://\S+"),
            re.compile(r"\[([^\]]+)\]\([^)]+\)"),
        ]
        for pat in patterns:
            text = pat.sub(self._store, text)
        return text

    def restore(self, text: str) -> str:
        def repl(m: re.Match) -> str:
            idx = int(m.group(0)[1:-1])
            if 0 <= idx < len(self._regions):
                return self._regions[idx][2]
            return m.group(0)
        return self._PAT.sub(repl, text)


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _split_sentences(text: str) -> List[str]:
    if not text:
        return []
    parts = _SENTENCE_SPLIT_RE.split(text.strip())
    merged = []
    for part in parts:
        if not merged:
            merged.append(part)
            continue
        prev = merged[-1].strip()
        match = re.search(r"\b([A-Za-z.]+)[.!?]?$", prev)
        if match:
            last = match.group(1).lower().rstrip(".")
            if last in _ABBREV:
                merged[-1] = prev + " " + part
                continue
        merged.append(part)
    return [s for s in merged if s.strip()]


def _word_count(sentence: str) -> int:
    return len(re.findall(r"\b\w+\b", sentence))


def _cv(values: List[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return (var ** 0.5) / mean


def _remove_attribution(text: str) -> str:
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        stripped = line.lstrip()
        if any(p.match(stripped) for p in _ATTR_START_RE):
            continue
        for pat in _BOILERPLATE_RE:
            line = pat.sub("", line)
        st = line.lstrip()
        if st and st[0].islower():
            prefix = line[:len(line) - len(st)]
            line = prefix + st[0].upper() + st[1:]
        cleaned.append(line)
    return "\n".join(cleaned)


def _remove_transitions(text: str) -> str:
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        for pat in _TRANSITION_RE:
            match = pat.search(line)
            if match and line.lstrip().startswith(match.group().strip()):
                line = pat.sub("", line, count=1)
        stripped = line.lstrip()
        if stripped and stripped[0].islower():
            prefix = line[:len(line) - len(stripped)]
            line = prefix + stripped[0].upper() + stripped[1:]
        cleaned.append(line)
    return "\n".join(cleaned)


def _normalize_emdash(text: str, rng: random.Random) -> str:
    def repl(m: re.Match) -> str:
        return rng.choice([", ", "; ", " - ", " "])
    return _EMDASH_RE.sub(repl, text)


def _normalize_punctuation(text: str) -> str:
    text = _EXCLAMATION_RE.sub("!", text)
    text = _QUESTION_RE.sub("?", text)
    text = _ELLIPSIS_RE.sub("...", text)
    return text


def _fix_spacing(text: str) -> str:
    text = _MULTI_SPACE_RE.sub(" ", text)
    text = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", text)
    text = _MISSING_SPACE_RE.sub(r"\1 \2", text)
    return text.strip()


def jitter(text: str, intensity: float = 0.15, seed: Optional[int] = None) -> str:
    if not text or intensity <= 0:
        return text

    rng = random.Random(seed)
    sentences = _split_sentences(text)
    if len(sentences) < 2:
        return text

    wcs = [_word_count(s) for s in sentences]
    if _cv([float(w) for w in wcs]) >= _TARGET_CV * 0.7:
        return text

    result = []
    i = 0
    while i < len(sentences):
        sent = sentences[i]
        wc = _word_count(sent)

        if wc > _TARGET_MEAN * 1.8:
            split_points = [m.end() for m in re.finditer(r",\s+", sent)]
            if split_points and rng.random() < intensity:
                idx = rng.choice(split_points)
                first = sent[:idx].rstrip(", ") + "."
                second = sent[idx:].lstrip(", ").capitalize()
                if not second.endswith((".", "!", "?")):
                    second += "."
                result.append(first)
                sentences.insert(i + 1, second)
                i += 1
                continue

        if wc < _TARGET_MEAN * 0.5 and i + 1 < len(sentences):
            if rng.random() < intensity * 0.6:
                next_sent = sentences[i + 1]
                merged = sent.rstrip(".!?") + ", " + next_sent[0].lower() + next_sent[1:]
                sentences[i] = merged
                sentences.pop(i + 1)
                continue

        if _TARGET_MEAN * 0.5 <= wc <= _TARGET_MEAN * 1.5:
            if rng.random() < intensity * 0.15:
                filler = rng.choice(_FILLER_WORDS)
                sent = sent.rstrip(".!?") + ", " + filler + "."
            elif rng.random() < intensity * 0.08:
                for fw in _FILLER_WORDS:
                    pat = re.compile(rf"\b{re.escape(fw)}\b\s*,?\s*", re.IGNORECASE)
                    new_sent, count = pat.subn("", sent, count=1)
                    if count:
                        sent = new_sent
                        break

        result.append(sent)
        i += 1

    return " ".join(result)


def normalize(text: str, intensity: float = 0.25, seed: Optional[int] = None) -> str:
    if not text or not isinstance(text, str):
        return text if isinstance(text, str) else ""

    protector = _ProtectedRegions()
    text = protector.protect(text)
    text = _nfc(text)

    rng = random.Random(seed)
    original = text

    text = _remove_attribution(text)
    text = _remove_transitions(text)
    text = _normalize_emdash(text, rng)
    text = _normalize_punctuation(text)
    text = _fix_spacing(text)

    text = _remove_attribution(text)
    text = _remove_transitions(text)
    text = _fix_spacing(text)

    text = jitter(text, intensity=intensity, seed=seed)
    text = _fix_spacing(text)
    text = re.sub(r"[.!?]{2,}", ".", text)

    if len(text.strip()) < len(original.strip()) * 0.3:
        text = _normalize_punctuation(original)
        text = _fix_spacing(text)

    text = protector.restore(text)
    return text.strip()
