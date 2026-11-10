"""Metin tabanli kural motoru.

Iki kademeli calisir:
  1. Tum kurallarin birlesiminden olusan tek bir "master" regex ile dosyada
     aday satirlar bulunur (dosyalarin buyuk cogunlugu burada elenir).
  2. Yalnizca aday satirlarda 70+ kural tek tek calistirilir.
Bu sayede buyuk depolarda tarama hizli kalirken hicbir eslesme kaybolmaz.
"""

from __future__ import annotations

import base64
import binascii
import re
from bisect import bisect_right

from .model import HIGH, LOW, Finding, FileStat
from .rules import TEXT_RULES

MAX_LINE = 4000          # cok uzun satirlarda yalnizca bas kismi taranir
DEFAULT_PER_RULE_CAP = 5  # ayni kuraldan dosya basina raporlanacak azami bulgu


def _non_capturing(pattern: str) -> str:
    """Desendeki yakalama gruplarini yakalamayan gruplara cevirir."""
    out, i, n, in_class = [], 0, len(pattern), False
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            out.append(pattern[i:i + 2]); i += 2; continue
        if in_class:
            out.append(c)
            if c == "]":
                in_class = False
            i += 1; continue
        if c == "[":
            in_class = True; out.append(c); i += 1; continue
        if c == "(":
            out.append("(" if (i + 1 < n and pattern[i + 1] == "?") else "(?:")
            i += 1; continue
        out.append(c); i += 1
    return "".join(out)


class RuleEngine:
    """Derlenmis kural kumesi (surec basina bir kez kurulur)."""

    def __init__(self, rules=None, disabled=frozenset()):
        self.rules = [r for r in (rules or TEXT_RULES) if r.id not in disabled]
        self.compiled = [
            (r, re.compile(r.pattern, re.IGNORECASE if r.ignorecase else 0))
            for r in self.rules
        ]
        ci = [_non_capturing(r.pattern) for r in self.rules if r.ignorecase]
        cs = [_non_capturing(r.pattern) for r in self.rules if not r.ignorecase]
        self.master_ci = re.compile("|".join(f"(?:{p})" for p in ci),
                                    re.IGNORECASE | re.MULTILINE) if ci else None
        self.master_cs = re.compile("|".join(f"(?:{p})" for p in cs),
                                    re.MULTILINE) if cs else None

    def candidate_lines(self, text: str) -> list:
        """Master regex ile eslesme iceren satir numaralarini dondurur."""
        offsets = set()
        for master in (self.master_ci, self.master_cs):
            if master is None:
                continue
            for m in master.finditer(text):
                offsets.add(m.start())
                if len(offsets) > 20000:
                    break
        if not offsets:
            return []
        starts = [0]
        for m in re.finditer(r"\n", text):
            starts.append(m.end())
        return sorted({bisect_right(starts, off) for off in offsets})


_ENGINE_CACHE: dict = {}


def get_engine(disabled=frozenset()) -> RuleEngine:
    key = tuple(sorted(disabled))
    eng = _ENGINE_CACHE.get(key)
    if eng is None:
        eng = RuleEngine(disabled=disabled)
        _ENGINE_CACHE[key] = eng
    return eng


# ---------------------------------------------------------------- uslup sayaclari

_EM = re.compile(r"[–—―]")
_CURLY = re.compile(r"[‘’“”]")
_NBSP = re.compile("[\\u00a0\\u202f\\u2007\\u2009\\u2002\\u2003]")
_ELL = re.compile(r"…")
_ARROW = re.compile(r"[→←⇒•✓]")
_COMMENT = re.compile(r"^\s*(?://|#|--|\*|/\*|<!--)")
_WORD = re.compile(r"\b\w+\b")


def _stats(path: str, text: str, lines: list) -> FileStat:
    st = FileStat(path=path)
    st.lines = len(lines)
    st.words = len(_WORD.findall(text)) if len(text) < 2_000_000 else 0
    st.em_dash = len(_EM.findall(text))
    st.curly_quote = len(_CURLY.findall(text))
    st.nbsp = len(_NBSP.findall(text))
    st.ellipsis = len(_ELL.findall(text))
    st.bullet_arrow = len(_ARROW.findall(text))
    st.comment_lines = sum(1 for ln in lines if _COMMENT.match(ln))
    return st


# ---------------------------------------------------------------- base64 gizleme

_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ENCODED_MARKERS = re.compile(
    r"(?:claude|anthropic|chatgpt|openai|copilot|gpt-[45]|gemini|"
    r"generated with|co-?authored-?by|ai[- ]generated|as an ai)", re.IGNORECASE)


def scan_encoded(path: str, text: str, lines: list, max_hits: int = 10) -> list:
    """Base64 kodlanmis metin icine saklanmis AI imzalarini bulur."""
    findings = []
    if len(text) > 5_000_000:
        return findings
    for lineno, line in enumerate(lines, 1):
        if len(findings) >= max_hits:
            break
        for m in _B64.finditer(line[:MAX_LINE]):
            blob = m.group()
            if len(blob) % 4:
                blob = blob[:len(blob) - (len(blob) % 4)]
            try:
                raw = base64.b64decode(blob, validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            hit = _ENCODED_MARKERS.search(decoded)
            if hit:
                findings.append(Finding(
                    rule_id="AI-ENC-001", category="attribution", severity=HIGH,
                    title="Base64 icine gizlenmis AI imzasi",
                    path=path, line=lineno, col=m.start() + 1,
                    match=blob[:60] + ("..." if len(blob) > 60 else ""),
                    excerpt=line[:160], source="file",
                    note="Kodlanmis veri cozuldugunde AI atif metni iceriyor.",
                    detail=f"COZULEN: {decoded[:300]!r}"))
                break
    return findings


# ---------------------------------------------------------------- ana tarayici


def scan_text(path: str, text: str, ext: str = "", disabled=frozenset(),
              per_rule_cap: int = DEFAULT_PER_RULE_CAP,
              check_encoded: bool = True) -> tuple:
    """Bir metin govdesini tum metin kurallarina karsi tarar.

    Donen: (findings, FileStat)
    """
    engine = get_engine(disabled)
    lines = text.splitlines()
    findings: list = []

    cand = engine.candidate_lines(text)
    if not cand:
        # Duz metinde eslesme yok; imza base64'e saklanmis olabilir.
        if check_encoded:
            findings.extend(scan_encoded(path, text, lines))
        return findings, _stats(path, text, lines)

    per_rule: dict = {}
    suppressed: dict = {}

    for lineno in cand:
        if lineno < 1 or lineno > len(lines):
            continue
        line = lines[lineno - 1]
        probe = line[:MAX_LINE]
        for rule, rx in engine.compiled:
            if rule.skip_ext and ext in rule.skip_ext:
                continue
            for m in rx.finditer(probe):
                n = per_rule.get(rule.id, 0) + 1
                per_rule[rule.id] = n
                if n > per_rule_cap:
                    suppressed[rule.id] = suppressed.get(rule.id, 0) + 1
                    break
                findings.append(Finding(
                    rule_id=rule.id, category=rule.category, severity=rule.severity,
                    title=rule.title, path=path, line=lineno, col=m.start() + 1,
                    match=_clip(m.group()), excerpt=_clip(line, 200),
                    source="file", note=rule.note))

    for rule_id, n in suppressed.items():
        rule = next(r for r, _ in engine.compiled if r.id == rule_id)
        findings.append(Finding(
            rule_id=rule_id, category=rule.category, severity=rule.severity,
            title=rule.title + f" (+{n} ek eslesme)", path=path, line=0, col=0,
            match=f"ayni kuraldan {n} eslesme daha bastirildi",
            excerpt="", source="file",
            note="Tamami icin --per-rule-cap degerini yukseltin."))

    if check_encoded:
        findings.extend(scan_encoded(path, text, lines))

    st = _stats(path, text, lines)
    st.ai_phrases = sum(1 for f in findings if f.category in ("stylometry", "boilerplate"))
    st.emoji_headers = sum(1 for f in findings if f.rule_id in ("AI-BP-006", "AI-BP-007"))
    return findings, st


def _clip(s: str, limit: int = 120) -> str:
    s = s.replace("\t", "    ")
    s = "".join(ch if ch.isprintable() or ch == " " else f"<U+{ord(ch):04X}>" for ch in s)
    return s[:limit] + ("..." if len(s) > limit else "")


# ---------------------------------------------------------------- yol kurallari


_PATH_CACHE: dict = {}


def scan_path(relpath: str, path_rules) -> list:
    findings = []
    compiled = _PATH_CACHE.get(id(path_rules))
    if compiled is None:
        compiled = [(r, re.compile(r.pattern, re.IGNORECASE if r.ignorecase else 0))
                    for r in path_rules]
        _PATH_CACHE[id(path_rules)] = compiled
    for rule, rx in compiled:
        if rx.search(relpath):
            findings.append(Finding(
                rule_id=rule.id, category=rule.category, severity=rule.severity,
                title=rule.title, path=relpath, line=0, col=0,
                match=relpath, excerpt="", source="path", note=rule.note))
    return findings
