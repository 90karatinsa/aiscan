"""Ortak veri modelleri ve severity mantigi."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
SEVERITY_TR = {
    CRITICAL: "KRITIK",
    HIGH: "YUKSEK",
    MEDIUM: "ORTA",
    LOW: "DUSUK",
    INFO: "BILGI",
}
SEVERITY_WEIGHT = {CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2, INFO: 0}

# Kategori -> insan okunur ad
CATEGORY_TR = {
    "attribution": "Acik AI imzasi / atif",
    "assistant-leak": "Sohbet asistani metni sizintisi",
    "prompt-leak": "Prompt / sistem mesaji sizintisi",
    "hidden-unicode": "Gorunmez Unicode (gizli watermark)",
    "homoglyph": "Karisik alfabe / homoglif",
    "provenance": "Git gecmisi provenance",
    "tooling": "AI arac artifacti (dosya/dizin)",
    "metadata": "Ikili dosya / dokuman metadata",
    "generator": "Uretici (generator) etiketi",
    "placeholder": "AI kalintisi placeholder / elision",
    "boilerplate": "AI kalibi yorum/aciklama",
    "stylometry": "Uslup parmak izi (istatistiksel)",
    "typography": "Tipografi parmak izi",
    "dependency": "AI SDK bagimliligi",
}


@dataclass
class Finding:
    """Tek bir bulgu."""

    rule_id: str
    category: str
    severity: str
    title: str
    path: str                    # dosya yolu ya da "git:<sha>" gibi sanal kaynak
    line: int = 0                # 1 tabanli, 0 = satir yok
    col: int = 0                 # 1 tabanli
    match: str = ""              # eslesen ham metin (kisaltilmis/escape'li)
    excerpt: str = ""            # bulgunun gectigi satir (kisaltilmis)
    source: str = "file"         # file | git | meta | path | stats
    note: str = ""               # kural aciklamasi
    detail: str = ""             # cozulmus gizli mesaj, decode ciktisi vb.
    fingerprint: str = ""        # tekillestirme / baseline anahtari

    def key(self) -> str:
        return self.fingerprint or f"{self.rule_id}|{self.path}|{self.line}|{self.match}"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class FileStat:
    """Dosya bazli uslup/tipografi sayaclari (istatistiksel sinyal)."""

    path: str
    lines: int = 0
    words: int = 0
    em_dash: int = 0
    curly_quote: int = 0
    nbsp: int = 0
    ellipsis: int = 0
    bullet_arrow: int = 0
    ai_phrases: int = 0
    comment_lines: int = 0
    emoji_headers: int = 0


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    stats: list = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: list = field(default_factory=list)
    elapsed: float = 0.0
    root: str = ""
    git_commits: int = 0

    def extend(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)
        self.stats.extend(other.stats)
        self.files_scanned += other.files_scanned
        self.files_skipped += other.files_skipped
        self.bytes_scanned += other.bytes_scanned
        self.errors.extend(other.errors)


def severity_at_least(sev: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(sev, 9) <= SEVERITY_ORDER.get(minimum, 9)


def risk_score(findings) -> int:
    """0-100 arasi AI izi skoru.

    Skor en yuksek siddet kademesine gore belirlenir; dusuk siddetli
    gurultunun (tipografi/uslup) skoru sismesine izin verilmez. Boylece
    skor ile sozel hukum her zaman tutarli kalir.
    """
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    n_crit = counts.get(CRITICAL, 0)
    n_high = counts.get(HIGH, 0)
    n_med = counts.get(MEDIUM, 0)
    n_low = counts.get(LOW, 0)

    if n_crit:
        base = 65 + min(35, (n_crit - 1) * 5)
    elif n_high:
        base = 32 + min(26, (n_high - 1) * 4)
    elif n_med:
        base = 12 + min(15, (n_med - 1) * 2)
    elif n_low:
        base = min(9, 2 + n_low // 5)
    else:
        base = 0
    return min(100, base)
