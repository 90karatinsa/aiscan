"""Gorunmez / sifir genislikli Unicode watermark tarayicisi.

Bu modul metne gomulen ve goz ile gorulemeyen izleri bulur:
  * sifir genislikli karakterler (ZWSP/ZWNJ/ZWJ/WJ/BOM ...)
  * Unicode TAG karakterleri (U+E0000-U+E007F) -- dogrudan ASCII'ye cozulur
  * varyasyon secicileri (U+FE00-FE0F, U+E0100-E01EF) -- bayt bayt cozulur
  * bidi kontrol karakterleri ("Trojan Source" saldirisi)
  * karisik alfabe (homoglif) kelimeler
ve mumkun oldugunda gizlenen mesaji GERI COZER.

NOT: Bu dosyada hicbir gorunmez karakter LITERAL olarak yer almaz; hepsi
chr()/\\u kacislari ile ifade edilir. Boylece dosyanin kendisi temiz kalir.
"""

from __future__ import annotations

import re
import unicodedata

from .model import CRITICAL, HIGH, MEDIUM, Finding

# ---------------------------------------------------------------- karakter kumeleri

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x2800: "BRAILLE PATTERN BLANK",
    0x2028: "LINE SEPARATOR",
    0x2029: "PARAGRAPH SEPARATOR",
}

BIDI_CONTROLS = {
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x061C: "ARABIC LETTER MARK",
}

DEPRECATED_FORMAT = {cp: "DEPRECATED FORMAT CHARACTER" for cp in range(0x206A, 0x2070)}

# Sifir genislikli karakterlerden ikili kodlamada kullanilanlar
ZW_CARRIERS = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)


def _cls(codepoints) -> str:
    """Kod noktalarindan literal olmayan bir regex karakter sinifi kurar."""
    return "".join("\\u%04x" % cp if cp <= 0xFFFF else "\\U%08x" % cp for cp in codepoints)


_ZW_CLS = _cls(ZERO_WIDTH)
_BIDI_CLS = _cls(BIDI_CONTROLS)
_DEP_CLS = _cls(DEPRECATED_FORMAT)
_CARRIER_CLS = _cls(ZW_CARRIERS)

TAG_RANGE = r"\U000e0000-\U000e007f"
VS_RANGE = "\\ufe00-\\ufe0f\\U000e0100-\\U000e01ef"
CTRL_RANGE = r"\x00-\x08\x0b\x0c\x0e-\x1f\x7f"

INVISIBLE_RE = re.compile(
    "[" + _ZW_CLS + _BIDI_CLS + _DEP_CLS + TAG_RANGE + VS_RANGE + CTRL_RANGE + "]")

TAG_RE = re.compile("[" + TAG_RANGE + "]{2,}")
VS_RE = re.compile("[" + VS_RANGE + "]{2,}")
ZW_RUN_RE = re.compile("[" + _CARRIER_CLS + "]{6,}")

# ---------------------------------------------------------------- cozuculer


def decode_tag_chars(s: str) -> str:
    """U+E0020-U+E007E -> ASCII. 'Gorunmez metin' hilesinin dogrudan cozumu."""
    out = []
    for ch in s:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def decode_variation_selectors(s: str) -> bytes:
    """VS1-16 -> 0x00-0x0F, VS17-256 -> 0x10-0xFF (emoji icine bayt gizleme)."""
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def decode_zero_width_binary(s: str) -> list:
    """Sifir genislikli karakter dizisini ikili veri olarak cozmeyi dener.

    Yaygin semalar: ZWSP=0/ZWNJ=1, ZWNJ=0/ZWJ=1 gibi ikili esleme ve 7/8 bit
    gruplama. Okunabilir ASCII ureten her cozumu dondurur.
    """
    results = []
    pairs = [
        (0x200B, 0x200C), (0x200C, 0x200D), (0x200B, 0x200D),
        (0x200C, 0x200B), (0x200D, 0x200C), (0x200D, 0x200B),
        (0x2060, 0xFEFF), (0xFEFF, 0x2060), (0x200B, 0xFEFF),
    ]
    for zero_cp, one_cp in pairs:
        zero, one = chr(zero_cp), chr(one_cp)
        bits = "".join("0" if c == zero else "1" if c == one else "" for c in s)
        if len(bits) < 14:
            continue
        for width in (8, 7):
            if len(bits) < width * 2:
                continue
            chars = []
            for i in range(0, len(bits) - width + 1, width):
                val = int(bits[i:i + width], 2)
                if 32 <= val <= 126 or val in (9, 10, 13):
                    chars.append(chr(val))
                else:
                    chars = []
                    break
            text = "".join(chars)
            if len(text) >= 2 and _plausible_payload(text):
                clean = " (tam)" if len(bits) % width == 0 else " (kismi)"
                results.append(
                    (f"{width}-bit, U+{zero_cp:04X}=0 / U+{one_cp:04X}=1{clean}", text))
    seen, uniq = set(), []
    for scheme, text in results:
        if text not in seen:
            seen.add(text)
            uniq.append((scheme, text))
    return uniq


def _plausible_payload(text: str) -> bool:
    """Cozulen metin gercek bir mesaj mi, rastgele bit yorumu mu?"""
    good = sum(1 for c in text if c.isalnum() or c in " _-.:/@{}\"'()[],=+")
    return good / len(text) >= 0.6


def _printable(b: bytes) -> str:
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return t if t and all(ch.isprintable() or ch in "\n\t" for ch in t) else ""


def char_name(cp: int) -> str:
    if cp in ZERO_WIDTH:
        return ZERO_WIDTH[cp]
    if cp in BIDI_CONTROLS:
        return BIDI_CONTROLS[cp]
    if 0xE0000 <= cp <= 0xE007F:
        return "UNICODE TAG CHARACTER"
    if 0xFE00 <= cp <= 0xFE0F:
        return f"VARIATION SELECTOR-{cp - 0xFE00 + 1}"
    if 0xE0100 <= cp <= 0xE01EF:
        return f"VARIATION SELECTOR-{cp - 0xE0100 + 17}"
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return f"U+{cp:04X}"


# ---------------------------------------------------------------- homoglif

SCRIPT_RANGES = [
    ("Latin", 0x0041, 0x024F),
    ("Greek", 0x0370, 0x03FF),
    ("Cyrillic", 0x0400, 0x04FF),
    ("Armenian", 0x0530, 0x058F),
    ("Hebrew", 0x0590, 0x05FF),
    ("Arabic", 0x0600, 0x06FF),
    ("Cherokee", 0x13A0, 0x13FF),
]

# Latin harf gibi gorunen ama baska alfabeden olan karakterler
CONFUSABLES = set("АВЕКМНОРСТХ"
                  "аеорсухіј"
                  "ΑΒΕΖΗΙΚΜΝΟΡ"
                  "ΤΥΧοαᎠᏂᏒᎩ")

WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)


def _script_of(ch: str) -> str:
    cp = ord(ch)
    for name, lo, hi in SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return ""


def find_mixed_script(line: str) -> list:
    """Ayni kelimede birden fazla alfabe -> homoglif gizleme/watermark.

    Yalnizca Latin bir harfle GORSEL OLARAK KARISTIRILABILIR karakterler
    (CONFUSABLES) bulgu uretir. Matematik/bilim notasyonu (sin0, alfa, omega
    gibi Yunan harfleri) mesru kullanimdir ve elenir.
    """
    hits = []
    for m in WORD_RE.finditer(line):
        word = m.group()
        if word.isascii():
            continue
        if not any(c in CONFUSABLES for c in word):
            continue
        latin = sum(1 for c in word if c.isascii() and c.isalpha())
        foreign = sum(1 for c in word if c in CONFUSABLES)
        if latin < 2:
            continue          # tamami yabanci alfabe: normal yabanci dil metni
        # Saldiri imzasi: cogunlukla Latin bir kelimeye BIRKAC karakter sizdirilmis.
        # "sifreleyici" gibi bastan sona yabanci kelimeler mesru cok dilli metindir.
        if foreign > max(2, int(len(word) * 0.3)):
            continue
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if len(scripts) > 1:
            odd = [f"{c!r} U+{ord(c):04X} ({_script_of(c)})"
                   for c in word if c in CONFUSABLES]
            hits.append((m.start() + 1, word, sorted(scripts), odd[:6]))
    return hits


# ---------------------------------------------------------------- ana tarayici


def scan_unicode(path: str, text: str, max_per_file: int = 40) -> list:
    """Bir metin govdesindeki tum gorunmez/supheli karakter izlerini bulur."""
    findings: list = []
    if text.isascii():
        return findings
    if not INVISIBLE_RE.search(text) and not _has_non_latin(text):
        return findings

    counts: dict = {}
    truncated = False

    for lineno, line in enumerate(text.splitlines(), 1):
        if len(findings) >= max_per_file:
            truncated = True
            break
        if line.isascii():
            continue

        covered = []   # dizi olarak zaten raporlanan araliklar

        # --- 1) TAG karakterleri: dogrudan ASCII'ye cozulur
        for m in TAG_RE.finditer(line):
            covered.append((m.start(), m.end()))
            decoded = decode_tag_chars(m.group())
            findings.append(Finding(
                rule_id="AI-UNI-001", category="hidden-unicode", severity=CRITICAL,
                title="Unicode TAG karakteri ile gizlenmis metin",
                path=path, line=lineno, col=m.start() + 1,
                match=f"{len(m.group())} adet U+E00xx TAG karakteri",
                excerpt=safe_excerpt(line), source="file",
                note="Gorunmez 'tag' blogu dogrudan ASCII'ye cozulur; klasik metin gizleme yontemi.",
                detail=(f"COZULEN GIZLI METIN: {decoded!r}" if decoded else "cozulemedi")))

        # --- 2) Varyasyon secicileri ile bayt gizleme
        for m in VS_RE.finditer(line):
            covered.append((m.start(), m.end()))
            raw = decode_variation_selectors(m.group())
            txt = _printable(raw)
            findings.append(Finding(
                rule_id="AI-UNI-002", category="hidden-unicode", severity=CRITICAL,
                title="Varyasyon secicilerine gomulmus veri",
                path=path, line=lineno, col=m.start() + 1,
                match=f"{len(m.group())} adet varyasyon secici",
                excerpt=safe_excerpt(line), source="file",
                note="Emoji/harf sonrasina eklenen VS dizisi bayt tasir (emoji smuggling).",
                detail=(f"COZULEN GIZLI METIN: {txt!r}" if txt
                        else f"cozulen bayt: {raw.hex(' ') if raw else '-'}")))

        # --- 3) Sifir genislikli ikili kodlama
        for m in ZW_RUN_RE.finditer(line):
            covered.append((m.start(), m.end()))
            decoded = decode_zero_width_binary(m.group())
            detail = "; ".join(f"[{scheme}] -> {txt!r}" for scheme, txt in decoded[:3])
            findings.append(Finding(
                rule_id="AI-UNI-003", category="hidden-unicode", severity=CRITICAL,
                title="Sifir genislikli karakter dizisi (kodlanmis yuk)",
                path=path, line=lineno, col=m.start() + 1,
                match=f"{len(m.group())} adet sifir genislikli karakter",
                excerpt=safe_excerpt(line), source="file",
                note="Ardisik ZW karakterleri rastgele olusmaz; ikili kodlanmis mesaj tasir.",
                detail=("COZULEN GIZLI METIN: " + detail) if detail
                       else "ikili cozum okunabilir metin uretmedi"))

        # --- 4/5) Tekil gorunmez, bidi ve kontrol karakterleri
        for i, ch in enumerate(line):
            cp = ord(ch)
            if cp in BIDI_CONTROLS:
                counts[cp] = counts.get(cp, 0) + 1
                if counts[cp] <= 3:
                    findings.append(Finding(
                        rule_id="AI-UNI-004", category="hidden-unicode", severity=CRITICAL,
                        title="Bidi kontrol karakteri (Trojan Source riski)",
                        path=path, line=lineno, col=i + 1,
                        match=f"U+{cp:04X} {BIDI_CONTROLS[cp]}",
                        excerpt=safe_excerpt(line), source="file",
                        note="Kodun goruntusu ile derlenen hali farklilasabilir."))
            elif cp in ZERO_WIDTH or cp in DEPRECATED_FORMAT:
                if cp == 0x200D and _emoji_join(line, i):
                    continue          # mesru emoji ZWJ dizisi
                counts[cp] = counts.get(cp, 0) + 1
                if counts[cp] <= 3 and not any(a <= i < b for a, b in covered):
                    benign = (cp == 0xFEFF and lineno == 1 and i == 0) or cp == 0x00AD
                    sev = MEDIUM if benign else HIGH
                    findings.append(Finding(
                        rule_id="AI-UNI-005", category="hidden-unicode", severity=sev,
                        title="Gorunmez/sifir genislikli karakter",
                        path=path, line=lineno, col=i + 1,
                        match=f"U+{cp:04X} {char_name(cp)}",
                        excerpt=safe_excerpt(line), source="file",
                        note="Metne goz ile gorulmeyen karakter yerlestirilmis."))
            elif (cp < 0x20 and ch != "\t") or cp == 0x7F:
                counts[cp] = counts.get(cp, 0) + 1
                if counts[cp] <= 2:
                    findings.append(Finding(
                        rule_id="AI-UNI-006", category="hidden-unicode", severity=MEDIUM,
                        title="Beklenmeyen kontrol karakteri",
                        path=path, line=lineno, col=i + 1,
                        match=f"U+{cp:04X} {char_name(cp)}",
                        excerpt=safe_excerpt(line), source="file"))

        # --- 6) Karisik alfabe (homoglif)
        for col, word, scripts, odd in find_mixed_script(line):
            findings.append(Finding(
                rule_id="AI-UNI-007", category="homoglyph", severity=HIGH,
                title="Karisik alfabe (homoglif) kelime",
                path=path, line=lineno, col=col,
                match=word, excerpt=safe_excerpt(line), source="file",
                note="Ayni kelimede birden fazla yazi sistemi: gizli isaretleme ya da taklit karakter.",
                detail=f"alfabeler: {', '.join(scripts)} | supheli: {'; '.join(odd)}"))

    # --- 7) Toplu ozet: ayni gorunmez karakterden cok sayida varsa
    for cp, n in sorted(counts.items()):
        if n > 3:
            findings.append(Finding(
                rule_id="AI-UNI-008", category="hidden-unicode", severity=HIGH,
                title="Gorunmez karakter yogunlugu",
                path=path, line=0, col=0,
                match=f"U+{cp:04X} {char_name(cp)} x{n}",
                excerpt="", source="file",
                note="Dosya genelinde tekrar eden gorunmez karakter -- sistematik isaretleme belirtisi.",
                detail=f"toplam {n} kez (ilk 3 tanesi ayrica listelendi)"))

    if truncated:
        findings.append(Finding(
            rule_id="AI-UNI-009", category="hidden-unicode", severity=MEDIUM,
            title="Unicode bulgu siniri asildi",
            path=path, line=0, col=0,
            match=f"ilk {max_per_file} bulgu listelendi",
            excerpt="", source="file",
            note="Dosyada cok sayida gorunmez karakter var; --max-unicode ile siniri artirin."))

    return findings


def _is_pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
            or 0x1F1E6 <= cp <= 0x1F1FF or cp in (0xFE0F, 0x20E3))


def _emoji_join(line: str, i: int) -> bool:
    """U+200D iki emoji arasinda mi? (mesru emoji birlestirme)"""
    before = line[i - 1] if i > 0 else ""
    after = line[i + 1] if i + 1 < len(line) else ""
    return bool(before and after and _is_pictographic(before) and _is_pictographic(after))


def _has_non_latin(text: str) -> bool:
    for ch in text:
        if ord(ch) > 0x2FF and _script_of(ch):
            return True
    return False


def safe_excerpt(line: str, limit: int = 160) -> str:
    """Gorunmez karakterleri gorunur hale getirerek satiri kisaltir."""
    out = []
    for ch in line[:limit]:
        cp = ord(ch)
        if (cp in ZERO_WIDTH or cp in BIDI_CONTROLS or cp in DEPRECATED_FORMAT
                or 0xE0000 <= cp <= 0xE007F or 0xFE00 <= cp <= 0xFE0F
                or 0xE0100 <= cp <= 0xE01EF or (cp < 0x20 and ch != "\t") or cp == 0x7F):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    s = "".join(out)
    return s + (" ..." if len(line) > limit else "")
