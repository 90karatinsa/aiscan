"""Ikili dosya ve dokuman metadata tarayicisi.

Metin olmayan dosyalar da imza tasir: PNG text chunk'lari, EXIF "Software"
alani, PDF /Producer, Office docProps, C2PA "Content Credentials" ve
Stable Diffusion / ComfyUI uretim parametreleri gibi.
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib

from .model import CRITICAL, HIGH, LOW, MEDIUM, Finding

# Ikili govdede aranan AI belirtecleri
BIN_MARKERS = re.compile(
    rb"(?i)(?:generated with claude code|co-?authored-?by:\s*claude|noreply@anthropic\.com|"
    rb"claude\.ai/code|anthropic|openai|chatgpt|gpt-4|gpt-5|copilot|midjourney|"
    rb"stable ?diffusion|stablediffusionxl|automatic1111|comfyui|novelai|dall[- ]?e|"
    rb"firefly|leonardo\.ai|ideogram|runwayml|sora|veo-?\d|imagen|flux\.1|"
    rb"c2pa|contentauth|content credentials|trainedAlgorithmicMedia|"
    rb"ai[- ]generated|generativeai|google/gemini|Adobe Firefly)")

# Metadata alan adi -> siddet
META_KEYS = ("software", "producer", "creator", "creatortool", "generator", "tool",
             "prompt", "parameters", "workflow", "comment", "description", "artist",
             "author", "lastmodifiedby", "application", "xmp", "usercomment",
             "digitalsourcetype", "title", "history")


def _mk(path, rule_id, severity, title, match, note="", detail="", line=0):
    return Finding(rule_id=rule_id, category="metadata", severity=severity, title=title,
                   path=path, line=line, col=0, match=match, excerpt="", source="meta",
                   note=note, detail=detail)


def _clip(s, n=300):
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s[:n] + ("..." if len(s) > n else "")


# ---------------------------------------------------------------- PNG


def scan_png(path: str, data: bytes) -> list:
    out = []
    i = 8
    while i + 8 <= len(data):
        try:
            length = struct.unpack(">I", data[i:i + 4])[0]
            ctype = data[i + 4:i + 8]
        except struct.error:
            break
        payload = data[i + 8:i + 8 + length]
        i += 12 + length
        if length > 20_000_000:
            break
        if ctype in (b"tEXt", b"iTXt", b"zTXt"):
            try:
                if ctype == b"tEXt":
                    key, _, val = payload.partition(b"\x00")
                    text = val.decode("latin-1", "replace")
                elif ctype == b"zTXt":
                    key, _, rest = payload.partition(b"\x00")
                    text = zlib.decompress(rest[1:]).decode("utf-8", "replace")
                else:  # iTXt
                    key, _, rest = payload.partition(b"\x00")
                    cflag = rest[0:1]
                    rest2 = rest[2:]
                    _, _, rest3 = rest2.partition(b"\x00")      # dil etiketi
                    _, _, val = rest3.partition(b"\x00")        # cevrilmis anahtar
                    text = (zlib.decompress(val) if cflag == b"\x01" else val
                            ).decode("utf-8", "replace")
            except (zlib.error, IndexError, UnicodeDecodeError):
                continue
            kname = key.decode("latin-1", "replace")
            sev = HIGH if BIN_MARKERS.search(text.encode("utf-8", "replace")) else LOW
            if sev == HIGH or kname.lower() in ("parameters", "prompt", "workflow"):
                out.append(_mk(path, "AI-META-001",
                               CRITICAL if kname.lower() in ("parameters", "workflow") else sev,
                               "PNG metin bloğunda uretim bilgisi",
                               f"{kname} = {_clip(text, 120)}",
                               note="Goruntu uretim araci PNG icine parametre/etiket yazmis.",
                               detail=_clip(text, 800)))
        elif ctype in (b"caBX", b"iDOT") or ctype == b"IEND":
            if ctype == b"caBX":
                out.append(_mk(path, "AI-META-002", HIGH, "PNG icinde C2PA (Content Credentials)",
                               "caBX chunk", note="Icerik kimlik bilgisi -- AI uretim beyani icerebilir."))
            if ctype == b"IEND":
                break
    return out


# ---------------------------------------------------------------- JPEG / EXIF


EXIF_TAGS = {0x010E: "ImageDescription", 0x0131: "Software", 0x013B: "Artist",
             0x8298: "Copyright", 0x9286: "UserComment", 0x010F: "Make", 0x0110: "Model"}


def scan_jpeg(path: str, data: bytes) -> list:
    out = []
    i = 2
    while i + 4 < len(data):
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xD8, 0xD9):
            i += 2
            continue
        try:
            seglen = struct.unpack(">H", data[i + 2:i + 4])[0]
        except struct.error:
            break
        seg = data[i + 4:i + 2 + seglen]
        if marker == 0xE1:                      # APP1: EXIF veya XMP
            if seg.startswith(b"Exif\x00\x00"):
                out.extend(_parse_exif(path, seg[6:]))
            elif b"ns.adobe.com/xap" in seg[:64] or b"<x:xmpmeta" in seg[:200]:
                txt = seg.decode("utf-8", "replace")
                if BIN_MARKERS.search(seg):
                    out.append(_mk(path, "AI-META-004", HIGH, "XMP metadata'sinda AI izi",
                                   _clip(_xmp_summary(txt), 160),
                                   note="XMP paketinde uretici/AI etiketi.",
                                   detail=_clip(txt, 900)))
        elif marker == 0xFE:                    # yorum
            if BIN_MARKERS.search(seg):
                out.append(_mk(path, "AI-META-005", HIGH, "JPEG yorum alaninda AI izi",
                               _clip(seg.decode("latin-1", "replace"), 160)))
        if marker == 0xDA:                      # goruntu verisi baslar
            break
        i += 2 + seglen
    return out


def _parse_exif(path: str, tiff: bytes) -> list:
    out = []
    if len(tiff) < 8:
        return out
    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        offset = struct.unpack(endian + "I", tiff[4:8])[0]
        count = struct.unpack(endian + "H", tiff[offset:offset + 2])[0]
    except (struct.error, IndexError):
        return out
    for n in range(min(count, 200)):
        base = offset + 2 + n * 12
        try:
            tag, typ, cnt = struct.unpack(endian + "HHI", tiff[base:base + 8])
        except struct.error:
            break
        if tag not in EXIF_TAGS or typ not in (1, 2, 7):
            continue
        size = cnt
        if size <= 4:
            raw = tiff[base + 8:base + 8 + size]
        else:
            try:
                doff = struct.unpack(endian + "I", tiff[base + 8:base + 12])[0]
                raw = tiff[doff:doff + min(size, 4096)]
            except struct.error:
                continue
        val = raw.split(b"\x00")[0].decode("latin-1", "replace").strip()
        if not val:
            continue
        sev = HIGH if BIN_MARKERS.search(val.encode()) else LOW
        if sev == HIGH:
            out.append(_mk(path, "AI-META-003", sev, f"EXIF {EXIF_TAGS[tag]} alaninda AI araci",
                           f"{EXIF_TAGS[tag]} = {_clip(val, 120)}",
                           note="Goruntu metadata'si uretici araci acikca yaziyor."))
    return out


def _xmp_summary(txt: str) -> str:
    keys = re.findall(r"<(?:xmp|dc|photoshop|Iptc4xmpExt|stEvt)?:?(\w+)>([^<]{1,120})</", txt)
    return "; ".join(f"{k}={v.strip()}" for k, v in keys[:6]) or txt[:160]


# ---------------------------------------------------------------- PDF


PDF_FIELDS = re.compile(rb"/(Producer|Creator|Title|Author|Subject|Keywords)\s*\(([^)]{0,300})\)")


def scan_pdf(path: str, data: bytes) -> list:
    out = []
    for m in PDF_FIELDS.finditer(data):
        field = m.group(1).decode()
        val = m.group(2).decode("latin-1", "replace")
        if BIN_MARKERS.search(val.encode("latin-1", "replace")):
            out.append(_mk(path, "AI-META-006", HIGH, f"PDF /{field} alaninda AI araci",
                           f"/{field} = {_clip(val, 140)}",
                           note="PDF uretici alanina AI araci yazilmis."))
    for m in re.finditer(rb"<x:xmpmeta.{0,20000}?</x:xmpmeta>", data, re.S):
        seg = m.group()
        if BIN_MARKERS.search(seg):
            txt = seg.decode("utf-8", "replace")
            out.append(_mk(path, "AI-META-007", HIGH, "PDF XMP metadata'sinda AI izi",
                           _clip(_xmp_summary(txt), 160), detail=_clip(txt, 900)))
    return out


# ---------------------------------------------------------------- Office / ODF / EPUB


OOXML_PARTS = ("docProps/core.xml", "docProps/app.xml", "meta.xml",
               "META-INF/manifest.xml", "word/comments.xml")


def scan_zip_doc(path: str, filepath: str) -> list:
    out = []
    try:
        with zipfile.ZipFile(filepath) as zf:
            names = set(zf.namelist())
            for part in OOXML_PARTS:
                if part not in names:
                    continue
                try:
                    raw = zf.read(part)[:200_000]
                except (KeyError, zlib.error, RuntimeError):
                    continue
                txt = raw.decode("utf-8", "replace")
                for m in re.finditer(r"<(?:dc|cp|meta|Properties|office):?(\w+)[^>]*>"
                                     r"([^<]{1,200})</", txt):
                    key, val = m.group(1).lower(), m.group(2).strip()
                    if key in META_KEYS and BIN_MARKERS.search(val.encode("utf-8", "replace")):
                        out.append(_mk(path, "AI-META-008", HIGH,
                                       f"Dokuman metadata'sinda AI araci ({part})",
                                       f"{m.group(1)} = {_clip(val, 140)}",
                                       note="Office/ODF ozellik alaninda uretici/yazar olarak AI araci."))
            # C2PA manifesti gomulu mu
            for n in names:
                if "c2pa" in n.lower() or n.endswith(".c2pa"):
                    out.append(_mk(path, "AI-META-009", HIGH, "Pakette C2PA manifesti",
                                   n, note="Icerik kimlik bilgisi dosyasi."))
    except (zipfile.BadZipFile, OSError):
        pass
    return out


# ---------------------------------------------------------------- genel ikili


def scan_generic_binary(path: str, data: bytes, limit: int = 4_000_000) -> list:
    """Bilinmeyen ikili formatlarda ham AI belirteci arar."""
    out = []
    seen = set()
    for m in BIN_MARKERS.finditer(data[:limit]):
        token = m.group().lower()
        if token in seen:
            continue
        seen.add(token)
        start = max(0, m.start() - 60)
        ctx = data[start:m.end() + 60].decode("latin-1", "replace")
        ctx = "".join(ch if ch.isprintable() else "." for ch in ctx)
        out.append(_mk(path, "AI-META-010", MEDIUM, "Ikili dosya icinde AI belirteci",
                       token.decode("latin-1", "replace"),
                       note="Ikili govdede AI araci/uretim izi gecen metin.",
                       detail=_clip(ctx, 200)))
        if len(out) >= 8:
            break
    return out


# ---------------------------------------------------------------- yonlendirici

ZIP_DOC_EXT = (".docx", ".dotx", ".xlsx", ".pptx", ".potx", ".odt", ".ods", ".odp",
               ".epub", ".pages", ".numbers", ".key")


def scan_binary(path: str, filepath: str, data: bytes, ext: str) -> list:
    """Dosya turune gore uygun metadata tarayicisini secer."""
    findings: list = []
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        findings += scan_png(path, data)
    elif data[:3] == b"\xff\xd8\xff":
        findings += scan_jpeg(path, data)
    elif data[:5] == b"%PDF-":
        findings += scan_pdf(path, data)
    elif data[:2] == b"PK" and ext in ZIP_DOC_EXT:
        findings += scan_zip_doc(path, filepath)

    if not findings:
        findings += scan_generic_binary(path, data)
    return findings
