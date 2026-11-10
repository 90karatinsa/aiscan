"""Dosya kesfi, okuma ve paralel tarama.

Ne taranir: metin dosyalari (kural + Unicode motoru), ikili dosyalar
(metadata motoru) ve dosya yollarinin kendisi (arac artifactlari).
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field

from . import binmeta, textscan, unicodescan
from .model import Finding, ScanResult
from .rules import PATH_ONLY_RULES

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "venv", ".venv", "env", ".env.d", "site-packages", "dist-info",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit",
    ".gradle", ".idea", "DerivedData", "Pods", "Carthage", ".terraform",
    "coverage", ".nyc_output", ".cache", ".parcel-cache", ".turbo",
    "bin.obj", "obj", ".dart_tool", ".expo", "Library",
}

# Bu dizinler AI izi tasidigi icin ASLA atlanmaz (kanit niteliginde)
NEVER_SKIP = {".claude", ".cursor", ".continue", ".aider", ".codeium", ".windsurf",
              ".github", ".specstory", ".cline", ".roo", ".gemini", ".codex"}

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".ico",
    ".heic", ".avif", ".psd", ".ai", ".sketch", ".fig",
    ".pdf", ".docx", ".dotx", ".xlsx", ".pptx", ".potx", ".odt", ".ods", ".odp",
    ".epub", ".pages", ".numbers", ".key",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".m4a", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".db", ".sqlite", ".sqlite3",
}

SKIP_EXT = {".pyc", ".pyo", ".map", ".lock", ".min.js", ".min.css"}


@dataclass
class Options:
    root: str = "."
    max_size: int = 10 * 1024 * 1024
    scan_binary: bool = True
    per_rule_cap: int = 5
    max_unicode: int = 40
    disabled: frozenset = frozenset()
    excludes: tuple = ()
    includes: tuple = ()
    follow_symlinks: bool = False
    check_encoded: bool = True
    include_self: bool = False
    jobs: int = 0


TEXT_HINT_EXT = {".txt", ".md", ".markdown", ".rst", ".json", ".yaml", ".yml", ".toml",
                 ".ini", ".cfg", ".csv", ".tsv", ".xml", ".html", ".htm", ".svg"}


def _is_binary(data: bytes) -> bool:
    chunk = data[:8192]
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    # yuksek oranda kontrol karakteri -> ikili
    ctrl = sum(1 for b in chunk if b < 9 or (13 < b < 32))
    return ctrl / len(chunk) > 0.15


def decode_text(data: bytes) -> tuple:
    """(metin, kodlama) dondurur; Turkce dosyalar icin cp1254 yedegi vardir."""
    for enc in ("utf-8", "utf-8-sig", "utf-16", "cp1254", "latin-1"):
        try:
            return data.decode(enc), enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("latin-1", "replace"), "latin-1/replace"


def scan_one(args) -> tuple:
    """Tek dosya tarar (is parcaciklari icin modul duzeyinde olmali)."""
    filepath, relpath, opts = args
    findings: list = []
    stats = None
    size = 0
    error = ""

    findings.extend(textscan.scan_path(relpath, PATH_ONLY_RULES))

    try:
        size = os.path.getsize(filepath)
        if size > opts.max_size:
            return findings, None, 0, f"{relpath}: boyut siniri asildi ({size} bayt)"
        with open(filepath, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return findings, None, 0, f"{relpath}: okunamadi ({exc})"

    ext = os.path.splitext(relpath)[1].lower()

    if ext in BINARY_EXT or _is_binary(data):
        if opts.scan_binary:
            try:
                findings.extend(binmeta.scan_binary(relpath, filepath, data, ext))
            except Exception as exc:                      # tarayici cokmesin
                error = f"{relpath}: metadata taramasi hata verdi ({exc})"
        return findings, None, size, error

    text, enc = decode_text(data)
    if enc.startswith("cp1254") or enc.startswith("latin-1"):
        pass  # kodlama bilgisi rapora girmiyor, sadece cozumleme icin

    try:
        rule_findings, stats = textscan.scan_text(
            relpath, text, ext=ext, disabled=opts.disabled,
            per_rule_cap=opts.per_rule_cap, check_encoded=opts.check_encoded)
        findings.extend(rule_findings)
        findings.extend(unicodescan.scan_unicode(relpath, text, max_per_file=opts.max_unicode))
    except Exception as exc:
        error = f"{relpath}: tarama hatasi ({exc})"

    return findings, stats, size, error


# ---------------------------------------------------------------- dosya kesfi


def _git_files(root: str, include_ignored: bool) -> list:
    """Git bilinen dosyalari (gitignore'a saygi duyar)."""
    args = ["git", "ls-files", "-z", "--cached", "--others"]
    if not include_ignored:
        args.append("--exclude-standard")
    try:
        p = subprocess.run(args, cwd=root, capture_output=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if p.returncode != 0:
        return []
    names = [n for n in p.stdout.decode("utf-8", "replace").split("\0") if n]
    return names


def _walk_files(root: str, opts: Options, extra_skip: set) -> list:
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
        dirnames[:] = [d for d in dirnames
                       if d in NEVER_SKIP or
                       (d not in DEFAULT_SKIP_DIRS and d not in extra_skip)]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            out.append(rel)
    return out


def discover(root: str, opts: Options, use_vcs: bool = True,
             include_ignored: bool = False, extra_skip=frozenset()) -> list:
    """Taranacak (mutlak, goreli) dosya yollarini belirler."""
    root = os.path.abspath(root)
    rels = []
    if use_vcs and os.path.isdir(os.path.join(root, ".git")):
        rels = _git_files(root, include_ignored)
    if not rels:
        rels = _walk_files(root, opts, set(extra_skip))

    self_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = []
    for rel in rels:
        full = os.path.join(root, rel)
        if not opts.follow_symlinks and os.path.islink(full):
            continue
        if not os.path.isfile(full):
            continue
        if not opts.include_self and os.path.abspath(full).startswith(self_dir + os.sep):
            continue
        if any(part in DEFAULT_SKIP_DIRS and part not in NEVER_SKIP
               for part in rel.split(os.sep)[:-1]):
            continue
        if opts.excludes and any(fnmatch.fnmatch(rel, pat) or
                                 fnmatch.fnmatch(os.path.basename(rel), pat)
                                 for pat in opts.excludes):
            continue
        if opts.includes and not any(fnmatch.fnmatch(rel, pat) or
                                     fnmatch.fnmatch(os.path.basename(rel), pat)
                                     for pat in opts.includes):
            continue
        if os.path.splitext(rel)[1].lower() in SKIP_EXT:
            continue
        result.append((full, rel))
    return sorted(result, key=lambda t: t[1])


def scan_files(files: list, opts: Options, progress=None) -> ScanResult:
    """Dosya listesini (gerekirse paralel) tarar."""
    res = ScanResult(root=opts.root)
    jobs = opts.jobs or min(8, (os.cpu_count() or 2))
    payload = [(full, rel, opts) for full, rel in files]

    def absorb(item):
        findings, stats, size, error = item
        res.findings.extend(findings)
        if stats is not None:
            res.stats.append(stats)
        res.bytes_scanned += size
        if error:
            res.errors.append(error)
            if "boyut siniri" in error or "okunamadi" in error:
                res.files_skipped += 1
                return
        res.files_scanned += 1

    if jobs > 1 and len(payload) > 40:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for n, item in enumerate(pool.map(scan_one, payload, chunksize=16), 1):
                absorb(item)
                if progress and n % 250 == 0:
                    progress(n, len(payload))
    else:
        for n, args in enumerate(payload, 1):
            absorb(scan_one(args))
            if progress and n % 250 == 0:
                progress(n, len(payload))
    return res
