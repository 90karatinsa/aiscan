"""aiscan komut satiri arayuzu."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time

from . import gitscan, report, walker
from .model import (CRITICAL, HIGH, INFO, LOW, MEDIUM, SEVERITY_ORDER, SEVERITY_TR,
                    ScanResult, severity_at_least)
from .rules import RULES_BY_ID, ALL_RULES, GIT_RULES

VERSION = "1.0.0"
IGNORE_FILE = ".aiscanignore"
PRAGMA = "aiscan:ignore"


def fingerprint(f) -> str:
    h = hashlib.sha1(f"{f.rule_id}|{f.path}|{f.match}".encode("utf-8", "replace"))
    return h.hexdigest()[:16]


# ---------------------------------------------------------------- yoksayma


def load_ignore(root: str, extra=()) -> tuple:
    """(yol_desenleri, (kural, yol) ciftleri) dondurur."""
    paths, pairs = list(extra), []
    fp = os.path.join(root, IGNORE_FILE)
    if os.path.isfile(fp):
        with open(fp, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line and line.split(":", 1)[0] in RULES_BY_ID:
                    rid, pat = line.split(":", 1)
                    pairs.append((rid.strip(), pat.strip()))
                else:
                    paths.append(line)
    return tuple(paths), tuple(pairs)


def apply_filters(findings, args, ignore_pairs, baseline) -> list:
    out = []
    for f in findings:
        if not severity_at_least(f.severity, args.min_severity):
            continue
        if args.only and f.rule_id not in args.only:
            continue
        if args.category and f.category not in args.category:
            continue
        if PRAGMA in (f.excerpt or ""):
            continue
        if any(f.rule_id == rid and (fnmatch.fnmatch(f.path, pat) or
                                     fnmatch.fnmatch(os.path.basename(f.path), pat))
               for rid, pat in ignore_pairs):
            continue
        f.fingerprint = fingerprint(f)
        if baseline and f.fingerprint in baseline:
            continue
        out.append(f)
    return out


# ---------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aiscan",
        description="AI tarafindan birakilan iz, imza, watermark ve metadata "
                    "kalintilarini bulan tamamen yerel tarayici.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  aiscan .                                  bulundugun dizini tara
  aiscan /proje --html rapor.html           HTML rapor uret
  aiscan /proje --out-dir ./rapor           tum formatlarda rapor yaz
  aiscan /proje --min-severity high         yalnizca ciddi bulgular
  aiscan /proje --category hidden-unicode   sadece gizli Unicode izleri
  aiscan /proje --no-git --no-binary        yalnizca kaynak metni tara
  aiscan --list-rules                       kural katalogunu goster
""")
    p.add_argument("paths", nargs="*", default=["."],
                   help="taranacak dizin(ler) veya dosya(lar) (varsayilan: .)")
    p.add_argument("--version", action="version", version=f"aiscan {VERSION}")

    g = p.add_argument_group("kapsam")
    g.add_argument("--no-git", action="store_true", help="git gecmisini tarama")
    g.add_argument("--git-limit", type=int, default=5000, help="taranacak azami commit (0=sinirsiz)")
    g.add_argument("--git-all", action="store_true", help="tum dallardaki commit'leri tara")
    g.add_argument("--no-binary", action="store_true", help="ikili dosya metadata'sini tarama")
    g.add_argument("--no-encoded", action="store_true", help="base64 cozumlemesini kapat")
    g.add_argument("--all-files", action="store_true",
                   help=".gitignore ile dislanan dosyalari da tara")
    g.add_argument("--no-vcs", action="store_true", help="git dosya listesini kullanma, dizini gez")
    g.add_argument("--include", action="append", default=[], metavar="GLOB")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    g.add_argument("--include-self", action="store_true",
                   help="aiscan'in kendi kaynagini da tara (kendi kurallarini bulur)")
    g.add_argument("--max-size", type=int, default=10, metavar="MB",
                   help="bu boyuttan buyuk dosyalari atla (varsayilan 10 MB)")
    g.add_argument("--follow-symlinks", action="store_true")

    g = p.add_argument_group("filtre")
    g.add_argument("--min-severity", choices=[CRITICAL, HIGH, MEDIUM, LOW, INFO],
                   default=LOW, help="bu siddetin altindakileri gizle (varsayilan: low)")
    g.add_argument("--only", action="append", default=[], metavar="KURAL_ID",
                   help="yalnizca bu kural(lar)")
    g.add_argument("--disable", action="append", default=[], metavar="KURAL_ID")
    g.add_argument("--category", action="append", default=[], metavar="KATEGORI")
    g.add_argument("--per-rule-cap", type=int, default=5,
                   help="dosya basina ayni kuraldan azami bulgu (varsayilan 5)")
    g.add_argument("--max-unicode", type=int, default=40,
                   help="dosya basina azami Unicode bulgusu")
    g.add_argument("--baseline", metavar="DOSYA", help="bu baseline'daki bulgulari gizle")
    g.add_argument("--write-baseline", metavar="DOSYA", help="mevcut bulgulari baseline olarak yaz")

    g = p.add_argument_group("cikti")
    g.add_argument("--format", choices=["terminal", "json", "md", "csv", "sarif", "html"],
                   default="terminal", help="stdout formati")
    g.add_argument("--json", metavar="DOSYA")
    g.add_argument("--md", metavar="DOSYA")
    g.add_argument("--html", metavar="DOSYA")
    g.add_argument("--csv", metavar="DOSYA")
    g.add_argument("--sarif", metavar="DOSYA")
    g.add_argument("--out-dir", metavar="DIZIN", help="tum formatlarda rapor yaz")
    g.add_argument("--limit", type=int, default=400,
                   help="terminalde gosterilecek azami bulgu (0=hepsi)")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--quiet", "-q", action="store_true", help="ilerleme bilgisini bastir")
    g.add_argument("--jobs", "-j", type=int, default=0, help="paralel surec sayisi")
    g.add_argument("--fail-on", choices=["none", CRITICAL, HIGH, MEDIUM, LOW],
                   default="none", help="bu siddette bulgu varsa cikis kodu 1")
    g.add_argument("--list-rules", action="store_true", help="kural katalogunu yazdir")
    return p


def list_rules() -> None:
    print(f"aiscan {VERSION} — kural katalogu ({len(ALL_RULES) + len(GIT_RULES)} kural)\n")
    groups = {}
    for r in ALL_RULES + GIT_RULES:
        groups.setdefault(r.category, []).append(r)
    from .model import CATEGORY_TR
    for cat in sorted(groups):
        print(f"\n=== {CATEGORY_TR.get(cat, cat)} ({cat}) ===")
        for r in sorted(groups[cat], key=lambda x: x.id):
            print(f"  {r.id:<15} {SEVERITY_TR[r.severity]:<7} {r.title}")
            if r.note:
                print(f"  {'':<15} {'':<7} {r.note}")
    print("\nUnicode motoru kurallari: AI-UNI-001..009 (gizli karakter/homoglif)")
    print("Metadata motoru kurallari: AI-META-001..010 (PNG/EXIF/PDF/Office/C2PA)")
    print("Kodlama motoru: AI-ENC-001 (base64 icine gizlenmis imza)")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        list_rules()
        return 0

    use_color = sys.stdout.isatty() and not args.no_color
    paths = [os.path.abspath(p) for p in (args.paths or ["."])]
    for p in paths:
        if not os.path.exists(p):
            print(f"hata: yol bulunamadi: {p}", file=sys.stderr)
            return 2

    root = paths[0] if len(paths) == 1 else os.path.commonpath(paths)
    if os.path.isfile(root):
        root = os.path.dirname(root)

    disabled = frozenset(x.strip() for a in args.disable for x in a.split(","))
    only = frozenset(x.strip() for a in args.only for x in a.split(","))
    args.only = only
    args.category = frozenset(x.strip() for a in args.category for x in a.split(","))

    ignore_paths, ignore_pairs = load_ignore(root, tuple(args.exclude))
    opts = walker.Options(
        root=root, max_size=args.max_size * 1024 * 1024,
        scan_binary=not args.no_binary, per_rule_cap=args.per_rule_cap,
        max_unicode=args.max_unicode, disabled=disabled,
        excludes=tuple(ignore_paths), includes=tuple(args.include),
        follow_symlinks=args.follow_symlinks, check_encoded=not args.no_encoded,
        include_self=args.include_self, jobs=args.jobs)

    started = time.time()

    # --- dosya kesfi
    files = []
    seen = set()
    for p in paths:
        if os.path.isfile(p):
            rel = os.path.relpath(p, root)
            if rel not in seen:
                seen.add(rel)
                files.append((p, rel))
            continue
        for full, rel in walker.discover(p, opts, use_vcs=not args.no_vcs,
                                         include_ignored=args.all_files):
            key = os.path.relpath(full, root)
            if key not in seen:
                seen.add(key)
                files.append((full, key))

    if not args.quiet:
        print(f"aiscan {VERSION}: {len(files):,} dosya taraniyor...", file=sys.stderr)

    def progress(n, total):
        if not args.quiet:
            print(f"  ... {n:,}/{total:,}", file=sys.stderr)

    res = walker.scan_files(files, opts, progress=progress)
    res.root = root

    # --- git gecmisi
    if not args.no_git:
        for p in paths:
            target = p if os.path.isdir(p) else os.path.dirname(p)
            if not os.path.isdir(os.path.join(target, ".git")):
                continue
            if not args.quiet:
                print("  ... git gecmisi taraniyor", file=sys.stderr)
            gf, commits, err = gitscan.scan_git(
                target, limit=args.git_limit or 1_000_000, all_refs=args.git_all)
            res.findings.extend(gf)
            res.findings.extend(gitscan.scan_git_artifacts(target))
            res.git_commits += commits
            if err and err != "git deposu degil":
                res.errors.append(f"git: {err}")

    res.elapsed = time.time() - started

    # --- filtreleme
    baseline = set()
    if args.baseline and os.path.isfile(args.baseline):
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                baseline = set(json.load(fh).get("parmak_izleri", []))
        except (OSError, ValueError) as exc:
            print(f"uyari: baseline okunamadi: {exc}", file=sys.stderr)

    findings = apply_filters(res.findings, args, ignore_pairs, baseline)

    if args.write_baseline:
        for f in findings:
            f.fingerprint = f.fingerprint or fingerprint(f)
        doc = {"arac": "aiscan", "surum": VERSION, "kok": root,
               "parmak_izleri": sorted({f.fingerprint for f in findings})}
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        print(f"baseline yazildi: {args.write_baseline} ({len(doc['parmak_izleri'])} kayit)",
              file=sys.stderr)

    # --- raporlar
    writers = {
        "json": (args.json, lambda: report.render_json(res, findings, {"version": VERSION})),
        "md": (args.md, lambda: report.render_markdown(res, findings)),
        "html": (args.html, lambda: report.render_html(res, findings)),
        "csv": (args.csv, lambda: report.render_csv(findings)),
        "sarif": (args.sarif, lambda: report.render_sarif(res, findings)),
    }
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        for ext in writers:
            path, fn = writers[ext]
            writers[ext] = (path or os.path.join(args.out_dir, f"aiscan-rapor.{ext}"), fn)

    for ext, (path, fn) in writers.items():
        if not path:
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(fn())
        if not args.quiet:
            print(f"rapor yazildi: {path}", file=sys.stderr)

    if args.format == "terminal":
        sys.stdout.write(report.render_terminal(
            res, findings, min_severity=args.min_severity,
            use_color=use_color, limit=args.limit))
    elif args.format == "json":
        sys.stdout.write(report.render_json(res, findings, {"version": VERSION}) + "\n")
    elif args.format == "md":
        sys.stdout.write(report.render_markdown(res, findings))
    elif args.format == "csv":
        sys.stdout.write(report.render_csv(findings))
    elif args.format == "sarif":
        sys.stdout.write(report.render_sarif(res, findings) + "\n")
    elif args.format == "html":
        sys.stdout.write(report.render_html(res, findings))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
