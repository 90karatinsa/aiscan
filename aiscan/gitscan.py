"""Git gecmisi provenance tarayicisi.

Kodun kendisi temizlenmis olsa bile git gecmisi izi tutar: commit yazari,
ortak yazar (trailer) satirlari, ajan dal adlari, yerel git yapilandirmasi.
Tum islemler yereldir; hicbir uzak sunucuya baglanti yapilmaz.
"""

from __future__ import annotations

import os
import re
import subprocess

from .model import CRITICAL, HIGH, LOW, MEDIUM, Finding
from .rules import ATTRIBUTION, GIT_RULES

REC = "\x1e"
FLD = "\x1f"

# Ajanlarin actigi tipik dal adi onekleri
AGENT_BRANCH = re.compile(
    r"^(?:origin/)?(?:claude|codex|cursor|copilot|devin|aider|jules|gemini|windsurf|"
    r"cline|roo|amp|goose|openhands|sweep|codegen|antigravity|bolt|lovable|v0|"
    r"ai|llm|agent|bot)[-/_]", re.IGNORECASE)


def _run(args, cwd, timeout=120):
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                                "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C.UTF-8"})
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return None, str(exc)
    if p.returncode != 0:
        return None, p.stderr.decode("utf-8", "replace").strip()
    return p.stdout.decode("utf-8", "replace"), ""


def is_git_repo(root: str) -> bool:
    out, _ = _run(["git", "rev-parse", "--is-inside-work-tree"], root, timeout=20)
    return bool(out and out.strip() == "true")


def scan_git(root: str, limit: int = 5000, all_refs: bool = False,
             scan_branches: bool = True) -> tuple:
    """Git gecmisini tarar. Donen: (findings, taranan_commit_sayisi, hata)"""
    findings: list = []
    if not is_git_repo(root):
        return findings, 0, "git deposu degil"

    git_rules = [(r, re.compile(r.pattern, re.IGNORECASE if r.ignorecase else 0))
                 for r in GIT_RULES]
    # commit mesajlarinda acik atif kurallari da gecerli
    attr_rules = [(r, re.compile(r.pattern, re.IGNORECASE if r.ignorecase else 0))
                  for r in ATTRIBUTION]

    fmt = FLD.join(["%H", "%an", "%ae", "%cn", "%ce", "%aI", "%s", "%b"]) + REC
    args = ["git", "log", f"--max-count={limit}", f"--format={fmt}"]
    if all_refs:
        args.append("--all")
    out, err = _run(args, root, timeout=300)
    if out is None:
        return findings, 0, f"git log basarisiz: {err}"

    commits = 0
    for record in out.split(REC):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split(FLD)
        if len(parts) < 8:
            continue
        sha, an, ae, cn, ce, when, subject, body = parts[:8]
        commits += 1
        ident = f"git:{sha[:10]}"
        meta = f"yazar: {an} <{ae}> | commit'leyen: {cn} <{ce}> | tarih: {when}"
        message = f"{subject}\n{body}"

        # --- yazar / commit'leyen kimligi
        for label, name, mail in (("yazar", an, ae), ("commit'leyen", cn, ce)):
            for rule, rx in git_rules:
                if rule.id != "AI-GIT-001":
                    continue
                if rx.search(name) or rx.search(mail.split("@")[0]):
                    findings.append(Finding(
                        rule_id=rule.id, category=rule.category, severity=rule.severity,
                        title=f"{rule.title} ({label})", path=ident, line=0, col=0,
                        match=f"{name} <{mail}>", excerpt=subject[:160], source="git",
                        note=rule.note, detail=meta))
            if re.search(r"(?i)(?:noreply@anthropic\.com|@openai\.com|copilot@|"
                         r"aider@|devin@|cursor@|bot@)", mail):
                findings.append(Finding(
                    rule_id="AI-GIT-005", category="provenance", severity=CRITICAL,
                    title=f"AI servis e-postasi commit {label} alaninda",
                    path=ident, line=0, col=0, match=f"{name} <{mail}>",
                    excerpt=subject[:160], source="git", detail=meta,
                    note="Commit dogrudan AI aracinin kimligiyle atilmis."))

        # --- commit mesaji
        for lineno, line in enumerate(message.splitlines(), 1):
            if not line.strip():
                continue
            for rule, rx in git_rules + attr_rules:
                if rule.id == "AI-GIT-001":
                    continue
                m = rx.search(line)
                if m:
                    findings.append(Finding(
                        rule_id=rule.id, category=rule.category, severity=rule.severity,
                        title=rule.title, path=ident, line=lineno, col=m.start() + 1,
                        match=m.group()[:140], excerpt=line[:200], source="git",
                        note=rule.note, detail=meta))

    if scan_branches:
        findings.extend(_scan_refs(root))
    findings.extend(_scan_config(root))
    return findings, commits, ""


def _scan_refs(root: str) -> list:
    findings = []
    out, _ = _run(["git", "for-each-ref", "--format=%(refname:short)%09%(objecttype)"], root)
    if not out:
        return findings
    for line in out.splitlines():
        name = line.split("\t")[0].strip()
        if name and AGENT_BRANCH.match(name):
            findings.append(Finding(
                rule_id="AI-GIT-006", category="provenance", severity=HIGH,
                title="AI ajani dal/etiket adi",
                path=f"git:ref/{name}", line=0, col=0, match=name, excerpt="",
                source="git",
                note="Dal adi ajan tarafindan olusturuldugunu gosteren onek tasiyor."))
    return findings


def _scan_config(root: str) -> list:
    """Depo yerel git yapilandirmasinda AI kimligi kalmis mi?"""
    findings = []
    out, _ = _run(["git", "config", "--local", "--list"], root)
    if not out:
        return findings
    for line in out.splitlines():
        if re.search(r"(?i)^(?:user\.(?:name|email)|committer\.)", line) and \
           re.search(r"(?i)(claude|anthropic|openai|chatgpt|copilot|cursor|aider|devin|bot)", line):
            findings.append(Finding(
                rule_id="AI-GIT-007", category="provenance", severity=HIGH,
                title="Depo git yapilandirmasinda AI kimligi",
                path="git:config", line=0, col=0, match=line[:160], excerpt="",
                source="git",
                note="Bu depoda atilan commit'ler AI kimligiyle imzalanacak."))
    return findings


def scan_git_artifacts(root: str) -> list:
    """.git dizinindeki ajan artifactlari (hook, mesaj taslagi, mailmap)."""
    findings = []
    gitdir = os.path.join(root, ".git")
    if not os.path.isdir(gitdir):
        return findings
    marker = re.compile(r"(?i)(claude|anthropic|openai|chatgpt|copilot|cursor|aider|devin|"
                        r"generated with|co-?authored-?by:\s*(?:claude|copilot|cursor))")
    targets = [("COMMIT_EDITMSG", MEDIUM, "Son commit mesaji taslaginda AI imzasi"),
               ("MERGE_MSG", MEDIUM, "Birlestirme mesajinda AI imzasi"),
               ("config", HIGH, "Git yapilandirmasinda AI kimligi"),
               ("info/exclude", LOW, "Git exclude dosyasinda ajan yolu")]
    for rel, sev, title in targets:
        fp = os.path.join(gitdir, rel)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(200_000)
        except OSError:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            m = marker.search(line)
            if m:
                findings.append(Finding(
                    rule_id="AI-GIT-008", category="provenance", severity=sev,
                    title=title, path=f".git/{rel}", line=lineno, col=m.start() + 1,
                    match=m.group()[:120], excerpt=line[:200], source="git"))
    hooks = os.path.join(gitdir, "hooks")
    if os.path.isdir(hooks):
        for name in sorted(os.listdir(hooks)):
            if name.endswith(".sample"):
                continue
            fp = os.path.join(hooks, name)
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(100_000)
            except OSError:
                continue
            m = marker.search(content)
            if m:
                findings.append(Finding(
                    rule_id="AI-GIT-009", category="provenance", severity=HIGH,
                    title="Git hook'unda AI imzasi/otomasyonu",
                    path=f".git/hooks/{name}", line=0, col=0, match=m.group()[:120],
                    excerpt="", source="git",
                    note="Hook her commit'e otomatik imza ekliyor olabilir."))
    return findings
