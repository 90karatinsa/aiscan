"""Rapor ureticileri: terminal, JSON, Markdown, CSV, SARIF, HTML."""

from __future__ import annotations

import csv
import datetime as _dt
import html
import io
import json
import os
from collections import Counter, defaultdict

from .model import (CATEGORY_TR, CRITICAL, HIGH, INFO, LOW, MEDIUM, SEVERITY_ORDER,
                    SEVERITY_TR, Finding, risk_score)

COLORS = {
    CRITICAL: "\033[1;97;41m", HIGH: "\033[1;31m", MEDIUM: "\033[33m",
    LOW: "\033[36m", INFO: "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _c(text, code, use_color=True):
    return f"{code}{text}{RESET}" if use_color else text


def sort_key(f: Finding):
    return (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line, f.rule_id)


# ---------------------------------------------------------------- uslup sinyalleri


def style_signals(stats, min_words: int = 120) -> list:
    """Dosya bazli tipografi/uslup yogunlugundan zayif sinyaller uretir."""
    out = []
    for st in stats:
        if st.words < min_words:
            continue
        per_k = lambda n: (n * 1000.0) / max(st.words, 1)
        reasons = []
        score = 0
        if per_k(st.em_dash) >= 2.0:
            reasons.append(f"em-tire yogunlugu {per_k(st.em_dash):.1f}/1000 kelime")
            score += 2
        if per_k(st.curly_quote) >= 4.0:
            reasons.append(f"kivrik tirnak {per_k(st.curly_quote):.1f}/1000")
            score += 1
        if st.nbsp:
            reasons.append(f"{st.nbsp} kirilmayan bosluk")
            score += 2
        if per_k(st.ellipsis) >= 1.5:
            reasons.append(f"uc-nokta karakteri {st.ellipsis} kez")
            score += 1
        if st.ai_phrases >= 4:
            reasons.append(f"{st.ai_phrases} AI kalibi ifade")
            score += 2
        if st.emoji_headers >= 3:
            reasons.append(f"{st.emoji_headers} emoji basligi")
            score += 2
        if st.lines and st.comment_lines / max(st.lines, 1) > 0.45 and st.lines > 60:
            reasons.append(f"yorum orani %{100*st.comment_lines/st.lines:.0f}")
            score += 1
        if score >= 4:
            out.append((st.path, score, reasons))
    return sorted(out, key=lambda t: -t[1])


def verdict(findings) -> tuple:
    """(baslik, aciklama) seklinde genel hukum."""
    sev = Counter(f.severity for f in findings)
    if sev[CRITICAL]:
        return ("AI IZI DOGRULANDI",
                "Dogrudan AI atif/imza kaniti bulundu. Bunlar tesadufi olamaz.")
    if sev[HIGH] >= 3:
        return ("GUCLU AI BELIRTISI",
                "Birden fazla yuksek guvenilirlikli iz var; elle dogrulama onerilir.")
    if sev[HIGH]:
        return ("SUPHELI",
                "Yuksek siddetli tek/az sayida iz; baglami kontrol edin.")
    if sev[MEDIUM]:
        return ("ZAYIF BELIRTI", "Yalnizca dolayli isaretler bulundu.")
    if sev[LOW]:
        return ("TEMIZE YAKIN", "Sadece uslup/tipografi duzeyinde zayif sinyaller var.")
    return ("TEMIZ", "Bilinen hicbir AI izi bulunamadi.")


# ---------------------------------------------------------------- terminal


def render_terminal(res, findings, min_severity=LOW, use_color=True, limit=0,
                    show_stats=True) -> str:
    buf = io.StringIO()
    w = buf.write
    sev_counts = Counter(f.severity for f in findings)
    cat_counts = Counter(f.category for f in findings)
    rule_counts = Counter(f.rule_id for f in findings)
    file_counts = Counter(f.path for f in findings if f.source != "git")

    title, desc = verdict(findings)
    score = risk_score(findings)

    w("\n" + _c("═" * 78, DIM, use_color) + "\n")
    w(_c("  AISCAN — AI iz / imza / watermark taramasi", BOLD, use_color) + "\n")
    w(_c("═" * 78, DIM, use_color) + "\n")
    w(f"  Kok dizin      : {res.root}\n")
    w(f"  Taranan dosya  : {res.files_scanned:,}  "
      f"({res.bytes_scanned/1048576:.1f} MB, {res.elapsed:.1f} sn)\n")
    if res.git_commits:
        w(f"  Git commit     : {res.git_commits:,} kayit tarandi\n")
    if res.files_skipped:
        w(f"  Atlanan dosya  : {res.files_skipped:,}\n")
    w(f"  Toplam bulgu   : {len(findings):,}\n")

    badge = COLORS[CRITICAL] if score >= 60 else COLORS[HIGH] if score >= 30 else \
        COLORS[MEDIUM] if score >= 10 else COLORS[LOW]
    w(f"  Risk skoru     : {_c(f' {score}/100 ', badge, use_color)}  "
      f"{_c(title, BOLD, use_color)}\n")
    w(f"                   {desc}\n")

    w("\n" + _c("  SIDDET DAGILIMI", BOLD, use_color) + "\n")
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        n = sev_counts.get(sev, 0)
        if n:
            bar = "█" * min(40, max(1, n * 40 // max(sev_counts.values())))
            w(f"    {_c(SEVERITY_TR[sev].ljust(7), COLORS[sev], use_color)} "
              f"{n:>6,}  {_c(bar, COLORS[sev], use_color)}\n")

    if cat_counts:
        w("\n" + _c("  KATEGORILER", BOLD, use_color) + "\n")
        for cat, n in cat_counts.most_common():
            w(f"    {n:>6,}  {CATEGORY_TR.get(cat, cat)}\n")

    if file_counts:
        w("\n" + _c("  EN COK IZ TASIYAN DOSYALAR", BOLD, use_color) + "\n")
        for path, n in file_counts.most_common(10):
            w(f"    {n:>6,}  {path}\n")

    w("\n" + _c("─" * 78, DIM, use_color) + "\n")
    w(_c("  BULGULAR", BOLD, use_color) + "\n")
    w(_c("─" * 78, DIM, use_color) + "\n")

    shown = 0
    by_file = defaultdict(list)
    for f in sorted(findings, key=sort_key):
        by_file[f.path].append(f)

    for path in sorted(by_file, key=lambda p: (SEVERITY_ORDER.get(
            min((x.severity for x in by_file[p]), key=lambda s: SEVERITY_ORDER[s]), 9), p)):
        group = by_file[path]
        w("\n" + _c(f"  {path}", BOLD, use_color) +
          _c(f"  ({len(group)} bulgu)", DIM, use_color) + "\n")
        for f in group:
            if limit and shown >= limit:
                w(_c(f"\n  ... ve {len(findings) - shown} bulgu daha "
                     f"(--limit 0 ile tamamini gorun)\n", DIM, use_color))
                return buf.getvalue()
            loc = f"{f.line}:{f.col}" if f.line else "-"
            w(f"    {_c(SEVERITY_TR[f.severity].ljust(7), COLORS[f.severity], use_color)} "
              f"{_c(f.rule_id.ljust(13), DIM, use_color)} {loc:>9}  {f.title}\n")
            if f.match:
                w(f"              {_c('eslesme:', DIM, use_color)} {f.match}\n")
            if f.excerpt and f.excerpt.strip() != f.match.strip():
                w(f"              {_c('satir  :', DIM, use_color)} {f.excerpt.strip()[:150]}\n")
            if f.detail:
                w(f"              {_c('detay  :', COLORS[CRITICAL] if 'COZULEN' in f.detail else DIM, use_color)} {f.detail[:300]}\n")
            if f.note:
                w(f"              {_c('not    : ' + f.note, DIM, use_color)}\n")
            shown += 1

    if show_stats:
        sig = style_signals(res.stats)
        if sig:
            w("\n" + _c("─" * 78, DIM, use_color) + "\n")
            w(_c("  USLUP / TIPOGRAFI SINYALLERI (istatistiksel, kanit degil)", BOLD, use_color) + "\n")
            w(_c("─" * 78, DIM, use_color) + "\n")
            for path, score_, reasons in sig[:15]:
                w(f"    [{score_:>2}] {path}\n         {', '.join(reasons)}\n")

    if res.errors:
        w("\n" + _c(f"  UYARILAR ({len(res.errors)})", BOLD, use_color) + "\n")
        for e in res.errors[:10]:
            w(f"    - {e}\n")
        if len(res.errors) > 10:
            w(f"    ... ve {len(res.errors)-10} uyari daha\n")

    w("\n")
    return buf.getvalue()


# ---------------------------------------------------------------- JSON


def render_json(res, findings, meta=None) -> str:
    sev_counts = Counter(f.severity for f in findings)
    title, desc = verdict(findings)
    doc = {
        "arac": "aiscan",
        "surum": meta.get("version", "1.0.0") if meta else "1.0.0",
        "tarih": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "kok": res.root,
        "ozet": {
            "risk_skoru": risk_score(findings),
            "hukum": title,
            "aciklama": desc,
            "taranan_dosya": res.files_scanned,
            "atlanan_dosya": res.files_skipped,
            "taranan_bayt": res.bytes_scanned,
            "git_commit": res.git_commits,
            "sure_sn": round(res.elapsed, 2),
            "toplam_bulgu": len(findings),
            "siddet": {k: sev_counts.get(k, 0) for k in
                       (CRITICAL, HIGH, MEDIUM, LOW, INFO)},
            "kategori": dict(Counter(f.category for f in findings)),
            "kural": dict(Counter(f.rule_id for f in findings)),
        },
        "bulgular": [f.to_dict() for f in sorted(findings, key=sort_key)],
        "uslup_sinyalleri": [
            {"dosya": p, "skor": s, "gerekceler": r} for p, s, r in style_signals(res.stats)
        ],
        "uyarilar": res.errors,
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- Markdown


def render_markdown(res, findings) -> str:
    title, desc = verdict(findings)
    sev_counts = Counter(f.severity for f in findings)
    buf = io.StringIO()
    w = buf.write
    now = _dt.datetime.now().strftime("%d.%m.%Y %H:%M")
    w(f"# AI Iz Tarama Raporu\n\n")
    w(f"**Kok dizin:** `{res.root}`  \n")
    w(f"**Tarih:** {now}  \n")
    w(f"**Risk skoru:** {risk_score(findings)}/100 — **{title}**  \n")
    w(f"**Hukum:** {desc}\n\n")
    w(f"| Olcut | Deger |\n|---|---|\n")
    w(f"| Taranan dosya | {res.files_scanned:,} |\n")
    w(f"| Taranan veri | {res.bytes_scanned/1048576:.1f} MB |\n")
    w(f"| Git commit | {res.git_commits:,} |\n")
    w(f"| Sure | {res.elapsed:.1f} sn |\n")
    w(f"| Toplam bulgu | {len(findings):,} |\n\n")

    w("## Siddet dagilimi\n\n| Siddet | Adet |\n|---|---|\n")
    for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        if sev_counts.get(sev):
            w(f"| {SEVERITY_TR[sev]} | {sev_counts[sev]:,} |\n")

    w("\n## Kategoriler\n\n| Kategori | Adet |\n|---|---|\n")
    for cat, n in Counter(f.category for f in findings).most_common():
        w(f"| {CATEGORY_TR.get(cat, cat)} | {n:,} |\n")

    w("\n## Bulgular\n")
    by_file = defaultdict(list)
    for f in sorted(findings, key=sort_key):
        by_file[f.path].append(f)
    for path, group in by_file.items():
        w(f"\n### `{path}` ({len(group)})\n\n")
        w("| Siddet | Kural | Konum | Bulgu | Eslesme |\n|---|---|---|---|---|\n")
        for f in group:
            loc = f"{f.line}:{f.col}" if f.line else "-"
            match = f.match.replace("|", "\\|")[:80]
            w(f"| {SEVERITY_TR[f.severity]} | {f.rule_id} | {loc} | {f.title} | `{match}` |\n")
        for f in group:
            if f.detail:
                w(f"\n> **{f.rule_id}** ({loc}): {f.detail[:400]}\n")

    sig = style_signals(res.stats)
    if sig:
        w("\n## Uslup / tipografi sinyalleri\n\n")
        w("_Istatistikseldir, tek basina kanit sayilmaz._\n\n")
        w("| Dosya | Skor | Gerekce |\n|---|---|---|\n")
        for p, s, r in sig[:40]:
            w(f"| `{p}` | {s} | {', '.join(r)} |\n")
    return buf.getvalue()


# ---------------------------------------------------------------- CSV


def render_csv(findings) -> str:
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["siddet", "kural", "kategori", "dosya", "satir", "sutun",
                 "baslik", "eslesme", "satir_icerigi", "detay", "kaynak"])
    for f in sorted(findings, key=sort_key):
        wr.writerow([SEVERITY_TR[f.severity], f.rule_id, f.category, f.path, f.line,
                     f.col, f.title, f.match, f.excerpt, f.detail, f.source])
    return buf.getvalue()


# ---------------------------------------------------------------- SARIF


SARIF_LEVEL = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning",
               LOW: "note", INFO: "note"}


def render_sarif(res, findings) -> str:
    from .rules import RULES_BY_ID
    used = sorted({f.rule_id for f in findings})
    rules = []
    for rid in used:
        r = RULES_BY_ID.get(rid)
        rules.append({
            "id": rid,
            "name": (r.title if r else rid),
            "shortDescription": {"text": (r.title if r else rid)},
            "fullDescription": {"text": (r.note or r.title) if r else rid},
            "properties": {"category": (r.category if r else "other")},
        })
    results = []
    for f in sorted(findings, key=sort_key):
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}: {f.match}" + (f" | {f.detail}" if f.detail else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                    "region": {"startLine": max(f.line, 1), "startColumn": max(f.col, 1)},
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "aiscan", "version": "1.0.0",
                                "informationUri": "local", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- HTML


def render_html(res, findings) -> str:
    title, desc = verdict(findings)
    score = risk_score(findings)
    sev_counts = Counter(f.severity for f in findings)
    cat_counts = Counter(f.category for f in findings)
    now = _dt.datetime.now().strftime("%d.%m.%Y %H:%M")
    e = html.escape

    rows = []
    for f in sorted(findings, key=sort_key):
        loc = f"{f.line}:{f.col}" if f.line else "—"
        detail = f'<div class="detail">{e(f.detail)}</div>' if f.detail else ""
        note = f'<div class="note">{e(f.note)}</div>' if f.note else ""
        excerpt = f'<pre class="excerpt">{e(f.excerpt)}</pre>' if f.excerpt else ""
        rows.append(
            f'<tr data-sev="{f.severity}" data-cat="{e(f.category)}" '
            f'data-text="{e((f.path + " " + f.rule_id + " " + f.title + " " + f.match).lower())}">'
            f'<td><span class="pill {f.severity}">{SEVERITY_TR[f.severity]}</span></td>'
            f'<td class="mono">{e(f.rule_id)}</td>'
            f'<td class="path mono">{e(f.path)}<span class="loc">{loc}</span></td>'
            f'<td><div class="ttl">{e(f.title)}</div>'
            f'<code class="match">{e(f.match)}</code>{excerpt}{detail}{note}</td></tr>')

    sev_bars = "".join(
        f'<div class="bar"><span class="pill {s}">{SEVERITY_TR[s]}</span>'
        f'<div class="track"><i class="{s}" style="width:{100*sev_counts[s]/max(1,max(sev_counts.values() or [1])):.0f}%"></i></div>'
        f'<b>{sev_counts[s]:,}</b></div>'
        for s in (CRITICAL, HIGH, MEDIUM, LOW, INFO) if sev_counts.get(s))

    cat_rows = "".join(f"<tr><td>{e(CATEGORY_TR.get(c, c))}</td><td class='num'>{n:,}</td></tr>"
                       for c, n in cat_counts.most_common())

    sig = style_signals(res.stats)
    sig_rows = "".join(
        f"<tr><td class='mono'>{e(p)}</td><td class='num'>{s}</td><td>{e(', '.join(r))}</td></tr>"
        for p, s, r in sig[:40])
    sig_block = (f"<h2>Uslup / tipografi sinyalleri</h2><p class='muted'>Istatistikseldir; "
                 f"tek basina kanit degildir.</p><table class='tbl'><thead><tr><th>Dosya</th>"
                 f"<th>Skor</th><th>Gerekce</th></tr></thead><tbody>{sig_rows}</tbody></table>"
                 ) if sig_rows else ""

    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aiscan raporu — {e(os.path.basename(res.root) or res.root)}</title>
<style>
:root{{--bg:#fbfbfa;--fg:#1a1a19;--mut:#6b6b68;--line:#e4e4e1;--card:#fff;
--crit:#b3261e;--high:#d1541c;--med:#b58900;--low:#2b7a9b;--info:#8a8a86;}}
@media(prefers-color-scheme:dark){{:root{{--bg:#17171a;--fg:#eceae5;--mut:#9a9a96;
--line:#2c2c30;--card:#1f1f23;--crit:#ff6b5e;--high:#ff9a5c;--med:#e8c547;--low:#6fc3e8;--info:#8a8a86;}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:32px 20px 80px}}
h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:18px;margin:36px 0 12px}}
.muted{{color:var(--mut);font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.card b{{display:block;font-size:24px;line-height:1.2}}
.card span{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.score{{font-size:38px;font-weight:700}}
.verdict{{border-left:4px solid var(--crit);padding:10px 14px;background:var(--card);border-radius:0 8px 8px 0;margin:14px 0}}
.bar{{display:flex;align-items:center;gap:10px;margin:6px 0}}
.track{{flex:1;height:9px;background:var(--line);border-radius:5px;overflow:hidden}}
.track i{{display:block;height:100%}}
i.critical{{background:var(--crit)}} i.high{{background:var(--high)}} i.medium{{background:var(--med)}}
i.low{{background:var(--low)}} i.info{{background:var(--info)}}
.pill{{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;
letter-spacing:.03em;color:#fff;white-space:nowrap}}
.pill.critical{{background:var(--crit)}} .pill.high{{background:var(--high)}}
.pill.medium{{background:var(--med);color:#000}} .pill.low{{background:var(--low)}}
.pill.info{{background:var(--info)}}
table.tbl{{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden}}
.tbl th{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);
font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}}
.tbl td{{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
.tbl tr:last-child td{{border-bottom:none}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}}
.path{{max-width:290px;word-break:break-all}}
.loc{{color:var(--mut);margin-left:6px}}
.ttl{{font-weight:600;margin-bottom:3px}}
code.match{{display:inline-block;background:var(--bg);border:1px solid var(--line);
border-radius:5px;padding:1px 6px;font-size:12px;word-break:break-all;max-width:100%}}
pre.excerpt{{margin:6px 0 0;padding:7px 9px;background:var(--bg);border:1px solid var(--line);
border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.detail{{margin-top:6px;font-size:12.5px;color:var(--crit);font-weight:600;word-break:break-all}}
.note{{margin-top:4px;font-size:12px;color:var(--mut)}}
.controls{{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0;position:sticky;top:0;
background:var(--bg);padding:10px 0;z-index:5;border-bottom:1px solid var(--line)}}
.controls input,.controls select{{padding:7px 10px;border:1px solid var(--line);
border-radius:7px;background:var(--card);color:var(--fg);font-size:13px}}
.controls input{{flex:1;min-width:220px}}
.scroll{{overflow-x:auto}}
</style></head><body><div class="wrap">
<h1>AI iz / imza tarama raporu</h1>
<p class="muted"><span class="mono">{e(res.root)}</span> &middot; {now} &middot; aiscan v1.0.0 &middot; tamamen yerel tarama</p>

<div class="verdict"><b>{e(title)}</b> — {e(desc)}</div>

<div class="grid">
<div class="card"><span>Risk skoru</span><b class="score">{score}<small style="font-size:15px;color:var(--mut)">/100</small></b></div>
<div class="card"><span>Toplam bulgu</span><b>{len(findings):,}</b></div>
<div class="card"><span>Taranan dosya</span><b>{res.files_scanned:,}</b></div>
<div class="card"><span>Git commit</span><b>{res.git_commits:,}</b></div>
<div class="card"><span>Sure</span><b>{res.elapsed:.1f}s</b></div>
</div>

<h2>Siddet dagilimi</h2>{sev_bars}

<h2>Kategoriler</h2>
<div class="scroll"><table class="tbl"><thead><tr><th>Kategori</th><th class="num">Adet</th></tr></thead>
<tbody>{cat_rows}</tbody></table></div>

<h2>Bulgular ({len(findings):,})</h2>
<div class="controls">
<input id="q" placeholder="Dosya, kural veya metin ara...">
<select id="sev"><option value="">Tum siddetler</option>
<option value="critical">KRITIK</option><option value="high">YUKSEK</option>
<option value="medium">ORTA</option><option value="low">DUSUK</option></select>
<span class="muted" id="cnt"></span></div>
<div class="scroll"><table class="tbl" id="t"><thead><tr><th>Siddet</th><th>Kural</th>
<th>Konum</th><th>Bulgu</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>

{sig_block}

<p class="muted" style="margin-top:40px">aiscan tamamen yerel calisir; hicbir veri disari gonderilmez.
Bulgular kanit niteligindedir ancak DUSUK siddetli uslup sinyalleri tek basina AI kaniti sayilmaz.</p>
</div>
<script>
const q=document.getElementById('q'),sev=document.getElementById('sev'),
rows=[...document.querySelectorAll('#t tbody tr')],cnt=document.getElementById('cnt');
function f(){{const t=q.value.toLowerCase(),s=sev.value;let n=0;
rows.forEach(r=>{{const ok=(!t||r.dataset.text.includes(t))&&(!s||r.dataset.sev===s);
r.style.display=ok?'':'none';if(ok)n++;}});cnt.textContent=n+' / '+rows.length+' gosteriliyor';}}
q.addEventListener('input',f);sev.addEventListener('change',f);f();
</script></body></html>"""
