"""Self-contained HTML report.

A dashboard, not a document: severity reads at a glance from colour and shape,
the summary comes before the detail, and every hit drills down to the exact
conversation and a reproduction command. No external assets, so the single file
travels anywhere.
"""

from __future__ import annotations

import html
import json
from typing import Any

from ..core.models import Attempt, Outcome
from ..evaluate.aggregate import Summary, VulnResult
from ..frameworks.presets import framework_map

_SEV_COLOR = {
    "critical": "#B3261E",
    "high": "#C2620B",
    "medium": "#9A7B0A",
    "low": "#3E7A3A",
    "info": "#5C6675",
}


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _bar(hits: int, total: int, color: str) -> str:
    pct = (hits / total * 100) if total else 0
    return (
        f'<div class="bar"><div class="bar-fill" style="width:{pct:.0f}%;background:{color}">'
        f'</div></div><span class="bar-label">{hits}/{total}</span>'
    )


def _hit_card(attempt: Attempt) -> str:
    score = attempt.worst_score
    rationale = score.rationale if score else ""
    confidence = f"{attempt.confidence:.0%}" if score else "n/a"
    convo = "\n".join(
        f"[{m.role.value}] {m.content}"
        + ("".join(f"\n    -> tool {tc.name}({json.dumps(tc.arguments, default=str)})" for tc in m.tool_calls))
        for m in attempt.conversation.messages
    )
    repro = f"lvscan repro {attempt.run_id} {attempt.id}"
    meta = " · ".join(
        [
            f"attack: {_esc(attempt.attack)}",
            f"turns: {attempt.turns}",
            f"confidence: {confidence}",
        ]
        + ([f"converters: {_esc(', '.join(attempt.converters))}"] if attempt.converters else [])
    )
    return f"""<details class="hit">
      <summary><span class="hit-attack">{_esc(attempt.attack)}</span>
        <span class="hit-rationale">{_esc(rationale[:160])}</span></summary>
      <div class="hit-body">
        <div class="hit-meta">{meta}</div>
        <div class="convo-label">conversation</div>
        <pre class="convo">{_esc(convo)}</pre>
        <div class="convo-label">reproduce</div>
        <pre class="repro">{_esc(repro)}</pre>
      </div>
    </details>"""


def _vuln_section(vuln: VulnResult, attempts_by_vuln: dict[str, list[Attempt]]) -> str:
    color = _SEV_COLOR.get(vuln.severity, "#5C6675")
    hits = [a for a in attempts_by_vuln.get(vuln.vulnerability, []) if a.outcome is Outcome.FAIL]
    z_html = ""
    if vuln.z_score is not None:
        z_html = f'<span class="z">z={vuln.z_score:+.2f} · {_esc(vuln.z_rating)}</span>'
    type_rows = "".join(
        f'<tr><td>{_esc(t)}</td><td>{c["hits"]}/{c["total"]}</td></tr>'
        for t, c in sorted(vuln.by_type.items())
    )
    attack_rows = "".join(
        f'<tr><td>{_esc(a)}</td><td>{c["hits"]}/{c["total"]}</td></tr>'
        for a, c in sorted(vuln.by_attack.items(), key=lambda kv: -kv[1]["hits"])
        if c["hits"]
    )
    hit_cards = "".join(_hit_card(a) for a in hits[:40])
    breakdown = ""
    if type_rows or attack_rows:
        breakdown = f"""<div class="breakdown">
          <div><div class="mini-label">by type</div><table class="mini">{type_rows}</table></div>
          {'<div><div class="mini-label">by attack (hits only)</div><table class="mini">' + attack_rows + '</table></div>' if attack_rows else ''}
        </div>"""
    status = "fail" if vuln.hits else ("clean" if vuln.total else "empty")
    return f"""<section class="vuln vuln-{status}" id="{_esc(vuln.vulnerability)}">
      <div class="vuln-head">
        <span class="sev-chip" style="--sev:{color}">{_esc(vuln.severity)}</span>
        <h3>{_esc(vuln.vulnerability.replace('_', ' '))}</h3>
        <span class="issue issue-{vuln.issue_level}">{_esc(vuln.issue_level)}</span>
        {z_html}
        <div class="vuln-bar">{_bar(vuln.hits, max(1, vuln.total), color)}</div>
      </div>
      <div class="tags">{''.join(f'<span class="tag">{_esc(t)}</span>' for t in vuln.tags)}</div>
      {breakdown}
      {'<div class="hits-wrap">' + hit_cards + '</div>' if hit_cards else '<p class="no-hits">No hits.</p>'}
    </section>"""


def render_html(summary: Summary, attempts: list[Attempt], *, title: str = "LLM Vulnerability Scan",
                meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    by_vuln: dict[str, list[Attempt]] = {}
    for a in attempts:
        by_vuln.setdefault(a.vulnerability, []).append(a)

    all_tags = sorted({t for v in summary.vulnerabilities for t in v.tags})
    frameworks = framework_map(all_tags)
    fw_html = ""
    for family, tags in frameworks.items():
        covered = tags
        fw_html += (
            f'<div class="fw"><div class="fw-name">{_esc(family)}</div>'
            + "".join(f'<span class="tag">{_esc(t.split(":", 1)[-1])}</span>' for t in covered)
            + "</div>"
        )

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_tiles = ""
    for sev in sev_order:
        count = summary.by_severity.get(sev, 0)
        color = _SEV_COLOR[sev]
        sev_tiles += (
            f'<div class="tile" style="--c:{color}"><div class="tile-n">{count}</div>'
            f'<div class="tile-l">{sev}</div></div>'
        )

    vulns_sorted = sorted(
        summary.vulnerabilities,
        key=lambda v: (-int(bool(v.hits)), -_sev_rank(v.severity), -v.fail_rate),
    )
    sections = "".join(_vuln_section(v, by_vuln) for v in vulns_sorted)

    meta_line = " · ".join(
        f"{k}: {_esc(v)}" for k, v in meta.items() if v not in (None, "")
    )
    cvss_html = (
        f'<div class="cvss"><div class="cvss-n">{summary.cvss}</div><div class="cvss-l">exposure</div></div>'
        if summary.cvss is not None
        else ""
    )

    return _TEMPLATE.format(
        title=_esc(title),
        meta_line=meta_line,
        run_id=_esc(summary.run_id),
        pass_rate=f"{summary.pass_rate:.1%}",
        total=summary.total,
        hits=summary.hits,
        errors=summary.errors,
        skipped=summary.skipped,
        cvss_html=cvss_html,
        sev_tiles=sev_tiles,
        fw_html=fw_html or '<span class="muted">no framework tags</span>',
        sections=sections,
    )


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{
  --bg:#F5F7FA;--surface:#fff;--ink:#1B222E;--muted:#5C6675;--rule:#E1E6EC;
  --accent:#0F6F8E;--code:#EEF2F6;--good:#3E7A3A;
}}
@media (prefers-color-scheme:dark){{:root{{
  --bg:#11161D;--surface:#171D26;--ink:#E6EAF0;--muted:#9AA5B5;--rule:#2B3441;
  --accent:#56B5D3;--code:#1C242F;--good:#8CC98A;
}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 20px 80px}}
header h1{{font-size:1.6rem;margin:0 0 4px;letter-spacing:-.02em}}
.meta{{color:var(--muted);font-size:13px;font-family:ui-monospace,Menlo,monospace}}
.summary{{display:grid;grid-template-columns:auto 1fr;gap:20px;margin:24px 0;align-items:center}}
@media(max-width:640px){{.summary{{grid-template-columns:1fr}}}}
.headline{{display:flex;gap:18px;align-items:center;background:var(--surface);
  border:1px solid var(--rule);border-radius:10px;padding:18px 22px}}
.headline .big{{font-size:2.4rem;font-weight:700;line-height:1}}
.headline .lbl{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}}
.counts{{display:flex;gap:22px;font-size:13px;color:var(--muted)}}
.counts b{{color:var(--ink);font-size:1.2rem;display:block}}
.cvss{{text-align:center;padding:0 8px;border-left:1px solid var(--rule)}}
.cvss-n{{font-size:2rem;font-weight:700;color:var(--accent)}}
.cvss-l{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap}}
.tile{{flex:1;min-width:78px;background:var(--surface);border:1px solid var(--rule);
  border-top:3px solid var(--c);border-radius:8px;padding:12px;text-align:center}}
.tile-n{{font-size:1.6rem;font-weight:700;color:var(--c)}}
.tile-l{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
.panel{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;
  padding:16px 20px;margin:18px 0}}
.panel h2{{font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
  margin:0 0 12px}}
.fw{{display:flex;gap:6px;align-items:baseline;flex-wrap:wrap;margin:6px 0;padding-bottom:6px;
  border-bottom:1px solid var(--rule)}}
.fw:last-child{{border-bottom:0}}
.fw-name{{font-family:ui-monospace,monospace;font-size:12px;color:var(--accent);min-width:70px;font-weight:600}}
.tag{{font-family:ui-monospace,monospace;font-size:11px;background:var(--code);color:var(--muted);
  padding:1px 7px;border-radius:4px}}
.vuln{{background:var(--surface);border:1px solid var(--rule);border-radius:10px;
  padding:16px 20px;margin:14px 0}}
.vuln-fail{{border-left:4px solid #B3261E}}
.vuln-clean{{border-left:4px solid var(--good);opacity:.9}}
.vuln-head{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
.vuln-head h3{{margin:0;font-size:1.1rem;text-transform:capitalize}}
.sev-chip{{font-family:ui-monospace,monospace;font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;color:var(--sev);border:1px solid var(--sev);border-radius:4px;padding:1px 7px}}
.issue{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:1px 8px;border-radius:10px}}
.issue-major{{background:#B3261E;color:#fff}}
.issue-medium{{background:#C2620B;color:#fff}}
.issue-minor{{background:#9A7B0A;color:#fff}}
.issue-none{{background:var(--code);color:var(--muted)}}
.z{{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted)}}
.vuln-bar{{margin-left:auto;display:flex;align-items:center;gap:8px}}
.bar{{width:120px;height:8px;background:var(--code);border-radius:4px;overflow:hidden}}
.bar-fill{{height:100%}}
.bar-label{{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}}
.tags{{display:flex;gap:5px;flex-wrap:wrap;margin:10px 0}}
.breakdown{{display:flex;gap:28px;flex-wrap:wrap;margin:10px 0 4px}}
.mini-label{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:3px}}
.mini{{border-collapse:collapse;font-size:13px}}
.mini td{{padding:1px 14px 1px 0;font-family:ui-monospace,monospace}}
.mini td:last-child{{color:var(--muted)}}
.hits-wrap{{margin-top:12px;display:flex;flex-direction:column;gap:6px}}
.hit{{border:1px solid var(--rule);border-radius:7px;background:var(--bg)}}
.hit summary{{cursor:pointer;padding:8px 12px;display:flex;gap:12px;align-items:baseline;list-style:none}}
.hit summary::-webkit-details-marker{{display:none}}
.hit summary::before{{content:"▸";color:var(--muted);font-size:11px}}
.hit[open] summary::before{{content:"▾"}}
.hit-attack{{font-family:ui-monospace,monospace;font-size:12px;color:var(--accent);font-weight:600;white-space:nowrap}}
.hit-rationale{{color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.hit-body{{padding:4px 12px 12px 26px}}
.hit-meta{{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted);margin-bottom:8px}}
.convo-label{{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:8px 0 3px}}
pre{{margin:0;background:var(--code);border-radius:6px;padding:10px 12px;overflow-x:auto;
  font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}}
.repro{{color:var(--accent)}}
.no-hits{{color:var(--good);font-size:13px;margin:8px 0 0}}
.muted{{color:var(--muted)}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>{title}</h1>
  <div class="meta">{meta_line}{run_sep}run {run_id}</div>
</header>

<div class="summary">
  <div class="headline">
    <div><div class="big">{pass_rate}</div><div class="lbl">pass rate</div></div>
    <div class="counts">
      <div><b>{total}</b>attempts</div>
      <div><b>{hits}</b>hits</div>
      <div><b>{errors}</b>errors</div>
      <div><b>{skipped}</b>skipped</div>
    </div>
    {cvss_html}
  </div>
  <div class="tiles">{sev_tiles}</div>
</div>

<div class="panel">
  <h2>Framework coverage</h2>
  {fw_html}
</div>

<h2 style="font-size:1rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:26px 0 4px">Findings</h2>
{sections}

<footer style="margin-top:40px;color:var(--muted);font-size:12px;text-align:center">
  Generated by llm_vuln_scan. Findings are evidence, not proof; confirm high-impact hits manually.
</footer>
</div>
</body>
</html>"""


# The template uses {run_sep}; fill it so the meta line reads cleanly with or without meta.
_TEMPLATE = _TEMPLATE.replace("{meta_line}{run_sep}run {run_id}", "{meta_line} · run {run_id}")
