"""Report renderers: HTML, JSON, plain-text.

Each renderer takes a :class:`Report` and returns a string that can be
stored, emailed, or served over the REST API.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict

from .model import Report, ReportFormat, ReportSection


# ------------------------------------------------------------------
# dispatch
# ------------------------------------------------------------------

def render_report(report: Report) -> str:
    if report.format == ReportFormat.HTML:
        return HtmlRenderer().render(report)
    if report.format == ReportFormat.TEXT:
        return TextRenderer().render(report)
    return JsonRenderer().render(report)


# ------------------------------------------------------------------
# JSON
# ------------------------------------------------------------------

class JsonRenderer:
    def render(self, report: Report) -> str:
        return json.dumps(report.to_dict(include_rendered=False), indent=2, default=str)


# ------------------------------------------------------------------
# plain text
# ------------------------------------------------------------------

class TextRenderer:
    def render(self, report: Report) -> str:
        lines = []
        lines.append("=" * 72)
        lines.append(report.title)
        lines.append("=" * 72)
        for sec in sorted(report.sections, key=lambda s: s.order):
            lines.append("")
            lines.append(f"--- {sec.title} ---")
            for k, v in sec.data.items():
                if isinstance(v, list):
                    lines.append(f"  {k}: [{len(v)} items]")
                elif isinstance(v, dict):
                    lines.append(f"  {k}:")
                    for dk, dv in v.items():
                        lines.append(f"    {dk}: {dv}")
                else:
                    lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append("=" * 72)
        lines.append(f"Generated: {report.to_dict().get('created_iso', '')}")
        return "\n".join(lines)


# ------------------------------------------------------------------
# HTML
# ------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
header{{background:#161b22;border-bottom:1px solid #30363d;padding:1.5rem 2rem}}
header h1{{color:#58a6ff;font-size:1.4rem;font-weight:600}}
header .sub{{color:#8b949e;font-size:.85rem;margin-top:.3rem}}
.container{{max-width:1200px;margin:0 auto;padding:2rem}}
.badge{{display:inline-block;padding:.2em .6em;border-radius:3px;font-size:.75rem;font-weight:600}}
.badge-ok{{background:#1a4731;color:#3fb950}}
.badge-warn{{background:#3d2b00;color:#d29922}}
.badge-crit{{background:#3d1515;color:#f85149}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1.5rem;overflow:hidden}}
.section-header{{padding:1rem 1.5rem;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:.75rem}}
.section-title{{color:#e6edf3;font-size:1rem;font-weight:600}}
.section-body{{padding:1.5rem}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:.5rem .75rem;color:#8b949e;border-bottom:1px solid #30363d;font-weight:500}}
td{{padding:.5rem .75rem;border-bottom:1px solid #21262d;color:#c9d1d9}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
.kv{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1rem}}
.kv-item{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:1rem}}
.kv-label{{color:#8b949e;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
.kv-value{{color:#e6edf3;font-size:1.4rem;font-weight:600;margin-top:.25rem}}
.bar-chart{{display:flex;flex-direction:column;gap:.4rem}}
.bar-row{{display:flex;align-items:center;gap:.5rem;font-size:.8rem}}
.bar-label{{color:#8b949e;min-width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-fill{{height:16px;border-radius:3px;min-width:2px;transition:width .3s}}
.bar-fill-blue{{background:#1f6feb}}
.bar-fill-orange{{background:#d29922}}
.bar-count{{color:#8b949e;min-width:2rem;text-align:right}}
footer{{text-align:center;padding:2rem;color:#8b949e;font-size:.8rem;border-top:1px solid #21262d;margin-top:2rem}}
</style>
</head>
<body>
<header>
  <h1>{title}</h1>
  <div class="sub">Generated {created_iso} &mdash; Period: {period_start_iso} to {period_end_iso}</div>
</header>
<div class="container">
{sections_html}
</div>
<footer>ThreatPipe Reporting Engine &mdash; {created_iso}</footer>
</body>
</html>
"""


class HtmlRenderer:
    def render(self, report: Report) -> str:
        sections_html = "\n".join(
            self._render_section(sec)
            for sec in sorted(report.sections, key=lambda s: s.order)
        )
        d = report.to_dict()
        return _HTML_TEMPLATE.format(
            title=html.escape(report.title),
            created_iso=d.get("created_iso", ""),
            period_start_iso=d.get("period_start_iso", ""),
            period_end_iso=d.get("period_end_iso", ""),
            sections_html=sections_html,
        )

    def _render_section(self, sec: ReportSection) -> str:
        if sec.render_hint == "prose" or sec.render_hint == "stats":
            body = self._render_kv(sec.data)
        elif sec.render_hint == "chart":
            body = self._render_chart(sec.data)
        else:
            body = self._render_table(sec.data)
        return (
            f'<div class="section">'
            f'<div class="section-header"><span class="section-title">{html.escape(sec.title)}</span></div>'
            f'<div class="section-body">{body}</div>'
            f"</div>"
        )

    def _render_kv(self, data: Dict[str, Any]) -> str:
        items = []
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                continue
            label = html.escape(str(k).replace("_", " ").title())
            value = html.escape(str(v))
            items.append(
                f'<div class="kv-item">'
                f'<div class="kv-label">{label}</div>'
                f'<div class="kv-value">{value}</div>'
                f"</div>"
            )
        return f'<div class="kv">{"".join(items)}</div>'

    def _render_table(self, data: Dict[str, Any]) -> str:
        # find first list-of-dicts or dict-of-counts to render as table
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                cols = list(v[0].keys())
                header = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
                rows = "".join(
                    "<tr>" + "".join(f"<td>{html.escape(str(row.get(c, '')))}</td>" for c in cols) + "</tr>"
                    for row in v[:20]
                )
                return f"<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
            if isinstance(v, dict) and all(isinstance(x, (int, float)) for x in v.values()):
                rows = "".join(
                    f"<tr><td>{html.escape(str(dk))}</td><td>{html.escape(str(dv))}</td></tr>"
                    for dk, dv in sorted(v.items(), key=lambda x: -x[1])[:15]
                )
                return f"<table><thead><tr><th>{html.escape(k)}</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>"
        return self._render_kv(data)

    def _render_chart(self, data: Dict[str, Any]) -> str:
        buckets = data.get("buckets", [])
        if not buckets:
            return "<p style='color:#8b949e'>No data for this period.</p>"
        max_count = max((b.get("count", 0) for b in buckets), default=1) or 1
        bars = ""
        for b in buckets:
            label = str(b.get("bucket_iso", b.get("bucket", "")))[:16]
            count = b.get("count", 0)
            width = max(2, int(count / max_count * 300))
            bars += (
                f'<div class="bar-row">'
                f'<span class="bar-label">{html.escape(label)}</span>'
                f'<div class="bar-fill bar-fill-blue" style="width:{width}px"></div>'
                f'<span class="bar-count">{count}</span>'
                f"</div>"
            )
        direction = data.get("trend_direction", "stable")
        color = "badge-warn" if direction == "increasing" else ("badge-ok" if direction == "decreasing" else "")
        badge = f'<span class="badge {color}">{html.escape(direction)}</span>' if color else f"<span>{html.escape(direction)}</span>"
        return f'<div style="margin-bottom:.75rem">Trend: {badge}</div><div class="bar-chart">{bars}</div>'
