"""Export lookup results to JSON, CSV and standalone HTML reports."""
from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import Config


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _ensure_dir(config: Config) -> Path:
    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    return out


def to_json(data: Any, kind: str, config: Config) -> Path:
    out = _ensure_dir(config)
    path = out / f"{kind}-{_timestamp()}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def to_csv(data: dict, kind: str, config: Config) -> Path:
    """CSV export. For list-style results (username) writes one row per item,
    otherwise writes a flat key/value CSV."""
    out = _ensure_dir(config)
    path = out / f"{kind}-{_timestamp()}.csv"
    rows = data.get("results") if isinstance(data, dict) else None
    with path.open("w", newline="", encoding="utf-8") as fh:
        if isinstance(rows, list) and rows:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        else:
            writer = csv.writer(fh)
            writer.writerow(["field", "value"])
            for k, v in (data.items() if isinstance(data, dict) else []):
                writer.writerow([k, v])
    return path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus report — {kind}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background: #0f1117; color: #e6e6e6; }}
  header {{ padding: 24px 32px; background: linear-gradient(135deg,#1b2735,#090a0f);
           border-bottom: 1px solid #2a3242; }}
  h1 {{ margin: 0; font-size: 1.4rem; }}
  .meta {{ color: #8a93a6; font-size: .85rem; margin-top: 4px; }}
  main {{ padding: 24px 32px; max-width: 1000px; margin: 0 auto; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #232838;
           font-size: .9rem; }}
  th {{ color: #7aa2f7; }}
  a {{ color: #7dcfff; }}
  .found {{ color: #9ece6a; font-weight: 600; }}
  .missing {{ color: #565f89; }}
  .blocked {{ color: #e0af68; font-weight: 600; }}
  footer {{ padding: 16px 32px; color: #565f89; font-size: .8rem; text-align: center; }}
</style></head>
<body>
<header><h1>Argus — {kind} report</h1>
<div class="meta">Generated {when} · authorized / educational use only</div></header>
<main>{body}</main>
<footer>Argus · Use responsibly and legally.</footer>
</body></html>
"""


def _dict_to_html_table(data: dict) -> str:
    rows = []
    for k, v in data.items():
        if k == "results":
            continue
        rows.append(f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>")
    return "<table>" + "".join(rows) + "</table>"


def _username_results_to_html(data: dict) -> str:
    rows = []
    for r in data.get("results", []):
        status = r.get("status")
        cls = {"found": "found", "blocked": "blocked"}.get(status, "missing")
        link = html.escape(r.get("url", ""))
        rows.append(
            f"<tr><td>{html.escape(str(r.get('site')))}</td>"
            f"<td class='{cls}'>{html.escape(str(r.get('status')))}</td>"
            f"<td>{html.escape(str(r.get('http_status')))}</td>"
            f"<td><a href='{link}' target='_blank' rel='noopener'>{link}</a></td></tr>"
        )
    header = (
        f"<p>Username <strong>{html.escape(str(data.get('username')))}</strong> — "
        f"found on <span class='found'>{data.get('found_count')}</span> of "
        f"{data.get('checked')} sites.</p>"
    )
    table = (
        "<table><tr><th>Site</th><th>Status</th><th>HTTP</th><th>URL</th></tr>"
        + "".join(rows)
        + "</table>"
    )
    return header + table


def to_html(data: dict, kind: str, config: Config) -> Path:
    out = _ensure_dir(config)
    path = out / f"{kind}-{_timestamp()}.html"
    if isinstance(data, dict) and "results" in data:
        body = _username_results_to_html(data)
    else:
        body = _dict_to_html_table(data)
    path.write_text(
        _HTML_TEMPLATE.format(
            kind=html.escape(kind),
            when=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            body=body,
        ),
        encoding="utf-8",
    )
    return path


def export(data: dict, kind: str, fmt: str, config: Config) -> Path:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(data, kind, config)
    if fmt == "csv":
        return to_csv(data, kind, config)
    if fmt == "html":
        return to_html(data, kind, config)
    raise ValueError(f"unsupported export format: {fmt}")
