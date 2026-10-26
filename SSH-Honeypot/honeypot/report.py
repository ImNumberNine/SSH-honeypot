"""
honeypot/report.py — Weekly HTML report generator.

Generates a standalone, printable HTML report summarizing honeypot
activity over the last N days. Designed to be:
  - Self-contained (no external dependencies, embeds all styles)
  - Emailable as a single .html attachment
  - Useful as a portfolio artifact demonstrating threat intelligence work

Usage (CLI):
  python main.py --report                  # last 7 days → report.html
  python main.py --report --days 30        # last 30 days
  python main.py --report --output /tmp/report.html

The report includes:
  - Executive summary with key metrics
  - Top credential pairs (username:password combos tried most often)
  - Top source countries and ASNs
  - Most active attacker IPs with session details
  - Full command log from interactive sessions
  - Decoy file access log (high-priority intelligence)
  - Hourly activity heatmap (SVG, no JS needed)
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import config


# ── Data fetching ──────────────────────────────────────────────────────────────

def _fetch_report_data(days: int = 7) -> Dict:
    """Query the database for report data covering the last `days` days."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    with sqlite3.connect(str(config.DB_PATH)) as db:
        db.row_factory = sqlite3.Row

        total_attempts = db.execute(
            "SELECT COUNT(*) FROM attempts WHERE timestamp >= ?", (since,)
        ).fetchone()[0]

        unique_ips = db.execute(
            "SELECT COUNT(DISTINCT ip) FROM attempts WHERE timestamp >= ?", (since,)
        ).fetchone()[0]

        unique_passwords = db.execute(
            "SELECT COUNT(DISTINCT password) FROM attempts WHERE timestamp >= ?", (since,)
        ).fetchone()[0]

        top_credentials = db.execute(
            """SELECT username, password, COUNT(*) as count
               FROM attempts WHERE timestamp >= ?
               GROUP BY username, password
               ORDER BY count DESC LIMIT 15""",
            (since,),
        ).fetchall()

        top_ips = db.execute(
            """SELECT ip, country, city, isp, COUNT(*) as count
               FROM attempts WHERE timestamp >= ?
               GROUP BY ip ORDER BY count DESC LIMIT 15""",
            (since,),
        ).fetchall()

        top_countries = db.execute(
            """SELECT country, country_code, COUNT(*) as count
               FROM attempts WHERE timestamp >= ? AND country IS NOT NULL
               GROUP BY country ORDER BY count DESC LIMIT 10""",
            (since,),
        ).fetchall()

        commands = db.execute(
            """SELECT c.ip, c.command, c.timestamp, a.country
               FROM commands c
               LEFT JOIN attempts a ON c.session_id = a.session_id
               WHERE c.timestamp >= ?
               ORDER BY c.timestamp DESC LIMIT 100""",
            (since,),
        ).fetchall()

        decoy_reads = db.execute(
            """SELECT ip, command as path, timestamp
               FROM commands
               WHERE timestamp >= ? AND command LIKE '[DECOY]%'
               ORDER BY timestamp DESC""",
            (since,),
        ).fetchall()

        hourly = db.execute(
            """SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
               FROM attempts WHERE timestamp >= ?
               GROUP BY hour ORDER BY hour""",
            (since,),
        ).fetchall()

    # Build hourly array (0-23)
    hourly_counts = [0] * 24
    for row in hourly:
        hourly_counts[int(row["hour"])] = row["count"]

    return {
        "generated_at":     datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "period_days":      days,
        "total_attempts":   total_attempts,
        "unique_ips":       unique_ips,
        "unique_passwords": unique_passwords,
        "total_commands":   len(commands),
        "total_decoys":     len(decoy_reads),
        "top_credentials":  [dict(r) for r in top_credentials],
        "top_ips":          [dict(r) for r in top_ips],
        "top_countries":    [dict(r) for r in top_countries],
        "commands":         [dict(r) for r in commands],
        "decoy_reads":      [dict(r) for r in decoy_reads],
        "hourly_counts":    hourly_counts,
    }


# ── SVG Heatmap ────────────────────────────────────────────────────────────────

def _hourly_heatmap_svg(hourly_counts: List[int]) -> str:
    """
    Generate an SVG heatmap of hourly attack activity (24 bars).
    No JavaScript needed — pure SVG.
    """
    max_count = max(hourly_counts) or 1
    bar_w     = 22
    gap       = 3
    height    = 80
    total_w   = 24 * (bar_w + gap) - gap + 40

    bars = []
    for hour, count in enumerate(hourly_counts):
        x     = 20 + hour * (bar_w + gap)
        bar_h = max(2, int((count / max_count) * (height - 20)))
        y     = height - bar_h - 2

        # Color: blue for low, amber for medium, red for high
        ratio = count / max_count
        if ratio >= 0.7:
            color = "#f85149"
        elif ratio >= 0.4:
            color = "#e3b341"
        else:
            color = "#388bfd"

        bars.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" '
            f'rx="2" fill="{color}" opacity="0.85"/>'
        )

        # Hour label every 4 hours
        if hour % 4 == 0:
            bars.append(
                f'<text x="{x + bar_w//2}" y="{height + 12}" '
                f'text-anchor="middle" font-family="monospace" '
                f'font-size="10" fill="#8b949e">{hour:02d}h</text>'
            )

    return (
        f'<svg viewBox="0 0 {total_w} {height + 20}" '
        f'xmlns="http://www.w3.org/2000/svg" width="100%">'
        + "\n".join(bars)
        + "</svg>"
    )


# ── HTML template ──────────────────────────────────────────────────────────────

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  font-size:14px;line-height:1.6}
.wrap{max-width:900px;margin:0 auto;padding:2rem 1.5rem 4rem}
h1{font-size:1.3rem;font-weight:600;margin-bottom:.25rem}
.meta{font-size:.75rem;color:#8b949e;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:10px;margin-bottom:2rem}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;
  padding:.9rem 1.1rem}
.card-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;
  color:#8b949e;margin-bottom:4px}
.card-value{font-size:1.5rem;font-weight:700}
.c-red{color:#f85149}.c-blue{color:#58a6ff}
.c-amber{color:#e3b341}.c-green{color:#3fb950}.c-purple{color:#bc8cff}
.section{margin-bottom:2.5rem}
.section-title{font-size:.7rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.1em;color:#8b949e;border-bottom:1px solid #21262d;
  padding-bottom:.5rem;margin-bottom:1rem}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:#6e7681;
  padding:5px 8px;text-align:left;border-bottom:1px solid #21262d}
td{padding:5px 8px;color:#8b949e;border-bottom:1px solid #161b22}
tr:hover td{background:#161b22;color:#e6edf3}
.badge{font-size:.6rem;padding:1px 6px;border-radius:10px;font-weight:700}
.b-decoy{background:#1a0505;color:#f85149;border:1px solid #4b1015}
.b-cmd{background:#111820;color:#58a6ff;border:1px solid #1a3050}
.heatmap{background:#161b22;border:1px solid #21262d;border-radius:8px;
  padding:1rem}
.heatmap-title{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;
  color:#8b949e;margin-bottom:.75rem}
@media print{
  body{background:#fff;color:#1f2328}
  .card{background:#f6f8fa;border-color:#d0d7de}
  .heatmap{background:#f6f8fa;border-color:#d0d7de}
  th{color:#6e7781}
  td{color:#57606a}
  tr:hover td{background:#f6f8fa}
  .c-red{color:#d1242f}.c-blue{color:#0550ae}
  .c-amber{color:#9a6700}.c-green{color:#1a7f37}
}
"""


def generate(days: int = 7, output_path: Optional[str] = None) -> str:
    """
    Generate the HTML report and return it as a string.
    Optionally write it to output_path.
    """
    data = _fetch_report_data(days)
    heatmap = _hourly_heatmap_svg(data["hourly_counts"])

    def esc(s):
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Stat cards ─────────────────────────────────────────────────────
    cards_html = f"""
    <div class="cards">
      <div class="card"><div class="card-label">Attempts</div>
        <div class="card-value c-red">{data['total_attempts']:,}</div></div>
      <div class="card"><div class="card-label">Unique IPs</div>
        <div class="card-value c-blue">{data['unique_ips']:,}</div></div>
      <div class="card"><div class="card-label">Passwords tried</div>
        <div class="card-value c-amber">{data['unique_passwords']:,}</div></div>
      <div class="card"><div class="card-label">Commands</div>
        <div class="card-value c-purple">{data['total_commands']:,}</div></div>
      <div class="card"><div class="card-label">Decoy reads</div>
        <div class="card-value c-red">{data['total_decoys']:,}</div></div>
    </div>"""

    # ── Top credentials table ─────────────────────────────────────────
    cred_rows = "".join(
        f"<tr><td style='color:#e6edf3'>{esc(r['username'])}</td>"
        f"<td style='color:#e3b341'>{esc(r['password'])}</td>"
        f"<td style='color:#58a6ff'>{r['count']}</td></tr>"
        for r in data["top_credentials"]
    )

    # ── Top IPs table ─────────────────────────────────────────────────
    ip_rows = "".join(
        f"<tr><td style='color:#58a6ff'>{esc(r['ip'])}</td>"
        f"<td>{esc(r['country'] or '—')}</td>"
        f"<td>{esc(r['isp'] or '—')}</td>"
        f"<td style='color:#e3b341'>{r['count']}</td></tr>"
        for r in data["top_ips"]
    )

    # ── Top countries table ───────────────────────────────────────────
    country_rows = "".join(
        f"<tr><td style='color:#e6edf3'>{esc(r['country'])}</td>"
        f"<td style='color:#58a6ff'>{r['count']}</td></tr>"
        for r in data["top_countries"]
    )

    # ── Commands table ────────────────────────────────────────────────
    cmd_rows = "".join(
        f"<tr>"
        f"<td style='color:#8b949e;font-size:.72rem'>"
        f"{esc(r['timestamp'][:16] if r['timestamp'] else '')}</td>"
        f"<td style='color:#58a6ff'>{esc(r['ip'])}</td>"
        f"<td style='color:{('#f85149' if r['command'].startswith('[DECOY]') else '#e3b341')}'>"
        f"{'<span class=\"badge b-decoy\">DECOY</span> ' if r['command'].startswith('[DECOY]') else ''}"
        f"{esc(r['command'])}</td></tr>"
        for r in data["commands"][:50]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SSH Honeypot Report — {data['generated_at']}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

<h1>SSH Honeypot — Activity Report</h1>
<div class="meta">
  Last {data['period_days']} days &nbsp;·&nbsp; Generated {data['generated_at']}
</div>

{cards_html}

<div class="section">
  <div class="heatmap">
    <div class="heatmap-title">Hourly attack distribution (UTC)</div>
    {heatmap}
  </div>
</div>

<div class="section">
  <div class="section-title">Top credential pairs</div>
  <table>
    <thead><tr><th>Username</th><th>Password</th><th>Count</th></tr></thead>
    <tbody>{cred_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Most active source IPs</div>
  <table>
    <thead><tr><th>IP</th><th>Country</th><th>ISP</th><th>Attempts</th></tr></thead>
    <tbody>{ip_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Top source countries</div>
  <table>
    <thead><tr><th>Country</th><th>Attempts</th></tr></thead>
    <tbody>{country_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Post-auth commands captured (last 50)</div>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>Command</th></tr></thead>
    <tbody>{cmd_rows}</tbody>
  </table>
</div>

</div>
</body>
</html>"""

    if output_path:
        Path(output_path).write_text(html)

    return html
