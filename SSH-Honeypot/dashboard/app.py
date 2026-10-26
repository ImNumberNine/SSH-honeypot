"""
dashboard/app.py — Flask dashboard with REST API and Server-Sent Events.

Endpoints:
  GET /                     → main dashboard HTML
  GET /api/stats            → aggregate stats (JSON)
  GET /api/attempts         → recent login attempts (JSON)
  GET /api/commands         → recent commands captured (JSON)
  GET /api/attacker/<ip>    → all data for a specific IP (JSON)
  GET /api/stream           → SSE stream for live updates

Server-Sent Events (SSE):
  The dashboard subscribes to /api/stream. Every 3 seconds the server
  pushes updated stats and the latest attempt, keeping the dashboard
  live without polling from the browser. This is simpler than WebSockets
  for one-way server→client data.
"""

import json
import logging
import sys
import time
from pathlib import Path

# Add project root to path so we can import config and honeypot.*
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, Response, jsonify, render_template, stream_with_context

import config
from honeypot import database

log = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates")
app.secret_key = config.FLASK_SECRET


# ── Main dashboard page ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── REST API ───────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    """Aggregate statistics for the header cards and charts."""
    return jsonify(database.get_stats())


@app.route("/api/attempts")
def api_attempts():
    """Last N login attempts, newest first. ?limit=N (default 100, max 1000)."""
    from flask import request
    limit = min(int(request.args.get("limit", 100)), 1000)
    return jsonify(database.get_recent_attempts(limit=limit))


@app.route("/api/commands")
def api_commands():
    """Last 50 commands captured, newest first."""
    return jsonify(database.get_recent_commands(limit=50))


@app.route("/api/attacker/<ip>")
def api_attacker(ip: str):
    """Full profile for a specific attacker IP."""
    return jsonify(database.get_attacker_profile(ip))


# ── Server-Sent Events ─────────────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    """
    SSE endpoint for real-time dashboard updates.

    Pushes a 'stats' event every 3 seconds with updated aggregate numbers,
    plus a 'latest' event whenever there's a new attempt.

    The browser subscribes with:
        const es = new EventSource('/api/stream');
        es.addEventListener('stats', e => { ... });
    """
    def event_generator():
        last_attempt_id = 0

        while True:
            try:
                # Always push updated stats
                stats = database.get_stats()
                yield f"event: stats\ndata: {json.dumps(stats)}\n\n"

                # Push latest attempt if there's a new one
                attempts = database.get_recent_attempts(limit=1)
                if attempts:
                    latest = attempts[0]
                    if latest["id"] != last_attempt_id:
                        last_attempt_id = latest["id"]
                        yield f"event: attempt\ndata: {json.dumps(latest)}\n\n"

                time.sleep(3)

            except GeneratorExit:
                break
            except Exception as e:
                log.error("SSE error: %s", e)
                break

    return Response(
        stream_with_context(event_generator()),
        mimetype       = "text/event-stream",
        headers        = {
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


def run_dashboard() -> None:
    """Start the Flask development server."""
    log.info(
        "Dashboard starting at http://%s:%d",
        config.DASHBOARD_HOST, config.DASHBOARD_PORT,
    )
    app.run(
        host  = config.DASHBOARD_HOST,
        port  = config.DASHBOARD_PORT,
        debug = config.DASHBOARD_DEBUG,
        use_reloader = False,   # reloader conflicts with the SSH server thread
        threaded     = True,
    )


@app.route('/api/export/json')
def api_export_json():
    """Export all attempts as JSON — useful for SIEM ingestion."""
    from flask import Response
    import json
    attempts = database.get_recent_attempts(limit=10000)
    return Response(
        json.dumps(attempts, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=honeypot-attempts.json'}
    )


@app.route('/api/export/csv')
def api_export_csv():
    """Export all attempts as CSV — importable into Excel or pandas."""
    import csv, io
    from flask import Response
    attempts = database.get_recent_attempts(limit=10000)
    output = io.StringIO()
    if attempts:
        writer = csv.DictWriter(output, fieldnames=attempts[0].keys())
        writer.writeheader()
        writer.writerows(attempts)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=honeypot-attempts.csv'}
    )
