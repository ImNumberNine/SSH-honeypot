"""
main.py — Entry point for the SSH Honeypot.

Starts two components concurrently:
  1. SSH honeypot server (in a daemon thread)
  2. Flask dashboard (in the main thread)

Running the dashboard in the main thread means Ctrl+C cleanly shuts
everything down — the SSH server thread is daemonized so it dies with
the process.

Usage:
  python main.py                    # start both
  python main.py --ssh-only         # SSH server without dashboard
  python main.py --dashboard-only   # dashboard only (read existing DB)
"""

import argparse
import signal
import sys
import threading

# Bootstrap: add project root to path
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import config
from honeypot import database, logger as hlog


def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument("--ssh-only",       action="store_true", help="Run SSH server only")
    parser.add_argument("--dashboard-only", action="store_true", help="Run dashboard only")
    parser.add_argument("--port",    type=int,  default=None,                    help="Override SSH port")
    parser.add_argument("--report",  action="store_true",                         help="Generate HTML activity report and exit")
    parser.add_argument("--days",    type=int,  default=7,                        help="Days of data for report (default: 7)")
    parser.add_argument("--output",  type=str,  default="honeypot-report.html",   help="Report output path")
    args = parser.parse_args()

    if args.port:
        config.SSH_PORT = args.port

    # ── Initialize ────────────────────────────────────────────────────
    hlog.setup_logging()
    database.init_db()

    # ── Report mode: generate report and exit ─────────────────────────
    if args.report:
        import logging
        from honeypot.report import generate
        log = logging.getLogger(__name__)
        log.info("Generating %d-day report → %s", args.days, args.output)
        generate(days=args.days, output_path=args.output)
        print(f"Report saved to {args.output}")
        return

    import logging
    log = logging.getLogger(__name__)
    log.info("SSH Honeypot starting...")
    log.info("Database: %s", config.DB_PATH)
    log.info("Event log: %s", config.LOG_PATH)

    # ── Start SSH server in a background thread ───────────────────────
    if not args.dashboard_only:
        from honeypot.server import HoneypotServer

        ssh_server = HoneypotServer()
        ssh_thread = threading.Thread(
            target = ssh_server.start,
            daemon = True,
            name   = "ssh-honeypot",
        )
        ssh_thread.start()
        log.info("SSH server started on port %d", config.SSH_PORT)

    # ── Start dashboard in the main thread ────────────────────────────
    if not args.ssh_only:
        from dashboard.app import run_dashboard
        run_dashboard()
    else:
        # SSH-only mode: block main thread until Ctrl+C
        log.info("Running in SSH-only mode. Press Ctrl+C to stop.")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down...")


if __name__ == "__main__":
    main()