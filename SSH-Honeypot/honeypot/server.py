"""
honeypot/server.py — TCP listener and thread pool for the SSH honeypot.

Listens on SSH_PORT (default 2222), accepts connections, and dispatches
each one to a handler thread. Uses a semaphore to cap concurrent sessions
at SSH_MAX_WORKERS to avoid resource exhaustion.

Host key management:
  On first run, generates a 2048-bit RSA key and saves it to data/server.key.
  On subsequent runs, loads the existing key so the fingerprint stays stable.
  A stable fingerprint is realistic — a changing one would alert some SSH clients.
"""

import logging
import socket
import threading
from pathlib import Path

import paramiko

import config
from honeypot.handler import handle_connection

log = logging.getLogger(__name__)


# ── Host key ───────────────────────────────────────────────────────────────────

def _load_or_generate_host_key() -> paramiko.RSAKey:
    """
    Load the RSA host key from disk, or generate one if it doesn't exist.
    2048 bits is realistic for an older Ubuntu server (our cover identity).
    """
    key_path = config.KEY_PATH

    if key_path.exists():
        log.info("Loading host key from %s", key_path)
        return paramiko.RSAKey(filename=str(key_path))

    log.info("Generating new RSA host key → %s", key_path)
    key = paramiko.RSAKey.generate(bits=2048)
    key.write_private_key_file(str(key_path))
    log.info("Host key fingerprint: %s", key.get_fingerprint().hex(":"))
    return key


# ── Server ─────────────────────────────────────────────────────────────────────

class HoneypotServer:
    """
    TCP server that dispatches SSH connections to handler threads.

    The semaphore limits concurrent sessions so a single botnet burst
    can't exhaust all system threads.
    """

    def __init__(self):
        self.host_key   = _load_or_generate_host_key()
        self._semaphore = threading.Semaphore(config.SSH_MAX_WORKERS)
        self._running   = False
        self._sock      = None

    def start(self) -> None:
        """Bind to the configured port and start accepting connections."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR avoids "Address already in use" on quick restarts
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((config.SSH_HOST, config.SSH_PORT))
        self._sock.listen(100)
        self._running = True

        log.info(
            "SSH honeypot listening on %s:%d (max %d concurrent sessions)",
            config.SSH_HOST, config.SSH_PORT, config.SSH_MAX_WORKERS,
        )
        log.info("Banner: %s", config.SSH_BANNER)

        self._accept_loop()

    def stop(self) -> None:
        """Gracefully stop the server."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        log.info("SSH honeypot stopped.")

    def _accept_loop(self) -> None:
        """Main accept loop — runs until stop() is called."""
        while self._running:
            try:
                client_socket, client_address = self._sock.accept()
            except OSError:
                # Socket was closed by stop()
                break

            # Acquire semaphore (blocks if we're at max workers)
            if not self._semaphore.acquire(blocking=False):
                log.warning(
                    "Max concurrent sessions reached (%d). "
                    "Dropping connection from %s.",
                    config.SSH_MAX_WORKERS, client_address[0],
                )
                client_socket.close()
                continue

            thread = threading.Thread(
                target = self._handle_with_semaphore,
                args   = (client_socket, client_address),
                daemon = True,   # daemon threads die when main thread exits
            )
            thread.start()

    def _handle_with_semaphore(
        self,
        client_socket: socket.socket,
        client_address: tuple,
    ) -> None:
        """Wrap handle_connection to release the semaphore when done."""
        try:
            handle_connection(client_socket, client_address, self.host_key)
        finally:
            self._semaphore.release()
