"""
honeypot/handler.py — Handles individual SSH connections.

Uses recv(1) to read one byte at a time — the only reliable way to
handle interactive terminal input without character ordering issues.
"""

import logging
import socket
import threading
import time
import uuid
from typing import Optional

import paramiko

import config
from honeypot import database, geoip, logger as hlog
from honeypot.filesystem import FakeFilesystem

log = logging.getLogger(__name__)


class HoneypotServerInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.session_id  = str(uuid.uuid4())[:8]
        self.event       = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        geo = geoip.lookup(self.client_ip)
        hlog.log_attempt(self.client_ip, self.client_port, username, password, self.session_id, geo)
        database.log_attempt(self.client_ip, self.client_port, username, password, self.session_id, geo)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password"


def _build_prompt(fs: FakeFilesystem) -> bytes:
    cwd     = fs.cwd
    display = "~" if cwd == "/root" else cwd
    return f"root@ubuntu:{display}# ".encode()


def _run_fake_shell(channel: paramiko.Channel, session_id: str, client_ip: str) -> None:
    """
    Fake interactive shell that reads ONE BYTE AT A TIME via recv(1).

    Why recv(1)?
      recv(1024) can return multiple characters in one call. When the user
      presses backspace while there are buffered chars, the ordering gets
      confused and the erase sequence fires at the wrong time.
      recv(1) guarantees we handle exactly one byte per iteration — no
      buffering surprises.

    Backspace handling:
      Most terminals send 0x7f (DEL) for backspace. Some send 0x08 (BS).
      We handle both. The erase sequence is: move-back + space + move-back
      (overwrites the character on screen and repositions the cursor).

    Escape sequences (arrow keys, F-keys, etc.):
      They start with 0x1b. We detect the start, accumulate the sequence,
      and discard it when complete. Arrow keys do nothing — which is more
      realistic than printing garbage.
    """

    def decoy_read(path: str, content: str) -> None:
        logging.getLogger("honeypot.DECOY").warning(
            "DECOY_READ  %s  path=%s", client_ip, path
        )
        hlog._write_event("decoy_read", {
            "session_id": session_id,
            "ip":         client_ip,
            "path":       path,
            "preview":    content[:120],
        })
        database.log_command(session_id, client_ip, f"[DECOY] {path}")

    fs = FakeFilesystem(decoy_callback=decoy_read)

    channel.send(
        b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        b"\r\n"
        b" * Documentation:  https://help.ubuntu.com\r\n"
        b" * Management:     https://landscape.canonical.com\r\n"
        b"\r\n"
    )
    channel.send(_build_prompt(fs))
    channel.settimeout(config.SESSION_TIMEOUT)

    line_buf  = []   # current line being typed (list of str chars)
    esc_seq   = []   # accumulator for ANSI escape sequences

    while True:
        # ── Read exactly one byte ─────────────────────────────────────
        try:
            byte = channel.recv(1)
        except socket.timeout:
            break
        if not byte:
            break

        b = byte[0]   # integer value 0-255

        # ── ANSI escape sequence ──────────────────────────────────────
        # Sequences: ESC [ <params> <letter>
        # e.g. arrow up = \x1b\x5b\x41  (\x1b [ A)
        if esc_seq:
            esc_seq.append(b)
            # Sequences end with a letter or ~
            if (0x40 <= b <= 0x7e):
                esc_seq = []   # complete — discard silently
            elif len(esc_seq) > 8:
                esc_seq = []   # safety drain
            continue

        if b == 0x1b:          # ESC — start of escape sequence
            esc_seq = [b]
            continue

        # ── Ctrl+C — abort current line ───────────────────────────────
        if b == 0x03:
            channel.send(b"^C\r\n")
            channel.send(_build_prompt(fs))
            line_buf = []
            continue

        # ── Ctrl+D — EOF / exit ───────────────────────────────────────
        if b == 0x04:
            if not line_buf:
                channel.send(b"logout\r\n")
                channel.close()
                return
            continue

        # ── Ctrl+L — clear screen ─────────────────────────────────────
        if b == 0x0c:
            channel.send(b"\x1b[2J\x1b[H")   # clear screen, cursor home
            channel.send(_build_prompt(fs))
            # Reprint the current buffer so the user doesn't lose their input
            if line_buf:
                channel.send("".join(line_buf).encode())
            continue

        # ── Backspace (DEL 0x7f) and BS (0x08) ───────────────────────
        if b in (0x7f, 0x08):
            if line_buf:
                line_buf.pop()
                # Erase: cursor back → overwrite with space → cursor back
                channel.send(b"\x08 \x08")
            continue

        # ── Enter: CR (0x0d) or LF (0x0a) ────────────────────────────
        if b in (0x0d, 0x0a):
            # Swallow the bare LF that Windows clients send after CR
            if b == 0x0a and not line_buf:
                continue

            channel.send(b"\r\n")
            command = "".join(line_buf).strip()
            line_buf = []

            if not command:
                channel.send(_build_prompt(fs))
                continue

            hlog.log_command(session_id, client_ip, command)
            database.log_command(session_id, client_ip, command)

            output, is_exit = fs.handle_command(command)

            if output:
                normalized = (
                    output
                    .replace("\r\n", "\n")
                    .replace("\r", "\n")
                    .replace("\n", "\r\n")
                )
                channel.send(normalized.encode("utf-8", errors="replace"))

            if is_exit:
                channel.close()
                return

            channel.send(_build_prompt(fs))
            continue

        # ── Printable ASCII and extended chars (UTF-8) ────────────────
        # Accept 0x20–0x7e (printable ASCII) and 0x80+ (UTF-8 multibyte)
        if b >= 0x20:
            try:
                ch = byte.decode("utf-8", errors="replace")
            except Exception:
                continue
            line_buf.append(ch)
            channel.send(byte)   # echo back to terminal

    channel.close()


def handle_connection(client_socket: socket.socket, client_address: tuple,
                      host_key: paramiko.RSAKey) -> None:
    client_ip   = client_address[0]
    client_port = client_address[1]
    start_time  = time.time()

    server_iface = HoneypotServerInterface(client_ip, client_port)
    session_id   = server_iface.session_id
    hlog.log_session_start(session_id, client_ip, client_port)

    transport: Optional[paramiko.Transport] = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = config.SSH_BANNER
        transport.add_server_key(host_key)
        transport.start_server(server=server_iface)

        channel = transport.accept(timeout=20)
        if channel is None:
            return

        server_iface.event.wait(timeout=10)
        if not server_iface.event.is_set():
            return

        _run_fake_shell(channel, session_id, client_ip)

    except paramiko.SSHException as e:
        log.debug("SSH error from %s: %s", client_ip, e)
    except EOFError:
        log.debug("EOF from %s", client_ip)
    except Exception as e:
        log.debug("Unexpected error from %s: %s", client_ip, e)
    finally:
        duration = time.time() - start_time
        hlog.log_session_end(session_id, client_ip, duration)
        if transport:
            try: transport.close()
            except Exception: pass
        try: client_socket.close()
        except Exception: pass