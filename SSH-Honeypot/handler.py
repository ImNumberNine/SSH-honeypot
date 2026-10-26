"""
honeypot/handler.py — Handles individual SSH connections.

Terminal input is processed one byte at a time (recv(1)) with proper
handling of backspace, escape sequences, Ctrl combinations, and tab.

Erase sequence uses ANSI CSI (ESC[D + ESC[K) instead of legacy
BS+SP+BS because modern terminal emulators (alacritty, kitty, konsole)
respond more reliably to cursor-movement + erase-to-EOL.
"""

import logging
import socket
import threading
import time
import uuid
from typing import List, Optional

import paramiko

import config
from honeypot import database, geoip, logger as hlog
from honeypot.filesystem import FakeFilesystem

log = logging.getLogger(__name__)

# ── Erase sequence ────────────────────────────────────────────────────────────
#
# To erase one character we need to:
#   1. Move cursor one position left  (ESC [ D  =  CSI Cursor Back)
#   2. Erase from cursor to end of line  (ESC [ K  =  CSI Erase in Line)
#
# This is more reliable than the legacy  BS SP BS  (\x08 \x08) on
# modern terminal emulators that handle ANSI sequences but may not
# respond to raw control characters the same way.
ERASE_CHAR = b"\x1b[D\x1b[K"


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
        hlog.log_attempt(self.client_ip, self.client_port, username, password,
                         self.session_id, geo)
        database.log_attempt(self.client_ip, self.client_port, username, password,
                              self.session_id, geo)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password"


def _prompt(fs: FakeFilesystem) -> bytes:
    cwd     = fs.cwd
    display = "~" if cwd == "/root" else cwd
    return f"root@ubuntu:{display}# ".encode()


def _redraw_line(channel: paramiko.Channel, buf: List[str], prompt: bytes) -> None:
    """
    Redraw the current input line from scratch.
    Used after Ctrl+C or whenever we need a clean reset.
    Sequence: carriage-return → erase line → prompt → current buffer content.
    """
    channel.send(b"\r\x1b[K")          # CR + erase to end of line
    channel.send(prompt)
    channel.send("".join(buf).encode())


def _run_fake_shell(channel: paramiko.Channel, session_id: str,
                    client_ip: str) -> None:
    """
    Fake interactive shell backed by FakeFilesystem.

    Input loop reads exactly ONE BYTE per recv() call. This eliminates
    any ordering ambiguity when backspace and regular characters arrive
    in the same TCP segment.

    Key handling:
      Printable chars  (0x20-0x7e, 0x80+) — echo + append to buffer
      0x7f / 0x08      — backspace: ANSI erase + pop from buffer
      0x1b [...]       — escape sequence (arrow keys etc.) — discard
      0x1b [3 ~        — Delete key — treated as backspace
      0x0d / 0x0a      — Enter: execute command
      0x03             — Ctrl+C: clear line
      0x04             — Ctrl+D: exit if buffer empty
      0x0c             — Ctrl+L: clear screen
      0x09             — Tab: show spaces (no completion, but no garbage)
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

    fs  = FakeFilesystem(decoy_callback=decoy_read)
    pmt = _prompt(fs)

    channel.send(
        b"\r\nWelcome to Ubuntu 22.04.3 LTS "
        b"(GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        b" * Documentation:  https://help.ubuntu.com\r\n"
        b" * Management:     https://landscape.canonical.com\r\n\r\n"
    )
    channel.send(pmt)
    channel.settimeout(config.SESSION_TIMEOUT)

    buf: List[str] = []    # characters forming the current command
    esc: List[int] = []    # bytes of an in-progress ANSI escape sequence
    last_was_cr    = False  # flag to swallow \n after \r (Windows Enter)

    while True:
        try:
            raw = channel.recv(1)
        except socket.timeout:
            break
        if not raw:
            break

        b = raw[0]   # integer 0-255

        # ── ANSI / VT escape sequence accumulation ────────────────────
        if esc:
            esc.append(b)

            # Sequences end with a letter (0x40-0x7e)
            if 0x40 <= b <= 0x7e:
                # Check for Delete key  ESC [ 3 ~  (0x1b 0x5b 0x33 0x7e)
                if esc == [0x1b, 0x5b, 0x33, 0x7e]:
                    # Treat Delete as Backspace
                    if buf:
                        buf.pop()
                        channel.send(ERASE_CHAR)
                esc = []
            elif len(esc) > 10:
                esc = []   # safety drain — malformed sequence
            continue

        if b == 0x1b:
            esc = [b]
            continue

        # ── Skip bare \n if it immediately follows \r ─────────────────
        if b == 0x0a and last_was_cr:
            last_was_cr = False
            continue
        last_was_cr = (b == 0x0d)

        # ── Ctrl+C ────────────────────────────────────────────────────
        if b == 0x03:
            channel.send(b"^C\r\n")
            buf = []
            pmt = _prompt(fs)
            channel.send(pmt)
            continue

        # ── Ctrl+D ────────────────────────────────────────────────────
        if b == 0x04:
            if not buf:
                channel.send(b"exit\r\nlogout\r\n")
                channel.close()
                return
            continue

        # ── Ctrl+L — clear screen ─────────────────────────────────────
        if b == 0x0c:
            channel.send(b"\x1b[2J\x1b[H")   # clear + cursor home
            pmt = _prompt(fs)
            _redraw_line(channel, buf, pmt)
            continue

        # ── Tab — ignore gracefully (no garbage printed) ──────────────
        if b == 0x09:
            continue

        # ── Backspace  (DEL 0x7f  or  BS 0x08) ───────────────────────
        if b in (0x7f, 0x08):
            if buf:
                buf.pop()
                channel.send(ERASE_CHAR)
            continue

        # ── Enter  (CR 0x0d  or  LF 0x0a) ────────────────────────────
        if b in (0x0d, 0x0a):
            channel.send(b"\r\n")
            command = "".join(buf).strip()
            buf     = []

            if not command:
                pmt = _prompt(fs)
                channel.send(pmt)
                continue

            hlog.log_command(session_id, client_ip, command)
            database.log_command(session_id, client_ip, command)

            output, is_exit = fs.handle_command(command)

            if output:
                # Normalise all line endings to \r\n for terminal display
                out = (
                    output
                    .replace("\r\n", "\n")
                    .replace("\r",   "\n")
                    .replace("\n",   "\r\n")
                )
                channel.send(out.encode("utf-8", errors="replace"))

            if is_exit:
                channel.close()
                return

            pmt = _prompt(fs)
            channel.send(pmt)
            continue

        # ── Printable ASCII (0x20-0x7e) and UTF-8 lead bytes (0x80+) ──
        if b >= 0x20:
            try:
                ch = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            buf.append(ch)
            channel.send(raw)   # echo the character back

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
