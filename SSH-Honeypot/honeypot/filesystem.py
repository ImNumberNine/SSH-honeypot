"""
honeypot/filesystem.py — Fake navigable Linux filesystem in memory.

Simulates a real Ubuntu server filesystem. Each session gets its own
FakeFilesystem instance so attackers don't interfere with each other
(each one has their own cwd, their own view of the tree).

Design:
  - The filesystem is a nested dict of FakeNode objects
  - Files have content, directories have children
  - Permissions, ownership, and timestamps look realistic
  - Decoy files with attractive names are placed in strategic locations
  - Commands like ls, cd, cat, find, grep work correctly

Attacker perspective:
  A convincing filesystem is what separates a honeypot an attacker
  abandons in 10 seconds from one they spend 10 minutes in. The more
  realistic the environment, the more of their toolkit they expose.
  Decoy files (passwords.txt, .env, backup.sql) reveal what they're
  hunting for when they read them.
"""

import random
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FakeNode:
    """
    Represents either a file or a directory in the fake filesystem.

    Attributes:
        name        : filename/dirname
        is_dir      : True for directories
        content     : file content (empty string for dirs)
        children    : child nodes (only for dirs)
        permissions : Linux permission string, e.g. "rwxr-xr-x"
        owner       : owning user
        group       : owning group
        size        : reported file size in bytes
        mtime       : last modified datetime
        is_decoy    : if True, reading this file is logged as HIGH interest
    """
    name:        str
    is_dir:      bool               = False
    content:     str                = ""
    children:    Dict[str, "FakeNode"] = field(default_factory=dict)
    permissions: str                = "rw-r--r--"
    owner:       str                = "root"
    group:       str                = "root"
    size:        int                = 0
    mtime:       datetime           = field(default_factory=datetime.now)
    is_decoy:    bool               = False

    def __post_init__(self):
        if self.size == 0 and self.content:
            self.size = len(self.content.encode())
        if self.is_dir and not self.permissions.startswith("d"):
            # Store without 'd' prefix internally; ls adds it
            pass

    @property
    def perm_string(self) -> str:
        prefix = "d" if self.is_dir else "-"
        return prefix + self.permissions

    @property
    def mtime_str(self) -> str:
        now = datetime.now()
        if (now - self.mtime).days < 180:
            return self.mtime.strftime("%b %d %H:%M")
        return self.mtime.strftime("%b %d  %Y")


def _dir(name: str, owner: str = "root", group: str = "root",
         perms: str = "rwxr-xr-x", mtime: datetime = None) -> FakeNode:
    return FakeNode(
        name        = name,
        is_dir      = True,
        permissions = perms,
        owner       = owner,
        group       = group,
        mtime       = mtime or _rand_mtime(90, 365),
    )


def _file(name: str, content: str, owner: str = "root", group: str = "root",
          perms: str = "rw-r--r--", mtime: datetime = None,
          is_decoy: bool = False) -> FakeNode:
    return FakeNode(
        name        = name,
        is_dir      = False,
        content     = content,
        permissions = perms,
        owner       = owner,
        group       = group,
        mtime       = mtime or _rand_mtime(7, 90),
        is_decoy    = is_decoy,
    )


def _rand_mtime(min_days_ago: int = 1, max_days_ago: int = 180) -> datetime:
    days = random.randint(min_days_ago, max_days_ago)
    return datetime.now() - timedelta(days=days, hours=random.randint(0, 23))


# ═══════════════════════════════════════════════════════════════════════════════
# FILESYSTEM TREE BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def _build_tree() -> FakeNode:
    """
    Build and return the root FakeNode of the fake filesystem.
    Structured like a real Ubuntu 22.04 server.
    """

    # ── /etc ──────────────────────────────────────────────────────────
    etc = _dir("etc")
    etc.children = {
        "passwd": _file("passwd", content=(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        ), perms="rw-r--r--"),

        "shadow": _file("shadow", content=(
            "root:$6$rounds=656000$randomsalt$hashedpassword:19000:0:99999:7:::\n"
            "ubuntu:$6$rounds=656000$anothersalt$anotherhashedpass:19000:0:99999:7:::\n"
        ), perms="rw-r-----", group="shadow"),

        "hostname": _file("hostname", content="ubuntu\n"),

        "hosts": _file("hosts", content=(
            "127.0.0.1\tlocalhost\n"
            "127.0.1.1\tubuntu\n"
            "::1\tlocalhost ip6-localhost ip6-loopback\n"
        )),

        "os-release": _file("os-release", content=(
            'NAME="Ubuntu"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\n'
            'ID_LIKE=debian\n'
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
            'VERSION_ID="22.04"\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
        )),

        "ssh": _dir("ssh"),  # sshd_config lives here but we keep it minimal

        "crontab": _file("crontab", content=(
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
            "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        )),
    }

    # ── /root (the attacker thinks they're root) ───────────────────────
    root_home = _dir("root", perms="rwx------")
    root_home.children = {
        ".bashrc": _file(".bashrc", content=(
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "export PATH=$PATH:/usr/local/sbin\n"
            'export PS1="\\u@\\h:\\w# "\n'
        )),
        ".bash_history": _file(".bash_history", content=(
            "apt update\n"
            "apt install -y nginx\n"
            "systemctl status nginx\n"
            "mysql -u root -p\n"
            "tail -f /var/log/nginx/access.log\n"
            "ufw allow 80\n"
            "ufw allow 443\n"
            "certbot --nginx -d example.com\n"
        )),
        ".ssh": _dir(".ssh", perms="rwx------"),

        # ── Decoy files — HIGH value intelligence triggers ─────────────
        ".env": _file(".env", is_decoy=True, content=(
            "# Application environment\n"
            "APP_ENV=production\n"
            "APP_KEY=base64:kXzCm3Y8Qv2Nw1Lp9Jf4Rh6Td5Bg0Ue7Is\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=127.0.0.1\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=webapp\n"
            "DB_USERNAME=webapp_user\n"
            "DB_PASSWORD=Str0ngP@ssw0rd_2024!\n"
            "REDIS_HOST=127.0.0.1\n"
            "STRIPE_KEY=sk_live_FAKE_KEY_DO_NOT_USE\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/FAKE\n"
        ), perms="rw-------"),

        "passwords.txt": _file("passwords.txt", is_decoy=True, content=(
            "# Server credentials — KEEP PRIVATE\n"
            "MySQL root: Tr0ub4dor&3_mysql\n"
            "Nginx admin: nG1nx@dm1n2024\n"
            "Backup user: B4ckup$ecure!\n"
            "VPN: vpn_secret_key_2024\n"
        ), perms="rw-------"),

        "backup.sh": _file("backup.sh", is_decoy=True, content=(
            "#!/bin/bash\n"
            "# Daily backup script\n"
            "BACKUP_DIR=/var/backups\n"
            "DB_PASS='Tr0ub4dor&3_mysql'\n"
            "mysqldump -u root -p$DB_PASS webapp > $BACKUP_DIR/webapp_$(date +%Y%m%d).sql\n"
            "tar czf $BACKUP_DIR/www_$(date +%Y%m%d).tar.gz /var/www/html\n"
            "aws s3 cp $BACKUP_DIR s3://company-backups/ --recursive\n"
        ), perms="rwx------"),
    }

    # ── /home ──────────────────────────────────────────────────────────
    home = _dir("home")
    ubuntu_home = _dir("ubuntu", owner="ubuntu", group="ubuntu", perms="rwxr-xr-x")
    ubuntu_home.children = {
        ".bashrc":       _file(".bashrc", content="# ubuntu user bashrc\n", owner="ubuntu", group="ubuntu"),
        ".bash_history": _file(".bash_history", owner="ubuntu", group="ubuntu", content=(
            "ls -la\n"
            "sudo apt update\n"
            "sudo systemctl restart nginx\n"
            "nano /var/www/html/index.html\n"
        )),
        ".ssh": _dir(".ssh", owner="ubuntu", group="ubuntu", perms="rwx------"),
        "notes.txt": _file("notes.txt", owner="ubuntu", group="ubuntu", is_decoy=True, content=(
            "TODO:\n"
            "- Renew SSL cert before Dec 15\n"
            "- Update MySQL password (current: Tr0ub4dor&3_mysql)\n"
            "- Move API keys to env vars\n"
            "- Setup 2FA for all admin accounts\n"
        )),
    }
    home.children = {"ubuntu": ubuntu_home}

    # ── /var ──────────────────────────────────────────────────────────
    var = _dir("var")
    var_log = _dir("log")
    var_log.children = {
        "auth.log": _file("auth.log", content=(
            "Nov 14 09:20:11 ubuntu sshd[411]: Server listening on 0.0.0.0 port 22.\n"
            "Nov 14 09:21:03 ubuntu sshd[511]: Accepted password for ubuntu from 10.0.2.2 port 54321\n"
            "Nov 14 09:21:03 ubuntu systemd-logind[312]: New session 1 of user ubuntu.\n"
        ), perms="rw-r-----", group="adm"),
        "syslog": _file("syslog", content=(
            "Nov 14 09:20:10 ubuntu kernel: Linux version 5.15.0-91-generic\n"
            "Nov 14 09:20:11 ubuntu systemd[1]: Started OpenBSD Secure Shell server.\n"
        ), perms="rw-r-----", group="adm"),
        "nginx": _dir("nginx"),
    }
    var_log.children["nginx"].children = {
        "access.log": _file("access.log", content=(
            '10.0.2.2 - - [14/Nov/2023:09:21:00 +0000] "GET / HTTP/1.1" 200 612\n'
            '10.0.2.2 - - [14/Nov/2023:09:21:01 +0000] "GET /favicon.ico HTTP/1.1" 404 197\n'
        ), perms="rw-r-----", group="adm"),
        "error.log": _file("error.log", content="", perms="rw-r-----", group="adm"),
    }

    var_www = _dir("www")
    var_www_html = _dir("html", owner="www-data", group="www-data")
    var_www_html.children = {
        "index.html": _file("index.html", owner="www-data", group="www-data",
                            content="<html><body><h1>Welcome to nginx!</h1></body></html>\n"),
        ".htaccess":  _file(".htaccess", owner="www-data", group="www-data", content=""),
    }
    var_www.children   = {"html": var_www_html}
    var.children       = {"log": var_log, "www": var_www, "backups": _dir("backups")}

    # ── /tmp ──────────────────────────────────────────────────────────
    tmp = _dir("tmp", perms="rwxrwxrwt")

    # ── /proc (minimal) ───────────────────────────────────────────────
    proc = _dir("proc")
    proc.children = {
        "version": _file("version",
            content="Linux version 5.15.0-91-generic (buildd@lcy02-amd64-032) "
                    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP Tue Nov 14\n"),
        "cpuinfo": _file("cpuinfo", content=(
            "processor\t: 0\nvendor_id\t: GenuineIntel\n"
            "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
            "cpu MHz\t\t: 2399.996\ncache size\t: 35840 KB\n"
        )),
        "meminfo": _file("meminfo", content=(
            "MemTotal:        2048000 kB\nMemFree:         1024000 kB\n"
            "MemAvailable:    1500000 kB\nSwapTotal:       1048576 kB\n"
            "SwapFree:        1048576 kB\n"
        )),
    }

    # ── /usr/bin (minimal — just enough for file lookups) ─────────────
    usr = _dir("usr")
    usr_bin = _dir("bin")
    for binary in ["python3", "python", "perl", "wget", "curl", "nc",
                   "nmap", "bash", "sh", "vim", "nano", "gcc"]:
        usr_bin.children[binary] = _file(
            binary, content="", perms="rwxr-xr-x",
            owner="root", group="root",
        )
    usr.children = {"bin": usr_bin, "sbin": _dir("sbin"), "local": _dir("local")}

    # ── Root node ──────────────────────────────────────────────────────
    root = _dir("/")
    root.children = {
        "etc":  etc,
        "root": root_home,
        "home": home,
        "var":  var,
        "tmp":  tmp,
        "proc": proc,
        "usr":  usr,
        "bin":  _dir("bin"),
        "sbin": _dir("sbin"),
        "dev":  _dir("dev"),
        "sys":  _dir("sys"),
        "run":  _dir("run"),
        "opt":  _dir("opt"),
        "srv":  _dir("srv"),
    }
    return root


# ═══════════════════════════════════════════════════════════════════════════════
# FILESYSTEM CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class FakeFilesystem:
    """
    A navigable fake Linux filesystem.

    Each session gets its own instance so cwd is isolated.
    Commands are dispatched through handle_command() which returns
    the string the fake shell should send back to the attacker.

    Decoy file reads are flagged via the decoy_read_callback so the
    handler can log them with elevated severity.
    """

    def __init__(self, decoy_callback=None):
        """
        Args:
            decoy_callback: callable(path: str) — called when attacker
                            reads a decoy file. Used for high-priority logging.
        """
        self._root    = _build_tree()
        self._cwd_parts: List[str] = []   # empty = root /
        self._decoy_cb = decoy_callback

    # ── Path utilities ─────────────────────────────────────────────────

    @property
    def cwd(self) -> str:
        if not self._cwd_parts:
            return "/"
        return "/" + "/".join(self._cwd_parts)

    def _resolve(self, path: str) -> Optional[List[str]]:
        """
        Resolve a path string to a list of path parts (from root).
        Handles absolute paths, relative paths, .., and ~.
        Returns None if the path does not exist.
        """
        if path.startswith("~"):
            path = "/root" + path[1:]

        if path.startswith("/"):
            parts = [p for p in path.split("/") if p]
        else:
            parts = self._cwd_parts + [p for p in path.split("/") if p]

        # Resolve . and ..
        resolved = []
        for part in parts:
            if part == ".":
                continue
            elif part == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(part)

        return resolved

    def _get_node(self, parts: List[str]) -> Optional[FakeNode]:
        """Walk the tree and return the node at the given path parts."""
        node = self._root
        for part in parts:
            if not node.is_dir or part not in node.children:
                return None
            node = node.children[part]
        return node

    def _node_at(self, path: str) -> Optional[FakeNode]:
        parts = self._resolve(path)
        if parts is None:
            return None
        return self._get_node(parts)

    # ── Command dispatcher ─────────────────────────────────────────────

    def handle_command(self, command: str) -> Tuple[str, bool]:
        """
        Process a shell command and return (output, is_exit).

        Returns:
            output   : string to send back to the attacker
            is_exit  : True if the command should end the session
        """
        command = command.strip()
        if not command:
            return ("", False)

        # Parse with shlex to handle quoted args correctly
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()

        if not parts:
            return ("", False)

        cmd  = parts[0]
        args = parts[1:]

        # Strip common env prefixes like TERM=xterm-256color bash
        if "=" in cmd and args:
            cmd  = args[0]
            args = args[1:]

        dispatch = {
            "ls":      self._cmd_ls,
            "ll":      lambda a: self._cmd_ls(["-la"] + a),
            "dir":     self._cmd_ls,
            "cd":      self._cmd_cd,
            "pwd":     self._cmd_pwd,
            "cat":     self._cmd_cat,
            "head":    self._cmd_head,
            "tail":    self._cmd_tail,
            "less":    self._cmd_cat,
            "more":    self._cmd_cat,
            "find":    self._cmd_find,
            "grep":    self._cmd_grep,
            "echo":    self._cmd_echo,
            "whoami":  lambda a: ("root\r\n", False),
            "id":      lambda a: ("uid=0(root) gid=0(root) groups=0(root)\r\n", False),
            "uname":   self._cmd_uname,
            "hostname":lambda a: ("ubuntu\r\n", False),
            "uptime":  lambda a: (" 15:42:11 up 1 day,  6:22,  1 user,  load average: 0.08, 0.12, 0.10\r\n", False),
            "w":       lambda a: (" 15:42:11 up 1 day,  6:22,  1 user\r\nUSER     TTY      FROM             LOGIN@   IDLE\r\nroot     pts/0    10.0.2.2         09:20    0.00s\r\n", False),
            "ps":      self._cmd_ps,
            "env":     self._cmd_env,
            "printenv":self._cmd_env,
            "history": self._cmd_history,
            "mkdir":   self._cmd_mkdir,
            "touch":   self._cmd_touch,
            "rm":      lambda a: ("", False),
            "cp":      lambda a: ("", False),
            "mv":      lambda a: ("", False),
            "chmod":   lambda a: ("", False),
            "chown":   lambda a: ("", False),
            "wget":    self._cmd_wget,
            "curl":    self._cmd_curl,
            "python":  self._cmd_python,
            "python3": self._cmd_python,
            "perl":    lambda a: ("", False),
            "bash":    lambda a: ("", False),
            "sh":      lambda a: ("", False),
            "which":   self._cmd_which,
            "file":    self._cmd_file,
            "stat":    self._cmd_stat,
            "df":      lambda a: ("Filesystem     1K-blocks    Used Available Use% Mounted on\r\n/dev/sda1       20971520 4194304  15728640  22% /\r\ntmpfs            1024000       0   1024000   0% /dev/shm\r\n", False),
            "free":    lambda a: ("               total        used        free\r\nMem:         2048000      512000     1536000\r\nSwap:        1048576           0     1048576\r\n", False),
            "netstat": lambda a: ("Active Internet connections (only servers)\r\nProto Recv-Q Send-Q Local Address  Foreign Address  State\r\ntcp   0      0     0.0.0.0:22     0.0.0.0:*        LISTEN\r\ntcp   0      0     0.0.0.0:80     0.0.0.0:*        LISTEN\r\n", False),
            "ss":      lambda a: ("Netid State  Recv-Q Send-Q  Local Address:Port\r\ntcp   LISTEN 0      128           0.0.0.0:22\r\ntcp   LISTEN 0      511           0.0.0.0:80\r\n", False),
            "ifconfig":lambda a: ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n", False),
            "ip":      lambda a: ("1: lo: <LOOPBACK,UP,LOWER_UP>\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\r\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\r\n", False),
            "exit":    lambda a: ("logout\r\n", True),
            "logout":  lambda a: ("logout\r\n", True),
            "quit":    lambda a: ("logout\r\n", True),
            "clear":   lambda a: ("\033[2J\033[H", False),
        }

        handler = dispatch.get(cmd)
        if handler:
            return handler(args)

        # Attempt to run unknown commands — "not found"
        return (f"-bash: {cmd}: command not found\r\n", False)

    # ── Command implementations ────────────────────────────────────────

    def _cmd_ls(self, args: List[str]) -> Tuple[str, bool]:
        show_hidden = "-a" in args or "-la" in args or "-al" in args
        long_fmt    = "-l" in args or "-la" in args or "-al" in args or "-lh" in args

        # Find the target path (last non-flag arg, or cwd)
        target = self.cwd
        for a in args:
            if not a.startswith("-"):
                target = a
                break

        node = self._node_at(target)
        if node is None:
            return (f"ls: cannot access '{target}': No such file or directory\r\n", False)

        if not node.is_dir:
            entries = [node]
        else:
            entries = list(node.children.values())
            if not show_hidden:
                entries = [e for e in entries if not e.name.startswith(".")]
            entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))

        if not long_fmt:
            names = []
            for e in entries:
                if e.is_dir:
                    names.append(e.name + "/")
                else:
                    names.append(e.name)
            return ("  ".join(names) + "\r\n" if names else "", False)

        # Long format
        lines = [f"total {len(entries) * 4}"]
        for e in entries:
            lines.append(
                f"{e.perm_string}  1 {e.owner:<8} {e.group:<8} "
                f"{e.size:>6}  {e.mtime_str}  {e.name}"
            )
        return ("\r\n".join(lines) + "\r\n", False)

    def _cmd_cd(self, args: List[str]) -> Tuple[str, bool]:
        path = args[0] if args else "/root"
        parts = self._resolve(path)
        node  = self._get_node(parts)

        if node is None:
            return (f"bash: cd: {path}: No such file or directory\r\n", False)
        if not node.is_dir:
            return (f"bash: cd: {path}: Not a directory\r\n", False)

        self._cwd_parts = parts
        return ("", False)

    def _cmd_pwd(self, args: List[str]) -> Tuple[str, bool]:
        return (self.cwd + "\r\n", False)

    def _cmd_cat(self, args: List[str]) -> Tuple[str, bool]:
        if not args:
            return ("", False)

        output = []
        for path in args:
            if path.startswith("-"):
                continue
            node = self._node_at(path)
            if node is None:
                output.append(f"cat: {path}: No such file or directory")
            elif node.is_dir:
                output.append(f"cat: {path}: Is a directory")
            else:
                # Fire decoy callback if this is a trap file
                if node.is_decoy and self._decoy_cb:
                    full_path = self._full_path(path)
                    self._decoy_cb(full_path, node.content)
                output.append(node.content.rstrip())

        return ("\r\n".join(output) + "\r\n", False)

    def _cmd_head(self, args: List[str]) -> Tuple[str, bool]:
        n = 10
        files = []
        skip_next = False
        for a in args:
            if skip_next:
                try: n = int(a)
                except ValueError: pass
                skip_next = False
            elif a == "-n":
                skip_next = True
            elif a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            elif not a.startswith("-"):
                files.append(a)

        if not files:
            return ("", False)

        node = self._node_at(files[0])
        if node is None or node.is_dir:
            return (f"head: {files[0]}: No such file or directory\r\n", False)

        lines = node.content.splitlines()[:n]
        return ("\r\n".join(lines) + "\r\n", False)

    def _cmd_tail(self, args: List[str]) -> Tuple[str, bool]:
        n = 10
        files = []
        for a in args:
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            elif not a.startswith("-"):
                files.append(a)

        if not files:
            return ("", False)

        node = self._node_at(files[0])
        if node is None or node.is_dir:
            return (f"tail: {files[0]}: No such file or directory\r\n", False)

        lines = node.content.splitlines()[-n:]
        return ("\r\n".join(lines) + "\r\n", False)

    def _cmd_find(self, args: List[str]) -> Tuple[str, bool]:
        """Simplified find: find <path> -name <pattern>"""
        start_path = "."
        name_pattern = None

        i = 0
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                name_pattern = args[i + 1].replace("*", ".*").replace("?", ".")
                i += 2
            elif not args[i].startswith("-"):
                start_path = args[i]
                i += 1
            else:
                i += 1

        results = []
        self._walk_find(self._resolve(start_path), start_path, name_pattern, results, depth=0)
        return ("\r\n".join(results) + "\r\n" if results else "", False)

    def _walk_find(self, parts, display_path, pattern, results, depth):
        if depth > 8:
            return
        node = self._get_node(parts or [])
        if node is None:
            return

        name = node.name if node.name != "/" else "."
        path_str = display_path if display_path else ("/" + "/".join(parts))

        if pattern is None or re.search(pattern, node.name):
            results.append(path_str)

        if node.is_dir and depth < 8:
            for child_name, child in node.children.items():
                child_display = path_str.rstrip("/") + "/" + child_name
                self._walk_find(
                    (parts or []) + [child_name],
                    child_display,
                    pattern,
                    results,
                    depth + 1,
                )

    def _cmd_grep(self, args: List[str]) -> Tuple[str, bool]:
        if len(args) < 2:
            return ("", False)

        flags   = [a for a in args if a.startswith("-")]
        nonflags = [a for a in args if not a.startswith("-")]
        if len(nonflags) < 2:
            return ("", False)

        pattern = nonflags[0]
        path    = nonflags[1]
        node    = self._node_at(path)

        if node is None:
            return (f"grep: {path}: No such file or directory\r\n", False)
        if node.is_dir:
            return (f"grep: {path}: Is a directory\r\n", False)

        ignore_case = "-i" in flags
        matches = []
        for line in node.content.splitlines():
            haystack = line.lower() if ignore_case else line
            needle   = pattern.lower() if ignore_case else pattern
            if re.search(needle, haystack):
                matches.append(line)

        return ("\r\n".join(matches) + "\r\n" if matches else "", False)

    def _cmd_echo(self, args: List[str]) -> Tuple[str, bool]:
        return (" ".join(args) + "\r\n", False)

    def _cmd_uname(self, args: List[str]) -> Tuple[str, bool]:
        if "-a" in args:
            return ("Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n", False)
        if "-r" in args:
            return ("5.15.0-91-generic\r\n", False)
        return ("Linux\r\n", False)

    def _cmd_ps(self, args: List[str]) -> Tuple[str, bool]:
        return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:02 systemd\r\n"
            "  411 ?        00:00:00 sshd\r\n"
            "  512 pts/0    00:00:00 bash\r\n"
            "  513 pts/0    00:00:00 ps\r\n",
            False,
        )

    def _cmd_env(self, args: List[str]) -> Tuple[str, bool]:
        return (
            "SHELL=/bin/bash\r\n"
            "TERM=xterm-256color\r\n"
            "USER=root\r\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
            "HOME=/root\r\n"
            "LOGNAME=root\r\n",
            False,
        )

    def _cmd_history(self, args: List[str]) -> Tuple[str, bool]:
        node = self._node_at("/root/.bash_history")
        if node:
            lines = node.content.strip().splitlines()
            numbered = [f"  {i+1}  {line}" for i, line in enumerate(lines)]
            return ("\r\n".join(numbered) + "\r\n", False)
        return ("", False)

    def _cmd_mkdir(self, args: List[str]) -> Tuple[str, bool]:
        for a in args:
            if a.startswith("-"):
                continue
            parts  = self._resolve(a)
            parent = self._get_node(parts[:-1])
            if parent and parent.is_dir:
                parent.children[parts[-1]] = _dir(parts[-1])
        return ("", False)

    def _cmd_touch(self, args: List[str]) -> Tuple[str, bool]:
        for a in args:
            if a.startswith("-"):
                continue
            parts  = self._resolve(a)
            parent = self._get_node(parts[:-1])
            if parent and parent.is_dir and parts[-1] not in parent.children:
                parent.children[parts[-1]] = _file(parts[-1], content="")
        return ("", False)

    def _cmd_wget(self, args: List[str]) -> Tuple[str, bool]:
        urls = [a for a in args if not a.startswith("-")]
        url  = urls[0] if urls else "?"
        # Log the URL — highly valuable intelligence
        if self._decoy_cb:
            self._decoy_cb(f"WGET:{url}", f"wget {' '.join(args)}")
        return (
            f"--2023-11-14 15:42:11--  {url}\r\n"
            f"Connecting to {url.split('/')[2] if '//' in url else url}... connected.\r\n"
            "HTTP request sent, awaiting response... 200 OK\r\n"
            "Length: 4096 (4.0K) [application/octet-stream]\r\n"
            "Saving to: 'payload'\r\n\r\n"
            "payload             100%[=================>]   4.00K  --.-KB/s    in 0s\r\n\r\n"
            "2023-11-14 15:42:11 (45.2 MB/s) - 'payload' saved [4096/4096]\r\n",
            False,
        )

    def _cmd_curl(self, args: List[str]) -> Tuple[str, bool]:
        urls = [a for a in args if not a.startswith("-") and ("http" in a or "." in a)]
        url  = urls[0] if urls else "?"
        if self._decoy_cb:
            self._decoy_cb(f"CURL:{url}", f"curl {' '.join(args)}")
        if "-s" in args or "--silent" in args:
            return ("", False)
        return (f"  % Total    % Received % Xferd\r\n100  4096  100  4096    0     0   8192      0\r\n", False)

    def _cmd_python(self, args: List[str]) -> Tuple[str, bool]:
        if "-c" in args:
            idx = args.index("-c")
            code = args[idx + 1] if idx + 1 < len(args) else ""
            if self._decoy_cb:
                self._decoy_cb(f"PYTHON:-c", code)
            return ("", False)
        return ("Python 3.10.12 (main, Nov 20 2023, 15:14:05)\r\n>>> ", False)

    def _cmd_which(self, args: List[str]) -> Tuple[str, bool]:
        known = {"python": "/usr/bin/python3", "python3": "/usr/bin/python3",
                 "wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
                 "bash": "/bin/bash", "sh": "/bin/sh", "nc": "/bin/nc",
                 "perl": "/usr/bin/perl", "gcc": "/usr/bin/gcc"}
        out = []
        for a in args:
            if a in known:
                out.append(known[a])
            else:
                out.append(f"which: no {a} in ($PATH)")
        return ("\r\n".join(out) + "\r\n", False)

    def _cmd_file(self, args: List[str]) -> Tuple[str, bool]:
        out = []
        for a in [x for x in args if not x.startswith("-")]:
            node = self._node_at(a)
            if node is None:
                out.append(f"{a}: ERROR: No such file or directory")
            elif node.is_dir:
                out.append(f"{a}: directory")
            else:
                out.append(f"{a}: ASCII text")
        return ("\r\n".join(out) + "\r\n" if out else "", False)

    def _cmd_stat(self, args: List[str]) -> Tuple[str, bool]:
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return ("", False)
        node = self._node_at(files[0])
        if node is None:
            return (f"stat: cannot statx '{files[0]}': No such file or directory\r\n", False)
        return (
            f"  File: {files[0]}\r\n"
            f"  Size: {node.size}\r\n"
            f"Access: ({node.perm_string})\r\n"
            f"  Uid: ( 0/ root)\r\n"
            f"  Gid: ( 0/ root)\r\n"
            f"Modify: {node.mtime.strftime('%Y-%m-%d %H:%M:%S')}\r\n",
            False,
        )

    def _full_path(self, path: str) -> str:
        parts = self._resolve(path)
        if not parts:
            return "/"
        return "/" + "/".join(parts)