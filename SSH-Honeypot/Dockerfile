# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps
RUN pip install --upgrade pip

# Copy only dependency files first (better layer caching)
COPY pyproject.toml .
COPY honeypot/    honeypot/
COPY dashboard/   dashboard/
COPY config.py    .
COPY main.py      .

# Install the package and its dependencies into a prefix dir
RUN pip install --prefix=/install .


# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="your-email@example.com"
LABEL description="SSH Honeypot with live dashboard"

# Create a non-root user for the dashboard process.
# The SSH server itself needs to bind to a port (we use 2222, not 22,
# so no root or CAP_NET_BIND_SERVICE needed).
RUN groupadd --gid 1000 honeypot \
 && useradd  --uid 1000 --gid honeypot --shell /bin/bash --create-home honeypot

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --from=builder /app /app

# Data volume — database, keys, and logs live here so they persist
# across container restarts. Mount this as a named volume in production.
RUN mkdir -p /data && chown honeypot:honeypot /data

# Environment defaults (override with -e or docker-compose.yml)
ENV SSH_HOST=0.0.0.0        \
    SSH_PORT=2222            \
    DASHBOARD_HOST=0.0.0.0   \
    DASHBOARD_PORT=8080      \
    SSH_MAX_WORKERS=50       \
    SESSION_TIMEOUT=30       \
    GEOIP_ENABLED=true       \
    LOG_LEVEL=INFO

# Override DATA_DIR so files go to the mounted volume
ENV DATA_DIR=/data

# Expose honeypot SSH port and dashboard port
EXPOSE 2222 8080

USER honeypot

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/stats')" \
  || exit 1

CMD ["python", "main.py"]
