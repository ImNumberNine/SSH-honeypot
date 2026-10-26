#!/bin/bash
# deploy.sh — One-command deploy to a fresh Ubuntu VPS
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh <VPS_IP>
#
# What it does:
#   1. Installs Docker and Docker Compose on the VPS
#   2. Opens firewall ports (2222 for honeypot, 8080 stays localhost-only)
#   3. Clones the repo and starts the honeypot
#   4. Sets up logrotate for the JSONL event log
#
# After running, access the dashboard via SSH tunnel:
#   ssh -L 8080:localhost:8080 user@<VPS_IP>
#   Open http://localhost:8080 in your browser

set -euo pipefail

VPS_IP="${1:?Usage: ./deploy.sh <VPS_IP>}"
VPS_USER="${2:-root}"
REPO_URL="${3:-https://github.com/YOUR_USERNAME/ssh-honeypot.git}"

echo "═══════════════════════════════════════"
echo "  SSH Honeypot — VPS Deployment"
echo "  Target: ${VPS_USER}@${VPS_IP}"
echo "═══════════════════════════════════════"

ssh "${VPS_USER}@${VPS_IP}" bash << 'REMOTE'
set -euo pipefail

echo "→ Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq

echo "→ Installing Docker..."
curl -fsSL https://get.docker.com | sh
systemctl enable docker
systemctl start docker

echo "→ Installing Docker Compose plugin..."
apt-get install -y -qq docker-compose-plugin

echo "→ Configuring firewall..."
ufw allow 2222/tcp comment "SSH Honeypot"
ufw allow 22/tcp   comment "Real SSH"
# Port 8080 intentionally NOT opened — access via SSH tunnel only
ufw --force enable

echo "→ Cloning repository..."
cd /opt
git clone "${REPO_URL:-https://github.com/YOUR_USERNAME/ssh-honeypot.git}" ssh-honeypot
cd ssh-honeypot

echo "→ Generating Flask secret key..."
SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/change-me-before-deploying/${SECRET}/" docker-compose.yml

echo "→ Building and starting containers..."
docker compose up -d --build

echo "→ Setting up logrotate..."
cat > /etc/logrotate.d/ssh-honeypot << 'EOF'
/var/lib/docker/volumes/ssh-honeypot_honeypot-data/_data/events.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
EOF

echo ""
echo "═══════════════════════════════════════"
echo "  Deployment complete!"
echo "  SSH Honeypot: ${VPS_IP}:2222"
echo ""
echo "  Access dashboard via SSH tunnel:"
echo "  ssh -L 8080:localhost:8080 ${VPS_USER}@${VPS_IP}"
echo "  Then open: http://localhost:8080"
echo ""
echo "  View logs:"
echo "  docker compose -f /opt/ssh-honeypot/docker-compose.yml logs -f"
echo "═══════════════════════════════════════"
REMOTE
