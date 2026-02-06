#!/bin/bash
# Deploy VVP Mock SIP Services to PBX VM
# Run from repo root: ./services/pbx/scripts/deploy-mock-services.sh

set -e

PBX_HOST="${PBX_HOST:-pbx.rcnx.io}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PBX_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== VVP Mock SIP Services Deployment ==="
echo "Target: $PBX_HOST"
echo ""

# Copy files
echo "[1/4] Copying files to PBX..."
scp "$PBX_DIR/test/mock_sip_redirect.py" "$PBX_HOST:/tmp/"
scp "$PBX_DIR/config/public-sip.xml" "$PBX_HOST:/tmp/"
scp "$PBX_DIR/config/vvp-mock-sip.service" "$PBX_HOST:/tmp/"
echo "  ✓ Files copied"

# Install on PBX
echo "[2/4] Installing mock service..."
ssh "$PBX_HOST" "sudo mkdir -p /opt/vvp/mock && sudo cp /tmp/mock_sip_redirect.py /opt/vvp/mock/"
echo "  ✓ Mock service installed"

echo "[3/4] Deploying dialplan..."
ssh "$PBX_HOST" "sudo cp /tmp/public-sip.xml /etc/freeswitch/dialplan/public.xml && sudo chown freeswitch:freeswitch /etc/freeswitch/dialplan/public.xml && fs_cli -x 'reloadxml'"
echo "  ✓ Dialplan deployed"

echo "[4/4] Installing and starting systemd service..."
ssh "$PBX_HOST" "sudo cp /tmp/vvp-mock-sip.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable vvp-mock-sip && sudo systemctl restart vvp-mock-sip"
echo "  ✓ Service started"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Service status:"
ssh "$PBX_HOST" "sudo systemctl status vvp-mock-sip --no-pager -l" || true

echo ""
echo "=== Test Instructions ==="
echo "1. Register extension 1001 via SIP.js client"
echo "2. Register extension 1006 via SIP.js client"
echo "3. From 1001, dial 71006"
echo "4. Extension 1006 should ring with VVP brand info:"
echo "   - Brand: VVP Mock Brand"
echo "   - Status: VALID"
echo ""
echo "View logs: ssh $PBX_HOST 'sudo journalctl -u vvp-mock-sip -f'"
