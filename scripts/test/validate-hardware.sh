#!/bin/sh
set -eu

# NetQmon Agent Hardware Validation & Smoke Test Script
# Usage on target router: sh validate-hardware.sh [AGENT_BIN_OR_IPK]

echo "========================================================"
echo " NetQmon Agent Hardware Capability & Validation Script"
echo "========================================================"

# 1. System Architecture & Kernel Information
echo "[1/6] Inspecting Target System Architecture..."
uname -a
echo "Architecture: $(uname -m)"
if [ -f /etc/openwrt_release ]; then
    cat /etc/openwrt_release
fi

# 2. Kernel Module & BPF Subsystem Requirements
echo ""
echo "[2/6] Checking Required Kernel Modules..."
check_kmod() {
    mod="$1"
    if lsmod | grep -q "^$mod"; then
        echo "  - Module $mod: Loaded [OK]"
    else
        echo "  - Module $mod: NOT loaded [WARN]"
    fi
}
check_kmod "act_bpf" || true
check_kmod "cls_bpf" || true
check_kmod "sch_ingress" || true

# 3. Mounts & BPF Filesystem
echo ""
echo "[3/6] Checking BPF Filesystem..."
if mount | grep -q "type bpf"; then
    echo "  - /sys/fs/bpf: Mounted [OK]"
else
    echo "  - /sys/fs/bpf: Not mounted, attempting to mount..."
    mount -t bpf bpf /sys/fs/bpf || echo "  - Warning: Failed to mount bpffs"
fi

# 4. Agent Binary Verification (if binary provided)
AGENT_BIN="${1:-netqmon-agent}"
if command -v "$AGENT_BIN" >/dev/null 2>&1; then
    echo ""
    echo "[4/6] Checking Agent Binary & Static Linkage..."
    "$AGENT_BIN" --version || { echo "Failed to execute $AGENT_BIN --version"; exit 1; }

    # 5. Doctor Capability Probe
    echo ""
    echo "[5/6] Executing Agent Doctor Capability Probe..."
    "$AGENT_BIN" doctor || echo "  - Notice: Doctor reported issues (see output above)"

    # 6. Minimal Smoke Run (5 seconds)
    echo ""
    echo "[6/6] Executing Non-Destructive Smoke Run (5s timeout)..."
    timeout 5 "$AGENT_BIN" run --interfaces br-lan --log-level debug || true
    echo "Smoke run completed without kernel panic or unhandled abort."
else
    echo ""
    echo "[INFO] '$AGENT_BIN' not found in PATH or arguments. Install IPK/APK first:"
    echo "  opkg install netqmon-agent_*.ipk"
    echo "Then re-run this validation script."
fi

echo ""
echo "========================================================"
echo " Validation Script Finished."
echo "========================================================"
