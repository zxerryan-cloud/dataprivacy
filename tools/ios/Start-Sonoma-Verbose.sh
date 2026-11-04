#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 "$script_dir/check-kvm.py"
if ! command -v mcopy >/dev/null; then
  apt-get update
  apt-get install -y mtools
fi
printf '1\n' > /sys/module/kvm/parameters/ignore_msrs
export QEMU_DIAGNOSTIC_DIR="$script_dir/../work/sonoma-kvm-diagnostics/verbose-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$QEMU_DIAGNOSTIC_DIR"
cd /opt/OSX-KVM
python3 "$script_dir/prepare-sonoma-verbose.py"
bash -n "$QEMU_DIAGNOSTIC_DIR/launch.sh"
printf 'Select macOS Base System. Verbose mode is automatic; no hotkeys needed.\n'
printf 'Logs: %s\n' "$QEMU_DIAGNOSTIC_DIR"
set +e
bash "$QEMU_DIAGNOSTIC_DIR/launch.sh" > >(tee "$QEMU_DIAGNOSTIC_DIR/console.log") 2>&1
status=$?
set -e
dmesg > "$QEMU_DIAGNOSTIC_DIR/dmesg-after.log" 2>&1 || true
printf 'QEMU exit status: %s\nLogs: %s\n' "$status" "$QEMU_DIAGNOSTIC_DIR"
exit "$status"
