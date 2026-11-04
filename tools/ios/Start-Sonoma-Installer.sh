#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd /opt/OSX-KVM
if [ ! -c /dev/kvm ]; then
  printf 'KVM is unavailable; not launching the VM.\n' >&2
  exit 2
fi
python3 "$script_dir/check-kvm.py"
for file in BaseSystem.dmg mac_hdd_ng.img OpenCore/OpenCore.qcow2 OVMF_CODE_4M.fd OVMF_VARS-1920x1080.fd OpenCore-Boot.sh; do
  if [ ! -f "$file" ]; then
    printf 'Required file missing: %s\n' "$file" >&2
    exit 2
  fi
done
if [ ! -f BaseSystem.img ]; then
  printf 'Converting verified recovery image...\n'
  dmg2img -i BaseSystem.dmg -o BaseSystem.img
fi
python3 - <<'PY'
from pathlib import Path
import re
source = Path('OpenCore-Boot.sh').read_text()
lines = []
cpu_replaced = False
for line in source.splitlines():
    if line.lstrip().startswith('-enable-kvm ') and '-cpu ' in line:
        line = re.sub(r'-cpu [^,\s]+', '-cpu Haswell-noTSX,stepping=4', line, count=1)
        cpu_replaced = True
    if line.startswith('ALLOCATED_RAM='):
        line = 'ALLOCATED_RAM="6144" # MiB'
    line = line.replace('hostfwd=tcp::2222-:22', 'hostfwd=tcp:127.0.0.1:2222-:22')
    lines.append(line)
if not cpu_replaced:
    raise SystemExit('Could not locate active CPU configuration; original script unchanged.')
Path('OpenCore-Boot-Sonoma.sh').write_text('\n'.join(lines) + '\n')
PY
bash -n OpenCore-Boot-Sonoma.sh
printf '1\n' > /sys/module/kvm/parameters/ignore_msrs
case "$(cat /sys/module/kvm/parameters/ignore_msrs)" in
  Y|y|1) printf 'KVM ignore_msrs enabled.\n' ;;
  *) printf 'Could not enable ignore_msrs; stopping.\n' >&2; exit 2 ;;
esac
printf 'Starting Sonoma installer: 6 GiB RAM; SSH forwarding bound to localhost:2222.\n'
printf 'Keep this terminal open while the VM is running.\n'
exec bash ./OpenCore-Boot-Sonoma.sh
