import os
from pathlib import Path
import plistlib
import struct
import subprocess

logs = Path(os.environ['QEMU_DIAGNOSTIC_DIR'])
raw = logs / 'OpenCore-verbose.img'
subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                'OpenCore/OpenCore.qcow2', str(raw)], check=True)
offsets = [0]
with raw.open('rb') as f:
    mbr = f.read(512)
    for n in range(4):
        entry = mbr[446+n*16:462+n*16]
        if entry[4] and entry[4] != 0xee:
            offsets.append(struct.unpack_from('<I', entry, 8)[0]*512)
    f.seek(512)
    header = f.read(512)
    if header[:8] == b'EFI PART':
        lba, count, size = struct.unpack_from('<QII', header, 72)
        if not (128 <= size <= 4096 and count <= 1024):
            raise SystemExit('Unexpected GPT layout; stopped.')
        f.seek(lba*512)
        for n in range(count):
            entry = f.read(size)
            if entry[:16] != bytes(16):
                offsets.append(struct.unpack_from('<Q', entry, 32)[0]*512)
config = logs / 'config.plist'
for offset in dict.fromkeys(offsets):
    image = str(raw) + '@@' + str(offset)
    probe = subprocess.run(['mcopy', '-o', '-i', image,
                            '::/EFI/OC/config.plist', str(config)], capture_output=True)
    if probe.returncode == 0:
        break
else:
    raise SystemExit('OpenCore config not found; original image unchanged.')
data = plistlib.loads(config.read_bytes())
(logs / 'config-original.plist').write_bytes(config.read_bytes())
guid = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
nvram = data.setdefault('NVRAM', {})
add = nvram.setdefault('Add', {}).setdefault(guid, {})
args = add.get('boot-args', '').split()
args = [a for a in args if not a.startswith(('debug=', 'keepsyms='))]
for arg in ['-v', 'keepsyms=1', 'debug=0x100']:
    if arg not in args:
        args.append(arg)
add['boot-args'] = ' '.join(args)
serial_patches = {
    'Send panic string to serial port',
    'Send early prints to serial port',
    'Enable early serial output on RELEASE kernel',
}
enabled = []
for patch in data.get('Kernel', {}).get('Patch', []):
    if patch.get('Comment') in serial_patches:
        patch['Enabled'] = True
        enabled.append(patch['Comment'])
if len(enabled) != len(serial_patches):
    raise SystemExit('Expected upstream serial diagnostic patches missing; stopped.')
delete = nvram.setdefault('Delete', {}).setdefault(guid, [])
if 'boot-args' not in delete:
    delete.append('boot-args')
config.write_bytes(plistlib.dumps(data))
subprocess.run(['mcopy', '-o', '-i', image, str(config), '::/EFI/OC/config.plist'], check=True)
source = Path('OpenCore-Boot-Sonoma.sh').read_text()
if '-cpu Haswell-noTSX,stepping=4,' not in source:
    if source.count('-cpu Haswell-noTSX,') != 1:
        raise SystemExit('Expected Haswell CPU configuration missing; stopped.')
    source = source.replace('-cpu Haswell-noTSX,', '-cpu Haswell-noTSX,stepping=4,', 1)
print('Virtual CPU: Haswell-noTSX, stepping=4')
needle = '$REPO_PATH/OpenCore/OpenCore.qcow2'
if source.count(needle) != 1:
    raise SystemExit('Unexpected launcher; stopped.')
source = source.replace(needle, '$QEMU_DIAGNOSTIC_DIR/OpenCore-verbose.img')
source = source.replace('snapshot=on,format=qcow2', 'snapshot=on,format=raw')
command = 'qemu-system-x86_64 "${args[@]}"'
if source.count(command) != 1:
    raise SystemExit('Unexpected QEMU invocation; stopped.')
source = source.replace(command, 'qemu-system-x86_64 -serial file:"$QEMU_DIAGNOSTIC_DIR/macos-serial.log" -no-reboot -d guest_errors,cpu_reset -D "$QEMU_DIAGNOSTIC_DIR/qemu-debug.log" "${args[@]}"')
(logs / 'launch.sh').write_text(source)
print('Verbose boot configured:', add['boot-args'])
print('Enabled upstream serial diagnostics:', ', '.join(enabled))
