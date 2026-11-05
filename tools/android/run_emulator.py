"""Launch emulator with merged native output, without PowerShell stderr wrapping."""
import subprocess
import sys
from pathlib import Path

emulator, adb, avd, log = sys.argv[1:]
subprocess.run([adb, 'start-server'], check=True)
with Path(log).open('ab') as output:
    process = subprocess.Popen(
        [emulator, '-avd', avd, '-no-snapshot-load', '-no-snapshot-save', '-gpu', 'auto'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    for line in iter(process.stdout.readline, b''):
        output.write(line)
        output.flush()
        print(line.decode('utf-8', errors='replace'), end='', flush=True)
    raise SystemExit(process.wait())
