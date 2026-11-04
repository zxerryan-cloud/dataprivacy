"""Validate distributed source without executing analysis or contacting services."""
import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
count = 0
for name in ('apk-scan-pipeline-meta', 'ipa-scan-pipeline-meta'):
    skill = ROOT / 'skills' / name
    text = (skill / 'SKILL.md').read_text(encoding='utf-8-sig')
    assert text.startswith('---\nname: ' + name + '\n'), f'Missing skill metadata: {name}'
    assert '\ndescription:' in text.split('---', 2)[1], name
    for path in (skill / 'scripts').glob('*.py'):
        ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
        count += 1
for path in (ROOT / 'tools' / 'ios').glob('*.py'):
    ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
for path in ROOT.rglob('*'):
    if not path.is_file() or '.git' in path.parts:
        continue
    assert path.suffix.lower() not in {'.apk', '.ipa', '.img', '.qcow2', '.dmg', '.db', '.msu', '.msi', '.log'}, path
    if path.suffix in {'.md', '.py', '.ps1', '.sh', '.java', '.yml'}:
        text = path.read_text(encoding='utf-8-sig')
        assert not re.search(r'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----', text), f'Credential pattern: {path}'
print(f'Validated {count} skill Python files, metadata and distribution file checks.')
