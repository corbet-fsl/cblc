"""Authenticate exact public source archives and prepare a B0-only source plan."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib

if not os.environ.get('CI'):
    raise SystemExit('CI only')
root = Path.cwd()
report = Path(os.environ['CBLC_DIAGNOSTIC_OUTPUT'])
archives = tomllib.loads((root / '.ci/archives.toml').read_text())['archives']
plan = {'schema': 1, 'sources': []}
relations = ['update', 'record_epoch', 'wave', 'outcome', 'deposit', 'record']
classes = ['update_genesis', 'update_consume', 'update_change', 'update_settlement', 'update_regular']

def add(variant, source, commit, digest):
    directory = source / 'circuits/extensions'
    absent = [kind for kind in relations if not (directory / kind / 'Nargo.toml').is_file()]
    selected = [kind for kind in classes if (directory / kind / 'Nargo.toml').is_file()]
    if selected and selected != classes:
        raise ValueError('Incomplete update class suite')
    plan['sources'].append({'variant': variant, 'root': str(source), 'sourceCommit': commit,
                            'sourceArchiveSha256': digest, 'absent': absent, 'updateClasses': selected})

for label, spec in archives.items():
    if not label.startswith('b0_'):
        continue
    source = Path(os.environ[spec['archive_variable']])
    digest = os.environ[spec['digest_variable']]
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Archive size')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Archive digest')
    actual = subprocess.check_output(['git', 'get-tar-commit-id'], input=data).decode().strip()
    if actual != spec['revision']:
        raise ValueError('Archive commit')
    target = report / 'sources' / label
    target.mkdir(parents=True, exist_ok=False)
    with tarfile.open(source, mode='r:') as archive:
        members = archive.getmembers()
        if len(members) > 20000 or sum(m.size for m in members) > 32 * 1024 * 1024:
            raise ValueError('Archive member bound')
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe archive entry')
        archive.extractall(target, members=members, filter='data')
    add(label.replace('_', '-'), target, actual, digest)
add('candidate-current', root, os.environ['CI_COMMIT_SHA'], os.environ['SOURCE_SHA256'])
(report / 'source-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
