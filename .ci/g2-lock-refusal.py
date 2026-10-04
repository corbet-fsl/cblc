"""Retain a failed metadata probe's lock delta, then restore both frozen locks."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def packages(lock):
    return {(p['name'], p['version'], p.get('source', '')): p
            for p in lock['package']}


def delta(before, after):
    left, right = tomllib.loads(before.decode()), tomllib.loads(after.decode())
    old, new = packages(left), packages(right)
    return {
        'before_sha256': sha256(before), 'after_sha256': sha256(after),
        'bytes_equal': before == after, 'toml_equal': left == right,
        'added_packages': [new[k] for k in sorted(new.keys() - old.keys())],
        'removed_packages': [old[k] for k in sorted(old.keys() - new.keys())],
        'changed_packages': [{'before': old[k], 'after': new[k]}
                             for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
        'patch_before': left.get('patch'), 'patch_after': right.get('patch'),
        'other_top_level_changes': {
            key: {'before': left.get(key), 'after': right.get(key)}
            for key in sorted(left.keys() | right.keys())
            if key not in {'package', 'patch'} and left.get(key) != right.get(key)},
    }


label, locked_code, probe_code = sys.argv[1:]
assert label in {'cblc', 'cwlt'} and int(locked_code) != 0
report = Path(os.environ['CBLC_DIAGNOSTIC_OUTPUT'])
locks = {'Cargo.lock': Path('Cargo.lock'),
         'cwlt-Cargo.lock': Path('experiments/private-accounting/node_modules/@corbet-labs/cwlt/Cargo.lock')}
original = {name: (report / name).read_bytes() for name in locks}
receipt = {'schema': 1, 'scope': 'failed-locked-metadata-diagnostic',
           'workspace': label, 'locked_exit_code': int(locked_code),
           'offline_probe_exit_code': int(probe_code), 'probe_timeout_seconds': 30,
           'probe_kill_grace_seconds': 5, 'permits_build_or_proof': False,
           'locks': {}}
try:
    for name, path in locks.items():
        after = path.read_bytes()
        (report / f'{label}-refusal-probe-{name}').write_bytes(after)
        (report / f'{label}-refusal-probe-{name}.diff').write_text(''.join(
            difflib.unified_diff(original[name].decode().splitlines(keepends=True),
                                 after.decode().splitlines(keepends=True),
                                 fromfile=f'resolved/{name}', tofile=f'probe/{name}')))
        receipt['locks'][name] = delta(original[name], after)
finally:
    for name, path in locks.items():
        path.write_bytes(original[name])
receipt['resolved_locks_restored'] = all(path.read_bytes() == original[name]
                                         for name, path in locks.items())
(report / f'{label}-lock-refusal.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
assert receipt['resolved_locks_restored']
