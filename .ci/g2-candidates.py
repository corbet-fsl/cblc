"""Compose explicitly named diagnostic archives using Cargo's ordinary patch table."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib

ROOT = Path.cwd()
NPM_CANDIDATES = ROOT / 'experiments/private-accounting/node_modules/@corbet-labs'
REPORT = Path(os.environ['CBLC_DIAGNOSTIC_OUTPUT'])
SOURCES = {
    'cssr': ('1091bafed66d9127a5f4ea4513cdf224470c4eea', 'CSSR', ROOT / '.g2-candidates/cssr'),
    'czkp': ('6e8755f2858dac3f72d61d8450158c2cd20d7d7c', 'CODEC', NPM_CANDIDATES / 'czkp'),
    'cvfy': ('30a78099a27581ee16ed17a589e64d089a839182', 'CVFY', ROOT / '.g2-candidates/cvfy'),
    'cwlt': ('ed86f90c41f31dc23a7e439ab88d64b246676a08', 'CWLT', NPM_CANDIDATES / 'cwlt'),
    'cbcn': ('22f3179cd661f46e6d77fda197b171f6c83c637c', 'CBCN', ROOT / '.g2-candidates/cbcn'),
    'ckmg': ('6910adaa591c1f2e9f2b51da8e2ac2a5716cbaca', 'CKMG', ROOT / '.g2-candidates/ckmg'),
    'cpsd': ('24a61c9500b4141b10abc1650c55767b4be9a9ef', 'CPSD', ROOT / '.g2-candidates/cpsd'),
}
RESOLUTION_ONLY = {'ckmg', 'cpsd'}
EXCLUDED_BUILDS = RESOLUTION_ONLY | {'cwlt-engine'}
PATCH_SETS = {'cblc': {'cssr', 'czkp', 'cvfy', 'cwlt', 'cbcn'},
              'cwlt': {'czkp', 'cwlt', 'ckmg', 'cpsd', 'cbcn'}}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def patch_bytes(label):
    return '\n'.join(f'[patch."https://github.com/corbet-foss/{name}"]\n'
                     f'{name} = {{ path = {json.dumps(str(target))} }}\n'
                     for name, (_, _, target) in SOURCES.items()
                     if name in PATCH_SETS[label]).encode()


def check_candidate_paths():
    paths = {}
    for name in ['czkp', 'cwlt']:
        target = SOURCES[name][2]
        alias = ROOT / 'node_modules/@corbet-labs' / name
        if target.resolve(strict=True) != target or alias.resolve(strict=True) != target:
            raise ValueError('Candidate npm alias differs from canonical Cargo source path')
        paths[name] = {'cargo_path': str(target), 'npm_alias': str(alias)}
    return paths


def check_patches(label=None):
    check_candidate_paths()
    for workspace in PATCH_SETS:
        if (REPORT / f'candidate-patches-{workspace}.toml').read_bytes() != patch_bytes(workspace):
            raise ValueError('Immutable workspace patch snapshot changed')
    active = (ROOT / '.cargo/config.toml').read_bytes()
    matched = [workspace for workspace in PATCH_SETS if active == patch_bytes(workspace)]
    if len(matched) != 1 or (label is not None and matched != [label]):
        raise ValueError('Unexpected active diagnostic workspace patches')
    return matched[0]


def select_patches(label, phase):
    previous = check_patches()
    if label not in PATCH_SETS or phase not in {'resolve', 'metadata', 'check', 'fmt', 'issuer', 'wasm', 'proof'}:
        raise ValueError('Unknown workspace patch phase')
    config = ROOT / '.cargo/config.toml'
    pending = config.with_name('g2-next.toml')
    with pending.open('xb') as stream:
        stream.write(patch_bytes(label))
    pending.replace(config)
    check_patches(label)
    with (REPORT / 'candidate-patch-phases.jsonl').open('a') as stream:
        stream.write(json.dumps({'workspace': label, 'phase': phase, 'previous': previous,
                                 'patch_sha256': digest(config)}, sort_keys=True) + '\n')


def metadata_patch_receipt(label):
    check_patches(label)
    return {'workspace': label, 'phase': 'metadata',
            'metadata_sha256': digest(REPORT / f'{label}-metadata.json'),
            'patch_sha256': hashlib.sha256(patch_bytes(label)).hexdigest(),
            'patch_owners': sorted(PATCH_SETS[label])}


def check_lock_patches():
    receipts = {}
    for label, path in [('cblc', ROOT / 'Cargo.lock'), ('cwlt', SOURCES['cwlt'][2] / 'Cargo.lock')]:
        lock = tomllib.loads(path.read_text())
        if lock.get('patch', {}).get('unused'):
            raise ValueError(f'{label}: unexpected unused patch; refuse unstable lock serialization')
        receipts[label] = {'lock_sha256': digest(path), 'unused_patches': [],
                           'patch_sha256': hashlib.sha256(patch_bytes(label)).hexdigest()}
    (REPORT / 'workspace-lock-patches.json').write_text(json.dumps(receipts, indent=2, sort_keys=True) + '\n')


def manifests():
    paths = [ROOT / 'Cargo.toml', ROOT / 'package.json',
             ROOT / 'experiments/private-accounting/package.json']
    for _, _, root in SOURCES.values():
        paths += list(root.rglob('Cargo.toml')) + list(root.rglob('package.json'))
    return {str(p.relative_to(ROOT)): digest(p) for p in paths}


FIRST_PARTY = re.compile(r'git\+https://github\.com/(corbet-foss|corbet-labs|corbet-libs|cmtymeet)/')
MAIN_SOURCE = re.compile(r'git\+https://github\.com/(corbet-foss|corbet-labs|corbet-libs|cmtymeet)/'
                         r'([A-Za-z0-9][A-Za-z0-9_.-]*)\?branch=main#([0-9a-f]{40})')


def observed_sources():
    path = REPORT / 'observed-main-closure.json'
    if path.read_bytes() != Path(os.environ['DEPENDENCY_CLOSURE_MANIFEST']).read_bytes():
        raise ValueError('Retained observed-main closure changed')
    closure = json.loads(path.read_text())
    if closure['freshness'] != 'main-observed':
        raise ValueError('Diagnostic needs observed-main dependencies')
    sources = {}
    for entry in closure['repositories']:
        url, oid = entry['url'], entry['main']
        if url in sources or not re.fullmatch('[0-9a-f]{40}', oid):
            raise ValueError('Ambiguous observed-main source identity')
        sources[url] = oid
    return sources


def bound_source(source, observed):
    match = MAIN_SOURCE.fullmatch(source)
    if match is None:
        raise ValueError('Noncanonical first-party source')
    org, repository, oid = match.groups()
    url = f'https://github.com/{org}/{repository.removesuffix(".git")}'
    if observed.get(url) != oid:
        raise ValueError(f'First-party source absent from observed-main closure or wrong OID: {url}')
    return f'git+{url}?branch=main#{oid}'


def graph_comparison(metadata, observed):
    # Include every owner found in either graph so a same-name registry or
    # foreign replacement in the other graph cannot disappear from comparison.
    names = {p['name'] for graph in metadata.values() for p in graph['packages']
             if p['source'] is None or FIRST_PARTY.match(p['source'])}
    graphs = {}
    for label, graph in metadata.items():
        identities = {}
        for package in graph['packages']:
            name, source = package['name'], package['source']
            if name not in names:
                continue
            if name in identities:
                raise ValueError(f'{label}: duplicate first-party package {name}')
            identity = {'name': name, 'version': package['version'], 'source': source}
            if source is None:
                path = Path(package['manifest_path']).resolve()
                if not path.is_relative_to(ROOT.resolve()):
                    raise ValueError(f'{label}: first-party path outside diagnostic source')
                identity['manifest_path'] = str(path)
            else:
                identity['source'] = bound_source(source, observed)
            identities[name] = identity
        graphs[label] = identities
    shared = sorted(graphs['cblc'].keys() & graphs['cwlt'].keys())
    for name in shared:
        if graphs['cblc'][name] != graphs['cwlt'][name]:
            raise ValueError(f'Root and Wallet resolved different first-party identity: {name}')
    receipt = {'schema': 1, 'graphs': graphs, 'compared_shared_owners': shared,
               'observed_main_sources': observed,
               'workspace_patches': {label: json.loads((REPORT / f'{label}-metadata-patches.json').read_text())
                                     for label in metadata},
               'observed_main_manifest_sha256': digest(REPORT / 'observed-main-closure.json'),
               'metadata_sha256': {label: digest(REPORT / f'{label}-metadata.json')
                                   for label in metadata}, 'product_acceptance': False}
    (REPORT / 'first-party-graph-comparison.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')


def selected_scope(metadata):
    receipts = {}
    for label, graph in metadata.items():
        target = ROOT if label == 'cblc' else SOURCES['cwlt'][2]
        selected = [p for p in graph['packages']
                    if Path(p['manifest_path']).resolve() == (target / 'Cargo.toml').resolve()]
        if len(selected) != 1 or selected[0]['name'] != label:
            raise ValueError('Ambiguous selected diagnostic package')
        seed = selected[0]['id']
        if graph['workspace_default_members'] != [seed] or graph['resolve']['root'] != seed:
            raise ValueError('Diagnostic build must select only its root package')
        packages = {p['id']: p for p in graph['packages']}
        nodes = {n['id']: n for n in graph['resolve']['nodes']}
        if len(packages) != len(graph['packages']) or len(nodes) != len(graph['resolve']['nodes']):
            raise ValueError('Duplicate resolved graph identity')
        reached, pending = set(), [seed]
        while pending:
            identity = pending.pop()
            if identity in reached:
                continue
            node, package = nodes[identity], packages[identity]
            if package['name'] in EXCLUDED_BUILDS:
                raise ValueError('Custody and internal engine must stay outside selected builds')
            if package['name'] == 'cwlt' and 'passport' in node['features']:
                raise ValueError('Diagnostic cannot activate Wallet passport')
            reached.add(identity)
            # Conservatively include normal, build, dev and target-specific edges.
            pending.extend(dependency['pkg'] for dependency in node['deps'])
        receipts[label] = {'root': seed, 'reachable_packages': sorted(reached),
                           'wallet_passport': False,
                           'resolution_only_selected': {name: False for name in sorted(RESOLUTION_ONLY)},
                           'engine_selected': False}
    (REPORT / 'selected-build-scope.json').write_text(json.dumps(receipts, indent=2, sort_keys=True) + '\n')


def check_issuer_build():
    check_patches('cblc')
    metadata = json.loads((REPORT / 'cblc-metadata.json').read_text())
    packages = {p['id']: p['name'] for p in metadata['packages']}
    artifacts = []
    for line in (REPORT / 'issuer-build.json').read_text().splitlines():
        message = json.loads(line)
        if message.get('reason') not in {'compiler-artifact', 'build-script-executed'}:
            continue
        name = packages[message['package_id']]
        if name in EXCLUDED_BUILDS or (name == 'cwlt' and 'passport' in message.get('features', [])):
            raise ValueError('Excluded custody or engine code reached issuer compilation')
        artifacts.append(message['package_id'])
    (REPORT / 'issuer-build-scope.json').write_text(json.dumps({
        'packages': sorted(set(artifacts)),
        'resolution_only_compiled': {name: False for name in sorted(RESOLUTION_ONLY)},
        'engine_compiled': False, 'wallet_passport': False,
        'resolution_only_qualified': False}, indent=2, sort_keys=True) + '\n')


def unpack():
    records = []
    for name, (oid, prefix, target) in SOURCES.items():
        archive = Path(os.environ[f'G2_{prefix}_SOURCE_ARCHIVE'])
        expected = os.environ[f'G2_{prefix}_SOURCE_SHA256']
        if archive.stat().st_size > 32 * 1024 * 1024 or digest(archive) != expected:
            raise ValueError('Candidate source archive identity/bound')
        with archive.open('rb') as stream:
            actual = subprocess.check_output(['git', 'get-tar-commit-id'], stdin=stream, text=True).strip()
        if actual != oid or target.exists():
            raise ValueError('Candidate commit differs or target is not fresh')
        target.mkdir(parents=True)
        with tarfile.open(archive, mode='r:') as source:
            members = source.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 32 * 1024 * 1024:
                raise ValueError('Candidate archive member bound')
            for item in members:
                path = PurePosixPath(item.name)
                if path.is_absolute() or '..' in path.parts or not (item.isfile() or item.isdir()):
                    raise ValueError('Unsafe candidate archive entry')
            source.extractall(target, members=members, filter='data')
        package = tomllib.loads((target / 'Cargo.toml').read_text())['package']
        if package['name'] != name or list(target.rglob('node_modules')):
            raise ValueError('Candidate owner differs or contains nested dependency installation')
        records.append({'owner': name, 'repository': f'https://github.com/corbet-foss/{name}.git',
                        'commit': oid, 'sha256': expected, 'path': str(target),
                        'identity': 'explicit diagnostic candidate, not observed main',
                        'resolution_only': name in RESOLUTION_ONLY, 'qualified_by_diagnostic': False})
    (REPORT / 'candidate-npm-paths.json').write_text(
        json.dumps(check_candidate_paths(), indent=2, sort_keys=True) + '\n')
    config = ROOT / '.cargo/config.toml'
    if config.exists():
        raise ValueError('Never overwrite existing Cargo configuration')
    config.parent.mkdir(exist_ok=True)
    for label in PATCH_SETS:
        with (REPORT / f'candidate-patches-{label}.toml').open('xb') as stream:
            stream.write(patch_bytes(label))
    config.write_bytes(patch_bytes('cblc'))
    (REPORT / 'candidate-sources.json').write_text(json.dumps(records, indent=2) + '\n')
    (REPORT / 'source-manifests.json').write_text(json.dumps(manifests(), indent=2, sort_keys=True) + '\n')


def check():
    if json.loads((REPORT / 'source-manifests.json').read_text()) != manifests():
        raise ValueError('Product manifest changed during diagnostic')
    check_patches('cblc')
    check_lock_patches()
    graphs = {}
    for label, required in [('cblc', set(SOURCES) - RESOLUTION_ONLY), ('cwlt', {'cwlt', 'czkp'})]:
        metadata = graphs[label] = json.loads((REPORT / f'{label}-metadata.json').read_text())
        receipt = json.loads((REPORT / f'{label}-metadata-patches.json').read_text())
        expected = {'workspace': label, 'phase': 'metadata',
                    'metadata_sha256': digest(REPORT / f'{label}-metadata.json'),
                    'patch_sha256': hashlib.sha256(patch_bytes(label)).hexdigest(),
                    'patch_owners': sorted(PATCH_SETS[label])}
        if receipt != expected:
            raise ValueError('Metadata is not bound to its exact workspace patch snapshot')
        for name, (_, _, path) in SOURCES.items():
            packages = [p for p in metadata['packages'] if p['name'] == name]
            if not packages and name not in required:
                continue
            if len(packages) != 1 or packages[0]['source'] is not None or Path(packages[0]['manifest_path']).resolve() != (path / 'Cargo.toml').resolve():
                raise ValueError(f'{label}: {name} did not resolve to one exact candidate')
    selected_scope(graphs)
    observed = observed_sources()
    graph_comparison(graphs, observed)
    versions = []
    for path in [ROOT / 'Cargo.lock', SOURCES['cwlt'][2] / 'Cargo.lock']:
        entries = tomllib.loads(path.read_text())['package']
        for name, (_, _, candidate) in SOURCES.items():
            matches = [p for p in entries if p['name'] == name]
            if not matches:
                continue
            version = tomllib.loads((candidate / 'Cargo.toml').read_text())['package']['version']
            if len(matches) != 1 or matches[0].get('source') is not None or matches[0]['version'] != version:
                raise ValueError('Resolved lock did not retain one exact candidate package')
        # Include optional and otherwise inactive packages absent from metadata.
        for package in entries:
            source = package.get('source', '')
            if FIRST_PARTY.match(source):
                bound_source(source, observed)
        found = {p['version'] for p in entries if p['name'] == 'wasm-bindgen'}
        if len(found) != 1:
            raise ValueError('Expected one wasm-bindgen ABI per resolved graph')
        versions.append(found.pop())
    if versions[0] != versions[1]:
        raise ValueError('Root and Wallet resolved different wasm-bindgen ABIs')
    print(json.dumps({'event': 'candidate-composition-checked', 'wasm_bindgen': versions[0],
                      'product_acceptance': False}))


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['unpack']:
        unpack()
    elif sys.argv[1:] == ['check']:
        check()
    elif sys.argv[1:] == ['check-issuer-build']:
        check_issuer_build()
    elif sys.argv[1:] == ['check-lock-patches']:
        check_lock_patches()
    elif len(sys.argv) == 4 and sys.argv[1] == 'select-patches':
        select_patches(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == 'verify-patches':
        check_patches(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == 'record-metadata-patches':
        label = sys.argv[2]
        (REPORT / f'{label}-metadata-patches.json').write_text(
            json.dumps(metadata_patch_receipt(label), indent=2, sort_keys=True) + '\n')
    else:
        raise SystemExit('Unknown diagnostic candidate operation')
