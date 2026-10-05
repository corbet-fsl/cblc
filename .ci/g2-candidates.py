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
    'cssr': ('868d0c6441f062d7be4fb17af8c966e2fa3034f0', 'CSSR', ROOT / '.g2-candidates/cssr'),
    'czkp': ('74008f418642ef2f001f0f3ae958f8342ef8f9e8', 'CODEC', NPM_CANDIDATES / 'czkp'),
    'cvfy': ('30a78099a27581ee16ed17a589e64d089a839182', 'CVFY', ROOT / '.g2-candidates/cvfy'),
    'cwlt': ('de0c19b7f14d17216a21a7c7f4114c4b367c5ee1', 'CWLT', NPM_CANDIDATES / 'cwlt'),
    'cbcn': ('22f3179cd661f46e6d77fda197b171f6c83c637c', 'CBCN', ROOT / '.g2-candidates/cbcn'),
    'ckmg': ('6910adaa591c1f2e9f2b51da8e2ac2a5716cbaca', 'CKMG', ROOT / '.g2-candidates/ckmg'),
    'cpsd': ('24a61c9500b4141b10abc1650c55767b4be9a9ef', 'CPSD', ROOT / '.g2-candidates/cpsd'),
    'cwst': ('de04691c4c654ddbc5f0cd985e342606059b98ba', 'CWST', ROOT / '.g2-candidates/cwst'),
}
RESOLUTION_ONLY = {'cpsd'}
EXCLUDED_BUILDS = RESOLUTION_ONLY | {'cwlt-engine'}
PATCH_SETS = {'cblc': {'cssr', 'czkp', 'cvfy', 'cwlt', 'cbcn'},
              'cwlt': {'czkp', 'cwlt', 'ckmg', 'cpsd', 'cbcn', 'cwst'},
              'czkp': set()}


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


def check_frozen_locks(required=None):
    required = set(PATCH_SETS) if required is None else required
    for label, name, path in [('cblc', 'Cargo.lock', ROOT / 'Cargo.lock'),
                              ('cwlt', 'cwlt-Cargo.lock', SOURCES['cwlt'][2] / 'Cargo.lock'),
                              ('czkp', 'czkp-Cargo.lock', SOURCES['czkp'][2] / 'Cargo.lock')]:
        binding = REPORT / f'{label}-resolved-lock.sha256'
        if label in required and not binding.exists():
            raise ValueError(f'{label}: frozen workspace lock binding is missing')
        if binding.exists():
            expected = binding.read_text().split()[0]
            if not re.fullmatch('[0-9a-f]{64}', expected) or digest(path) != expected or digest(REPORT / name) != expected:
                raise ValueError(f'{label}: frozen workspace lock changed')


def select_patches(label, phase):
    previous = check_patches()
    required = {'cblc': set(), 'cwlt': {'cblc'}, 'czkp': {'cblc', 'cwlt'}}.get(label, set()) if phase == 'resolve' else set(PATCH_SETS)
    check_frozen_locks(required)
    if label not in PATCH_SETS or phase not in {'resolve', 'metadata', 'check', 'fmt', 'issuer', 'wasm', 'proof', 'codec-native', 'codec-wasm'}:
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
    for label, path in [('cblc', ROOT / 'Cargo.lock'),
                        ('cwlt', SOURCES['cwlt'][2] / 'Cargo.lock'),
                        ('czkp', SOURCES['czkp'][2] / 'Cargo.lock')]:
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
    if set(graphs['czkp']) != {'czkp'} or graphs['czkp']['czkp'] != graphs['cblc']['czkp']:
        raise ValueError('Codec workspace must select the same sole exact CZKP owner')
    receipt = {'schema': 1, 'graphs': graphs, 'compared_shared_owners': shared,
               'codec_shared_owners': ['czkp'],
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
        target = ROOT if label == 'cblc' else SOURCES[label][2]
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


def codec_source_snapshot():
    archive = Path(os.environ['G2_CODEC_SOURCE_ARCHIVE'])
    expected = os.environ['G2_CODEC_SOURCE_SHA256']
    if digest(archive) != expected:
        raise ValueError('Codec archive changed')
    with tarfile.open(archive, mode='r:') as source:
        files = {item.name: hashlib.sha256(source.extractfile(item).read()).hexdigest()
                 for item in source.getmembers() if item.isfile() and item.name != 'Cargo.lock'}
    return {'candidate_commit': SOURCES['czkp'][0], 'archive_sha256': expected,
            'excluded': ['Cargo.lock'], 'files': files}


def check_codec_source():
    snapshot = codec_source_snapshot()
    if json.loads((REPORT / 'codec-source-files.json').read_text()) != snapshot:
        raise ValueError('Original codec source snapshot changed')
    root = SOURCES['czkp'][2]
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Codec source cannot acquire symlinks')
        if path.is_file() and path != root / 'Cargo.lock':
            files[str(path.relative_to(root))] = digest(path)
    if files != snapshot['files']:
        raise ValueError('Original codec archive files changed')


def codec_artifact(variant, verify=False):
    if variant not in {'native', 'wasm'}:
        raise ValueError('Unknown codec target')
    check_patches('czkp')
    check_frozen_locks()
    check_codec_source()
    codec = SOURCES['czkp'][2]
    metadata_path = REPORT / 'czkp-metadata.json'
    stream_path = REPORT / f'codec-{variant}-build.json'
    metadata = json.loads(metadata_path.read_text())
    if json.loads((REPORT / 'czkp-metadata-patches.json').read_text()) != metadata_patch_receipt('czkp'):
        raise ValueError('Codec metadata patch binding changed')
    root = metadata['resolve']['root']
    packages = {p['id']: p for p in metadata['packages']}
    if len(packages) != len(metadata['packages']) or metadata['workspace_members'] != [root] or metadata['workspace_default_members'] != [root]:
        raise ValueError('Codec tests require the original sole-package workspace')
    package = packages[root]
    if package['name'] != 'czkp' or package['source'] is not None or Path(package['manifest_path']).resolve() != codec / 'Cargo.toml':
        raise ValueError('Codec test root differs from candidate')
    target_source = codec / 'tests/record.rs'
    targets = [t for t in package['targets'] if t['name'] == 'record' and t['kind'] == ['test']]
    if len(targets) != 1 or Path(targets[0]['src_path']).resolve() != target_source:
        raise ValueError('Expected original record integration test source')
    features = next(n['features'] for n in metadata['resolve']['nodes'] if n['id'] == root)
    artifacts, compiled = [], set()
    messages = [json.loads(line) for line in stream_path.read_text().splitlines()]
    if len([m for m in messages if m.get('reason') == 'build-finished' and m.get('success') is True]) != 1:
        raise ValueError('Codec compiler stream did not finish successfully')
    for message in messages:
        if message.get('reason') not in {'compiler-artifact', 'build-script-executed'}:
            continue
        identity = message['package_id']
        current = packages[identity]
        if identity != root and not (current['source'] or '').startswith('registry+'):
            raise ValueError('Unexpected first-party or path code in codec compilation')
        compiled.add(identity)
        target = message.get('target', {})
        if identity == root and target.get('name') == 'record' and target.get('kind') == ['test']:
            if message.get('profile', {}).get('test') is not True or sorted(message.get('features', [])) != sorted(features) or Path(target['src_path']).resolve() != target_source:
                raise ValueError('Codec test target or features differ from metadata')
            artifacts.append(message)
    if len(artifacts) != 1 or not artifacts[0].get('executable'):
        raise ValueError('Expected one actual compiled codec test executable')
    executable = Path(artifacts[0]['executable'])
    target_dir = Path(os.environ['CARGO_TARGET_DIR']).resolve(strict=True)
    if not executable.is_absolute() or not executable.is_file() or not executable.resolve(strict=True).is_relative_to(target_dir) or str(executable) not in artifacts[0]['filenames']:
        raise ValueError('Codec artifact must identify the actual target output')
    if (executable.suffix == '.wasm') != (variant == 'wasm'):
        raise ValueError('Codec artifact target mismatch')
    receipt = {'variant': variant, 'executable': str(executable),
               'artifact_sha256': digest(executable), 'package_id': root,
               'candidate_commit': SOURCES['czkp'][0],
               'source_snapshot_sha256': digest(REPORT / 'codec-source-files.json'),
               'target_source_sha256': digest(target_source),
               'metadata_sha256': digest(metadata_path), 'compiler_stream_sha256': digest(stream_path),
               'lock_sha256': digest(codec / 'Cargo.lock'),
               'patch_sha256': hashlib.sha256(patch_bytes('czkp')).hexdigest(),
               'compiled_packages': sorted(compiled), 'product_acceptance': False}
    receipt_path = REPORT / f'codec-{variant}-test-binding.json'
    if verify:
        if json.loads(receipt_path.read_text()) != receipt:
            raise ValueError('Codec test artifact identity changed')
    else:
        with receipt_path.open('x') as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return str(executable)


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
    (REPORT / 'codec-source-files.json').write_text(
        json.dumps(codec_source_snapshot(), indent=2, sort_keys=True) + '\n')
    check_codec_source()
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
    check_codec_source()
    check_lock_patches()
    check_frozen_locks()
    graphs = {}
    # cwst is optional in the default Wallet build. Its exact identity remains
    # mandatory in the frozen lock below, even when metadata omits that edge.
    for label, required in [('cblc', PATCH_SETS['cblc']), ('cwlt', {'cwlt', 'czkp', 'ckmg'}),
                            ('czkp', {'czkp'})]:
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
    codec = graphs['czkp']
    root_id = codec['resolve']['root']
    if codec['workspace_members'] != [root_id]:
        raise ValueError('Codec tests require the original sole-package workspace')
    for package in codec['packages']:
        if package['id'] != root_id and not (package['source'] or '').startswith('registry+'):
            raise ValueError('Codec graph must contain only its original package and registry dependencies')
    selected_scope(graphs)
    observed = observed_sources()
    graph_comparison(graphs, observed)
    versions = []
    for label, path in [('cblc', ROOT / 'Cargo.lock'), ('cwlt', SOURCES['cwlt'][2] / 'Cargo.lock')]:
        entries = tomllib.loads(path.read_text())['package']
        for name, (_, _, candidate) in SOURCES.items():
            matches = [p for p in entries if p['name'] == name]
            if name in PATCH_SETS[label] and not matches:
                raise ValueError(f'{label}: required candidate {name} missing from frozen lock')
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
    elif sys.argv[1:] == ['check-codec-source']:
        check_patches('czkp')
        check_frozen_locks()
        check_codec_source()
    elif sys.argv[1:] == ['check-lock-patches']:
        check_lock_patches()
    elif len(sys.argv) == 3 and sys.argv[1] in {'codec-artifact', 'verify-codec-artifact'}:
        print(codec_artifact(sys.argv[2], verify=sys.argv[1] == 'verify-codec-artifact'))
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
