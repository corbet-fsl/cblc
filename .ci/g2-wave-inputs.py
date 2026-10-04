#!/usr/bin/env python3
"""Bind a public-only replay to the retained failed run and original sources."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

ROOT = Path.cwd().resolve()
REPORT = Path(os.environ['CBLC_DIAGNOSTIC_OUTPUT'])
EVIDENCE = REPORT / 'evidence'
CODEC = ROOT / 'experiments/private-accounting/node_modules/@corbet-labs/czkp'
CODEC_OID = '6e8755f2858dac3f72d61d8450158c2cd20d7d7c'
CODEC_SHA = '9f171efe874735ebdf53b3899a5cd4de314b0c81dfbe2724be883eb380a71fe0'
EVIDENCE_SHA = '31bd9e04a29c84744bed55949d0dd15b78a7d6630ce67f53b97da5260087a543'
RECEIPT_SHA = '589e2897a7ec816ef760d9de9d6a2490844c2c7694166d09e2727ddabcf2a632'
PEER_SHA = '0a5292149bbaaf49599677f80100e0be2cdda4ecea731559c63d78cad1f684db'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def archive_files(path, expected, maximum, oid=None, destination=None):
    assert path.stat().st_size <= maximum and digest(path) == expected
    if oid:
        with path.open('rb') as stream:
            assert subprocess.check_output(['git', 'get-tar-commit-id'], stdin=stream, text=True).strip() == oid
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        assert len(members) <= 10000 and sum(m.size for m in members) <= maximum
        names = set()
        files = {}
        for member in members:
            name = PurePosixPath(member.name)
            assert not name.is_absolute() and '..' not in name.parts and str(name) == member.name.rstrip('/')
            assert member.isfile() or member.isdir()
            assert str(name) not in names
            names.add(str(name))
            if member.isfile():
                files[str(name)] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        if destination:
            assert not destination.exists() and not destination.is_symlink()
            destination.mkdir(parents=True)
            archive.extractall(destination, members=members, filter='data')
    return files


def tree(path):
    result = {}
    for item in path.rglob('*'):
        assert not item.is_symlink()
        if item.is_file():
            result[str(item.relative_to(path))] = digest(item)
    return result


def check_files(root, files):
    for name, expected in files.items():
        path = root / name
        assert path.is_file() and not path.is_symlink() and digest(path) == expected, name


def run(mode):
    peer = mode.startswith('peer-')
    mode = mode.removeprefix('peer-')
    assert os.environ.get('CI') and mode in {'unpack', 'check'}
    unpack = mode == 'unpack'
    source = archive_files(Path(os.environ['SOURCE_ARCHIVE']), os.environ['SOURCE_SHA256'], 32 * 1024 * 1024, os.environ['CI_COMMIT_SHA'])
    check_files(ROOT, source)
    assert os.environ['G2_CODEC_SOURCE_SHA256'] == CODEC_SHA
    codec = archive_files(Path(os.environ['G2_CODEC_SOURCE_ARCHIVE']), CODEC_SHA, 32 * 1024 * 1024, CODEC_OID, CODEC if unpack else None)
    assert os.environ['G2_WAVE_EVIDENCE_SHA256'] == EVIDENCE_SHA
    evidence = archive_files(Path(os.environ['G2_WAVE_EVIDENCE_ARCHIVE']), EVIDENCE_SHA, 256 * 1024 * 1024, destination=EVIDENCE if unpack else None)
    assert tree(CODEC) == codec and tree(EVIDENCE) == evidence
    assert (ROOT / 'node_modules/@corbet-labs/czkp').resolve() == CODEC and not CODEC.is_symlink()
    derivation = json.loads((EVIDENCE / 'derivation.json').read_bytes())
    assert set(evidence) == set(derivation['files']) | {'derivation.json'} and len(evidence) == 12
    assert {k: evidence[k] for k in derivation['files']} == derivation['files']
    assert evidence['original-receipt.json'] == RECEIPT_SHA == derivation['original_receipt_sha256']
    receipt = json.loads((EVIDENCE / 'original-receipt.json').read_bytes())
    assert receipt['commit'] == '1567f773c212ebf17c00351f59e8f18f03ee5061'
    assert receipt['scope'] == 'g2-full-extension-proof-diagnostic' and receipt['exit_code'] == 1
    for name in evidence:
        if name.startswith('public/'):
            assert evidence[name] == receipt['artifacts'][name]
    assert digest(ROOT / 'experiments/private-accounting/package-lock.json') == receipt['artifacts']['experiment-package-lock.json']
    for relative in ['runtime/node-verifier.mjs', 'src/process.rs']:
        expected = derivation['sources']['czkp/' + relative]
        assert expected['commit'] == CODEC_OID and codec[relative] == expected['sha256']
    wallet_source = derivation['sources']['cwlt/src/wave.rs']
    wallet = archive_files(Path(os.environ['G2_CWLT_SOURCE_ARCHIVE']), os.environ['G2_CWLT_SOURCE_SHA256'], 32 * 1024 * 1024, wallet_source['commit'])
    assert wallet['src/wave.rs'] == wallet_source['sha256']
    # Original npm lock pins/integrities select the installation. Snapshot all
    # backend package bytes before executing the public verifier and check after.
    backend = ROOT / 'experiments/private-accounting/node_modules/@aztec/bb.js'
    assert json.loads((backend / 'package.json').read_bytes())['version'] == '5.0.0'
    node = next(Path(p) / 'node' for p in os.environ['PATH'].split(os.pathsep)
                if Path(p).is_absolute() and (Path(p) / 'node').is_file())
    bindings = {'source': source, 'codec': codec, 'wallet_wave_source': wallet_source, 'evidence': evidence,
                'backend': tree(backend), 'node': str(node), 'node_realpath': str(node.resolve()),
                'node_sha256': digest(node), 'codec_commit': CODEC_OID,
                'reconstructed_request_is_authority': False, 'proof_regeneration': False}
    if peer:
        assert os.environ['G2_WAVE_PEER_SHA256'] == PEER_SHA
        target = REPORT / 'peer'
        files = archive_files(Path(os.environ['G2_WAVE_PEER_ARCHIVE']), PEER_SHA, 64 * 1024 * 1024,
                              destination=target if unpack else None)
        assert tree(target) == files and len(files) == 5
        for name in files:
            if name != 'wave_verifier':
                assert files[name] == receipt['artifacts'][name]
        binding = json.loads((target / 'wave-verifier-binding.json').read_bytes())
        assert files['wave_verifier'] == binding['executable_sha256'] == 'ad916c4c00904d00916e8be87c844a7343f1cacd163af6c15b6f944fee1d94f7'
        assert files['issuer-build.json'] == binding['compiler_artifacts_sha256']
        assert files['cblc-metadata.json'] == binding['metadata_sha256']
        metadata = json.loads((target / 'cblc-metadata.json').read_bytes())
        artifacts = [json.loads(row) for row in (target / 'issuer-build.json').read_text().splitlines()]
        matched = [row for row in artifacts if row.get('reason') == 'compiler-artifact'
                   and row.get('package_id') == metadata['resolve']['root']
                   and row.get('target', {}).get('kind') == ['example']
                   and row.get('target', {}).get('name') == 'wave_verifier'
                   and row.get('executable') == binding['executable']]
        assert len(matched) == 1
        original = Path(json.loads((EVIDENCE / 'public/config.json').read_bytes())['directory'])
        assert original.is_absolute()
        # The first peer uses the original absolute configuration/artifact paths.
        # Refuse missing or changed retained files instead of relocating silently.
        check_files(original, {name.removeprefix('public/'): sha for name, sha in evidence.items()
                               if name.startswith('public/')})
        bindings['peer'] = {'files': files, 'original_public_directory': str(original),
                            'compiler_root': metadata['resolve']['root']}
    snapshot = REPORT / 'replay-input-bindings.json'
    if unpack:
        with snapshot.open('x') as stream:
            json.dump(bindings, stream, indent=2, sort_keys=True)
            stream.write('\n')
    else:
        assert bindings == json.loads(snapshot.read_bytes())
    print(json.dumps({'input_guards': mode, 'original_receipt_sha256': RECEIPT_SHA, 'files': len(evidence)}))


run(sys.argv[1])
