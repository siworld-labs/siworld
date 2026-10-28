#!/usr/bin/env python3
"""Bind three native engineering relations to public keys and unchanged sources.

This offline manifest is not a consensus activation or independent security
approval. The issuance key covers exactly three initial notes; policy/resource
limits and durable node integration remain separate requirements.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
TRANSACTION = 'crates/bench-multi-asset/artifacts/v1-transaction-profile.json'
MANIFEST = 'crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json'
TOOLS = ('scripts/check-native-proof-profiles.py', 'scripts/native-proof-artifacts.rs')
KINDS = ('transaction', 'settlement', 'issuance')
CAPACITIES = (0, 576, 3)
SHAPES = ((256, 1420, 243), (1024, 516, 587), (128, 438, 10))


def freeze_module(root=ROOT):
    spec = importlib.util.spec_from_file_location('native_transaction_freeze', root / 'scripts/freeze-multi-asset.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parameters(kind):
    return dict(log_blowup=7 if kind == 'transaction' else 8,
                num_queries=41 if kind == 'transaction' else 36,
                query_pow_bits=20, commit_pow_bits=0, batch_pow_bits=20,
                max_log_arity=1, log_final_poly_len=0)


def transaction_profile(root=ROOT):
    value = json.loads((root / TRANSACTION).read_text())
    freeze_module(root).validate(value, root)
    return value


def validate_relation(value, kind, transaction, freeze):
    index = KINDS.index(kind)
    if set(value) != {'kind', 'capacity', 'parameters', 'security', 'public_verifier_key',
                      'cryptographic_approval', 'network_activation'}:
        raise ValueError('Unexpected native relation fields')
    p = parameters(kind)
    if (value['kind'] != kind or type(value['capacity']) is not int
            or value['capacity'] != CAPACITIES[index] or value['parameters'] != p
            or not isinstance(value['parameters'], dict)
            or any(type(n) is not int for n in value['parameters'].values())
            or value['cryptographic_approval'] is not False or value['network_activation'] is not False):
        raise ValueError('Native relation identity or parameters changed')
    security = value['security']
    summary = freeze.MEASUREMENT.security_summary(security)
    shape = summary['shape']
    rows, main, pre = SHAPES[index]
    if (not summary['screen']['passes_selected_model'] or security['fri'] != p
            or (shape['base_trace_rows'], shape['main_width'], shape['preprocessed_width']) != (rows, main, pre)):
        raise ValueError('Native actual-AIR security or shape changed')
    key = value['public_verifier_key']
    if set(key) != {'encoding', 'hex', 'sha256', 'width', 'degree_bits'} or key['encoding'] != 'SWMP-v1':
        raise ValueError('Unexpected native public-key fields')
    raw = bytes.fromhex(key['hex'])
    if not 48 <= len(raw) <= 4143 or raw[:7] != b'SWMP\x01\x00' + bytes([index + 1]):
        raise ValueError('Native public-key header or length changed')
    if int.from_bytes(raw[7:11], 'little') != CAPACITIES[index]:
        raise ValueError('Native public-key capacity changed')
    words = [int.from_bytes(raw[i:i+4], 'little') for i in range(11, 47, 4)]
    if (words[:6] != [p[n] for n in ('log_blowup', 'num_queries', 'query_pow_bits',
                                    'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')]
            or words[6:] != [pre, rows.bit_length(), len(raw) - 47]
            or key['width'] != pre or key['degree_bits'] != rows.bit_length()
            or key['sha256'] != hashlib.sha256(raw).hexdigest()):
        raise ValueError('Native public-key dimensions, parameters or hash changed')
    # Preserve and reproduce the original transaction commitment; no existing
    # proof profile, public verifier key or measured source is rewritten.
    if kind == 'transaction':
        original = bytes.fromhex(transaction['public_verifier_key']['hex'])
        if raw[47:] != original[43:] or summary != transaction['selected_security']:
            raise ValueError('Transaction key or security differs from frozen profile')
    return value


def create(reproduced, root=ROOT):
    freeze = freeze_module(root)
    transaction = transaction_profile(root)
    relations = [validate_relation(json.loads((reproduced / (kind + '.json')).read_text()),
                                   kind, transaction, freeze) for kind in KINDS]
    return {'schema': 1, 'status': 'engineering-frozen-native-relations',
            'suite': freeze.SUITE, 'cryptographic_approval': False, 'network_activation': False,
            'transaction_profile': TRANSACTION, 'transaction_profile_sha256': sha(root / TRANSACTION),
            'tool_source_sha256': {name: sha(root / name) for name in TOOLS},
            'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
            'resource_qualification': 'existing isolated diagnostics; no new performance measurement',
            'node_integration': False, 'relations': relations}


def validate(value, root=ROOT, reproduced=None):
    expected = {'schema', 'status', 'suite', 'cryptographic_approval', 'network_activation',
                'transaction_profile', 'transaction_profile_sha256', 'tool_source_sha256',
                'scope', 'resource_qualification', 'node_integration', 'relations'}
    if set(value) != expected or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Unexpected native freeze manifest schema')
    freeze = freeze_module(root)
    transaction = transaction_profile(root)
    for name, wanted in {'status': 'engineering-frozen-native-relations', 'suite': freeze.SUITE,
                         'transaction_profile': TRANSACTION,
                         'transaction_profile_sha256': sha(root / TRANSACTION),
                         'tool_source_sha256': {n: sha(root / n) for n in TOOLS},
                         'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
                         'resource_qualification': 'existing isolated diagnostics; no new performance measurement'}.items():
        if value[name] != wanted:
            raise ValueError('Native manifest source, scope or status changed')
    if any(value[n] is not False for n in ('cryptographic_approval', 'network_activation', 'node_integration')):
        raise ValueError('Native freeze cannot claim approval, integration or activation')
    if not isinstance(value['relations'], list) or len(value['relations']) != 3:
        raise ValueError('Exactly three fixed native relations required')
    for kind, relation in zip(KINDS, value['relations']):
        validate_relation(relation, kind, transaction, freeze)
        if reproduced is not None and relation != json.loads((reproduced / (kind + '.json')).read_text()):
            raise ValueError('Reproduced native key or security report differs')
    return value


def prepare(output, root=ROOT):
    transaction_profile(root)
    output.mkdir(parents=True, exist_ok=False)
    application = root / 'crates/bench-multi-asset'
    text = (application / 'Cargo.toml').read_text()
    text = text.replace('[package]\n', '[package]\nautobins = false\n', 1)
    text = text.replace('path = "../bench-d8"', 'path = ' + json.dumps(str(root / 'crates/bench-d8')))
    text += '\n[lib]\npath = ' + json.dumps(str(application / 'src/lib.rs')) + '\n'
    text += '\n[[bin]]\nname = "native-proof-artifacts"\npath = ' + json.dumps(str(root / 'scripts/native-proof-artifacts.rs')) + '\n'
    text += '\n[[test]]\nname = \"public_codec_rejections\"\npath = ' + json.dumps(str(root / 'crates/bench-multi-asset/tests/public_codec_rejections.rs')) + '\n'
    (output / 'Cargo.toml').write_text(text)
    shutil.copyfile(application / 'Cargo.lock', output / 'Cargo.lock')
    return output / 'Cargo.toml'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path)
    mode.add_argument('--create', type=Path, metavar='REPRODUCED_DIRECTORY')
    mode.add_argument('--check', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reproduced', type=Path)
    args = parser.parse_args()
    if args.prepare:
        if args.output or args.reproduced:
            parser.error('prepare accepts only its output directory')
        print(prepare(args.prepare))
    elif args.create:
        if not args.output or args.reproduced:
            parser.error('create requires output and no reproduced option')
        value = create(args.create)
        validate(value)
        with args.output.open('x') as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
        print('Three source-bound native engineering relations recorded.')
    else:
        if args.output:
            parser.error('output is only valid with create')
        validate(json.loads(args.check.read_text()), reproduced=args.reproduced)
        print('Native relation parameters, source identity and public keys validated.')


if __name__ == '__main__':
    main()
