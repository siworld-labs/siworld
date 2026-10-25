#!/usr/bin/env python3
"""Build a bounded intra-proof experiment without changing node dependencies.

The upstream hiding prover defaults to a one-worker Rayon pool. This isolated
copy permits one or two workers, retaining the default and all verifier code.
It is an execution experiment, not a cryptographic approval of parallel hiding.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import re

ROOT = Path(__file__).resolve().parents[1]
PIN = "3a69ba61f713c8400b14eb3d8f0e52caa13512c7"
URL = "https://github.com/Plonky3/Plonky3-recursion"
PACKAGES = {"p3-circuit": "circuit", "p3-circuit-prover": "circuit-prover",
            "p3-recursion": "recursion", "p3-poseidon-circuit-cols": "poseidon-circuit-cols",
            "p3-poseidon1-circuit-air": "poseidon1-circuit-air",
            "p3-poseidon2-circuit-air": "poseidon2-circuit-air"}


def command(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="existing upstream clone; copied at its pinned commit")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    destination = ROOT / ".local" / "composition-intra"
    if destination.exists():
        raise SystemExit("Refusing to overwrite an existing experiment; retain its evidence")
    upstream = destination / "upstream"
    upstream.mkdir(parents=True)
    command("git", "init", "--quiet", str(upstream))
    command("git", "-C", str(upstream), "fetch", "--depth=1", str(args.source) if args.source else URL, PIN)
    command("git", "-C", str(upstream), "checkout", "--quiet", "--detach", "FETCH_HEAD")
    for package_manifest in upstream.glob("*/Cargo.toml"):
        text = package_manifest.read_text()
        if "[package]" in text:
            package_manifest.write_text(text.replace("[package]", '[package]\nworkspace = ".."', 1))
    target = upstream / "circuit-prover/src/batch_stark_prover.rs"
    original = target.read_text()
    needle = "            .num_threads(1)\n"
    if original.count(needle) != 1:
        raise SystemExit("Pinned one-worker isolation point changed")
    replacement = '''            .num_threads({
                extern crate std;
                match std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS") {
                Ok(value) if value == "2" => 2,
                Ok(value) if value == "1" => 1,
                Err(std::env::VarError::NotPresent) => 1,
                _ => return Err(BatchStarkProverError::Prove("experimental hiding workers must be 1 or 2".into())),
                }
            })
'''
    target.write_text(original.replace(needle, replacement))
    source = ROOT / "crates/bench-stark"
    benchmark = destination / "benchmark"
    for directory in ("common", "plonky3"):
        shutil.copytree(source / directory, benchmark / directory,
                        ignore=shutil.ignore_patterns("target"))
        crate_manifest = benchmark / directory / "Cargo.toml"
        text = crate_manifest.read_text()
        # Keep dependencies outside this small workspace at their original
        # technical source paths; the generated manifest remains private.
        text = re.sub(r'path = "(\.\./\.\./[^\"]+)"',
                      lambda match: "path = " + json.dumps(str((source / directory / match[1]).resolve())), text)
        crate_manifest.write_text(text)
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(source / name, benchmark / name)
    manifest = benchmark / "Cargo.toml"
    text = manifest.read_text()
    for name, directory in PACKAGES.items():
        text = re.sub(r'^' + re.escape(name) + r' = \{ git = [^\n]+$',
                      f'{name} = {{ path = {json.dumps(str(upstream / directory))} }}', text, flags=re.M)
    manifest.write_text(text)
    receipt = {"upstream_commit": PIN,
               "original_source_sha256": hashlib.sha256(original.encode()).hexdigest(),
               "modified_source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
               "bootstrap_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (destination / "source-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if args.prepare_only:
        print(benchmark / "Cargo.toml")
        return
    command("cargo", "build", "--release", "--manifest-path", str(manifest),
            "-p", "siworld-bench-plonky3", "--features", "experimental-fanin,phase-profile",
            "--bin", "composition-bench")
    # Cargo may change source identities for patched packages, but must retain
    # every registry version and checksum from the original locked graph.
    before = (source / "Cargo.lock").read_text()
    after = (benchmark / "Cargo.lock").read_text()
    def registry(text):
        entries = set()
        for block in text.split("[[package]]")[1:]:
            fields = dict(re.findall(r'^([a-z]+) = "([^"\n]+)"$', block, re.M))
            if fields.get("source", "").startswith("registry+"):
                entries.add(tuple(fields[k] for k in ("name", "version", "checksum")))
        return entries
    if registry(before) != registry(after):
        raise SystemExit("Registry dependency pins changed; experiment rejected")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", str(benchmark / "target"))).resolve()
    binary = target_dir / "release/composition-bench"
    receipt["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (destination / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(binary)


if __name__ == "__main__":
    main()
