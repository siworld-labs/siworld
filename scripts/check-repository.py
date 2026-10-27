"""Validate the publication boundary and relative documentation links."""

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".editorconfig", ".gitattributes", ".gitignore", "Cargo.toml", "Cargo.lock",
    "rust-toolchain.toml", "LICENSE", "NOTICE", "README.md", "CONTRIBUTING.md",
    "SECURITY.md",
}
DOCUMENTS = {
    "00-decisions.md", "bht-security-accounting.md", "d8-dependency-patch.md",
    "README.md", "whitepaper.md", "architecture.md", "protocol.md",
    "cryptography.md", "security-model.md", "node-operations.md", "rpc.md",
    "benchmarks.md", "testing.md", "development.md",
    "proof-composition.md", "worker-control.md", "memory-budgets.md",
    "proof-security-review.md", "prover-acceptance.md", "d8-w24-recursion.md",
    "d4-security-controls.md", "d8-parameter-screen.md", "linux-proof-measurement.md",
    "route-a-v1.md", "fee-settlement.md", "fee-settlement-evaluation.md",
}
PUBLIC_ARTIFACTS = {
    *(f"crates/prover/keys/root-n{n}.bin" for n in (2, 4, 8, 16, 32, 64, 128)),
    "crates/prover/tests/data/root-proof-n16.bin",
    "crates/prover/tests/data/root-statement-n16.bin",
}
CRATES = {
    "core", "crypto", "poseidon2", "state", "circuits", "consensus",
    "storage", "prover", "node", "bench-stark", "bench-d8",
}
NON_ENGLISH = re.compile(
    "[\u3400-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]"
)


def allowed(path):
    name = path.as_posix()
    if len(path.parts) == 1:
        return name in ROOT_FILES
    if path.parts[0] == "docs":
        return len(path.parts) == 2 and path.name in DOCUMENTS
    if name in {".cargo/config.toml", "scripts/prover-launcher.rs",
                "crates/bench-stark/patches/recursion-d8-w24.patch"}:
        return True
    if path.parts[0] == "scripts":
        return path.suffix == ".py" and (len(path.parts) == 2 or (len(path.parts) == 3 and path.parts[1] == "tests"))
    if path.parts[0] == "tools":
        return name in {"tools/control-panel/memory_trend.py", "tools/control-panel/test_memory_trend.py"}
    if name == ".github/audit-registry.json":
        return True
    if path.parts[0] == ".github":
        return path.suffix in {".yml", ".yaml", ".md"} or path.name == "CODEOWNERS"
    if path.parts[0] == "crates" and path.parts[1] in CRATES:
        return (
            name in PUBLIC_ARTIFACTS
            or path.suffix in {".rs", ".toml", ".lock", ".py"}
            or path.name == "README.md"
        )
    return False


def main():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    ).decode().split("\0")
    errors = []
    for name in sorted(set(filter(None, names))):
        relative = Path(name)
        path = ROOT / relative
        if not allowed(relative):
            errors.append(f"Outside the publication manifest: {name}")
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"Expected a regular file: {name}")
            continue
        if name in PUBLIC_ARTIFACTS:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"Expected UTF-8 text: {name}")
            continue
        if NON_ENGLISH.search(name + content):
            errors.append(f"Non-English text: {name}")
        if re.search(r"(?:/Users/|/home/)[A-Za-z0-9_.-]+/", content):
            errors.append(f"Personal filesystem path: {name}")
        if path.suffix == ".md":
            for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^\s)]+)\)", content):
                if target.startswith(("https://", "http://", "#", "mailto:")):
                    continue
                target = unquote(target.split("#", 1)[0])
                resolved = (path.parent / target).resolve()
                if not resolved.is_relative_to(ROOT) or not resolved.exists():
                    errors.append(f"Invalid relative link in {name}: {target}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Publication manifest, English text and documentation links validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
