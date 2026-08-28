#!/usr/bin/env python3

import argparse
import copy
import re
import subprocess
import tomllib
from pathlib import Path


FIRST_PARTY = {
    "yon",
    "yon-relay",
    "yonder-config",
    "yonder-core",
    "yonder-fuzz",
    "yonder-net",
}
MANIFESTS = (
    "Cargo.toml",
    "crates/yon/Cargo.toml",
    "crates/yon-relay/Cargo.toml",
    "crates/yonder-config/Cargo.toml",
    "crates/yonder-core/Cargo.toml",
    "crates/yonder-net/Cargo.toml",
    "fuzz/Cargo.toml",
)
LOCKFILES = ("Cargo.lock", "fuzz/Cargo.lock")
ALLOWED_FILES = {
    *MANIFESTS,
    *LOCKFILES,
    ".github/scripts/verify-version-only-recovery.py",
    ".github/workflows/release.yml",
    "AGENTS.md",
    "README.md",
}


def git(*args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ("git", *args),
        check=True,
        capture_output=True,
        text=text,
    )
    return result.stdout


def read_toml(revision: str, path: str) -> dict:
    raw = git("show", f"{revision}:{path}", text=False)
    assert isinstance(raw, bytes)
    return tomllib.loads(raw.decode("utf-8"))


def normalize_manifest(document: dict) -> dict:
    normalized = copy.deepcopy(document)
    package = normalized.get("package")
    if (
        isinstance(package, dict)
        and package.get("name") in FIRST_PARTY
        and isinstance(package.get("version"), str)
    ):
        package["version"] = "<first-party-version>"
    workspace_package = normalized.get("workspace", {}).get("package")
    if isinstance(workspace_package, dict):
        workspace_package["version"] = "<first-party-version>"

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for name, child in value.items():
                if (
                    name in FIRST_PARTY
                    and isinstance(child, dict)
                    and "path" in child
                    and "version" in child
                ):
                    child["version"] = "=<first-party-version>"
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(normalized)
    return normalized


def normalize_lockfile(document: dict) -> dict:
    normalized = copy.deepcopy(document)
    dependency = re.compile(
        rf"^({'|'.join(re.escape(name) for name in sorted(FIRST_PARTY))}) 0\.2\.[01]( .+)?$"
    )
    for package in normalized.get("package", []):
        if package.get("name") in FIRST_PARTY:
            package["version"] = "<first-party-version>"
        package["dependencies"] = [
            dependency.sub(r"\1 <first-party-version>\2", item)
            for item in package.get("dependencies", [])
        ]
    return normalized


def assert_manifest_versions(document: dict, expected: str, path: str) -> None:
    package = document.get("package")
    if (
        isinstance(package, dict)
        and package.get("name") in FIRST_PARTY
        and isinstance(package.get("version"), str)
    ):
        if package.get("version") != expected:
            raise SystemExit(f"{path}: package version is not {expected}")
    workspace_package = document.get("workspace", {}).get("package")
    if isinstance(workspace_package, dict) and workspace_package.get("version") != expected:
        raise SystemExit(f"{path}: workspace version is not {expected}")

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for name, child in value.items():
                if name in FIRST_PARTY and isinstance(child, dict) and "path" in child:
                    if child.get("version") != f"={expected}":
                        raise SystemExit(
                            f"{path}: {name} path dependency is not pinned to ={expected}"
                        )
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.base) is None:
        raise SystemExit("base must be a full lowercase commit SHA")

    head = str(git("rev-parse", "HEAD")).strip()
    subprocess.run(("git", "merge-base", "--is-ancestor", args.base, head), check=True)
    statuses = str(
        git("diff", "--name-status", "--diff-filter=ACDMRT", f"{args.base}..{head}")
    ).splitlines()
    changed: list[str] = []
    for status in statuses:
        kind, path = status.split("\t", maxsplit=1)
        if kind not in {"A", "M"}:
            raise SystemExit(f"version-only recovery rejects {status}")
        if path not in ALLOWED_FILES and not path.startswith("docs/"):
            raise SystemExit(f"version-only recovery rejects changed file: {path}")
        changed.append(path)

    required = {"Cargo.toml", "Cargo.lock", "fuzz/Cargo.toml", "fuzz/Cargo.lock"}
    if not required.issubset(changed):
        missing = ", ".join(sorted(required.difference(changed)))
        raise SystemExit(f"version-only recovery is missing: {missing}")

    for path in MANIFESTS:
        before = read_toml(args.base, path)
        after = read_toml(head, path)
        assert_manifest_versions(before, "0.2.0", path)
        assert_manifest_versions(after, "0.2.1", path)
        if normalize_manifest(before) != normalize_manifest(after):
            raise SystemExit(f"version-only recovery changed manifest semantics: {path}")

    for path in LOCKFILES:
        before = read_toml(args.base, path)
        after = read_toml(head, path)
        if normalize_lockfile(before) != normalize_lockfile(after):
            raise SystemExit(f"version-only recovery changed dependency resolution: {path}")

    print(
        f"validated 0.2.0 -> 0.2.1 metadata-only recovery from {args.base} to {head}"
    )


if __name__ == "__main__":
    main()
