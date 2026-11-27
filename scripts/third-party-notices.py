#!/usr/bin/env python3
"""Writes THIRD-PARTY-NOTICES.txt for a binary release of the `archydes` tool.

    python3 scripts/third-party-notices.py [--target TRIPLE] [--out FILE]

Takes every crate the tool is built from (cargo metadata, normal dependencies of archydes-cli,
without proc-macros, which do not end up in the binary) with its license files, plus the C
libraries built in: zlib (archydes-zlib), Zstandard (zstd-sys), XZ Utils/liblzma
(liblzma-sys) and Leopard-RS (in the LICENSE of reed-solomon-simd). Where a crate offers a
choice of licenses, GPL/LGPL texts are never taken. Only needs Python 3 and cargo.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LICENSE_NAMES = ("license", "copying", "notice", "unlicense")
SKIP = ("gpl", "lgpl")
C_LIBRARIES = {
    "archydes-zlib": [("zlib 1.3.1", "zlib-1.3.1/LICENSE")],
    "zstd-sys": [("Zstandard (libzstd)", "zstd/LICENSE")],
    "liblzma-sys": [("XZ Utils (liblzma)", "xz/COPYING.0BSD")],
}


def shipped_packages(target):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if target:
        cmd += ["--filter-platform", target]
    meta = json.loads(subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    packages = {p["id"]: p for p in meta["packages"]}
    root = next(p["id"] for p in meta["packages"] if p["name"] == "archydes-cli")
    seen, stack = set(), [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        package = packages[pid]
        if any("proc-macro" in t["kind"] for t in package["targets"]):
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    return sorted((packages[i] for i in seen), key=lambda p: (p["name"], p["version"]))


def license_files(folder):
    return [e for e in sorted(folder.iterdir())
            if e.is_file() and e.name.lower().startswith(LICENSE_NAMES) and not any(s in e.name.lower() for s in SKIP)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="target triple, e.g. x86_64-unknown-linux-gnu")
    parser.add_argument("--out", default="THIRD-PARTY-NOTICES.txt")
    args = parser.parse_args()

    texts, rows = {}, []

    def add(name, path):
        if not path.exists():
            sys.exit(f"{path} missing")
        texts.setdefault(path.read_text(errors="replace").strip(), []).append(name)

    for package in shipped_packages(args.target):
        name = f'{package["name"]} {package["version"]}'
        rows.append(f'{name} – {package["license"] or "see license file"}')
        folder = Path(package["manifest_path"]).parent
        for file in license_files(folder):
            add(name, file)
        for title, relative in C_LIBRARIES.get(package["name"], []):
            rows.append(f'{title} – built in by {package["name"]}')
            add(title, folder / relative)

    parts = ["The archydes tool is built from these components:", "", *rows, ""]
    for text, names in texts.items():
        parts += ["=" * 78, ", ".join(sorted(set(names))), "=" * 78, "", text, ""]
    Path(args.out).write_text("\n".join(parts), encoding="utf-8")
    print(f"{args.out}: {len(rows)} components, {len(texts)} license texts")


main()
