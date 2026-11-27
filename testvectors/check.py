#!/usr/bin/env python3
"""Checks an Archydes decoder against the test vectors in this folder (SPEC A14).

    python3 testvectors/check.py                       uses target/release/archydes, else `archydes` on PATH
    python3 testvectors/check.py --archydes PATH       another build of the reference tool
    python3 testvectors/check.py --write               rewrites the expected entries in manifest.json
                                                       (maintainers only, after adding a vector)

For every archive in manifest.json it checks the SHA-256 of the archive file, runs `verify`
(which must succeed, or fail for the damaged vector), extracts every listed snapshot and
compares each entry: kind, permission bits, size, SHA-256 of the content and link targets.
The damaged vector must repair to a byte-identical copy of its original.

Other implementations can use manifest.json directly; this script only needs Python 3.9+.
Extended attributes are not compared here (Python's standard library cannot read them on
macOS); `metadata.archy` holds one (`com.example.x` on d/a.txt).
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
KINDS = {"-": "file", "d": "dir", "l": "symlink", "h": "hardlink"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class Tool:
    def __init__(self, path):
        self.path = path

    def run(self, *args, password=None, check=True):
        cmd = [self.path, *args[:1]]
        rest = list(args[1:])
        with tempfile.TemporaryDirectory() as tmp:
            if password is not None:
                pw = Path(tmp) / "password"
                pw.write_text(password + "\n", encoding="utf-8")
                cmd += ["--password-file", str(pw)]
            out = subprocess.run(cmd + rest, capture_output=True, text=True)
        if check and out.returncode != 0:
            raise SystemExit(f"{' '.join(cmd + rest)} failed:\n{out.stdout}{out.stderr}")
        return out


def listed_entries(tool, archive, snapshot, password):
    """Kinds and link targets as the tool lists them (`list -l`)."""
    out = tool.run("list", "-l", "-s", str(snapshot), str(archive), password=password).stdout
    entries = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        kind, rest = KINDS[line[0]], line[1:]
        mode = int(rest[:4], 8)
        # Columns: mode, size, date, time, two spaces, path.
        fields = rest.split(None, 4)
        path = fields[4]
        target = None
        for arrow in (" -> ", " => "):
            if kind in ("symlink", "hardlink") and arrow in path:
                path, target = path.split(arrow, 1)
        path = path.rstrip("/")
        entries[path] = {"kind": kind, "mode": f"{mode:04o}", "target": target}
    return entries


def extracted(tool, archive, snapshot, password, dest):
    tool.run("extract", "--no-xattrs", "-s", str(snapshot), "-C", str(dest), str(archive), password=password)


def describe(dest, listed):
    """The expected entries: listed kinds plus what is on disk."""
    result = []
    for path, entry in sorted(listed.items()):
        item = {"path": path, "kind": entry["kind"], "mode": entry["mode"]}
        full = dest / path
        if entry["kind"] in ("file", "hardlink"):
            item["size"] = full.stat().st_size
            item["sha256"] = sha256(full)
        if entry["target"] is not None:
            item["target"] = entry["target"]
        result.append(item)
    return result


def compare(name, snapshot, dest, expected):
    problems = []
    on_disk = set()
    for root, dirs, files in os.walk(dest):
        for n in dirs + files:
            on_disk.add(os.path.relpath(os.path.join(root, n), dest).replace(os.sep, "/"))
    for item in expected:
        path, full = item["path"], dest / item["path"]
        where = f"{name} snapshot {snapshot}: {path}"
        on_disk.discard(path)
        if not os.path.lexists(full):
            problems.append(f"{where}: missing")
            continue
        st = os.lstat(full)
        kind = item["kind"]
        if kind == "dir" and not stat.S_ISDIR(st.st_mode):
            problems.append(f"{where}: not a folder")
        elif kind == "symlink":
            if not stat.S_ISLNK(st.st_mode):
                problems.append(f"{where}: not a symlink")
            elif os.readlink(full) != item["target"]:
                problems.append(f"{where}: link target {os.readlink(full)!r}, expected {item['target']!r}")
        elif kind in ("file", "hardlink"):
            if not stat.S_ISREG(st.st_mode):
                problems.append(f"{where}: not a file")
                continue
            if st.st_size != item["size"] or sha256(full) != item["sha256"]:
                problems.append(f"{where}: content differs")
            if kind == "hardlink":
                original = dest / item["target"]
                if not original.exists() or os.stat(original).st_ino != st.st_ino:
                    problems.append(f"{where}: not a hard link to {item['target']}")
        if kind != "symlink" and os.name == "posix" and f"{stat.S_IMODE(st.st_mode):04o}" != item["mode"]:
            problems.append(f"{where}: mode {stat.S_IMODE(st.st_mode):04o}, expected {item['mode']}")
    for extra in sorted(on_disk):
        problems.append(f"{name} snapshot {snapshot}: {extra}: not expected")
    return problems


def find_tool(given):
    if given:
        return given
    local = HERE.parent / "target/release/archydes"
    if local.exists():
        return str(local)
    found = shutil.which("archydes")
    if not found:
        raise SystemExit("archydes not found: build it (cargo build --release) or pass --archydes")
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archydes", help="path to the archydes tool")
    parser.add_argument("--write", action="store_true", help="rewrite the expected entries")
    args = parser.parse_args()
    tool = Tool(find_tool(args.archydes))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = []

    for vector in manifest["vectors"]:
        name, archive = vector["file"], HERE / vector["file"]
        password = vector.get("password")
        if args.write:
            vector["sha256"] = sha256(archive)
        elif sha256(archive) != vector["sha256"]:
            problems.append(f"{name}: the file is not the published vector (SHA-256 differs)")
            continue

        verify = tool.run("verify", str(archive), password=password, check=False)
        if vector.get("damaged"):
            if verify.returncode == 0:
                problems.append(f"{name}: verify reports no damage")
        elif verify.returncode != 0:
            problems.append(f"{name}: verify failed:\n{verify.stdout}{verify.stderr}")

        if "repairs_to" in vector:
            with tempfile.TemporaryDirectory() as tmp:
                copy = Path(tmp) / name
                shutil.copy(archive, copy)
                tool.run("repair", str(copy), password=password)
                repaired = copy.with_name(copy.stem + "-repaired.archy")
                if sha256(repaired) != sha256(HERE / vector["repairs_to"]):
                    problems.append(f"{name}: repaired copy differs from {vector['repairs_to']}")

        for snapshot in vector.get("snapshots", []):
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp)
                extracted(tool, archive, snapshot["id"], password, dest)
                if args.write:
                    listed = listed_entries(tool, archive, snapshot["id"], password)
                    snapshot["entries"] = describe(dest, listed)
                else:
                    problems += compare(name, snapshot["id"], dest, snapshot["entries"])

    if args.write:
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"manifest.json: {len(manifest['vectors'])} vectors written")
        return
    for p in problems:
        print(p)
    count = len(manifest["vectors"])
    if problems:
        sys.exit(f"{len(problems)} problem(s) in {count} vectors")
    print(f"All {count} test vectors pass ({tool.path}).")


main()
