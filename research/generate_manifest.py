#!/usr/bin/env python3
"""
SecuraX Dataset Manifest Generator
=====================================
Generates a SHA-256 manifest for all dataset files to ensure reproducibility.

Usage:
    python research/generate_manifest.py --datasets datasets/ --output datasets/dataset-v1.0.0-manifest.json
    # or via Makefile:
    make dataset-manifest
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest(datasets_dir: Path, output_path: Path) -> dict:
    manifest = {
        "_comment": "SecuraX Dataset Integrity Manifest",
        "_version": (datasets_dir / "VERSION").read_text().strip() if (datasets_dir / "VERSION").exists() else "unknown",
        "_generated_at": datetime.now(timezone.utc).isoformat(),
        "_generator": "research/generate_manifest.py v1.0.0",
        "files": {}
    }

    for path in sorted(datasets_dir.rglob("*")):
        if path.is_file() and not path.name.endswith("-manifest.json"):
            rel = str(path.relative_to(ROOT)).replace("\\", "/")
            manifest["files"][rel] = {
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }

    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[OUT] Manifest: {output_path} ({len(manifest['files'])} files)")
    return manifest


def verify_manifest(manifest_path: Path) -> bool:
    manifest = json.loads(manifest_path.read_text())
    all_ok = True
    for rel_path, info in manifest["files"].items():
        full_path = ROOT / rel_path
        if not full_path.exists():
            print(f"[MISSING] {rel_path}")
            all_ok = False
            continue
        actual = sha256_file(full_path)
        if actual != info["sha256"]:
            print(f"[MISMATCH] {rel_path}")
            print(f"  Expected: {info['sha256']}")
            print(f"  Actual:   {actual}")
            all_ok = False
        else:
            print(f"[OK] {rel_path}")
    return all_ok


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate or verify dataset manifest")
    parser.add_argument("--datasets", default="datasets/", help="Datasets directory")
    parser.add_argument("--output", default="datasets/dataset-v1.0.0-manifest.json")
    parser.add_argument("--verify", action="store_true", help="Verify existing manifest")
    args = parser.parse_args()

    if args.verify:
        ok = verify_manifest(ROOT / args.output)
        sys.exit(0 if ok else 1)
    else:
        generate_manifest(ROOT / args.datasets, ROOT / args.output)
