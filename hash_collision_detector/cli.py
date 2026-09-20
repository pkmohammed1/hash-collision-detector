from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SUPPORTED_ALGORITHMS = tuple(sorted(hashlib.algorithms_available & {"md5", "sha1", "sha256", "sha512"}))


@dataclass(frozen=True)
class FileDigest:
    path: str
    digest: str
    size: int
    content_fingerprint: str


def iter_files(paths: Iterable[Path], recursive: bool = True) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            iterator = path.rglob("*") if recursive else path.glob("*")
            yield from (item for item in iterator if item.is_file())
        else:
            raise FileNotFoundError(f"Path does not exist: {path}")


def hash_file(path: Path, algorithm: str, chunk_size: int = 1024 * 1024) -> tuple[str, str, int]:
    hasher = hashlib.new(algorithm)
    content_hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            size += len(chunk)
            hasher.update(chunk)
            content_hasher.update(chunk)
    return hasher.hexdigest(), content_hasher.hexdigest(), size


def scan(paths: Iterable[Path], algorithm: str = "md5", recursive: bool = True) -> list[FileDigest]:
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    results = []
    for path in iter_files(paths, recursive=recursive):
        digest, content_fingerprint, size = hash_file(path, algorithm)
        results.append(FileDigest(str(path), digest, size, content_fingerprint))
    return results


def find_collisions(records: Iterable[FileDigest]) -> dict[str, list[FileDigest]]:
    by_digest: dict[str, list[FileDigest]] = defaultdict(list)
    for record in records:
        by_digest[record.digest].append(record)
    return {
        digest: entries
        for digest, entries in by_digest.items()
        if len({entry.content_fingerprint for entry in entries}) > 1
    }


def find_duplicates(records: Iterable[FileDigest]) -> dict[str, list[FileDigest]]:
    by_digest: dict[str, list[FileDigest]] = defaultdict(list)
    for record in records:
        by_digest[record.digest].append(record)
    return {digest: entries for digest, entries in by_digest.items() if len(entries) > 1}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect cryptographic hash collisions in files.")
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan")
    parser.add_argument("-a", "--algorithm", default="md5", choices=SUPPORTED_ALGORITHMS, help="Hash algorithm (default: md5)")
    parser.add_argument("--no-recursive", action="store_true", help="Do not recurse into directories")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--include-duplicates", action="store_true", help="Also report identical-content files sharing a digest")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        records = scan(args.paths, args.algorithm, recursive=not args.no_recursive)
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    collisions = find_collisions(records)
    duplicates = find_duplicates(records) if args.include_duplicates else {}
    payload = {
        "algorithm": args.algorithm,
        "files_scanned": len(records),
        "collisions": {
            digest: [{"path": r.path, "size": r.size} for r in entries]
            for digest, entries in sorted(collisions.items())
        },
    }
    if args.include_duplicates:
        payload["duplicates"] = {
            digest: [{"path": r.path, "size": r.size} for r in entries]
            for digest, entries in sorted(duplicates.items())
        }

    if args.json:
        print(json.dumps(payload, indent=2))
    elif collisions:
        print(f"Found {len(collisions)} {args.algorithm.upper()} collision(s):")
        for digest, entries in sorted(collisions.items()):
            print(f"  {digest}")
            for entry in entries:
                print(f"    - {entry.path} ({entry.size} bytes)")
    else:
        print(f"No {args.algorithm.upper()} collisions found across {len(records)} file(s).")
        if args.include_duplicates and duplicates:
            print(f"Found {len(duplicates)} duplicate digest group(s).")
    return 1 if collisions else 0


if __name__ == "__main__":
    raise SystemExit(main())
