# Hash Collision Detector

A small Python command-line tool that scans files and reports **true hash collisions**: two or more different file contents producing the same digest. It supports MD5, SHA-1, SHA-256, and SHA-512.

Identical files are not reported as collisions, even though they naturally have the same digest. Use `--include-duplicates` to include duplicate-content groups in the JSON report.

## Install

```bash
python -m pip install .
```

## Usage

```bash
# MD5 is the default
hash-collision-detector ./files

# Explicit MD5 scan with machine-readable output
hash-collision-detector ./files --algorithm md5 --json

# Scan recursively and include identical-file groups
hash-collision-detector ./files --include-duplicates --json

# Use a stronger digest algorithm
hash-collision-detector ./files --algorithm sha256
```

The process exits with status `0` when no collision is found, `1` when at least one true collision is found, and `2` for invalid input or an operational error. The detector reads files in chunks, so it does not load entire files into memory.

## Development

```bash
python -m unittest discover -s tests -v
```

## Security note

MD5 and SHA-1 are cryptographically broken for adversarial integrity or security purposes. They are included for compatibility and collision research only. Prefer SHA-256 or SHA-512 for new integrity checks.

## License

MIT
