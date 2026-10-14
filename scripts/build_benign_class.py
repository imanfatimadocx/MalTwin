#!/usr/bin/env python3
"""
Build the "Benign" class for the static CNN from clean binaries on this machine.

Malimg contains malware only, so without this class every file — including
clean ones — is assigned to some malware family. Run this BEFORE training.

Default sources (pick clean, built-in folders only):
    Windows:  C:\\Windows\\System32
    Linux:    /usr/bin /usr/sbin /usr/lib

Usage:
    python scripts/build_benign_class.py                       # defaults above
    python scripts/build_benign_class.py --src "C:\\Windows\\System32" --max 1500
    python scripts/build_benign_class.py --src /usr/bin /usr/lib --max 1500

Output:
    data/malimg/Benign/<sha256>.png   (Malimg-format images)
    data/malimg/Benign/manifest.csv   (what was used — keep it for the report)

Then train as usual:  python scripts/train.py   (26 classes: 25 families + Benign)
"""
import argparse
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402


def default_sources() -> list[str]:
    if platform.system() == 'Windows':
        return [r'C:\Windows\System32']
    return ['/usr/bin', '/usr/sbin', '/usr/lib']


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--src', nargs='+', default=None, help='Folders with clean PE/ELF binaries')
    p.add_argument('--out', default=str(config.DATA_DIR / config.BENIGN_CLASS_NAME))
    p.add_argument('--max', type=int, default=1500, help='Maximum images (Malimg families have 80–2,949)')
    p.add_argument('--max-mb', type=float, default=10.0, help='Skip files larger than this')
    p.add_argument('--seed', type=int, default=config.RANDOM_SEED)
    a = p.parse_args()

    src = a.src or default_sources()
    if not config.DATA_DIR.exists():
        print(f"ERROR: Malimg dataset not found at {config.DATA_DIR}. Put Malimg there first.", file=sys.stderr)
        sys.exit(1)

    from modules.dataset.benign import build_benign_class
    print(f"Scanning {', '.join(src)} for clean PE/ELF binaries...")
    rows = build_benign_class([Path(s) for s in src], Path(a.out), max_files=a.max, seed=a.seed,
                              max_size=int(a.max_mb * 1024 * 1024))
    if not rows:
        print("ERROR: no PE/ELF files found in those folders.", file=sys.stderr)
        sys.exit(2)
    pe = sum(r['format'] == 'PE' for r in rows)
    print(f"Wrote {len(rows)} benign images ({pe} PE, {len(rows) - pe} ELF) → {a.out}")
    print("Next: python scripts/train.py")


if __name__ == '__main__':
    main()
