# modules/dataset/benign.py
"""
Benign class for the static detector.

Why this exists
---------------
Malimg contains malware only (25 families). A classifier trained on it has no
way to say "this file is clean": every input is assigned to the nearest malware
family. That is why clean files were reported as malware.

The fix is a 26th class, ``Benign``, built from clean PE/ELF binaries that every
machine already has (e.g. C:\\Windows\\System32, /usr/bin). Each binary is laid
out with the same Nataraj width table used to build Malimg and saved as a PNG,
so the Benign images are produced by exactly the same process as the malware
images and the network cannot tell them apart by format alone.

A second function measures the false-positive rate on clean software the model
has NOT seen during training (a different folder, with training files excluded
by SHA-256), which is the honest answer to "does it call clean files malware?".
"""
from __future__ import annotations

import csv
import hashlib
import os
import random
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator, Optional

import numpy as np

import config

BENIGN = config.BENIGN_CLASS_NAME
MAGIC_PE = b'MZ'
MAGIC_ELF = b'\x7fELF'


def sniff_format(path: Path) -> Optional[str]:
    """Return 'PE' / 'ELF' from the first bytes, or None (unreadable / other)."""
    try:
        with open(path, 'rb') as f:
            head = f.read(4)
    except (OSError, PermissionError):
        return None
    if head[:2] == MAGIC_PE:
        return 'PE'
    if head == MAGIC_ELF:
        return 'ELF'
    return None


def iter_candidate_binaries(
    src_dirs: Iterable[Path],
    min_size: int = 4 * 1024,
    max_size: int = 10 * 1024 * 1024,
    recursive: bool = True,
) -> Iterator[tuple[Path, str]]:
    """Yield (path, format) for every PE/ELF file within the size limits."""
    for src in src_dirs:
        src = Path(src)
        if not src.exists():
            continue
        walker = os.walk(src) if recursive else [(str(src), [], os.listdir(src))]
        for root, _dirs, files in walker:
            for name in files:
                p = Path(root) / name
                try:
                    if p.is_symlink() or not p.is_file():
                        continue
                    size = p.stat().st_size
                except OSError:
                    continue
                if not (min_size <= size <= max_size):
                    continue
                fmt = sniff_format(p)
                if fmt:
                    yield p, fmt


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def load_manifest_hashes(manifest: Path) -> set[str]:
    if not Path(manifest).exists():
        return set()
    with open(manifest, newline='', encoding='utf-8') as f:
        return {row['sha256'] for row in csv.DictReader(f)}


def build_benign_class(
    src_dirs: Iterable[Path],
    out_dir: Path,
    max_files: int = 1500,
    seed: int = 42,
    min_size: int = 4 * 1024,
    max_size: int = 10 * 1024 * 1024,
    exclude_hashes: Optional[set[str]] = None,
) -> list[dict]:
    """
    Convert clean binaries into Malimg-format PNGs under ``out_dir``.

    Duplicates (same SHA-256) are written once. A ``manifest.csv`` records the
    SHA-256, original name, format and size of every image so the experiment
    can be reproduced and the evaluation set can exclude training files.
    """
    import cv2
    from modules.binary_to_image.converter import BinaryConverter

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = list(iter_candidate_binaries(src_dirs, min_size, max_size))
    random.Random(seed).shuffle(candidates)

    conv = BinaryConverter(layout='malimg')
    seen = set(exclude_hashes or ())
    rows: list[dict] = []
    for path, fmt in candidates:
        if len(rows) >= max_files:
            break
        try:
            data = path.read_bytes()
        except (OSError, PermissionError):
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        try:
            img = conv.layout_2d(data)
        except ValueError:
            continue
        if not cv2.imwrite(str(out_dir / f'{digest}.png'), img):
            continue
        rows.append({'sha256': digest, 'name': path.name, 'format': fmt, 'size': len(data)})

    with open(out_dir / 'manifest.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['sha256', 'name', 'format', 'size'])
        w.writeheader()
        w.writerows(rows)
    return rows


def evaluate_on_benign(
    model,
    class_names: list[str],
    paths: Iterable[Path],
    device=config.DEVICE,
    thresholds: Iterable[float] = (config.CONFIDENCE_AMBER, config.CONFIDENCE_GREEN),
) -> dict:
    """
    Run the trained CNN on clean binaries and report how often it says malware.

    A file counts as a false positive when the top-1 class is not ``Benign``.
    Per-threshold rows show how many of those false alarms are *confident*
    (top-1 confidence at or above the dashboard's amber/green thresholds),
    because a low-confidence red result already tells the analyst to check.
    """
    from modules.binary_to_image.converter import BinaryConverter
    from modules.detection.inference import predict_single

    conv = BinaryConverter(layout='malimg')
    has_benign = BENIGN in class_names
    n, fp, confs, fp_families = 0, 0, [], Counter()
    fp_conf = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
            img = conv.convert(data)
        except (OSError, PermissionError, ValueError):
            continue
        r = predict_single(model, img, class_names, device)
        n += 1
        confs.append(r['confidence'])
        if r['predicted_family'] != BENIGN:
            fp += 1
            fp_families[r['predicted_family']] += 1
            fp_conf.append(r['confidence'])

    if n == 0:
        raise ValueError("No readable PE/ELF files to evaluate")
    fp_conf_arr = np.asarray(fp_conf)
    return {
        'model_has_benign_class': has_benign,
        'n_files': n,
        'false_positives': fp,
        'false_positive_rate': fp / n,
        'correctly_benign_rate': 1 - fp / n,
        'confident_false_positive_rate': {
            f'{t:.2f}': float((fp_conf_arr >= t).sum() / n) for t in thresholds
        },
        'mean_confidence': float(np.mean(confs)),
        'top_false_families': fp_families.most_common(5),
    }
