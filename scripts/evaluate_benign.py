#!/usr/bin/env python3
"""
Measure how often the trained model calls CLEAN software malware.

Use a folder that was NOT used to build the Benign class, e.g.
    Windows:  "C:\\Program Files"   (installed applications)
    Linux:    /usr/lib/python3* or /opt
Files whose SHA-256 appears in data/malimg/Benign/manifest.csv are skipped
automatically, so no training file is ever counted.

Usage:
    python scripts/evaluate_benign.py --src "C:\\Program Files" --max 500

Output:
    data/processed/benign_eval.json
"""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--src', nargs='+', required=True, help='Folders with clean binaries not used in training')
    p.add_argument('--max', type=int, default=500)
    p.add_argument('--seed', type=int, default=config.RANDOM_SEED)
    a = p.parse_args()

    from modules.dataset.benign import iter_candidate_binaries, load_manifest_hashes, sha256_file, evaluate_on_benign
    from modules.dataset.preprocessor import load_class_names
    from modules.detection.inference import load_model

    if not config.BEST_MODEL_PATH.exists():
        print("ERROR: no trained model — run scripts/train.py first.", file=sys.stderr)
        sys.exit(1)
    names = load_class_names(config.CLASS_NAMES_PATH)
    model = load_model(config.BEST_MODEL_PATH, len(names), config.DEVICE)
    if config.BENIGN_CLASS_NAME not in names:
        print("NOTE: this model has no Benign class, so every file will be called malware. "
              "Run scripts/build_benign_class.py and retrain.")

    train_hashes = load_manifest_hashes(config.DATA_DIR / config.BENIGN_CLASS_NAME / 'manifest.csv')
    cands = [pth for pth, _ in iter_candidate_binaries([Path(s) for s in a.src])]
    random.Random(a.seed).shuffle(cands)
    chosen, skipped = [], 0
    for pth in cands:
        if len(chosen) >= a.max:
            break
        try:
            if sha256_file(pth) in train_hashes:
                skipped += 1
                continue
        except OSError:
            continue
        chosen.append(pth)
    print(f"Evaluating {len(chosen)} unseen clean binaries (skipped {skipped} used in training)...")

    res = evaluate_on_benign(model, names, chosen)
    res.update({'sources': a.src, 'skipped_training_files': skipped})
    out = config.PROCESSED_DIR / 'benign_eval.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(res, f, indent=2)

    print(f"\nClean files tested:           {res['n_files']}")
    print(f"Correctly called Benign:      {res['correctly_benign_rate']:.1%}")
    print(f"Wrongly called malware (FPR): {res['false_positive_rate']:.1%}")
    for t, v in res['confident_false_positive_rate'].items():
        print(f"  ...with confidence ≥ {t}:    {v:.1%}")
    if res['top_false_families']:
        print("Most common wrong families:   " + ", ".join(f"{f} ({c})" for f, c in res['top_false_families']))
    print(f"\nSaved → {out}")


if __name__ == '__main__':
    main()
