# modules/detection/balanced_eval.py
"""
Evaluation on a class-balanced test set.

Malimg is 36:1 imbalanced (Allaple.A 2,949 images vs Skintrim.N 80), so the
natural test split is dominated by a few large families and plain accuracy
mostly measures how well the model does on those. To report results on a
balanced dataset, this module:

  1. draws a balanced subset of the held-out test split — the same number of
     samples k from every class (k = size of the smallest class in the split),
     without replacement;
  2. computes accuracy, macro precision / recall / F1 and FPR on that subset;
  3. repeats the draw n_draws times with different seeds and reports the
     mean and standard deviation, so the figure does not depend on one lucky
     sample of the large classes.

It also reports balanced accuracy (mean per-class recall) on the full test
split, which is the closed-form equivalent of an infinitely repeated balanced
draw.

The model's predictions are computed once (by evaluator.evaluate, which
returns y_true and y_prob), so no extra inference is needed.

Training is balanced separately: ClassAwareOversampler draws every class with
equal probability in each epoch (strategy 'oversample_minority', the default).
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score,
)


def balanced_indices(y_true: np.ndarray, per_class: int | None = None,
                     seed: int = 0) -> np.ndarray:
    """Indices of a subset with exactly `per_class` samples from every class
    present in y_true (default: the smallest class size). Sampling is without
    replacement and deterministic for a given seed."""
    y_true = np.asarray(y_true)
    classes, counts = np.unique(y_true, return_counts=True)
    if len(classes) == 0:
        raise ValueError("y_true is empty")
    k = int(counts.min()) if per_class is None else int(per_class)
    if k < 1:
        raise ValueError("per_class must be at least 1")
    if k > counts.min():
        raise ValueError(f"per_class={k} exceeds the smallest class size ({counts.min()})")
    rng = np.random.default_rng(seed)
    idx = [rng.choice(np.flatnonzero(y_true == c), size=k, replace=False) for c in classes]
    return np.sort(np.concatenate(idx))


def _subset_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[int]) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    tp = np.diag(cm)
    fp = cm.sum(axis=0) - tp
    tn = cm.sum() - tp - fp - (cm.sum(axis=1) - tp)
    present = np.isin(labels, np.unique(y_true))
    with np.errstate(divide='ignore', invalid='ignore'):
        fpr = np.where((fp + tn) > 0, fp / (fp + tn), 0.0)
    kw = dict(labels=[l for l, p in zip(labels, present) if p], average='macro', zero_division=0)
    return {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision_macro': float(precision_score(y_true, y_pred, **kw)),
        'recall_macro': float(recall_score(y_true, y_pred, **kw)),
        'f1_macro': float(f1_score(y_true, y_pred, **kw)),
        'fpr_macro': float(fpr[present].mean()),
    }


def evaluate_balanced(y_true, y_prob, class_names: list[str], n_draws: int = 10,
                      per_class: int | None = None, seed: int = 42) -> dict:
    """Balanced-test-set evaluation from already computed predictions.

    Returns a JSON-serialisable dict:
      per_class_samples, n_classes, n_draws, subset_size,
      mean / std of accuracy, precision_macro, recall_macro, f1_macro, fpr_macro,
      balanced_accuracy_full (mean per-class recall on the whole test split),
      imbalanced_accuracy_full (plain accuracy on the whole test split),
      per_draw (list of the individual results).
    """
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob)
    if len(y_true) == 0:
        raise ValueError("no test predictions to evaluate")
    if y_prob.shape != (len(y_true), len(class_names)):
        raise ValueError(f"y_prob shape {y_prob.shape} does not match "
                         f"{len(y_true)} samples × {len(class_names)} classes")
    if n_draws < 1:
        raise ValueError("n_draws must be at least 1")
    y_pred = y_prob.argmax(axis=1)
    labels = list(range(len(class_names)))

    draws = []
    for d in range(n_draws):
        idx = balanced_indices(y_true, per_class, seed=seed + d)
        draws.append(_subset_metrics(y_true[idx], y_pred[idx], labels))

    k = len(idx) // len(np.unique(y_true))
    out = {
        'per_class_samples': k,
        'n_classes': int(len(np.unique(y_true))),
        'n_draws': n_draws,
        'subset_size': int(len(idx)),
        'balanced_accuracy_full': float(balanced_accuracy_score(y_true, y_pred)),
        'imbalanced_accuracy_full': float(accuracy_score(y_true, y_pred)),
        'per_draw': draws,
    }
    for m in draws[0]:
        vals = np.array([dr[m] for dr in draws])
        out[f'{m}_mean'] = float(vals.mean())
        out[f'{m}_std'] = float(vals.std(ddof=1)) if n_draws > 1 else 0.0
    return out


def format_balanced_table(res: dict) -> str:
    rows = [
        f"Balanced test set: {res['per_class_samples']} samples × {res['n_classes']} classes "
        f"= {res['subset_size']} per draw, {res['n_draws']} draws",
        f"  Accuracy         {res['accuracy_mean']:.4f} ± {res['accuracy_std']:.4f}",
        f"  Macro precision  {res['precision_macro_mean']:.4f} ± {res['precision_macro_std']:.4f}",
        f"  Macro recall     {res['recall_macro_mean']:.4f} ± {res['recall_macro_std']:.4f}",
        f"  Macro F1         {res['f1_macro_mean']:.4f} ± {res['f1_macro_std']:.4f}",
        f"  Macro FPR        {res['fpr_macro_mean']:.4f} ± {res['fpr_macro_std']:.4f}",
        f"Full test split: accuracy {res['imbalanced_accuracy_full']:.4f}, "
        f"balanced accuracy {res['balanced_accuracy_full']:.4f}",
    ]
    return "\n".join(rows)
