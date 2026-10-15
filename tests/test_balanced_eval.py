# tests/test_balanced_eval.py
"""Results on a class-balanced test set (committee comment: 'results should be
produced on the balanced dataset')."""
import json

import numpy as np
import pytest

from modules.detection.balanced_eval import (
    balanced_indices, evaluate_balanced, format_balanced_table,
)


def _imbalanced_predictions():
    """90 samples of class 0 (all predicted correctly), 10 of class 1 (all wrong)."""
    y_true = np.array([0] * 90 + [1] * 10)
    y_prob = np.zeros((100, 2))
    y_prob[:, 0] = 0.9
    y_prob[:, 1] = 0.1
    return y_true, y_prob


@pytest.mark.rtm("AT-M5-12", "FR4.12")
def test_balanced_subset_has_equal_class_counts():
    y = np.array([0] * 50 + [1] * 7 + [2] * 20)
    idx = balanced_indices(y, seed=3)
    _, counts = np.unique(y[idx], return_counts=True)
    assert counts.tolist() == [7, 7, 7]                     # k = smallest class
    assert len(set(idx.tolist())) == len(idx)               # no duplicates
    assert np.array_equal(idx, balanced_indices(y, seed=3))  # deterministic
    assert not np.array_equal(idx, balanced_indices(y, seed=4))


def test_balanced_subset_rejects_bad_sizes():
    y = np.array([0, 0, 1])
    with pytest.raises(ValueError):
        balanced_indices(y, per_class=2)
    with pytest.raises(ValueError):
        balanced_indices(y, per_class=0)
    with pytest.raises(ValueError):
        balanced_indices(np.array([], dtype=int))


@pytest.mark.rtm("AT-M5-13", "FR4.12", "FR4.11")
def test_balanced_metrics_expose_majority_class_bias():
    y_true, y_prob = _imbalanced_predictions()
    res = evaluate_balanced(y_true, y_prob, ['Allaple.A', 'Skintrim.N'], n_draws=5)
    assert res['imbalanced_accuracy_full'] == pytest.approx(0.90)
    assert res['balanced_accuracy_full'] == pytest.approx(0.50)
    assert res['accuracy_mean'] == pytest.approx(0.50)      # 10 + 10 per draw, half right
    assert res['recall_macro_mean'] == pytest.approx(0.50)
    assert res['subset_size'] == 20 and res['per_class_samples'] == 10
    assert len(res['per_draw']) == 5
    json.dumps(res)                                         # saved as balanced_eval.json
    assert 'Balanced test set' in format_balanced_table(res)


def test_perfect_model_scores_one_with_zero_spread():
    y_true = np.array([0] * 30 + [1] * 5 + [2] * 12)
    y_prob = np.eye(3)[y_true]
    res = evaluate_balanced(y_true, y_prob, ['a', 'b', 'c'], n_draws=4)
    for m in ('accuracy', 'precision_macro', 'recall_macro', 'f1_macro'):
        assert res[f'{m}_mean'] == pytest.approx(1.0) and res[f'{m}_std'] == pytest.approx(0.0)
    assert res['fpr_macro_mean'] == pytest.approx(0.0)


def test_shape_mismatch_and_empty_input_raise():
    with pytest.raises(ValueError):
        evaluate_balanced(np.array([0, 1]), np.zeros((2, 3)), ['a', 'b'])
    with pytest.raises(ValueError):
        evaluate_balanced(np.array([], dtype=int), np.zeros((0, 2)), ['a', 'b'])
    with pytest.raises(ValueError):
        evaluate_balanced(np.array([0, 1]), np.eye(2), ['a', 'b'], n_draws=0)


def test_extended_metrics_include_balanced_accuracy():
    from sklearn.metrics import confusion_matrix
    from modules.detection.evaluator import compute_extended_metrics
    y_true, y_prob = _imbalanced_predictions()
    cm = confusion_matrix(y_true, y_prob.argmax(1), labels=[0, 1])
    m = compute_extended_metrics(y_true, y_prob, cm, ['A', 'B'])
    assert m['balanced_accuracy'] == pytest.approx(0.5)
