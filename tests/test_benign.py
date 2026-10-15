# tests/test_benign.py
"""Tests for the Benign class builder, benign evaluation, and their dashboard wiring."""
import csv
import os

import cv2
import numpy as np
import pytest
import torch

import config
from modules.binary_to_image.converter import BinaryConverter
from modules.dataset.benign import (
    sniff_format, iter_candidate_binaries, build_benign_class, load_manifest_hashes,
    evaluate_on_benign,
)


def _pe(n, seed):
    rng = np.random.default_rng(seed)
    return b'MZ' + rng.integers(0, 256, n - 2, dtype=np.uint8).tobytes()


def _elf(n, seed):
    rng = np.random.default_rng(seed)
    return b'\x7fELF' + rng.integers(0, 256, n - 4, dtype=np.uint8).tobytes()


@pytest.fixture
def clean_dir(tmp_path):
    src = tmp_path / 'sys'
    (src / 'sub').mkdir(parents=True)
    (src / 'a.exe').write_bytes(_pe(8 * 1024, 1))
    (src / 'b.dll').write_bytes(_pe(40 * 1024, 2))
    (src / 'sub' / 'tool').write_bytes(_elf(20 * 1024, 3))
    (src / 'dup.exe').write_bytes(_pe(8 * 1024, 1))          # duplicate of a.exe
    (src / 'readme.txt').write_bytes(b'hello' * 2000)          # not a binary
    (src / 'tiny.exe').write_bytes(b'MZ' + b'\0' * 100)        # below min size
    return src


class TestSniff:
    def test_formats(self, clean_dir):
        assert sniff_format(clean_dir / 'a.exe') == 'PE'
        assert sniff_format(clean_dir / 'sub' / 'tool') == 'ELF'
        assert sniff_format(clean_dir / 'readme.txt') is None
        assert sniff_format(clean_dir / 'missing') is None

    def test_candidates_filter_size_and_type(self, clean_dir):
        names = sorted(p.name for p, _ in iter_candidate_binaries([clean_dir]))
        assert names == ['a.exe', 'b.dll', 'dup.exe', 'tool']


class TestBuildBenignClass:
    @pytest.mark.rtm("AT-M5-10", "FR4.14")
    def test_writes_malimg_format_pngs_and_manifest(self, clean_dir, tmp_path):
        out = tmp_path / 'malimg' / 'Benign'
        rows = build_benign_class([clean_dir], out, max_files=10)
        assert len(rows) == 3                                   # duplicate skipped
        assert {r['format'] for r in rows} == {'PE', 'ELF'}
        # Each PNG is the full Malimg layout (not resized): width from the table
        b = next(r for r in rows if r['name'] == 'b.dll')       # 40 KB → width 128
        img = cv2.imread(str(out / f"{b['sha256']}.png"), cv2.IMREAD_GRAYSCALE)
        assert img.shape == (40 * 1024 // 128, 128)
        expected = BinaryConverter(layout='malimg').layout_2d((clean_dir / 'b.dll').read_bytes())
        assert np.array_equal(img, expected)
        with open(out / 'manifest.csv') as f:
            assert len(list(csv.DictReader(f))) == 3

    def test_max_files_and_determinism(self, clean_dir, tmp_path):
        r1 = build_benign_class([clean_dir], tmp_path / 'o1', max_files=2, seed=7)
        r2 = build_benign_class([clean_dir], tmp_path / 'o2', max_files=2, seed=7)
        assert len(r1) == 2 and [r['sha256'] for r in r1] == [r['sha256'] for r in r2]

    def test_exclude_hashes(self, clean_dir, tmp_path):
        first = build_benign_class([clean_dir], tmp_path / 'o1', max_files=10)
        hashes = load_manifest_hashes(tmp_path / 'o1' / 'manifest.csv')
        assert hashes == {r['sha256'] for r in first}
        again = build_benign_class([clean_dir], tmp_path / 'o2', max_files=10, exclude_hashes=hashes)
        assert again == []

    def test_missing_manifest_is_empty_set(self, tmp_path):
        assert load_manifest_hashes(tmp_path / 'nope.csv') == set()


class TestEvaluateOnBenign:
    def _model(self, n_classes):
        from modules.detection.model import MalTwinCNN
        torch.manual_seed(0)
        return MalTwinCNN(num_classes=n_classes).eval()

    def test_reports_rates(self, clean_dir):
        names = ['Allaple.A', 'Benign', 'Yuner.A']
        paths = [p for p, _ in iter_candidate_binaries([clean_dir])]
        res = evaluate_on_benign(self._model(3), names, paths, device=torch.device('cpu'))
        assert res['n_files'] == 4
        assert res['model_has_benign_class'] is True
        assert res['false_positives'] + round(res['correctly_benign_rate'] * 4) == 4
        assert 0.0 <= res['false_positive_rate'] <= 1.0

    @pytest.mark.rtm("AT-M5-09", "FR4.14")
    def test_without_benign_class_everything_is_flagged(self, clean_dir):
        names = ['Allaple.A', 'Yuner.A']
        paths = [p for p, _ in iter_candidate_binaries([clean_dir])]
        res = evaluate_on_benign(self._model(2), names, paths, device=torch.device('cpu'))
        assert res['model_has_benign_class'] is False
        assert res['false_positive_rate'] == 1.0

    def test_no_files_raises(self):
        with pytest.raises(ValueError):
            evaluate_on_benign(self._model(2), ['A', 'Benign'], [], device=torch.device('cpu'))


class TestDashboardWiring:
    @pytest.mark.rtm("AT-M5-11", "FR1.2", "FR5.8")
    def test_stats_count_benign(self, tmp_path):
        from modules.dashboard.db import init_db, log_detection_event, get_detection_stats
        db = tmp_path / 'x.db'
        init_db(db)
        for fam in ['Allaple.A', 'Benign', 'Benign']:
            log_detection_event(db, 'f.exe', '0' * 64, 'PE', 100, fam, 0.9, 'cpu')
        s = get_detection_stats(db)
        assert s['total_analyzed'] == 3 and s['total_benign'] == 2 and s['total_malware'] == 1

    def test_static_evidence_with_benign_class(self):
        from modules.dashboard.pages.hybrid import static_evidence
        score, fam = static_evidence({'predicted_family': 'Benign', 'confidence': 0.9,
                                      'probabilities': {'Benign': 0.9, 'Allaple.A': 0.1}})
        assert fam is None and score == pytest.approx(0.1)
        score, fam = static_evidence({'predicted_family': 'Allaple.A', 'confidence': 0.7,
                                      'probabilities': {'Benign': 0.2, 'Allaple.A': 0.7, 'X': 0.1}})
        assert fam == 'Allaple.A' and score == pytest.approx(0.8)

    def test_static_evidence_without_benign_class(self):
        from modules.dashboard.pages.hybrid import static_evidence
        score, fam = static_evidence({'predicted_family': 'Allaple.A', 'confidence': 0.6,
                                      'probabilities': {'Allaple.A': 0.6, 'X': 0.4}})
        assert fam == 'Allaple.A' and score == pytest.approx(0.6)
