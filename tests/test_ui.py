# tests/test_ui.py
"""
Automated UI tests for the Streamlit dashboard (functional requirements FR1.x,
FR3.x, FR5.x, USE-3 and the M9/M10 pages).

Uses Streamlit's own headless test runner (streamlit.testing.v1.AppTest), which
executes the real app script, lets the test click buttons / change the sidebar,
and inspects the rendered elements — no browser needed, so it runs in CI.

Each test runs against an isolated temporary environment (model, class list,
SQLite log) so it never touches the developer's real data.
"""
import json

import numpy as np
import pytest
import torch  # imported in the main thread first: importing it inside the
              # app's script thread is very slow and makes AppTest time out

pytest.importorskip("streamlit.testing.v1")
from streamlit.testing.v1 import AppTest  # noqa: E402

import config  # noqa: E402
from modules.dashboard import state  # noqa: E402

APP = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "modules" / "dashboard" / "app.py")
CLASSES = ["Allaple.A", "Benign", "Yuner.A"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Tiny trained-model stand-in + empty DB in a temp folder; config patched to use them."""
    from modules.detection.model import MalTwinCNN
    from modules.dataset.preprocessor import save_class_names
    from modules.dashboard.db import init_db

    models, processed, logs = tmp_path / "models", tmp_path / "processed", tmp_path / "logs"
    for d in (models, processed, logs):
        d.mkdir()
    torch.manual_seed(0)
    net = MalTwinCNN(num_classes=len(CLASSES))
    with torch.no_grad():                       # make the prediction deterministic:
        net.classifier[-1].bias.copy_(torch.tensor([10.0, 0.0, 0.0]))   # → Allaple.A
    torch.save(net.state_dict(), models / "best_model.pt")
    save_class_names(CLASSES, processed / "class_names.json")
    with open(processed / "eval_metrics.json", "w") as f:
        json.dump({"accuracy": 0.97}, f)

    for name, val in {
        "MODEL_DIR": models, "BEST_MODEL_PATH": models / "best_model.pt",
        "PROCESSED_DIR": processed, "CLASS_NAMES_PATH": processed / "class_names.json",
        "EVAL_METRICS_PATH": processed / "eval_metrics.json",
        "LOG_DIR": logs, "DB_PATH": logs / "maltwin.db",
        "DYNAMIC_MODEL_PATH": models / "dynamic_model.joblib",
        "DYNAMIC_METRICS_PATH": processed / "dynamic_metrics.json",
        "DATA_DIR": tmp_path / "no_dataset",
    }.items():
        monkeypatch.setattr(config, name, val)
    init_db(config.DB_PATH)
    return tmp_path


def _run(at=None, page=None, **session):
    fresh = at is None
    at = at or AppTest.from_file(APP, default_timeout=120)
    for k, v in session.items():
        at.session_state[k] = v
    if page:
        if fresh:                       # first run needed to create the sidebar
            at.run()
            for k, v in session.items():
                at.session_state[k] = v
        at.sidebar.radio[0].set_value(page)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def _text(at) -> str:
    parts = [m.value for m in at.markdown] + [c.value for c in at.caption]
    parts += [e.value for e in at.error] + [w.value for w in at.warning]
    parts += [s.value for s in at.success] + [i.value for i in at.info]
    parts += [h.value for h in at.subheader] + [t.value for t in at.title]
    return "\n".join(str(p) for p in parts)


def _uploaded_pe():
    from modules.binary_to_image.converter import BinaryConverter
    from modules.binary_to_image.utils import get_file_metadata
    rng = np.random.default_rng(1)
    data = b"MZ" + rng.integers(0, 256, 30 * 1024, dtype=np.uint8).tobytes()
    return {state.KEY_IMG_ARRAY: BinaryConverter().convert(data),
            state.KEY_FILE_META: get_file_metadata(data, "sample.exe", "PE")}


@pytest.mark.rtm("AT-UI-01", "FR1.3")
def test_every_page_reachable_from_sidebar(env):
    at = _run()
    pages = at.sidebar.radio[0].options
    assert len(pages) == 8
    for p in pages:
        at.sidebar.radio[0].set_value(p).run()
        assert not at.exception, (p, [e.value for e in at.exception])


@pytest.mark.rtm("AT-UI-02", "FR1.1", "FR1.2")
def test_dashboard_shows_module_status_and_kpis(env):
    at = _run()
    txt = _text(at)
    for kpi in ("Total Analyzed", "Malware Detected", "Benign Files", "Model Accuracy"):
        assert kpi.lower() in txt.lower()
    assert "97.0%" in txt                       # model accuracy read from eval_metrics.json
    status_tables = [d.value for d in at.dataframe if "M10" in d.value.to_string()]
    assert status_tables, "module status table with M1–M10 not shown"


@pytest.mark.rtm("AT-UI-03", "USE-3", "FR5.1")
def test_detection_without_upload_shows_guidance(env):
    at = _run(page="Malware Detection")
    assert "upload a file on the **Binary Upload** page" in _text(at)
    assert not [b for b in at.button if "Run Detection" in b.label]


@pytest.mark.rtm("AT-UI-04", "FR5.1", "FR5.2", "FR5.3", "FR5.5", "FR-B2", "FR-B3")
def test_run_detection_end_to_end(env):
    from modules.dashboard.db import get_detection_stats
    at = _run(page="Malware Detection", **_uploaded_pe())
    [btn] = [b for b in at.button if "Run Detection" in b.label]
    btn.click().run()
    assert not at.exception, [e.value for e in at.exception]
    txt = _text(at)
    assert "Detected: Allaple.A" in txt                       # FR5.2 top-1 label
    assert "Class Probability Distribution" in txt            # FR5.3 chart section
    assert "MITRE ATT&CK" in txt                               # FR5.5 mapping section
    assert at.session_state[state.KEY_DETECTION]["predicted_family"] == "Allaple.A"
    stats = get_detection_stats(config.DB_PATH)               # FR-B3 logged to SQLite
    assert stats["total_analyzed"] == 1 and stats["total_malware"] == 1


@pytest.mark.rtm("AT-UI-05", "FR5.6")
def test_report_section_offers_pdf_and_json(env):
    at = _run(page="Malware Detection", **_uploaded_pe())
    [b for b in at.button if "Run Detection" in b.label][0].click().run()
    assert "Forensic Report" in _text(at)
    labels = [b.label for b in at.button]
    assert any("Generate PDF Report" in l for l in labels)
    pdf = [b for b in at.button if "Generate PDF Report" in b.label][0]
    pdf.click().run()
    assert not at.exception and not [e for e in at.error if "PDF generation failed" in e.value]
    from modules.dashboard.db import get_connection           # report linked to its detection
    with get_connection(config.DB_PATH) as conn:
        rows = conn.execute("SELECT report_format, detection_event_id FROM report_events").fetchall()
    assert [(r[0], r[1]) for r in rows] == [("PDF", at.session_state[state.KEY_DETECTION_EVENT_ID])]
    assert rows[0][1] is not None


@pytest.mark.rtm("AT-UI-06", "FR1.4", "FR1.2")
def test_detection_appears_in_dashboard_history(env):
    at = _run(page="Malware Detection", **_uploaded_pe())
    [b for b in at.button if "Run Detection" in b.label][0].click().run()
    at.sidebar.radio[0].set_value("Dashboard").run()
    assert not at.exception
    recent = [d.value for d in at.dataframe if "sample.exe" in d.value.to_string()]
    assert recent, "recent detections feed does not list the analysed file"


@pytest.mark.rtm("AT-UI-07", "FR6.7", "USE-3")
def test_dynamic_page_without_model_explains_how_to_train(env):
    at = _run(page="Dynamic Analysis")
    assert "No dynamic model available" in _text(at)


@pytest.mark.rtm("AT-UI-08", "FR7.3")
def test_hybrid_whatif_simulator_flags_novel_variant(env):
    at = _run(page="Hybrid Verdict")
    # default sliders: static 0.30, dynamic 0.85 → NOVEL VARIANT, SUSPICIOUS
    txt = _text(at)
    assert "SUSPICIOUS" in txt and "NOVEL VARIANT" in txt


@pytest.mark.rtm("AT-UI-09", "FR2.7")
def test_digital_twin_page_reports_status(env):
    at = _run(page="Digital Twin")
    txt = _text(at)
    assert "implementation is scheduled" in txt and "Deployment prerequisites".upper() in txt.upper()


@pytest.mark.rtm("AT-UI-10", "FR1.7")
def test_sidebar_shows_model_and_file_status(env):
    at = _run(page="Binary Upload", **_uploaded_pe())
    side = "\n".join(str(m.value) for m in at.sidebar.markdown)
    assert "Model loaded" in side
    assert "sample.exe" in side                       # the uploaded file is named in the sidebar
    assert "No Malimg dataset" in side                # DATA_DIR points to a missing folder


@pytest.mark.rtm("AT-UI-11", "FR1.6", "FR1.5")
def test_history_offers_csv_export(env):
    at = _run(page="Malware Detection", **_uploaded_pe())
    [b for b in at.button if "Run Detection" in b.label][0].click().run()
    at.sidebar.radio[0].set_value("Dashboard").run()
    assert not at.exception
    downloads = at.get("download_button")
    assert any("Export to CSV" in str(d.proto) for d in downloads), "CSV export button missing"


@pytest.mark.rtm("AT-UI-12", "FR5.8", "FR1.2")
def test_benign_prediction_is_shown_as_benign(env):
    from modules.detection.model import MalTwinCNN
    from modules.dashboard.db import get_detection_stats
    torch.manual_seed(0)
    net = MalTwinCNN(num_classes=len(CLASSES))
    with torch.no_grad():                                   # bias the output towards "Benign"
        net.classifier[-1].bias.copy_(torch.tensor([0.0, 10.0, 0.0]))
    torch.save(net.state_dict(), config.BEST_MODEL_PATH)
    at = _run(page="Malware Detection", **_uploaded_pe())
    [b for b in at.button if "Run Detection" in b.label][0].click().run()
    assert not at.exception, [e.value for e in at.exception]
    txt = _text(at)
    assert "classified **Benign**" in txt
    assert "No MITRE ATT&CK techniques" in txt
    stats = get_detection_stats(config.DB_PATH)
    assert stats["total_benign"] == 1 and stats["total_malware"] == 0
