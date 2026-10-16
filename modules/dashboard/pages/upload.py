# modules/dashboard/pages/upload.py
"""
Binary Upload & Visualization page.
Implements SRS Mockup M3 — Binary Upload and Visualization Screen.
SRS refs: FR3.1, FR3.2, FR3.3, FR3.4, UC-01
"""
import streamlit as st
import plotly.graph_objects as go
import numpy as np

import config
from modules.binary_to_image.converter import BinaryConverter
from modules.binary_to_image.utils import (
    validate_binary_format,
    compute_pixel_histogram,
    get_file_metadata,
    compute_sha256,
)
from modules.dashboard import state
from modules.dashboard.theme import image_full_width
from modules.dashboard.theme import mono

def render():
    from modules.dashboard.theme import apply_theme, COLORS, section_header, mono, status_badge, confidence_bar_html, kpi_card
    apply_theme()
    st.title("Binary Upload")
    st.markdown(
        "Upload a PE (.exe, .dll) or ELF binary file to convert it into a grayscale "
        "image for analysis. The image captures the structural byte patterns of the "
        "binary and is used as input to the malware detection model."
    )
    st.markdown("---")

    tab_bin, tab_test = st.tabs(["Upload binary", "Malimg test-set sample"])
    with tab_test:
        _render_test_sample_picker()

    # ── File uploader ─────────────────────────────────────────────────────────
    # SRS ref: FR3.1
    with tab_bin:
        uploaded_file = st.file_uploader(
            label="Upload Binary File",
            type=["exe", "dll", "elf"],
            help=(
                "Accepted formats: PE (.exe, .dll) or ELF (.elf) binaries. "
                "ELF binaries from Linux/IIoT systems have no extension by default — "
                "rename them to .elf before uploading (e.g. mv malware malware.elf). "
                f"Maximum file size: {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB. "
                "Format is validated by magic bytes, not extension."
            ),
            key="binary_uploader",
        )

        with st.expander("ℹ️ Uploading ELF binaries (Linux/IIoT malware)", expanded=False):
            st.markdown(
                "ELF binaries from Linux-based IIoT devices (PLCs, routers, embedded systems) "
                "typically have no file extension. To upload them:\n\n"
                "1. Rename the file to add a `.elf` extension:\n"
                "   ```bash\n"
                "   mv suspicious_binary suspicious_binary.elf\n"
                "   ```\n"
                "2. Upload the renamed file using the uploader above.\n\n"
                "The system validates format using ELF magic bytes (`\\x7fELF`), "
                "not the file extension — the extension is only required by the browser file picker."
            )

    if uploaded_file is not None:
        _process_upload(uploaded_file)

    if state.has_uploaded_file():
        st.success(
            "✅ File processed successfully. "
            "Navigate to **Malware Detection** in the sidebar to analyze."
        )
        _render_results()
    elif uploaded_file is None:
        st.info("👆 Upload a binary file, or pick a Malimg test-set sample, to begin.")


@st.cache_data(ttl=600, show_spinner=False)
def _test_split_index(data_dir: str) -> dict[str, list[str]]:
    """Family -> image paths in the held-out TEST split (same seed and ratios as
    training), so a demo never shows the model an image it was trained on."""
    from pathlib import Path
    from modules.dataset.loader import MalimgDataset
    ds = MalimgDataset(Path(data_dir), split='test', img_size=config.IMG_SIZE,
                       train_ratio=config.TRAIN_RATIO, val_ratio=config.VAL_RATIO,
                       test_ratio=config.TEST_RATIO, random_seed=config.RANDOM_SEED)
    index: dict[str, list[str]] = {}
    for path, label in ds.samples:
        index.setdefault(ds.class_names[label], []).append(str(path))
    return {k: sorted(v) for k, v in sorted(index.items())}


def _render_test_sample_picker() -> None:
    """Load an image from the held-out Malimg test split as the current sample.
    Malimg is distributed as images only (no executables), so this is how the
    detector is demonstrated on real malware without handling live binaries."""
    from pathlib import Path
    st.caption(
        "Malimg ships the malware as images, not executables. These images come from the "
        "held-out test split (15%), which the model never saw during training."
    )
    if not Path(config.DATA_DIR).exists():
        st.info(f"Malimg dataset not found at `{config.DATA_DIR}`.")
        return
    try:
        index = _test_split_index(str(config.DATA_DIR))
    except Exception as e:
        st.error(f"Error: Could not read the test split. Cause: {e}. "
                 "Action: Check that data/malimg has one folder per family.")
        return
    c1, c2 = st.columns([2, 3])
    family = c1.selectbox("True family", list(index.keys()), key="test_family")
    files = index[family]
    pick = c2.selectbox(f"Test image ({len(files)} in test split)", files,
                        format_func=lambda p: Path(p).name, key="test_file")
    if st.button("Load this sample", type="primary", key="test_load"):
        _load_test_sample(Path(pick), family)


def _load_test_sample(path, family: str) -> None:
    import cv2
    from datetime import datetime, timezone
    raw = path.read_bytes()
    img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None:
        st.error(f"Error: Could not read image. Cause: {path.name} is not a valid PNG. "
                 "Action: Pick another sample.")
        return
    # Same resize as the training/evaluation loader
    img = cv2.resize(img, (config.IMG_SIZE, config.IMG_SIZE), interpolation=cv2.INTER_LINEAR)
    state.clear_file_state()
    size = len(raw)
    st.session_state[state.KEY_IMG_ARRAY] = img.astype(np.uint8)
    st.session_state[state.KEY_FILE_META] = {
        'name':        f"{family}/{path.name}",
        'size_bytes':  size,
        'size_human':  f"{size / 1024:.2f} KB" if size >= 1024 else f"{size:.2f} B",
        'format':      'PE',            # every Malimg sample is a Windows PE
        'sha256':      compute_sha256(raw),
        'upload_time': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        'source':      'malimg_test',
        'true_family': family,
    }
    st.rerun()


def _process_upload(uploaded_file) -> None:
    """
    Reads, validates, and converts the uploaded file.
    Stores img_array and file_meta in session_state.
    Clears previous state before processing a new file.

    Error messages follow SRS USE-3 format:
        "Error: [what]. Cause: [why]. Action: [what to do]."
    """
    file_bytes = uploaded_file.read()

    # ── Size check ────────────────────────────────────────────────────────────
    if len(file_bytes) > config.MAX_UPLOAD_BYTES:
        size_mb = len(file_bytes) // (1024 * 1024)
        st.error(
            f"Error: File too large. "
            f"Cause: File exceeds the 50 MB limit (uploaded: {size_mb} MB). "
            "Action: Upload a smaller binary file."
        )
        return

    # Streamlit re-runs this page on every interaction while the uploader still
    # holds the file. Skip files we have already processed (same SHA-256) so a
    # rerun does not wipe the detection result for the current file.
    # Also skip when the analyst has since loaded a test-set sample: the uploader
    # keeps the old file, and re-processing it would replace their sample.
    sha = compute_sha256(file_bytes)
    if st.session_state.get('last_upload_sha256') == sha:
        return
    st.session_state['last_upload_sha256'] = sha

    # Clear stale results from any previous upload
    state.clear_file_state()

    # ── Format validation ─────────────────────────────────────────────────────
    try:
        file_format = validate_binary_format(file_bytes)
    except ValueError as e:
        st.error(
            "Error: Unsupported file format. "
            f"Cause: {e} "
            "Action: Upload a valid PE (.exe, .dll) or ELF binary file."
        )
        return

    # ── Conversion ────────────────────────────────────────────────────────────
    try:
        converter = BinaryConverter(img_size=config.IMG_SIZE)
        img_array = converter.convert(file_bytes)
    except ValueError as e:
        st.error(
            "Error: Binary too small to convert. "
            f"Cause: {e} "
            "Action: Upload a valid binary file of at least 64 bytes."
        )
        return
    except Exception as e:
        st.error(
            "Error: Conversion failed. "
            f"Cause: {e} "
            "Action: Ensure the file is a valid PE or ELF binary and try again."
        )
        return

    # ── Store in session state ────────────────────────────────────────────────
    st.session_state[state.KEY_IMG_ARRAY] = img_array
    st.session_state[state.KEY_FILE_META] = get_file_metadata(
        file_bytes, uploaded_file.name, file_format
    )
    # Re-run once so the sidebar (drawn before this page) shows the new file
    st.rerun()


def _render_results() -> None:
    """
    Display the grayscale image, metadata table, and pixel intensity histogram.
    Called when session_state has a processed image.
    """
    img_array = st.session_state[state.KEY_IMG_ARRAY]
    meta      = st.session_state[state.KEY_FILE_META]

    col_left, col_right = st.columns(2)

    # ── Left: Grayscale image ─────────────────────────────────────────────────
    with col_left:
        st.subheader("Grayscale Visualization")
        converter = BinaryConverter(img_size=config.IMG_SIZE)
        png_bytes = converter.to_png_bytes(img_array)
        image_full_width(
            png_bytes,
            caption=f"Grayscale visualization ({config.IMG_SIZE}×{config.IMG_SIZE} pixels, 8-bit)",
        )

    # ── Right: Metadata + Histogram ───────────────────────────────────────────
    with col_right:
        st.subheader("File Metadata")
        meta_table = {
            "Property": ["File Name", "File Size", "Format", "SHA-256", "Upload Time"],
            "Value":    [
                meta['name'],
                meta['size_human'],
                meta['format'],
                meta['sha256'],
                meta['upload_time'],
            ],
        }
        if meta.get('source') == 'malimg_test':
            meta_table["Property"].append("Source")
            meta_table["Value"].append(f"Malimg test split (true family: {meta['true_family']})")
        st.table(meta_table)

        # SHA-256 in monospace for easy copying
        st.markdown("**SHA-256 (copy):**")
        st.markdown(mono(meta['sha256']), unsafe_allow_html=True)

        # Pixel intensity histogram
        st.subheader("Pixel Intensity Distribution")
        hist = compute_pixel_histogram(img_array)
        fig = go.Figure(go.Bar(
            x=hist['bins'],
            y=hist['counts'],
            marker_color='#4A90D9',
            name='Byte frequency',
        ))
        fig.update_layout(
            xaxis_title="Byte Value (0–255)",
            yaxis_title="Pixel Count",
            height=300,
            showlegend=False,
        )
        from modules.dashboard.theme import apply_chart_theme
        apply_chart_theme(fig, title='Pixel Intensity Distribution (256 bins)')
        st.plotly_chart(fig, use_container_width=True)

    st.info("➡️ Navigate to **Malware Detection** in the sidebar to run analysis.")
