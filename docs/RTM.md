# Requirement Traceability Matrix — MalTwin

Generated 2026-10-15 14:14 by `scripts/generate_rtm.py` from a live test run. Each automated test case ID is an `@pytest.mark.rtm` marker on a real test in `tests/`.

## Requirements → automated tests

| Requirement | Description | Status | Automated test cases | Result |
|---|---|---|---|---|
| FR1.1 | Dashboard shows operational status of all modules | Implemented | AT-M6-01, AT-M6-02, AT-UI-02 | PASS |
| FR1.2 | Cumulative detection statistics (analysed / malware / benign) | Implemented | AT-DB-04, AT-M5-11, AT-UI-02, AT-UI-06 | PASS |
| FR1.3 | Persistent sidebar navigation between all screens | Implemented | AT-UI-01 | PASS |
| FR1.4 | Feed of the most recent detection events | Implemented | AT-DB-03, AT-UI-06 | PASS |
| FR2.1 | Start/stop Digital Twin simulation | Deferred (final evaluation) | — | — |
| FR2.2 | Live Digital Twin traffic log | Deferred (final evaluation) | — | — |
| FR2.3 | Digital Twin node status panel | Deferred (final evaluation) | — | — |
| FR2.4 | Protocol traffic pie chart | Deferred (final evaluation) | — | — |
| FR3.1 | Upload PE/ELF binary (max 50 MB, magic-byte validation) | Implemented | AT-M2-03, AT-M2-04 | PASS |
| FR3.2 | Convert binary to grayscale image | Implemented | AT-M2-01, AT-M2-02 | PASS |
| FR3.3 | Show metadata incl. SHA-256 | Implemented | AT-M2-06 | PASS |
| FR3.4 | Pixel intensity histogram (256 bins) | Implemented | AT-M2-07 | PASS |
| FR5.1 | Run detection model on uploaded binary | Implemented | AT-M5-02, AT-UI-03, AT-UI-04 | PASS |
| FR5.2 | Top-1 label with colour-coded confidence | Implemented | AT-M5-03, AT-UI-04 | PASS |
| FR5.3 | Per-class probability chart | Implemented | AT-UI-04 | PASS |
| FR5.4 | Grad-CAM heatmap on request | Implemented | AT-M7-01 | PASS |
| FR5.5 | MITRE ATT&CK for ICS mapping | Implemented | AT-M8-01, AT-M8-02, AT-UI-04 | PASS |
| FR5.6 | PDF / JSON forensic report download | Implemented | AT-M8-03, AT-M8-04, AT-M8-05, AT-UI-05 | PASS |
| FR-B1 | Backend: validate, read bytes, build 2-D image | Implemented | AT-M2-01, AT-M2-02, AT-M2-08 | PASS |
| FR-B2 | Backend: load model, preprocess, forward pass | Implemented | AT-M5-01, AT-M5-02, AT-M5-06, AT-UI-04 | PASS |
| FR-B3 | Backend: log detection event to SQLite | Implemented | AT-DB-01, AT-DB-05, AT-UI-04 | PASS |
| FR-B4 | Backend: compile report with MITRE data | Implemented | AT-M8-03, AT-M8-04 | PASS |
| FR-B5 | Backend: start Digital Twin | Deferred (final evaluation) | — | — |
| FR-B6 | Backend: Grad-CAM hooks on last conv layer | Implemented | AT-M7-01, AT-M7-02, AT-M7-03 | PASS |
| REL-1 | Identical results for identical input | Implemented | AT-M2-09, AT-M5-05 | PASS |
| REL-2 | Corrupt/malformed files handled without crash | Implemented | AT-M2-04, AT-M2-05, AT-M2-10, AT-M7-03 | PASS |
| REL-4 | No detection records lost (WAL) | Implemented | AT-DB-02 | PASS |
| SEC-3 | Database file permission 600 | Implemented | AT-DB-06 | PASS |
| SEC-4 | SHA-256 computed locally | Implemented | AT-M2-06 | PASS |
| USE-3 | Errors state what, cause and action | Implemented | AT-UI-03, AT-UI-07 | PASS |
| M3-FE2 | Label encoding | Implemented | AT-M3-02 | PASS |
| M3-FE3 | Stratified train/val/test split | Implemented | AT-M3-01 | PASS |
| M3-FE4 | Dataset integrity validation | Implemented | AT-M3-03 | PASS |
| M4-FE1 | Augmentation (rotation, flip, brightness) | Implemented | AT-M4-01 | PASS |
| M4-FE2 | Gaussian noise injection | Implemented | AT-M4-02 | PASS |
| M4-FE3 | Class-aware oversampling | Implemented | AT-M4-03, AT-M4-04 | PASS |
| M5-FE2 | Configurable CNN training | Implemented | AT-M5-04 | PASS |
| M5-FE3 | Evaluation metrics incl. ROC-AUC, FPR, unseen-family | Implemented | AT-M5-07, AT-M5-08 | PASS |
| M5-FE5 | Model serialisation | Implemented | AT-M5-05 | PASS |
| M5-BEN | Benign class and benign false-positive evaluation | Implemented | AT-M5-09, AT-M5-10, AT-M5-11 | PASS |
| M9-1 | Parse Zeek / IoT-23 conn.log | Implemented | AT-M9-01, AT-M9-02 | PASS |
| M9-2 | IP-free behavioural flow features | Implemented | AT-M9-03 | PASS |
| M9-3 | Behaviour classification model | Implemented | AT-M9-04, AT-M9-07 | PASS |
| M9-4 | Capture-level verdict | Implemented | AT-M9-05, AT-M9-06 | PASS |
| M9-5 | Feature-importance explanation | Implemented | AT-M9-05 | PASS |
| M9-6 | MITRE ATT&CK for ICS per behaviour | Implemented | AT-M9-05 | PASS |
| M9-7 | Dynamic Analysis dashboard page | Implemented | AT-UI-07 | PASS |
| M10-1 | Decision-level fusion with agreement categories | Implemented | AT-M10-01, AT-M10-02 | PASS |
| M10-2 | Combined MITRE mapping tagged by source | Implemented | AT-M10-03 | PASS |
| M10-3 | Hybrid Verdict page and what-if simulator | Implemented | AT-UI-08 | PASS |
| M1-DESIGN | Digital Twin design page and prerequisite checks | Implemented (design only) | AT-UI-09 | PASS |

## Automated test cases → code

| Test ID | Requirements | Test function | Cases | Result |
|---|---|---|---|---|
| AT-DB-01 | FR-B3 | `tests/test_db.py::TestLogDetectionEvent::test_stored_sha256_matches` | 1 | PASS |
| AT-DB-02 | REL-4 | `tests/test_db.py::TestInitDb::test_wal_mode_enabled` | 1 | PASS |
| AT-DB-03 | FR1.4 | `tests/test_db.py::TestGetRecentEvents::test_limit_parameter` | 1 | PASS |
| AT-DB-04 | FR1.2 | `tests/test_db.py::TestGetDetectionStats::test_total_analyzed_increments` | 1 | PASS |
| AT-DB-05 | FR-B3 | `tests/test_db.py::TestLogDetectionEvent::test_never_raises_on_bad_confidence` | 1 | PASS |
| AT-DB-06 | SEC-3 | `tests/test_db.py::test_database_file_permission_is_owner_only` | 1 | PASS |
| AT-M10-01 | M10-1 | `tests/test_fusion.py::TestDecisionTable::test_cases` | 6 | PASS |
| AT-M10-02 | M10-1 | `tests/test_fusion.py::TestValidation::test_out_of_range` | 2 | PASS |
| AT-M10-03 | M10-2 | `tests/test_fusion.py::TestMitreMerge::test_corroborated_first_and_tagged` | 1 | PASS |
| AT-M2-01 | FR-B1, FR3.2 | `tests/test_converter.py::TestBinaryConverterOutputShape::test_pe_returns_128x128` | 1 | PASS |
| AT-M2-02 | FR-B1, FR3.2 | `tests/test_converter.py::TestBinaryConverterOutputShape::test_elf_returns_128x128` | 1 | PASS |
| AT-M2-03 | FR3.1 | `tests/test_converter.py::TestValidateBinaryFormat::test_accepts_pe` | 1 | PASS |
| AT-M2-04 | FR3.1, REL-2 | `tests/test_converter.py::TestValidateBinaryFormat::test_rejects_invalid` | 1 | PASS |
| AT-M2-05 | REL-2 | `tests/test_converter.py::TestValidateBinaryFormat::test_rejects_empty_bytes` | 1 | PASS |
| AT-M2-06 | FR3.3, SEC-4 | `tests/test_converter.py::TestComputeSha256::test_matches_reference_hash` | 1 | PASS |
| AT-M2-07 | FR3.4 | `tests/test_converter.py::TestHistogram::test_counts_sum_to_total_pixels` | 1 | PASS |
| AT-M2-08 | FR-B1 | `tests/test_converter.py::TestMalimgLayout::test_malimg_layout_matches_reference_pipeline` | 1 | PASS |
| AT-M2-09 | REL-1 | `tests/test_converter.py::TestBinaryConverterDeterminism::test_same_bytes_same_output` | 1 | PASS |
| AT-M2-10 | REL-2 | `tests/test_converter.py::TestMalimgLayout::test_tiny_file_does_not_crash` | 1 | PASS |
| AT-M3-01 | M3-FE3 | `tests/test_dataset.py::TestMalimgDataset::test_splits_sum_to_total` | 1 | PASS |
| AT-M3-02 | M3-FE2 | `tests/test_dataset.py::TestLabelEncoding::test_encode_indices_are_contiguous` | 1 | PASS |
| AT-M3-03 | M3-FE4 | `tests/test_dataset.py::TestMalimgDataset::test_missing_dir_raises` | 1 | PASS |
| AT-M4-01 | M4-FE1 | `tests/test_enhancement.py::TestTrainTransforms::test_augmentation_produces_variation` | 1 | PASS |
| AT-M4-02 | M4-FE2 | `tests/test_enhancement.py::TestGaussianNoise::test_nonzero_noise_modifies_tensor` | 1 | PASS |
| AT-M4-03 | M4-FE3 | `tests/test_enhancement.py::TestClassAwareOversampler::test_minority_weight_greater_than_majority` | 1 | PASS |
| AT-M4-04 | M4-FE3 | `tests/test_enhancement.py::TestClassAwareOversampler::test_invalid_strategy_raises` | 1 | PASS |
| AT-M5-01 | FR-B2 | `tests/test_model.py::TestForwardPassShape::test_output_shape_batch2` | 1 | PASS |
| AT-M5-02 | FR5.1, FR-B2 | `tests/test_model.py::TestInferenceHelpers::test_predict_single_has_required_keys` | 1 | PASS |
| AT-M5-03 | FR5.2 | `tests/test_model.py::TestInferenceHelpers::test_predict_confidence_in_zero_one` | 1 | PASS |
| AT-M5-04 | M5-FE2 | `tests/test_model.py::TestTrainingBehaviour::test_loss_decreases_on_overfit_single_batch` | 1 | PASS |
| AT-M5-05 | M5-FE5, REL-1 | `tests/test_model.py::TestModelSerialization::test_save_and_reload_same_output` | 1 | PASS |
| AT-M5-06 | FR-B2 | `tests/test_model.py::TestLoadModel::test_load_model_raises_helpful_error_for_unknown_checkpoint_keys` | 1 | PASS |
| AT-M5-07 | M5-FE3 | `tests/test_evaluation_extended.py::TestExtendedMetrics::test_per_class_fpr_matches_hand_calculation` | 1 | PASS |
| AT-M5-08 | M5-FE3 | `tests/test_evaluation_extended.py::TestOpenSet::test_perfect_separation` | 1 | PASS |
| AT-M5-09 | M5-BEN | `tests/test_benign.py::TestEvaluateOnBenign::test_without_benign_class_everything_is_flagged` | 1 | PASS |
| AT-M5-10 | M5-BEN | `tests/test_benign.py::TestBuildBenignClass::test_writes_malimg_format_pngs_and_manifest` | 1 | PASS |
| AT-M5-11 | FR1.2, M5-BEN | `tests/test_benign.py::TestDashboardWiring::test_stats_count_benign` | 1 | PASS |
| AT-M6-01 | FR1.1 | `tests/test_health.py::TestGetAllModuleStatuses::test_module_ids_are_m1_through_m10` | 1 | PASS |
| AT-M6-02 | FR1.1 | `tests/test_health.py::TestGetAllModuleStatuses::test_does_not_raise` | 1 | PASS |
| AT-M7-01 | FR5.4, FR-B6 | `tests/test_gradcam.py::TestGenerateGradcam::test_heatmap_array_range` | 1 | PASS |
| AT-M7-02 | FR-B6 | `tests/test_gradcam.py::TestGenerateGradcam::test_uses_model_gradcam_layer_attribute` | 1 | PASS |
| AT-M7-03 | FR-B6, REL-2 | `tests/test_gradcam.py::TestGenerateGradcam::test_returns_none_on_bad_target_class` | 1 | PASS |
| AT-M8-01 | FR5.5 | `tests/test_reporting.py::TestMitreMapper::test_all_25_families_present` | 1 | PASS |
| AT-M8-02 | FR5.5 | `tests/test_reporting.py::TestMitreMapper::test_get_mitre_mapping_unknown_family` | 1 | PASS |
| AT-M8-03 | FR5.6, FR-B4 | `tests/test_reporting.py::TestJsonReport::test_contains_mitre_section` | 1 | PASS |
| AT-M8-04 | FR5.6, FR-B4 | `tests/test_reporting.py::TestPdfReport::test_output_starts_with_pdf_magic` | 1 | PASS |
| AT-M8-05 | FR5.6 | `tests/test_reporting.py::TestPdfReport::test_does_not_raise_on_bad_input` | 1 | PASS |
| AT-M9-01 | M9-1 | `tests/test_dynamic.py::TestParser::test_iot23_space_separated_tail` | 1 | PASS |
| AT-M9-02 | M9-1 | `tests/test_dynamic.py::TestParser::test_empty_file_raises` | 1 | PASS |
| AT-M9-03 | M9-2 | `tests/test_dynamic.py::TestFeatures::test_no_ip_features` | 1 | PASS |
| AT-M9-04 | M9-3 | `tests/test_dynamic.py::TestDetector::test_learns_synthetic_behaviours` | 1 | PASS |
| AT-M9-05 | M9-4, M9-5, M9-6 | `tests/test_dynamic.py::TestDetector::test_malicious_capture_verdict_and_mitre` | 1 | PASS |
| AT-M9-06 | M9-4 | `tests/test_dynamic.py::TestDetector::test_benign_capture_verdict` | 1 | PASS |
| AT-M9-07 | M9-3 | `tests/test_dynamic.py::TestDetector::test_untrained_raises` | 1 | PASS |
| AT-UI-01 | FR1.3 | `tests/test_ui.py::test_every_page_reachable_from_sidebar` | 1 | PASS |
| AT-UI-02 | FR1.1, FR1.2 | `tests/test_ui.py::test_dashboard_shows_module_status_and_kpis` | 1 | PASS |
| AT-UI-03 | USE-3, FR5.1 | `tests/test_ui.py::test_detection_without_upload_shows_guidance` | 1 | PASS |
| AT-UI-04 | FR5.1, FR5.2, FR5.3, FR5.5, FR-B2, FR-B3 | `tests/test_ui.py::test_run_detection_end_to_end` | 1 | PASS |
| AT-UI-05 | FR5.6 | `tests/test_ui.py::test_report_section_offers_pdf_and_json` | 1 | PASS |
| AT-UI-06 | FR1.4, FR1.2 | `tests/test_ui.py::test_detection_appears_in_dashboard_history` | 1 | PASS |
| AT-UI-07 | M9-7, USE-3 | `tests/test_ui.py::test_dynamic_page_without_model_explains_how_to_train` | 1 | PASS |
| AT-UI-08 | M10-3 | `tests/test_ui.py::test_hybrid_whatif_simulator_flags_novel_variant` | 1 | PASS |
| AT-UI-09 | M1-DESIGN | `tests/test_ui.py::test_digital_twin_page_reports_status` | 1 | PASS |

## Summary

- Automated test cases in RTM: **63** (69 executions incl. parameters)
- Passed: **63**, failed: **0**, skipped: **0**
- Implemented requirements covered by at least one automated test: **46 / 46**
- Deferred requirements (Digital Twin): FR2.1, FR2.2, FR2.3, FR2.4, FR-B5
