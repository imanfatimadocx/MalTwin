# Requirement Traceability Matrix — MalTwin

Generated 2026-10-16 21:25 by `scripts/generate_rtm.py` from a live test run. Each automated test case ID is an `@pytest.mark.rtm` marker on a real test in `tests/`.

## Requirements → automated tests

| Requirement | Description | Status | Verification | Automated test cases | Result |
|---|---|---|---|---|---|
| FR1.1 | The system shall display the operational status (active or inactive) of all ten modules on the main dashboard. | Implemented | Test | AT-M6-01, AT-M6-02, AT-UI-02 | PASS |
| FR1.2 | The system shall display cumulative detection statistics: total files analysed, malware detected, benign files and model accuracy. | Implemented | Test | AT-DB-04, AT-M5-11, AT-UI-02, AT-UI-06, AT-UI-12 | PASS |
| FR1.3 | The system shall provide persistent sidebar navigation to every screen. | Implemented | Test | AT-UI-01 | PASS |
| FR1.4 | The system shall display a feed of the most recent detection events. | Implemented | Test | AT-DB-03, AT-UI-06 | PASS |
| FR1.5 | The system shall let the user filter the detection history by malware family, minimum confidence and date range, and sort it by time. | Implemented | Test | AT-M6-03, AT-M6-04, AT-UI-11 | PASS |
| FR1.6 | The system shall let the user export the filtered detection history as a CSV file. | Implemented | Test | AT-UI-11 | PASS |
| FR1.7 | The system shall show in the sidebar whether a model is loaded, whether the dataset is available and which file is currently uploaded. | Implemented | Test | AT-UI-10 | PASS |
| FR2.1 | The system shall let the user start and stop the Digital Twin IIoT simulation from the dashboard. | Deferred (final evaluation) | Deferred | — | — |
| FR2.2 | The system shall display a live log of the traffic exchanged between simulated IIoT nodes. | Deferred (final evaluation) | Deferred | — | — |
| FR2.3 | The system shall display the status of each simulated node (PLC, HMI, sensor, sandbox). | Deferred (final evaluation) | Deferred | — | — |
| FR2.4 | The system shall display a chart of simulated traffic by protocol (Modbus, MQTT, other). | Deferred (final evaluation) | Deferred | — | — |
| FR2.5 | The system shall execute each sample inside an isolated container network with no route to the host's network. | Deferred (final evaluation) | Deferred | — | — |
| FR2.6 | The system shall capture the network traffic of each simulation run and export it as a Zeek conn.log for dynamic analysis. | Deferred (final evaluation) | Deferred | — | — |
| FR2.7 | The system shall show the planned Digital Twin architecture and live checks of its deployment prerequisites (Docker, Zeek, behaviour model). | Implemented (design only) | Test | AT-UI-09 | PASS |
| FR3.1 | The system shall accept PE and ELF binaries of up to 50 MB, identified by their magic bytes (MZ or 0x7F ELF). | Implemented | Test | AT-M2-03, AT-M2-04 | PASS |
| FR3.2 | The system shall convert an accepted binary into a 128 × 128 grayscale image and display it within 3 seconds. | Implemented | Test | AT-M2-01, AT-M2-02 | PASS |
| FR3.3 | The system shall display the file's metadata: name, size, format and SHA-256 hash. | Implemented | Test | AT-M2-06 | PASS |
| FR3.4 | The system shall display a 256-bin pixel intensity histogram of the image. | Implemented | Test | AT-M2-07 | PASS |
| FR3.5 | The system shall reject an empty, oversized or non-PE/ELF file with an error message that states what happened, its cause and the action to take. | Implemented | Test | AT-M2-04, AT-M2-05 | PASS |
| FR3.6 | The system shall lay out the bytes using the Malimg (Nataraj) file-size width table before resizing, so that uploaded binaries match the training images. | Implemented | Test | AT-M2-08 | PASS |
| FR4.1 | The system shall load the Malimg dataset (one folder per family) and validate its integrity, reporting corrupt images, class counts and the imbalance ratio. | Implemented | Test | AT-M3-03 | PASS |
| FR4.2 | The system shall encode family labels as contiguous integer indices and normalise pixel values before training. | Implemented | Test | AT-M3-02 | PASS |
| FR4.3 | The system shall split the dataset into stratified training, validation and test sets (70 / 15 / 15) with a fixed random seed. | Implemented | Test | AT-M3-01 | PASS |
| FR4.4 | The system shall provide optional augmentation of training images with random rotation, flips and brightness changes (disabled by default after the Evaluation 3 ablation showed it lowers accuracy on byte images). | Implemented | Test | AT-M4-01 | PASS |
| FR4.5 | The system shall provide optional Gaussian-noise injection into training images, as part of the augmentation option. | Implemented | Test | AT-M4-02 | PASS |
| FR4.6 | The system shall balance the training data with class-aware oversampling so that every family is drawn with equal probability in each epoch. | Implemented | Test | AT-M4-03, AT-M4-04 | PASS |
| FR4.7 | The system shall display a dataset gallery with sample images and the number of images per family. | Implemented | Test | AT-M4-05, AT-M4-06 | PASS |
| FR4.8 | The system shall train the CNN with configurable epochs, learning rate, batch size, oversampling strategy and augmentation on/off, from the dashboard or the command line. | Implemented | Test | AT-M5-04 | PASS |
| FR4.9 | The system shall display training progress and log output while training runs, and allow the user to stop it. | Implemented | Test | AT-M5-14, AT-M5-15, AT-M5-16 | PASS |
| FR4.10 | The system shall save the best model weights (by validation accuracy) and the class list, and reload them for inference. | Implemented | Test | AT-M5-05 | PASS |
| FR4.11 | The system shall evaluate the model on the held-out test set and report accuracy, precision, recall, F1, the confusion matrix, ROC-AUC, per-class false positive rate and MCC. | Implemented | Test | AT-M5-07, AT-M5-13 | PASS |
| FR4.12 | The system shall report results on a class-balanced test set (equal samples per family, repeated random draws) together with balanced accuracy. | Implemented | Test | AT-M5-12, AT-M5-13 | PASS |
| FR4.13 | The system shall measure detection of families not seen in training with a leave-families-out experiment. | Implemented | Test | AT-M5-08 | PASS |
| FR4.14 | The system shall include a Benign class built from clean system binaries and measure the false positive rate on clean files. | Implemented | Test | AT-M5-09, AT-M5-10 | PASS |
| FR5.1 | The system shall run the detection model on the uploaded binary when the user requests it. | Implemented | Test | AT-M5-02, AT-UI-03, AT-UI-04 | PASS |
| FR5.2 | The system shall display the top-1 family with a confidence bar coloured green (≥ 80%), amber (50–79%) or red (< 50%). | Implemented | Test | AT-M5-03, AT-UI-04 | PASS |
| FR5.3 | The system shall display a chart of the probability of every class. | Implemented | Test | AT-UI-04 | PASS |
| FR5.4 | The system shall display a Grad-CAM heatmap over the binary image when the user requests it. | Implemented | Test | AT-M7-01 | PASS |
| FR5.5 | The system shall display the MITRE ATT&CK for ICS tactics and techniques of the predicted family. | Implemented | Test | AT-M8-01, AT-M8-02, AT-UI-04 | PASS |
| FR5.6 | The system shall generate downloadable PDF and JSON forensic reports. | Implemented | Test | AT-M8-03, AT-M8-04, AT-M8-05, AT-UI-05 | PASS |
| FR5.7 | The system shall explain the Grad-CAM colours in text and let the user download the heatmap overlay as a PNG image. | Implemented | Test | AT-M7-04 | PASS |
| FR5.8 | The system shall present a file classified as Benign as benign, show no MITRE techniques for it and count it under benign files. | Implemented | Test | AT-M5-11, AT-UI-12 | PASS |
| FR6.1 | The system shall parse Zeek conn.log and IoT-23 conn.log.labeled network captures. | Implemented | Test | AT-M9-01, AT-M9-02 | PASS |
| FR6.2 | The system shall extract behavioural features from each flow without using IP addresses. | Implemented | Test | AT-M9-03 | PASS |
| FR6.3 | The system shall classify each flow as Benign, PortScan, C&C, DDoS, Attack, FileDownload or Okiru behaviour. | Implemented | Test | AT-M9-04, AT-M9-07 | PASS |
| FR6.4 | The system shall compute a capture-level score and verdict (MALICIOUS, SUSPICIOUS or BENIGN). | Implemented | Test | AT-M9-05, AT-M9-06 | PASS |
| FR6.5 | The system shall explain the capture verdict with feature importance and each feature's deviation from benign traffic. | Implemented | Test | AT-M9-05 | PASS |
| FR6.6 | The system shall map observed behaviours to MITRE ATT&CK for ICS techniques. | Implemented | Test | AT-M9-05 | PASS |
| FR6.7 | The system shall provide a Dynamic Analysis screen to upload a capture and view its results. | Implemented | Test | AT-UI-07 | PASS |
| FR7.1 | The system shall fuse the static confidence and the dynamic score into one verdict with an agreement category (confirmed, static only, novel variant, no evidence). | Implemented | Test | AT-M10-01, AT-M10-02 | PASS |
| FR7.2 | The system shall combine the MITRE techniques of both sources, tagged by the source that supports them. | Implemented | Test | AT-M10-03 | PASS |
| FR7.3 | The system shall provide a Hybrid Verdict screen with a what-if simulator for the fusion rules. | Implemented | Test | AT-UI-08 | PASS |
| FR7.4 | The system shall evaluate fusion on paired static and dynamic evidence of the same samples. | Deferred (final evaluation) | Deferred | — | — |
| FR-B1 | When a binary is uploaded, the system shall validate it, read its bytes and build the 2-D image. | Implemented | Test | AT-M2-01, AT-M2-02, AT-M2-08 | PASS |
| FR-B2 | When detection is requested, the system shall load the model, preprocess the image and run a forward pass. | Implemented | Test | AT-M5-01, AT-M5-02, AT-M5-06, AT-UI-04 | PASS |
| FR-B3 | When a detection result is available, the system shall log the event to SQLite without blocking the result. | Implemented | Test | AT-DB-01, AT-DB-05, AT-DB-07, AT-DB-08, AT-UI-04 | PASS |
| FR-B4 | When a report is requested, the system shall compile it with the MITRE data of the predicted family. | Implemented | Test | AT-DB-07, AT-M8-03, AT-M8-04 | PASS |
| FR-B5 | When the Digital Twin is started, the system shall create the containers and the isolated network. | Deferred (final evaluation) | Deferred | — | — |
| FR-B6 | When a heatmap is requested, the system shall compute Grad-CAM through hooks on the last convolutional layer. | Implemented | Test | AT-M7-01, AT-M7-02, AT-M7-03 | PASS |
| REL-1 | Identical input shall give identical results (variance < 0.5% over 10 runs). | Implemented | Test | AT-M2-09, AT-M5-05 | PASS |
| REL-2 | Corrupt or malformed files shall be handled without a crash. | Implemented | Test | AT-DB-08, AT-M2-04, AT-M2-05, AT-M2-10, AT-M7-03 | PASS |
| REL-3 | The Digital Twin shall run for at least 4 hours between failures. | Deferred (final evaluation) | Deferred | — | — |
| REL-4 | No detection record shall be lost on an unclean shutdown (SQLite WAL). | Implemented | Test | AT-DB-02 | PASS |
| REL-5 | Two concurrent dashboard sessions shall not interfere with each other. | Implemented | Inspection | — | — |
| USE-1 | A first-time user shall complete upload and detection in under 5 minutes. | Implemented | User trial | — | — |
| USE-2 | Visual indicators shall be interpretable without a machine-learning background. | Implemented | Inspection | — | — |
| USE-3 | Every error message shall state what happened, its cause and the action to take. | Implemented | Test | AT-UI-03, AT-UI-07 | PASS |
| USE-4 | Technical terms shall have tooltips. | Implemented | Inspection | — | — |
| USE-5 | Reports shall download in under 10 seconds and open in standard viewers. | Implemented | Benchmark | — | — |
| PER-1 | Conversion shall take < 3 s for files ≤ 10 MB and < 10 s for files ≤ 50 MB. | Implemented | Benchmark | — | — |
| PER-2 | Inference shall take < 5 s on CPU and < 1 s on GPU. | Implemented | Benchmark | — | — |
| PER-3 | The dashboard shall render within 4 s on the local network. | Implemented | User trial | — | — |
| PER-4 | Grad-CAM shall take < 8 s on CPU and < 3 s on GPU. | Implemented | Benchmark | — | — |
| PER-5 | Report generation shall take < 10 s. | Implemented | Benchmark | — | — |
| PER-6 | The database shall hold 100,000 records with queries under 500 ms. | Implemented | Benchmark | — | — |
| SEC-1 | Uploaded files shall be processed only inside an isolated container. | Partial | Inspection | — | — |
| SEC-2 | The Digital Twin network shall be isolated from the host network. | Deferred (final evaluation) | Deferred | — | — |
| SEC-3 | The database file shall have permission 600 (owner read/write only). | Implemented | Test | AT-DB-06 | PASS |
| SEC-4 | SHA-256 shall be computed locally, with no external service. | Implemented | Test | AT-M2-06 | PASS |
| SEC-5 | The dashboard shall be bound to localhost by default. | Implemented | Inspection | — | — |

## Automated test cases → code

| Test ID | Requirements | Test function | Cases | Result |
|---|---|---|---|---|
| AT-DB-01 | FR-B3 | `tests/test_db.py::TestLogDetectionEvent::test_stored_sha256_matches` | 1 | PASS |
| AT-DB-02 | REL-4 | `tests/test_db.py::TestInitDb::test_wal_mode_enabled` | 1 | PASS |
| AT-DB-03 | FR1.4 | `tests/test_db.py::TestGetRecentEvents::test_limit_parameter` | 1 | PASS |
| AT-DB-04 | FR1.2 | `tests/test_db.py::TestGetDetectionStats::test_total_analyzed_increments` | 1 | PASS |
| AT-DB-05 | FR-B3 | `tests/test_db.py::TestLogDetectionEvent::test_never_raises_on_bad_confidence` | 1 | PASS |
| AT-DB-06 | SEC-3 | `tests/test_db.py::test_database_file_permission_is_owner_only` | 1 | PASS |
| AT-DB-07 | FR-B3, FR-B4 | `tests/test_db.py::test_report_event_references_its_detection` | 1 | PASS |
| AT-DB-08 | FR-B3, REL-2 | `tests/test_db.py::test_foreign_key_and_check_constraints_are_enforced` | 1 | PASS |
| AT-M10-01 | FR7.1 | `tests/test_fusion.py::TestDecisionTable::test_cases` | 6 | PASS |
| AT-M10-02 | FR7.1 | `tests/test_fusion.py::TestValidation::test_out_of_range` | 2 | PASS |
| AT-M10-03 | FR7.2 | `tests/test_fusion.py::TestMitreMerge::test_corroborated_first_and_tagged` | 1 | PASS |
| AT-M2-01 | FR-B1, FR3.2 | `tests/test_converter.py::TestBinaryConverterOutputShape::test_pe_returns_128x128` | 1 | PASS |
| AT-M2-02 | FR-B1, FR3.2 | `tests/test_converter.py::TestBinaryConverterOutputShape::test_elf_returns_128x128` | 1 | PASS |
| AT-M2-03 | FR3.1 | `tests/test_converter.py::TestValidateBinaryFormat::test_accepts_pe` | 1 | PASS |
| AT-M2-04 | FR3.1, FR3.5, REL-2 | `tests/test_converter.py::TestValidateBinaryFormat::test_rejects_invalid` | 1 | PASS |
| AT-M2-05 | FR3.5, REL-2 | `tests/test_converter.py::TestValidateBinaryFormat::test_rejects_empty_bytes` | 1 | PASS |
| AT-M2-06 | FR3.3, SEC-4 | `tests/test_converter.py::TestComputeSha256::test_matches_reference_hash` | 1 | PASS |
| AT-M2-07 | FR3.4 | `tests/test_converter.py::TestHistogram::test_counts_sum_to_total_pixels` | 1 | PASS |
| AT-M2-08 | FR-B1, FR3.6 | `tests/test_converter.py::TestMalimgLayout::test_malimg_layout_matches_reference_pipeline` | 1 | PASS |
| AT-M2-09 | REL-1 | `tests/test_converter.py::TestBinaryConverterDeterminism::test_same_bytes_same_output` | 1 | PASS |
| AT-M2-10 | REL-2 | `tests/test_converter.py::TestMalimgLayout::test_tiny_file_does_not_crash` | 1 | PASS |
| AT-M3-01 | FR4.3 | `tests/test_dataset.py::TestMalimgDataset::test_splits_sum_to_total` | 1 | PASS |
| AT-M3-02 | FR4.2 | `tests/test_dataset.py::TestLabelEncoding::test_encode_indices_are_contiguous` | 1 | PASS |
| AT-M3-03 | FR4.1 | `tests/test_dataset.py::TestMalimgDataset::test_missing_dir_raises` | 1 | PASS |
| AT-M4-01 | FR4.4 | `tests/test_enhancement.py::TestTrainTransforms::test_augmentation_produces_variation` | 1 | PASS |
| AT-M4-02 | FR4.5 | `tests/test_enhancement.py::TestGaussianNoise::test_nonzero_noise_modifies_tensor` | 1 | PASS |
| AT-M4-03 | FR4.6 | `tests/test_enhancement.py::TestClassAwareOversampler::test_minority_weight_greater_than_majority` | 1 | PASS |
| AT-M4-04 | FR4.6 | `tests/test_enhancement.py::TestClassAwareOversampler::test_invalid_strategy_raises` | 1 | PASS |
| AT-M4-05 | FR4.7 | `tests/test_gallery.py::TestGalleryHelpers::test_load_sample_images_respects_max_images` | 1 | PASS |
| AT-M4-06 | FR4.7 | `tests/test_gallery.py::TestGalleryHelpers::test_count_family_images_correct` | 1 | PASS |
| AT-M5-01 | FR-B2 | `tests/test_model.py::TestForwardPassShape::test_output_shape_batch2` | 1 | PASS |
| AT-M5-02 | FR5.1, FR-B2 | `tests/test_model.py::TestInferenceHelpers::test_predict_single_has_required_keys` | 1 | PASS |
| AT-M5-03 | FR5.2 | `tests/test_model.py::TestInferenceHelpers::test_predict_confidence_in_zero_one` | 1 | PASS |
| AT-M5-04 | FR4.8 | `tests/test_model.py::TestTrainingBehaviour::test_loss_decreases_on_overfit_single_batch` | 1 | PASS |
| AT-M5-05 | FR4.10, REL-1 | `tests/test_model.py::TestModelSerialization::test_save_and_reload_same_output` | 1 | PASS |
| AT-M5-06 | FR-B2 | `tests/test_model.py::TestLoadModel::test_load_model_raises_helpful_error_for_unknown_checkpoint_keys` | 1 | PASS |
| AT-M5-07 | FR4.11 | `tests/test_evaluation_extended.py::TestExtendedMetrics::test_per_class_fpr_matches_hand_calculation` | 1 | PASS |
| AT-M5-08 | FR4.13 | `tests/test_evaluation_extended.py::TestOpenSet::test_perfect_separation` | 1 | PASS |
| AT-M5-09 | FR4.14 | `tests/test_benign.py::TestEvaluateOnBenign::test_without_benign_class_everything_is_flagged` | 1 | PASS |
| AT-M5-10 | FR4.14 | `tests/test_benign.py::TestBuildBenignClass::test_writes_malimg_format_pngs_and_manifest` | 1 | PASS |
| AT-M5-11 | FR1.2, FR5.8 | `tests/test_benign.py::TestDashboardWiring::test_stats_count_benign` | 1 | PASS |
| AT-M5-12 | FR4.12 | `tests/test_balanced_eval.py::test_balanced_subset_has_equal_class_counts` | 1 | PASS |
| AT-M5-13 | FR4.12, FR4.11 | `tests/test_balanced_eval.py::test_balanced_metrics_expose_majority_class_bias` | 1 | PASS |
| AT-M5-14 | FR4.9 | `tests/test_training_manager.py::TestTrainingJobLifecycle::test_log_lines_accumulate_across_polls` | 1 | PASS |
| AT-M5-15 | FR4.9 | `tests/test_training_manager.py::TestTrainingJobLifecycle::test_stop_sets_status_stopped` | 1 | PASS |
| AT-M5-16 | FR4.9 | `tests/test_training_manager.py::TestHelperFunctions::test_estimate_progress_parses_epoch_line` | 1 | PASS |
| AT-M6-01 | FR1.1 | `tests/test_health.py::TestGetAllModuleStatuses::test_module_ids_are_m1_through_m10` | 1 | PASS |
| AT-M6-02 | FR1.1 | `tests/test_health.py::TestGetAllModuleStatuses::test_does_not_raise` | 1 | PASS |
| AT-M6-03 | FR1.5 | `tests/test_gallery.py::TestGetFilteredEvents::test_combined_filters` | 1 | PASS |
| AT-M6-04 | FR1.5 | `tests/test_gallery.py::TestGetFilteredEvents::test_no_sql_injection_via_family_filter` | 1 | PASS |
| AT-M7-01 | FR5.4, FR-B6 | `tests/test_gradcam.py::TestGenerateGradcam::test_heatmap_array_range` | 1 | PASS |
| AT-M7-02 | FR-B6 | `tests/test_gradcam.py::TestGenerateGradcam::test_uses_model_gradcam_layer_attribute` | 1 | PASS |
| AT-M7-03 | FR-B6, REL-2 | `tests/test_gradcam.py::TestGenerateGradcam::test_returns_none_on_bad_target_class` | 1 | PASS |
| AT-M7-04 | FR5.7 | `tests/test_gradcam.py::TestGenerateGradcam::test_overlay_png_is_valid_image` | 1 | PASS |
| AT-M8-01 | FR5.5 | `tests/test_reporting.py::TestMitreMapper::test_all_25_families_present` | 1 | PASS |
| AT-M8-02 | FR5.5 | `tests/test_reporting.py::TestMitreMapper::test_get_mitre_mapping_unknown_family` | 1 | PASS |
| AT-M8-03 | FR5.6, FR-B4 | `tests/test_reporting.py::TestJsonReport::test_contains_mitre_section` | 1 | PASS |
| AT-M8-04 | FR5.6, FR-B4 | `tests/test_reporting.py::TestPdfReport::test_output_starts_with_pdf_magic` | 1 | PASS |
| AT-M8-05 | FR5.6 | `tests/test_reporting.py::TestPdfReport::test_does_not_raise_on_bad_input` | 1 | PASS |
| AT-M9-01 | FR6.1 | `tests/test_dynamic.py::TestParser::test_iot23_space_separated_tail` | 1 | PASS |
| AT-M9-02 | FR6.1 | `tests/test_dynamic.py::TestParser::test_empty_file_raises` | 1 | PASS |
| AT-M9-03 | FR6.2 | `tests/test_dynamic.py::TestFeatures::test_no_ip_features` | 1 | PASS |
| AT-M9-04 | FR6.3 | `tests/test_dynamic.py::TestDetector::test_learns_synthetic_behaviours` | 1 | PASS |
| AT-M9-05 | FR6.4, FR6.5, FR6.6 | `tests/test_dynamic.py::TestDetector::test_malicious_capture_verdict_and_mitre` | 1 | PASS |
| AT-M9-06 | FR6.4 | `tests/test_dynamic.py::TestDetector::test_benign_capture_verdict` | 1 | PASS |
| AT-M9-07 | FR6.3 | `tests/test_dynamic.py::TestDetector::test_untrained_raises` | 1 | PASS |
| AT-UI-01 | FR1.3 | `tests/test_ui.py::test_every_page_reachable_from_sidebar` | 1 | PASS |
| AT-UI-02 | FR1.1, FR1.2 | `tests/test_ui.py::test_dashboard_shows_module_status_and_kpis` | 1 | PASS |
| AT-UI-03 | USE-3, FR5.1 | `tests/test_ui.py::test_detection_without_upload_shows_guidance` | 1 | PASS |
| AT-UI-04 | FR5.1, FR5.2, FR5.3, FR5.5, FR-B2, FR-B3 | `tests/test_ui.py::test_run_detection_end_to_end` | 1 | PASS |
| AT-UI-05 | FR5.6 | `tests/test_ui.py::test_report_section_offers_pdf_and_json` | 1 | PASS |
| AT-UI-06 | FR1.4, FR1.2 | `tests/test_ui.py::test_detection_appears_in_dashboard_history` | 1 | PASS |
| AT-UI-07 | FR6.7, USE-3 | `tests/test_ui.py::test_dynamic_page_without_model_explains_how_to_train` | 1 | PASS |
| AT-UI-08 | FR7.3 | `tests/test_ui.py::test_hybrid_whatif_simulator_flags_novel_variant` | 1 | PASS |
| AT-UI-09 | FR2.7 | `tests/test_ui.py::test_digital_twin_page_reports_status` | 1 | PASS |
| AT-UI-10 | FR1.7 | `tests/test_ui.py::test_sidebar_shows_model_and_file_status` | 1 | PASS |
| AT-UI-11 | FR1.6, FR1.5 | `tests/test_ui.py::test_history_offers_csv_export` | 1 | PASS |
| AT-UI-12 | FR5.8, FR1.2 | `tests/test_ui.py::test_benign_prediction_is_shown_as_benign` | 1 | PASS |

## Summary

- Automated test cases in RTM: **78** (84 executions incl. parameters)
- Passed: **78**, failed: **0**, skipped: **0**
- Requirements verified by test that are covered by at least one automated test: **57 / 57**
- Deferred requirements (Digital Twin): FR2.1, FR2.2, FR2.3, FR2.4, FR2.5, FR2.6, FR7.4, FR-B5, REL-3, SEC-2
- Verified by benchmark / inspection / user trial: REL-5, USE-1, USE-2, USE-4, USE-5, PER-1, PER-2, PER-3, PER-4, PER-5, PER-6, SEC-1, SEC-5
