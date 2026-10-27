# Evidence: A1-T1059.001-encoded-powershell

Rule version 1, run on 2026-10-27. Raw output: `results/kusto.json`, `results/splunk.json`.
Rerun: `python -m harness fetch`, then `python -m harness run --engine kusto --rule A1` (and `--engine splunk`); see docs/components/engine-tests.md.

## Engines

- Sentinel query: Kustainer (ADX engine) 1.0.9796.17726, product 2026.10.27.0942-2643-eb20c9c-master, the Azure Data Explorer emulator. It runs real KQL, but it is the ADX engine, not Log Analytics; no Sentinel workspace was used.
- Splunk search: Splunk Enterprise 10.6.1.1 (build b2ae2962645c), XmlWinEventLog extraction from harness/engines.py. The Windows add-on is not installed; field extraction is the minimal one in harness/engines.py.
- SecOps YARA-L: **not run**. There is no YARA-L engine outside a SecOps tenant. The rule uses the same regular expressions as the two versions that were run, but its UDM field names and syntax are untested.

## Samples

| Engine | Positive events | Rows | Negative events | Rows |
|---|---|---|---|---|
| kusto | 6 (2 recorded, 4 hand-written) | 6 | 6 (2 recorded, 4 hand-written) | 0 |
| splunk | 6 (2 recorded, 4 hand-written) | 6 | 6 (2 recorded, 4 hand-written) | 0 |

Every sample carries `_provenance`: `recorded:<dataset path @ commit>` or `hand-written` (with a `_note`). Hand-written events use host `HANDWRITTEN-01` and documentation IP ranges; they are not attack data.

## Recorded datasets

OTRF Security-Datasets, MIT License, Open Threat Research Forge. Collected by NXLog in a lab domain; rebuilt into each SIEM's shape by harness/mapping.py (what that approximates is listed in its docstring).

| Dataset | File in repo @ commit | SHA-256 (zip) | Events |
|---|---|---|---|
| otrf-empire-launcher-vbs | `datasets/atomic/windows/execution/host/empire_launcher_vbs.zip` @ d9d40ef | `812da270cf8cda6f...` | 2,067 |
| otrf-empire-runkey-standard-user | `datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip` @ d9d40ef | `2965f791bcaf5e6c...` | 40,569 |
| otrf-empire-runkey-elevated-user | `datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip` @ d9d40ef | `2809354d67902585...` | 657 |
| otrf-empire-reg-dump-sam | `datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam.zip` @ d9d40ef | `5a8ee19860f35da6...` | 738 |
| otrf-bitsadmin-download | `datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip` @ d9d40ef | `8fb7bc9f3d82f672...` | 424 |
| otrf-sam-copy-esentutl | `datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl.zip` @ d9d40ef | `f7a71135778aeff6...` | 915 |

All 45,370 events (attack and host background together) were loaded at once, then the rule ran over all of them.

| Engine | Rows returned |
|---|---|
| kusto | 2 |
| splunk | 2 |

Both dataset rows are Empire stagers: the VBS launcher's child and the stager relaunched from the Run key. The third `powershell.exe` 4688 in the data (`-c "$x=...; powershell -Win Hidden -enc $x"`) is not matched by design; its child is.

## What this does not show

- False-positive rate in a real environment: the background is one lab host per dataset over minutes to hours, not a production estate.
- That the rule runs in a Sentinel workspace or a Splunk with the Windows add-on: both were approximated (see above).
- Column names: the Sentinel tables were created from schemas/reference/sentinel/, which came through a summarising fetch tool. Recorded EventData fields with no column there were dropped on load (listed in results/kusto.json under `columns_dropped_in_mapping`); the rule reads none of them.
