#!/usr/bin/env python3
"""Repeat the Paper 2 Phase A v4 harness and summarize run-to-run variability.

This wrapper does not alter the harness or claim isolated primitive timings. It
runs each repetition in a fresh process, preserving each run's JSON/CSV and
capturing console logs for auditability.
"""
import argparse
import json
import math
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

METRICS = [
    "runtime_ms_including_setup_and_log_checks",
    "median_aes_gcm_encryption_ms",
    "median_receiver_total_validation_ms",
    "aggregate_overhead_percent_excluding_json_framing",
    "median_overhead_percent_per_object",
    "total_payload_MiB",
    "objects_successfully_processed",
    "checks_passed",
    "checks_total",
]


def percentile(values, p):
    if not values:
        return None
    vals = sorted(float(v) for v in values)
    if len(vals) == 1:
        return vals[0]
    pos = (len(vals) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return vals[lo]
    return vals[lo] + (vals[hi] - vals[lo]) * (pos - lo)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--module", required=True, help="Path to Phase A v4 harness .py")
    ap.add_argument("--input", required=True, help="DICOM input file or directory")
    ap.add_argument("--output-dir", required=True, help="Benchmark output directory")
    ap.add_argument("--runs", type=int, default=10, help="Number of independent harness runs (default: 10)")
    ap.add_argument("--max-files", type=int, default=0, help="Objects per run; 0 means all (default: 0)")
    args = ap.parse_args()

    harness = Path(args.module).expanduser().resolve()
    input_path = Path(args.input).expanduser().resolve()
    out = Path(args.output_dir).expanduser().resolve()
    if not harness.is_file():
        ap.error(f"Harness not found: {harness}")
    if not input_path.exists():
        ap.error(f"Input path not found: {input_path}")
    if args.runs < 2:
        ap.error("Use at least 2 runs to estimate run-to-run variability.")
    out.mkdir(parents=True, exist_ok=True)

    records = []
    for i in range(1, args.runs + 1):
        run_dir = out / f"run_{i:02d}"
        run_dir.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(harness), "--input", str(input_path),
               "--max-files", str(args.max_files), "--output-dir", str(run_dir)]
        started = datetime.now(timezone.utc).isoformat()
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        (run_dir / "console_stdout.txt").write_text(proc.stdout, encoding="utf-8")
        (run_dir / "console_stderr.txt").write_text(proc.stderr, encoding="utf-8")
        summary_path = run_dir / "paper2_dicom_exchange_summary.json"
        row = {
            "run": i,
            "started_utc": started,
            "return_code": proc.returncode,
            "summary_json": str(summary_path),
            "all_checks_passed": False,
        }
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                row["all_checks_passed"] = bool(summary.get("all_checks_passed", False))
                for key in METRICS:
                    if key in summary:
                        row[key] = summary[key]
            except Exception as exc:
                row["summary_parse_error"] = repr(exc)
        else:
            row["summary_missing"] = True
        records.append(row)
        print(f"Run {i}/{args.runs}: return_code={proc.returncode}, "
              f"summary={'yes' if summary_path.is_file() else 'NO'}, "
              f"all_checks_passed={row['all_checks_passed']}")

    numeric_summary = {}
    for key in METRICS:
        vals = [r[key] for r in records if isinstance(r.get(key), (int, float)) and not isinstance(r.get(key), bool)]
        if vals:
            numeric_summary[key] = {
                "n": len(vals),
                "mean": statistics.mean(vals),
                "stdev_sample": statistics.stdev(vals) if len(vals) > 1 else None,
                "median": statistics.median(vals),
                "p95_nearest_rank_interpolated": percentile(vals, 0.95),
                "min": min(vals),
                "max": max(vals),
            }

    result = {
        "experiment": "Paper 2 Phase A repeated-run variability benchmark",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "harness_path": str(harness),
        "input_path_disclosed": False,
        "requested_runs": args.runs,
        "runs_with_summary": sum(1 for r in records if not r.get("summary_missing", False)),
        "runs_all_checks_passed": sum(1 for r in records if r.get("all_checks_passed", False)),
        "all_runs_successful": all(r.get("return_code") == 0 and r.get("all_checks_passed") for r in records),
        "per_run": records,
        "metric_summary": numeric_summary,
        "limitations": [
            "Repeated harness runs estimate run-to-run variability for this small input set and machine only.",
            "Harness-reported per-run medians are summarized across runs; they are not per-operation raw timing distributions.",
            "This wrapper does not isolate ML-KEM or ML-DSA primitive timings and does not provide a TLS/DICOMweb baseline.",
            "Fresh processes and ephemeral keys are used for each repetition; this is not a persistence or concurrency test."
        ],
    }
    summary_out = out / "paper2_phaseA_repeated_run_summary.json"
    summary_out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    # Compact CSV for spreadsheet analysis.
    csv_out = out / "paper2_phaseA_repeated_run_per_run.csv"
    keys = ["run", "return_code", "all_checks_passed"] + METRICS
    def csv_cell(v):
        if v is None:
            return ""
        s = str(v)
        if any(c in s for c in ',"\r\n'):
            return '"' + s.replace('"', '""') + '"'
        return s
    lines = [",".join(keys)]
    for r in records:
        lines.append(",".join(csv_cell(r.get(k)) for k in keys))
    csv_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\nSummary JSON:", summary_out)
    print("Per-run CSV:", csv_out)
    print("All runs successful:", result["all_runs_successful"])
    if not result["all_runs_successful"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()