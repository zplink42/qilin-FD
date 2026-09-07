#!/usr/bin/env python3
"""Summarize raw OWASP/FlowDroid outputs for the downstream case study.

The paper comparison is deliberately *paired*: a batch contributes to the
quantitative comparison only if both the baseline and FSpec configurations
terminate normally, without FlowDroid timeout/OOM markers and without
cross-test flows introduced by batching.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import shutil
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PRECOMPUTED_DATA = ROOT / "reports" / "owasp-paper" / "data"
PRECOMPUTED_FILES = (
    "compare-{pta}.log",
    "coverage-summary-{pta}.txt",
    "paired-summary-{pta}.csv",
    "paired-differences-{pta}.csv",
    "run-status-{pta}.csv",
    "remaining-failures-{pta}.csv",
)


def load_runner() -> Any:
    runner_path = ROOT / "scripts" / "run_owasp_fspec.py"
    spec = importlib.util.spec_from_file_location("owasp_runner", runner_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {runner_path}")
    module = importlib.util.module_from_spec(spec)
    # Required by Python 3.12 dataclasses when a module is loaded manually.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def safe_int(metadata: dict[str, str], key: str) -> int:
    try:
        return int(metadata.get(key, "0") or 0)
    except ValueError:
        return 0


def safe_float(metadata: dict[str, str], key: str) -> float:
    try:
        return float(metadata.get(key, "0") or 0)
    except ValueError:
        return 0.0


def percent_delta(new_value: float, old_value: float) -> float | str:
    return "" if old_value == 0 else round((new_value - old_value) * 100.0 / old_value, 2)


def read_failure_reason(failure_dir: Path, batch: Any, mode: str, pta: str) -> str:
    failure = failure_dir / f"{batch.key}-{pta}-{mode}.txt"
    if not failure.exists():
        return "no-failure-file"
    text = failure.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("failureReason="):
            return line.split("=", 1)[1]
    return "failure-file-without-reason"


def is_completed(metadata: dict[str, str]) -> bool:
    return (
        metadata.get("flowDroidTimedOut", "false").lower() != "true"
        and metadata.get("flowDroidOutOfMemory", "false").lower() != "true"
        and metadata.get("flowDroidTerminationState", "0") == "0"
        and int(metadata.get("crossTestFlowCount", "0") or 0) == 0
    )


def score(expected_by_test: dict[str, Any], tests: set[str], reported: set[str]) -> dict[str, int | float]:
    reported = set(reported) & tests
    vulnerable = {test for test in tests if expected_by_test[test].vulnerable}
    safe = tests - vulnerable
    tp = len(vulnerable & reported)
    fn = len(vulnerable - reported)
    fp = len(safe & reported)
    tn = len(safe - reported)
    tpr = safe_ratio(tp, tp + fn)
    fpr = safe_ratio(fp, fp + tn)
    return {
        "reported": len(reported),
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "tpr": round(tpr, 6),
        "fpr": round(fpr, 6),
        "score": round(tpr - fpr, 6),
    }


def copy_precomputed_outputs(pta: str, out_dir: Path) -> bool:
    copied = False
    for template in PRECOMPUTED_FILES:
        name = template.format(pta=pta)
        source = PRECOMPUTED_DATA / name
        if not source.exists():
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, out_dir / name)
        copied = True
    return copied


def summarize(args: argparse.Namespace) -> None:
    runner = load_runner()
    result_root = ROOT / "results" / "owasp"
    raw_dir = result_root / "raw"
    failure_dir = result_root / "failures"
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    batches = runner.read_batch_manifest()
    cases = runner.read_expected_cases()
    expected_by_test = {case.test: case for case in cases}
    expected_raw_runs = len(batches) * 2
    actual_raw_runs = len(list(raw_dir.glob(f"*-{args.pta}-*.txt")))

    if (
        not args.force_raw
        and actual_raw_runs < expected_raw_runs * args.min_raw_fraction
        and (PRECOMPUTED_DATA / f"paired-summary-{args.pta}.csv").exists()
    ):
        copy_precomputed_outputs(args.pta, out_dir)
        print(
            "Local raw results are incomplete "
            f"({actual_raw_runs}/{expected_raw_runs}); copied precomputed paper data instead."
        )
        print(f"Output directory: {out_dir}")
        return

    def load_result(batch: Any, mode: str) -> dict[str, Any]:
        result = raw_dir / f"{batch.key}-{args.pta}-{mode}.txt"
        if not result.exists():
            return {
                "status": "missing",
                "reason": read_failure_reason(failure_dir, batch, mode, args.pta),
                "metadata": {},
                "reported": set(),
                "path": str(result),
            }
        metadata, reported = runner.parse_result(result)
        if is_completed(metadata):
            return {
                "status": "completed",
                "reason": "",
                "metadata": metadata,
                "reported": reported,
                "path": str(result),
            }

        reasons: list[str] = []
        if metadata.get("flowDroidTimedOut", "false").lower() == "true":
            reasons.append("flowdroid-timeout")
        if metadata.get("flowDroidOutOfMemory", "false").lower() == "true":
            reasons.append("flowdroid-oom")
        if metadata.get("flowDroidTerminationState", "0") != "0":
            reasons.append("termination-" + metadata.get("flowDroidTerminationState", "unknown"))
        if int(metadata.get("crossTestFlowCount", "0") or 0) > 0:
            reasons.append("cross-test-flow")
        return {
            "status": "excluded",
            "reason": "+".join(reasons) if reasons else "excluded-unknown",
            "metadata": metadata,
            "reported": reported,
            "path": str(result),
        }

    records: list[dict[str, Any]] = []
    for batch in batches:
        baseline = load_result(batch, "baseline")
        fspec = load_result(batch, "fspec")
        records.append(
            {
                "batch": batch,
                "baseline": baseline,
                "fspec": fspec,
                "paired": baseline["status"] == "completed" and fspec["status"] == "completed",
            }
        )

    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_category[record["batch"].category.key].append(record)

    def sum_metric(records_for_category: list[dict[str, Any]], mode: str, key: str) -> int:
        return sum(safe_int(record[mode]["metadata"], key) for record in records_for_category)

    def sum_float_metric(records_for_category: list[dict[str, Any]], mode: str, key: str) -> float:
        return round(sum(safe_float(record[mode]["metadata"], key) for record in records_for_category), 3)

    def mean_metric(records_for_category: list[dict[str, Any]], mode: str, key: str) -> int:
        values = [safe_int(record[mode]["metadata"], key) for record in records_for_category]
        return round(sum(values) / len(values)) if values else 0

    def median_metric(records_for_category: list[dict[str, Any]], mode: str, key: str) -> int:
        values = [safe_int(record[mode]["metadata"], key) for record in records_for_category]
        return round(statistics.median(values)) if values else 0

    def summarize_category(category: str, category_records: list[dict[str, Any]]) -> dict[str, Any]:
        paired = [record for record in category_records if record["paired"]]
        tests = sorted({test for record in paired for test in record["batch"].tests})
        row: dict[str, Any] = {
            "category": category,
            "pairedBatches": len(paired),
            "totalBatches": len(category_records),
            "pairedBatchCoveragePct": round(len(paired) * 100.0 / len(category_records), 2)
            if category_records
            else 0,
            "evaluatedTests": len(tests),
        }

        for mode in ("baseline", "fspec"):
            reported: set[str] = set()
            for record in paired:
                reported |= set(record[mode]["reported"])

            for key, value in score(expected_by_test, set(tests), reported).items():
                row[f"{mode}_{key}"] = value

            row[f"{mode}_ptaRuntimeMs"] = sum_metric(paired, mode, "ptaRuntimeMs")
            row[f"{mode}_flowDroidRuntimeMs"] = sum_metric(paired, mode, "flowDroidRuntimeMs")
            row[f"{mode}_flowDroidTaintPropagationSeconds"] = sum_float_metric(
                paired, mode, "flowDroidTaintPropagationSeconds"
            )
            row[f"{mode}_totalRuntimeMs"] = sum_metric(paired, mode, "totalRuntimeMs")
            row[f"{mode}_totalRuntimeMeanMs"] = mean_metric(paired, mode, "totalRuntimeMs")
            row[f"{mode}_totalRuntimeMedianMs"] = median_metric(paired, mode, "totalRuntimeMs")
            row[f"{mode}_qilinCallEdgesProjectedMean"] = mean_metric(
                paired, mode, "qilinCallEdgesProjected"
            )
            row[f"{mode}_qilinCallEdgesSpecializedMean"] = mean_metric(
                paired, mode, "qilinCallEdgesSpecialized"
            )
            row[f"{mode}_flowDroidEdgePropagationCount"] = sum_metric(
                paired, mode, "flowDroidEdgePropagationCount"
            )
            row[f"{mode}_rejectedAliasAccessPaths"] = sum_metric(
                paired, mode, "flowDroidRejectedAliasAccessPaths"
            )

        delta_keys = (
            "ptaRuntimeMs",
            "flowDroidRuntimeMs",
            "flowDroidTaintPropagationSeconds",
            "totalRuntimeMs",
            "qilinCallEdgesProjectedMean",
            "qilinCallEdgesSpecializedMean",
            "flowDroidEdgePropagationCount",
        )
        for key in delta_keys:
            baseline_value = row[f"baseline_{key}"]
            fspec_value = row[f"fspec_{key}"]
            row[f"delta_{key}"] = round(fspec_value - baseline_value, 3)
            row[f"delta_{key}Pct"] = percent_delta(fspec_value, baseline_value)

        baseline_reported: set[str] = set()
        fspec_reported: set[str] = set()
        for record in paired:
            baseline_reported |= set(record["baseline"]["reported"])
            fspec_reported |= set(record["fspec"]["reported"])
        tests_set = set(tests)
        baseline_reported &= tests_set
        fspec_reported &= tests_set
        row["addedByFspec"] = len(fspec_reported - baseline_reported)
        row["removedByFspec"] = len(baseline_reported - fspec_reported)
        return row

    summary_rows = [
        summarize_category(category, by_category[category])
        for category in sorted(by_category)
    ]
    summary_rows.append(summarize_category("ALL", records))

    summary_path = out_dir / f"paired-summary-{args.pta}.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)

    difference_rows: list[dict[str, Any]] = []
    for category in sorted(by_category):
        paired = [record for record in by_category[category] if record["paired"]]
        tests = sorted({test for record in paired for test in record["batch"].tests})
        baseline_reported: set[str] = set()
        fspec_reported: set[str] = set()
        for record in paired:
            baseline_reported |= set(record["baseline"]["reported"])
            fspec_reported |= set(record["fspec"]["reported"])
        tests_set = set(tests)
        baseline_reported &= tests_set
        fspec_reported &= tests_set
        for test in sorted(baseline_reported ^ fspec_reported):
            difference_rows.append(
                {
                    "category": category,
                    "test": test,
                    "expectedVulnerable": expected_by_test[test].vulnerable,
                    "baselineReported": test in baseline_reported,
                    "fspecReported": test in fspec_reported,
                    "change": "added_by_fspec"
                    if test in fspec_reported
                    else "removed_by_fspec",
                }
            )

    difference_path = out_dir / f"paired-differences-{args.pta}.csv"
    with difference_path.open("w", newline="", encoding="utf-8") as stream:
        fieldnames = [
            "category",
            "test",
            "expectedVulnerable",
            "baselineReported",
            "fspecReported",
            "change",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(difference_rows)

    status_rows: list[dict[str, Any]] = []
    for record in records:
        batch = record["batch"]
        status_rows.append(
            {
                "category": batch.category.key,
                "batch": batch.index,
                "key": batch.key,
                "tests": ";".join(batch.tests),
                "pairedCompleted": record["paired"],
                "baselineStatus": record["baseline"]["status"],
                "baselineReason": record["baseline"]["reason"],
                "fspecStatus": record["fspec"]["status"],
                "fspecReason": record["fspec"]["reason"],
                "baselineTotalRuntimeMs": safe_int(record["baseline"]["metadata"], "totalRuntimeMs"),
                "fspecTotalRuntimeMs": safe_int(record["fspec"]["metadata"], "totalRuntimeMs"),
                "baselineProjectedCG": safe_int(record["baseline"]["metadata"], "qilinCallEdgesProjected"),
                "fspecProjectedCG": safe_int(record["fspec"]["metadata"], "qilinCallEdgesProjected"),
            }
        )

    status_path = out_dir / f"run-status-{args.pta}.csv"
    with status_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(status_rows[0]))
        writer.writeheader()
        writer.writerows(status_rows)

    remaining_path = out_dir / f"remaining-failures-{args.pta}.csv"
    with remaining_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(status_rows[0]))
        writer.writeheader()
        writer.writerows(
            row
            for row in status_rows
            if row["baselineStatus"] != "completed" or row["fspecStatus"] != "completed"
        )

    status_counter = Counter(
        (
            row["baselineStatus"],
            row["baselineReason"],
            row["fspecStatus"],
            row["fspecReason"],
        )
        for row in status_rows
        if row["baselineStatus"] != "completed" or row["fspecStatus"] != "completed"
    )
    coverage_path = out_dir / f"coverage-summary-{args.pta}.txt"
    coverage_path.write_text(
        "\n".join(
            [
                f"expectedRawRuns={len(records) * 2}",
                f"actualRawRuns={len(list(raw_dir.glob(f'*-{args.pta}-*.txt')))}",
                f"totalBatches={len(records)}",
                f"pairedCompletedBatches={sum(1 for record in records if record['paired'])}",
                f"unpairedOrFailedBatches={sum(1 for record in records if not record['paired'])}",
                f"baselineCompleted={sum(1 for record in records if record['baseline']['status'] == 'completed')}",
                f"fspecCompleted={sum(1 for record in records if record['fspec']['status'] == 'completed')}",
                "",
                "failureStatusCounts:",
                *[f"{key}={value}" for key, value in sorted(status_counter.items())],
                "",
            ]
        ),
        encoding="utf-8",
    )

    print("Wrote:")
    for path in (summary_path, difference_path, status_path, remaining_path, coverage_path):
        print(path)
    print("\nKey summary:")
    for row in summary_rows:
        print(
            row["category"],
            "paired",
            f"{row['pairedBatches']}/{row['totalBatches']}",
            "label changes",
            f"+{row['addedByFspec']}/-{row['removedByFspec']}",
            "projected CG",
            f"{row['delta_qilinCallEdgesProjectedMeanPct']}%",
            "IFDS edges",
            f"{row['delta_flowDroidEdgePropagationCountPct']}%",
            "total time",
            f"{row['delta_totalRuntimeMsPct']}%",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build paired summaries from OWASP/FlowDroid raw outputs."
    )
    parser.add_argument("--pta", default="1o")
    parser.add_argument("--output-dir", default="results/owasp/analysis")
    parser.add_argument(
        "--min-raw-fraction",
        type=float,
        default=0.5,
        help="Use precomputed paper data if fewer than this fraction of raw runs exists locally.",
    )
    parser.add_argument(
        "--force-raw",
        action="store_true",
        help="Always summarize local raw results, even if they look incomplete.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    summarize(parse_args())
