#!/usr/bin/env python3
"""Prepare, run, and compare Qilin/FlowDroid on OWASP Benchmark Java v1.2.

The script is intentionally platform-neutral. It uses the repository's Gradle
wrapper, creates bounded-size entry-point harnesses for each taint-style CWE
category, runs the same Qilin + FlowDroid configuration with and without FSpec,
and scores each configuration against OWASP's expected-results file.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
OWASP_DIR = ROOT / "owasp-benchmark-java"
OWASP_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
OWASP_COMMIT = "3bcffb0f6b5a9e45f5874c8cf0deec476ba4dc7b"
BASE_CONFIG = ROOT / "benchmarks" / "config" / "owasp-benchmark-qilin.properties"
GENERATED_SRC = ROOT / "build" / "generated" / "owasp-benchmark" / "src"
BUILD_ROOT = ROOT / "build" / "owasp-benchmark"
RESULT_ROOT = ROOT / "results" / "owasp"
QILIN_REPO = ROOT.parent / "qilin-generics"
QILIN_JAR_NAME = "Qilin-0.10.10.3-SNAPSHOT.jar"


@dataclass(frozen=True)
class Category:
    key: str
    harness: str
    sink_file: str
    display_name: str


CATEGORIES = {
    item.key: item
    for item in [
        Category("cmdi", "OwaspCmdiHarness", "owasp-cmdi-sinks.txt", "Command Injection"),
        Category("ldapi", "OwaspLdapiHarness", "owasp-ldapi-sinks.txt", "LDAP Injection"),
        Category(
            "pathtraver",
            "OwaspPathTraversalHarness",
            "owasp-pathtraver-sinks.txt",
            "Path Traversal",
        ),
        Category("sqli", "OwaspSqliHarness", "owasp-sqli-sinks.txt", "SQL Injection"),
        Category(
            "trustbound",
            "OwaspTrustBoundaryHarness",
            "owasp-trustbound-sinks.txt",
            "Trust Boundary Violation",
        ),
        Category("xpathi", "OwaspXpathHarness", "owasp-xpathi-sinks.txt", "XPath Injection"),
        Category("xss", "OwaspXssHarness", "owasp-xss-sinks.txt", "Cross-Site Scripting"),
    ]
}


@dataclass(frozen=True)
class ExpectedCase:
    test: str
    category: str
    vulnerable: bool
    cwe: str


@dataclass(frozen=True)
class HarnessBatch:
    category: Category
    index: int
    harness: str
    tests: tuple[str, ...]

    @property
    def key(self) -> str:
        contents = "\n".join(self.tests).encode("utf-8")
        digest = hashlib.sha256(contents).hexdigest()[:10]
        return f"{self.category.key}-b{self.index:04d}-{digest}"


def run_checked(
    command: list[str],
    cwd: Path = ROOT,
    log: Path | None = None,
    process_timeout: int = 0,
) -> None:
    print("+", " ".join(command), flush=True)
    if log is None:
        subprocess.run(command, cwd=cwd, check=True)
        return

    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8", newline="") as stream:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        timed_out = threading.Event()

        def kill_timed_out_process() -> None:
            timed_out.set()
            process.kill()

        timer = (
            threading.Timer(process_timeout, kill_timed_out_process)
            if process_timeout > 0
            else None
        )
        if timer is not None:
            timer.daemon = True
            timer.start()
        assert process.stdout is not None
        try:
            for line in process.stdout:
                print(line, end="")
                stream.write(line)
            return_code = process.wait()
        finally:
            if timer is not None:
                timer.cancel()
        if timed_out.is_set():
            raise subprocess.TimeoutExpired(command, process_timeout)
    if return_code:
        raise subprocess.CalledProcessError(return_code, command)


def gradle_wrapper(repo: Path) -> list[str]:
    if os.name == "nt":
        return [str(repo / "gradlew.bat")]
    wrapper = repo / "gradlew"
    return [str(wrapper)] if os.access(wrapper, os.X_OK) else ["sh", str(wrapper)]


def java_executable() -> str:
    executable = "java.exe" if os.name == "nt" else "java"
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / executable
        if candidate.exists():
            return str(candidate)
    resolved = shutil.which(executable)
    if resolved:
        return resolved
    raise RuntimeError("Java was not found; set JAVA_HOME or add java to PATH.")


def bridge_command(heap: str, config: Path) -> list[str]:
    portable_jar = ROOT / "qilin-FD.jar"
    if portable_jar.exists():
        return [
            java_executable(),
            f"-Xmx{heap}",
            "-jar",
            str(portable_jar),
            "run",
            "--config",
            str(config),
        ]
    classpath = os.pathsep.join(
        [
            str(ROOT / "build" / "classes" / "java" / "main"),
            str(ROOT / "build" / "resources" / "main"),
            str(ROOT / "build" / "bridge-runtime" / "lib" / "*"),
        ]
    )
    return [
        java_executable(),
        f"-Xmx{heap}",
        "-cp",
        classpath,
        "dev.qilinfd.bridge.BridgeMain",
        "run",
        "--config",
        str(config),
    ]


def ensure_owasp_checkout() -> None:
    if not (OWASP_DIR / ".git").exists():
        run_checked(["git", "clone", "--no-checkout", OWASP_URL, str(OWASP_DIR)])

    status = subprocess.run(
        ["git", "-C", str(OWASP_DIR), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if status:
        raise RuntimeError(
            f"{OWASP_DIR} has local changes; refusing to switch the pinned benchmark revision."
        )

    has_commit = subprocess.run(
        ["git", "-C", str(OWASP_DIR), "cat-file", "-e", f"{OWASP_COMMIT}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not has_commit:
        run_checked(["git", "-C", str(OWASP_DIR), "fetch", "origin", OWASP_COMMIT])
    run_checked(["git", "-C", str(OWASP_DIR), "checkout", "--detach", OWASP_COMMIT])


def read_expected_cases() -> list[ExpectedCase]:
    expected_file = OWASP_DIR / "expectedresults-1.2.csv"
    prepared_file = BUILD_ROOT / "expected-taint-cases.csv"
    if not expected_file.exists() and prepared_file.exists():
        expected_file = prepared_file
    cases: list[ExpectedCase] = []
    with expected_file.open(newline="", encoding="utf-8-sig") as stream:
        rows = csv.reader(stream)
        next(rows)
        for row in rows:
            if len(row) < 4:
                continue
            cases.append(
                ExpectedCase(
                    test=row[0].strip(),
                    category=row[1].strip(),
                    vulnerable=row[2].strip().lower() == "true",
                    cwe=row[3].strip(),
                )
            )
    return cases


def java_harness(harness: str, tests: Iterable[str]) -> str:
    lines = [
        "package org.owasp.benchmark.testcode;",
        "",
        f"public final class {harness} {{",
        f"    private {harness}() {{}}",
        "",
        "    public static void main(String[] args) throws Exception {",
    ]
    for test in tests:
        lines.append(f"        new {test}().doPost(null, null);")
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def generate_harnesses(
    cases: list[ExpectedCase], categories: list[Category], batch_size: int
) -> list[HarnessBatch]:
    if batch_size <= 0:
        raise ValueError("--batch-size must be positive")
    if GENERATED_SRC.exists():
        shutil.rmtree(GENERATED_SRC)
    package_dir = GENERATED_SRC / "org" / "owasp" / "benchmark" / "testcode"
    package_dir.mkdir(parents=True, exist_ok=True)
    batches: list[HarnessBatch] = []
    for category in categories:
        tests = sorted(case.test for case in cases if case.category == category.key)
        if not tests:
            raise RuntimeError(f"No OWASP tests found for category {category.key}")
        for index, offset in enumerate(range(0, len(tests), batch_size)):
            batch_tests = tuple(tests[offset : offset + batch_size])
            harness = f"{category.harness}Batch{index:03d}"
            batch = HarnessBatch(category, index, harness, batch_tests)
            batches.append(batch)
            (package_dir / f"{harness}.java").write_text(
                java_harness(harness, batch_tests), encoding="utf-8", newline="\n"
            )

    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    with (BUILD_ROOT / "expected-taint-cases.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.writer(stream)
        writer.writerow(["test", "category", "vulnerable", "cwe"])
        for case in cases:
            if any(case.category == category.key for category in categories):
                writer.writerow([case.test, case.category, str(case.vulnerable).lower(), case.cwe])
    with (BUILD_ROOT / "batch-manifest.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.writer(stream)
        writer.writerow(["category", "batch", "harness", "test"])
        for batch in batches:
            for test in batch.tests:
                writer.writerow([batch.category.key, batch.index, batch.harness, test])
    return batches


def read_batch_manifest() -> list[HarnessBatch]:
    manifest = BUILD_ROOT / "batch-manifest.csv"
    if not manifest.exists():
        raise RuntimeError("Run the prepare action before run or compare.")
    grouped: dict[tuple[str, int, str], list[str]] = {}
    with manifest.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            key = (row["category"], int(row["batch"]), row["harness"])
            grouped.setdefault(key, []).append(row["test"])
    batches: list[HarnessBatch] = []
    for (category_key, index, harness), tests in sorted(grouped.items()):
        batches.append(
            HarnessBatch(CATEGORIES[category_key], index, harness, tuple(tests))
        )
    return batches


def refresh_qilin_jar() -> None:
    if not QILIN_REPO.exists():
        raise RuntimeError(f"Qilin repository not found at {QILIN_REPO}")
    run_checked([*gradle_wrapper(QILIN_REPO), "fatJar", "--no-daemon"], cwd=QILIN_REPO)
    source = QILIN_REPO / "artifact" / QILIN_JAR_NAME
    if not source.exists():
        raise RuntimeError(f"Expected Qilin artifact not found: {source}")
    destination = ROOT / "lib" / "qilin" / QILIN_JAR_NAME
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    print(f"Copied {source} -> {destination}")


def prepare(
    refresh_qilin: bool, categories: list[Category], batch_size: int
) -> None:
    ensure_owasp_checkout()
    cases = read_expected_cases()
    generate_harnesses(cases, categories, batch_size)
    if refresh_qilin:
        refresh_qilin_jar()
    run_checked(
        [
            *gradle_wrapper(ROOT),
            "owaspBenchmarkFullJar",
            "stageOwaspBenchmarkFullLibraries",
            "stageBridgeRuntimeLibraries",
            "classes",
            "--no-daemon",
        ]
    )


def write_run_config(batch: HarnessBatch, mode: str, pta: str, timeout: int) -> Path:
    config_dir = RESULT_ROOT / "configs"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / f"{batch.key}-{pta}-{mode}.properties"
    generic_flag = " -generic=FS" if mode == "fspec" else ""
    text = BASE_CONFIG.read_text(encoding="utf-8")
    text += "\n".join(
        [
            "",
            f"label=owasp-{batch.key}-{pta}-{mode}",
            f"mainClass=org.owasp.benchmark.testcode.{batch.harness}",
            f"timeoutSeconds={timeout}",
            f"qilinFlags=-pae -pe -clinit=ONFLY -lcs -mh -se -pta={pta}{generic_flag}",
            f"sinks=benchmarks/definitions/{batch.category.sink_file}",
            f"output=results/owasp/raw/{batch.key}-{pta}-{mode}.txt",
            "",
        ]
    )
    config_path.write_text(text, encoding="utf-8", newline="\n")
    return config_path


def run_experiments(
    categories: list[Category],
    modes: list[str],
    pta: str,
    heap: str,
    timeout: int,
    force: bool,
    batch_indices: set[int] | None,
    shard_count: int,
    shard_index: int,
    process_timeout: int,
) -> None:
    selected_keys = {category.key for category in categories}
    batches = [
        batch
        for batch in read_batch_manifest()
        if batch.category.key in selected_keys
        and (batch_indices is None or batch.index in batch_indices)
        and batch.index % shard_count == shard_index
    ]
    if not batches:
        raise RuntimeError("No prepared batches match the requested selection.")
    for batch in batches:
        for mode in modes:
            result = RESULT_ROOT / "raw" / f"{batch.key}-{pta}-{mode}.txt"
            if result.exists() and not force:
                print(f"Skipping existing result {result}")
                continue
            config = write_run_config(batch, mode, pta, timeout)
            log = RESULT_ROOT / "logs" / f"{batch.key}-{pta}-{mode}.log"
            failure = RESULT_ROOT / "failures" / f"{batch.key}-{pta}-{mode}.txt"
            try:
                run_checked(
                    bridge_command(heap, config),
                    log=log,
                    process_timeout=process_timeout,
                )
                if failure.exists():
                    failure.unlink()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                failure.parent.mkdir(parents=True, exist_ok=True)
                log_text = (
                    log.read_text(encoding="utf-8", errors="replace")
                    if log.exists()
                    else ""
                )
                if isinstance(error, subprocess.TimeoutExpired):
                    reason = "process-timeout"
                elif "OutOfMemoryError" in log_text:
                    reason = "out-of-memory"
                elif "Exception in thread" in log_text:
                    reason = "uncaught-exception"
                else:
                    reason = "nonzero-exit"
                exception_lines = [
                    line
                    for line in log_text.splitlines()
                    if line.startswith("Exception in thread")
                    or "OutOfMemoryError" in line
                ]
                failure.write_text(
                    f"returnCode={getattr(error, 'returncode', 124)}\n"
                    f"failureReason={reason}\n"
                    f"exception={exception_lines[-1] if exception_lines else ''}\n"
                    f"command={' '.join(str(value) for value in error.cmd)}\n"
                    f"log={log}\n",
                    encoding="utf-8",
                    newline="\n",
                )
                print(
                    f"FAILED {batch.key} {mode}; continuing. See {failure}",
                    file=sys.stderr,
                    flush=True,
                )


def parse_result(path: Path) -> tuple[dict[str, str], set[str]]:
    metadata: dict[str, str] = {}
    reported: set[str] = set()
    cross_test_flows = 0
    in_flows = False
    with path.open(newline="", encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.rstrip("\r\n")
            if line == "sourceMethod,sourceStmt,sinkMethod,sinkStmt":
                in_flows = True
                continue
            if not in_flows:
                if "=" in line:
                    key, value = line.split("=", 1)
                    metadata[key] = value
                continue
            if not line:
                continue
            fields = next(csv.reader([line]))
            source_tests = set(
                re.findall(r"BenchmarkTest\d{5}", " ".join(fields[:2]))
            )
            sink_tests = set(
                re.findall(r"BenchmarkTest\d{5}", " ".join(fields[2:4]))
            )
            # OWASP assigns a finding to the test that owns the sink. Counting
            # every class on a row would mark a safe source-side test as
            # vulnerable if batching manufactured a cross-test flow.
            reported.update(sink_tests)
            if source_tests and sink_tests and source_tests.isdisjoint(sink_tests):
                cross_test_flows += 1
    metadata["crossTestFlowCount"] = str(cross_test_flows)
    return metadata, reported


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def score(expected: list[ExpectedCase], reported: set[str]) -> dict[str, float | int]:
    vulnerable = {case.test for case in expected if case.vulnerable}
    safe = {case.test for case in expected if not case.vulnerable}
    tp = len(vulnerable & reported)
    fn = len(vulnerable - reported)
    fp = len(safe & reported)
    tn = len(safe - reported)
    return {
        "tests": len(expected),
        "reported": len(reported),
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "tpr": safe_ratio(tp, tp + fn),
        "fpr": safe_ratio(fp, fp + tn),
        "score": safe_ratio(tp, tp + fn) - safe_ratio(fp, fp + tn),
    }


def compare(pta: str) -> None:
    cases = read_expected_cases()
    batches = read_batch_manifest()
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    summary_rows: list[dict[str, object]] = []
    differences: list[dict[str, object]] = []

    prepared_categories = {
        batch.category.key: batch.category for batch in batches
    }
    for category in prepared_categories.values():
        category_batches = [
            batch for batch in batches if batch.category.key == category.key
        ]
        expected_by_test = {
            case.test: case for case in cases if case.category == category.key
        }
        mode_data: dict[str, tuple[set[str], set[str]]] = {}
        for mode in ("baseline", "fspec"):
            attempted: list[tuple[HarnessBatch, dict[str, str], set[str]]] = []
            failed: list[HarnessBatch] = []
            for batch in category_batches:
                result = RESULT_ROOT / "raw" / f"{batch.key}-{pta}-{mode}.txt"
                if result.exists():
                    metadata, reported = parse_result(result)
                    attempted.append((batch, metadata, reported))
                failure = RESULT_ROOT / "failures" / f"{batch.key}-{pta}-{mode}.txt"
                if failure.exists():
                    failed.append(batch)
            if not attempted and not failed:
                continue
            completed = [
                item
                for item in attempted
                if item[1].get("flowDroidTimedOut", "false").lower() != "true"
                and item[1].get("flowDroidOutOfMemory", "false").lower() != "true"
                and item[1].get("flowDroidTerminationState", "0") == "0"
                and int(item[1].get("crossTestFlowCount", "0") or 0) == 0
            ]
            evaluated_tests = {
                test for batch, _, _ in completed for test in batch.tests
            }
            reported = set().union(*(items for _, _, items in completed))
            expected = [expected_by_test[test] for test in sorted(evaluated_tests)]
            if completed:
                mode_data[mode] = (evaluated_tests, reported)
            row: dict[str, object] = {
                "category": category.key,
                "displayName": category.display_name,
                "pta": pta,
                "mode": mode,
                "batchesCompleted": len(completed),
                "batchesAttempted": len(attempted) + len(failed),
                "batchesTotal": len(category_batches),
                "failedRuns": len(failed),
                "timedOutRuns": sum(
                    metadata.get("flowDroidTimedOut", "false").lower() == "true"
                    for _, metadata, _ in attempted
                ),
                "crossTestRuns": sum(
                    int(metadata.get("crossTestFlowCount", "0") or 0) > 0
                    for _, metadata, _ in attempted
                ),
                **score(expected, reported),
            }
            for key in (
                "ptaRuntimeMs",
                "flowDroidRuntimeMs",
                "totalRuntimeMs",
                "flowDroidEdgePropagationCount",
            ):
                row[key] = sum(
                    int(metadata.get(key, "0") or 0)
                    for _, metadata, _ in attempted
                )
            for key in ("qilinCallEdgesSpecialized", "qilinCallEdgesProjected"):
                values = [
                    int(metadata.get(key, "0") or 0)
                    for _, metadata, _ in attempted
                ]
                row[key] = round(sum(values) / len(values)) if values else 0
            summary_rows.append(row)

        if "baseline" in mode_data and "fspec" in mode_data:
            common_tests = mode_data["baseline"][0] & mode_data["fspec"][0]
            baseline = mode_data["baseline"][1] & common_tests
            fspec = mode_data["fspec"][1] & common_tests
            truth = {
                test: expected_by_test[test].vulnerable for test in common_tests
            }
            for change, tests in (
                ("removed_by_fspec", sorted(baseline - fspec)),
                ("added_by_fspec", sorted(fspec - baseline)),
            ):
                for test in tests:
                    differences.append(
                        {
                            "category": category.key,
                            "test": test,
                            "expectedVulnerable": truth.get(test, ""),
                            "change": change,
                        }
                    )

    if not summary_rows:
        raise RuntimeError(f"No completed OWASP results found for PTA {pta}")

    summary_path = RESULT_ROOT / f"summary-{pta}.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)

    difference_path = RESULT_ROOT / f"differences-{pta}.csv"
    with difference_path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["category", "test", "expectedVulnerable", "change"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(differences)

    write_markdown_report(pta, summary_rows, differences)
    print(f"Wrote {summary_path}")
    print(f"Wrote {difference_path}")


def integer(row: dict[str, object], key: str) -> int:
    value = row.get(key, "")
    return int(value) if str(value).strip() else 0


def write_markdown_report(
    pta: str, rows: list[dict[str, object]], differences: list[dict[str, object]]
) -> None:
    by_key = {(str(row["category"]), str(row["mode"])): row for row in rows}
    lines = [
        "# OWASP Benchmark Java downstream case study",
        "",
        f"- Qilin PTA: `{pta}`",
        f"- OWASP revision: `{OWASP_COMMIT}`",
        "- Client: FlowDroid `soot-infoflow` 2.14.1 with Qilin call graph and points-to results",
        "- Comparison: identical source/sink definitions and FlowDroid settings; FSpec is the only toggle",
        "",
        "| Category | Mode | Complete | Failed | Timeout | Cross-test | TP | FP | FN | TN | TPR | FPR | Projected CG edges | FlowDroid edges | Total ms |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for category in CATEGORIES.values():
        for mode in ("baseline", "fspec"):
            row = by_key.get((category.key, mode))
            if row is None:
                continue
            lines.append(
                f"| {category.display_name} | {mode} | "
                f"{row['batchesCompleted']}/{row['batchesTotal']} | {row['failedRuns']} | "
                f"{row['timedOutRuns']} | "
                f"{row['crossTestRuns']} | "
                f"{row['tp']} | {row['fp']} | "
                f"{row['fn']} | {row['tn']} | {float(row['tpr']):.3f} | "
                f"{float(row['fpr']):.3f} | {row['qilinCallEdgesProjected']} | "
                f"{row['flowDroidEdgePropagationCount']} | {row['totalRuntimeMs']} |"
            )

    removed_false = sum(
        1
        for row in differences
        if row["change"] == "removed_by_fspec" and row["expectedVulnerable"] is False
    )
    removed_true = sum(
        1
        for row in differences
        if row["change"] == "removed_by_fspec" and row["expectedVulnerable"] is True
    )
    added_true = sum(
        1
        for row in differences
        if row["change"] == "added_by_fspec" and row["expectedVulnerable"] is True
    )
    added_false = sum(
        1
        for row in differences
        if row["change"] == "added_by_fspec" and row["expectedVulnerable"] is False
    )
    lines.extend(
        [
            "",
            "## Paired-result changes",
            "",
            f"- False-positive test reports removed by FSpec: **{removed_false}**",
            f"- True-positive test reports removed by FSpec: **{removed_true}**",
            f"- True-positive test reports added by FSpec: **{added_true}**",
            f"- False-positive test reports added by FSpec: **{added_false}**",
            "",
            "## Interpretation constraints",
            "",
            "- OWASP Benchmark is synthetic and simpler than production applications.",
            "- The current bridge models sources and sinks, but not OWASP-specific sanitizers.",
            "- Counts are deduplicated by `BenchmarkTestNNNNN`, not by raw FlowDroid path count.",
            "- A finding is assigned to the test class that owns its sink; any batch with a cross-test source-to-sink flow is excluded.",
            "- Each row aggregates completed bounded-size batches; call-graph edges are the per-batch mean.",
            "- Rows with incomplete or timed-out batches are preliminary and must not be used as final accuracy numbers.",
            "- Every changed test must be inspected before attributing the change to generic specialization.",
            "",
        ]
    )
    (RESULT_ROOT / f"preliminary-report-{pta}.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )


def selected_categories(raw: str) -> list[Category]:
    if raw == "all":
        return list(CATEGORIES.values())
    keys = [value.strip() for value in raw.split(",") if value.strip()]
    unknown = [key for key in keys if key not in CATEGORIES]
    if unknown:
        raise ValueError(f"Unknown categories: {', '.join(unknown)}")
    return [CATEGORIES[key] for key in keys]


def selected_modes(raw: str) -> list[str]:
    modes = [value.strip() for value in raw.split(",") if value.strip()]
    unknown = [mode for mode in modes if mode not in {"baseline", "fspec"}]
    if unknown:
        raise ValueError(f"Unknown modes: {', '.join(unknown)}")
    return modes


def selected_batch_indices(raw: str) -> set[int] | None:
    if raw == "all":
        return None
    try:
        selected: set[int] = set()
        for token in (value.strip() for value in raw.split(",") if value.strip()):
            if "-" not in token:
                selected.add(int(token))
                continue
            first, last = token.split("-", 1)
            start, end = int(first), int(last)
            if start > end:
                raise ValueError
            selected.update(range(start, end + 1))
        return selected
    except ValueError as error:
        raise ValueError(
            "--batch-indices must be 'all' or comma-separated integers/ranges, e.g. 0-49,75"
        ) from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "run", "compare", "all"), nargs="?", default="all")
    parser.add_argument("--categories", default="all", help="all or comma-separated category keys")
    parser.add_argument("--modes", default="baseline,fspec")
    parser.add_argument("--pta", default="1o", help="Qilin PTA pattern; primary study defaults to 1o")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2,
        help="Tests per generated harness during prepare/all (default: 2; validated for isolation and throughput)",
    )
    parser.add_argument(
        "--batch-indices",
        default="all",
        help="all or comma-separated prepared batch indices",
    )
    parser.add_argument(
        "--shard-count",
        type=int,
        default=1,
        help="Number of parallel shards (default: 1)",
    )
    parser.add_argument(
        "--shard-index",
        type=int,
        default=0,
        help="Zero-based shard selected by batch-index modulo shard-count",
    )
    parser.add_argument("--heap", default="16g", help="Maximum heap for each bridge JVM")
    parser.add_argument("--timeout", type=int, default=3600, help="FlowDroid timeout per category/mode")
    parser.add_argument(
        "--process-timeout",
        type=int,
        default=7200,
        help="Hard wall-clock limit per Qilin+FlowDroid JVM; 0 disables it (default: 7200)",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite completed raw results")
    parser.add_argument("--refresh-qilin", action="store_true", help="Build and copy the sibling Qilin jar")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    categories = selected_categories(args.categories)
    modes = selected_modes(args.modes)
    batch_indices = selected_batch_indices(args.batch_indices)
    if args.shard_count <= 0 or not 0 <= args.shard_index < args.shard_count:
        raise ValueError("--shard-count must be positive and shard-index must be in range")
    if args.action in {"prepare", "all"}:
        prepare(args.refresh_qilin, categories, args.batch_size)
    if args.action in {"run", "all"}:
        run_experiments(
            categories,
            modes,
            args.pta,
            args.heap,
            args.timeout,
            args.force,
            batch_indices,
            args.shard_count,
            args.shard_index,
            args.process_timeout,
        )
    if args.action in {"compare", "all"}:
        compare(args.pta)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        RuntimeError,
        ValueError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
