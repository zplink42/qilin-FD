#!/usr/bin/env python3
"""Generate a restart-safe Ubuntu rerun package from an OWASP run-status CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import textwrap
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATUS = ROOT / "reports" / "owasp-paper" / "data" / "run-status-1o.csv"
SUMMARIZER = ROOT / "scripts" / "paper" / "summarize_owasp_downstream.py"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate exact failed-side rerun scripts for Ubuntu."
    )
    parser.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "release" / "owasp-rerun-1o-20260729",
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--heap", default="96g")
    parser.add_argument("--timeout", type=int, default=14400)
    parser.add_argument("--process-timeout", type=int, default=28800)
    parser.add_argument("--pta", default="1o")
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def build_tasks(
    rows: list[dict[str, str]], workers: int
) -> list[dict[str, str | int]]:
    tasks: list[dict[str, str | int]] = []
    for row in rows:
        for mode in ("baseline", "fspec"):
            status = row[f"{mode}Status"]
            if status == "completed":
                continue
            tasks.append(
                {
                    "category": row["category"],
                    "batch": int(row["batch"]),
                    "key": row["key"],
                    "tests": row["tests"],
                    "mode": mode,
                    "previousStatus": status,
                    "previousReason": row[f"{mode}Reason"],
                }
            )
    tasks.sort(
        key=lambda task: (
            str(task["category"]),
            str(task["mode"]),
            int(task["batch"]),
        )
    )
    for index, task in enumerate(tasks):
        task["worker"] = index % workers
    return tasks


def write_manifest(path: Path, tasks: list[dict[str, str | int]]) -> None:
    fields = [
        "worker",
        "category",
        "batch",
        "key",
        "tests",
        "mode",
        "previousStatus",
        "previousReason",
    ]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(tasks)


def helper_source() -> str:
    return textwrap.dedent(
        """\
        #!/usr/bin/env python3
        \"\"\"Run one OWASP side only when its current raw result is not valid.\"\"\"

        from __future__ import annotations

        import argparse
        import importlib.util
        import subprocess
        import sys
        from pathlib import Path


        PACKAGE_DIR = Path(__file__).resolve().parent
        ROOT = PACKAGE_DIR.parents[1]


        def load_runner():
            path = ROOT / "scripts" / "run_owasp_fspec.py"
            spec = importlib.util.spec_from_file_location("owasp_runner", path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot load {path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module


        def valid(metadata: dict[str, str]) -> bool:
            return (
                metadata.get("flowDroidTimedOut", "false").lower() != "true"
                and metadata.get("flowDroidOutOfMemory", "false").lower() != "true"
                and metadata.get("flowDroidTerminationState", "0") == "0"
                and int(metadata.get("crossTestFlowCount", "0") or 0) == 0
            )


        def main() -> int:
            parser = argparse.ArgumentParser()
            parser.add_argument("--category", required=True)
            parser.add_argument("--mode", choices=("baseline", "fspec"), required=True)
            parser.add_argument("--batch", type=int, required=True)
            parser.add_argument("--pta", default="1o")
            parser.add_argument("--heap", required=True)
            parser.add_argument("--timeout", type=int, required=True)
            parser.add_argument("--process-timeout", type=int, required=True)
            args = parser.parse_args()

            runner = load_runner()
            matches = [
                batch
                for batch in runner.read_batch_manifest()
                if batch.category.key == args.category and batch.index == args.batch
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    f"Expected one batch for {args.category}/{args.batch}, found {len(matches)}"
                )

            result = (
                ROOT
                / "results"
                / "owasp"
                / "raw"
                / f"{matches[0].key}-{args.pta}-{args.mode}.txt"
            )
            if result.exists():
                metadata, _ = runner.parse_result(result)
                if valid(metadata):
                    print(
                        f"SKIP completed {args.category} batch={args.batch} mode={args.mode}",
                        flush=True,
                    )
                    return 0

            command = [
                sys.executable,
                "-u",
                str(ROOT / "scripts" / "run_owasp_fspec.py"),
                "run",
                "--categories",
                args.category,
                "--modes",
                args.mode,
                "--batch-indices",
                str(args.batch),
                "--pta",
                args.pta,
                "--heap",
                args.heap,
                "--timeout",
                str(args.timeout),
                "--process-timeout",
                str(args.process_timeout),
                "--force",
            ]
            print(
                f"RUN {args.category} batch={args.batch} mode={args.mode}",
                flush=True,
            )
            return subprocess.run(command, cwd=ROOT).returncode


        if __name__ == "__main__":
            raise SystemExit(main())
        """
    )


def progress_source() -> str:
    return textwrap.dedent(
        """\
        #!/usr/bin/env python3
        \"\"\"Refresh and print paired OWASP progress, optionally in a loop.\"\"\"

        from __future__ import annotations

        import argparse
        import csv
        import subprocess
        import sys
        import time
        from collections import Counter
        from datetime import datetime
        from pathlib import Path


        PACKAGE_DIR = Path(__file__).resolve().parent
        ROOT = PACKAGE_DIR.parents[1]


        def snapshot() -> None:
            subprocess.run(
                [
                    sys.executable,
                    str(PACKAGE_DIR / "summarize_owasp_downstream.py"),
                    "--pta",
                    "1o",
                    "--force-raw",
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            status_path = ROOT / "results" / "owasp" / "analysis" / "run-status-1o.csv"
            with status_path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))

            sides = [
                {
                    "status": row[f"{mode}Status"],
                    "reason": row[f"{mode}Reason"],
                }
                for row in rows
                for mode in ("baseline", "fspec")
            ]
            paired = [
                row for row in rows if row["pairedCompleted"].lower() == "true"
            ]
            paired_tests = sum(
                len([test for test in row["tests"].split(";") if test])
                for row in paired
            )
            completed = sum(side["status"] == "completed" for side in sides)
            excluded = sum(side["status"] == "excluded" for side in sides)
            missing = sum(side["status"] == "missing" for side in sides)
            present = len(sides) - missing

            print(datetime.now().isoformat(timespec="seconds"))
            print(f"Expected raw runs        : {len(sides)}")
            print(f"Present raw files        : {present}")
            print(f"Completed run sides      : {completed}")
            print(f"Excluded/invalid raw     : {excluded}")
            print(f"Missing run sides        : {missing}")
            print(f"Completed batch pairs    : {len(paired)} / {len(rows)}")
            print(f"Paired configuration runs: {len(paired) * 2}")
            print(f"Paired OWASP test cases  : {paired_tests}")
            print(f"Failed sides to rerun    : {excluded + missing}")
            reasons = Counter(
                side["reason"] or side["status"]
                for side in sides
                if side["status"] != "completed"
            )
            print("Failure reasons:")
            for reason, count in reasons.most_common():
                print(f"  {count:4d}  {reason}")


        def main() -> None:
            parser = argparse.ArgumentParser()
            parser.add_argument(
                "--watch",
                type=int,
                default=0,
                metavar="SECONDS",
                help="Refresh repeatedly at this interval; default is one snapshot.",
            )
            args = parser.parse_args()
            while True:
                snapshot()
                if args.watch <= 0:
                    return
                print()
                time.sleep(args.watch)


        if __name__ == "__main__":
            main()
        """
    )


def write_worker_scripts(
    output: Path,
    tasks: list[dict[str, str | int]],
    workers: int,
    heap: str,
    timeout: int,
    process_timeout: int,
    pta: str,
) -> None:
    for old in output.glob("remaining-rerun-worker-*.sh"):
        old.unlink()
    for worker in range(workers):
        assigned = [task for task in tasks if task["worker"] == worker]
        lines = [
            "#!/usr/bin/env bash",
            "set -uo pipefail",
            'PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
            'ROOT="$(cd "$PACKAGE_DIR/../.." && pwd)"',
            'cd "$ROOT"',
            'test -f scripts/run_owasp_fspec.py || { echo "Not in a qilin-FD package" >&2; exit 2; }',
            f'HEAP="${{HEAP:-{heap}}}"',
            f'FLOWDROID_TIMEOUT="${{FLOWDROID_TIMEOUT:-{timeout}}}"',
            f'PROCESS_TIMEOUT="${{PROCESS_TIMEOUT:-{process_timeout}}}"',
            "",
        ]
        for task in assigned:
            lines.extend(
                [
                    (
                        f'echo "TASK {task["category"]} batch={task["batch"]} '
                        f'mode={task["mode"]} previous={task["previousReason"]}"'
                    ),
                    (
                        'python3 -u "$PACKAGE_DIR/run_one_if_needed.py" '
                        f'--category {task["category"]} '
                        f'--mode {task["mode"]} '
                        f'--batch {task["batch"]} '
                        f'--pta {pta} '
                        '--heap "$HEAP" '
                        '--timeout "$FLOWDROID_TIMEOUT" '
                        '--process-timeout "$PROCESS_TIMEOUT" '
                        f'|| echo "TASK COMMAND FAILED: {task["category"]} '
                        f'batch={task["batch"]} mode={task["mode"]}" >&2'
                    ),
                    "",
                ]
            )
        script = output / f"remaining-rerun-worker-{worker}.sh"
        script.write_text("\n".join(lines), encoding="utf-8", newline="\n")
        script.chmod(0o755)


def write_start_script(output: Path) -> None:
    text = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        ROOT="$(cd "$PACKAGE_DIR/../.." && pwd)"
        cd "$ROOT"

        if pgrep -a -u "$USER" -f 'scripts/run_owasp_fspec.py run|qilin-FD.jar run' >/dev/null; then
          echo "Existing OWASP/Qilin workers were found; refusing to start duplicates." >&2
          pgrep -a -u "$USER" -f 'scripts/run_owasp_fspec.py run|qilin-FD.jar run' >&2
          exit 2
        fi

        mkdir -p worker-logs worker-pids
        for script in "$PACKAGE_DIR"/remaining-rerun-worker-*.sh; do
          name="$(basename "$script" .sh)"
          nohup bash "$script" > "worker-logs/${name}.log" 2>&1 &
          echo $! > "worker-pids/${name}.pid"
          echo "started $name pid=$!"
        done
        """
    )
    path = output / "start-workers.sh"
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def write_readme(
    output: Path,
    source_status: Path,
    rows: list[dict[str, str]],
    tasks: list[dict[str, str | int]],
    workers: int,
    heap: str,
    timeout: int,
    process_timeout: int,
) -> None:
    try:
        source_status_display = source_status.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        source_status_display = str(source_status.resolve())
    paired = sum(row["pairedCompleted"].lower() == "true" for row in rows)
    paired_tests = sum(
        len([test for test in row["tests"].split(";") if test])
        for row in rows
        if row["pairedCompleted"].lower() == "true"
    )
    reasons = Counter(str(task["previousReason"]) for task in tasks)
    reason_lines = "\n".join(
        f"- `{reason}`: {count}" for reason, count in reasons.most_common()
    )
    text = f"""# OWASP/FlowDroid Ubuntu rerun package

This package was generated from the local `{source_status_display}` snapshot.
The exact source snapshot is included as `source-run-status-1o.csv`.

## Snapshot

- Total batches: {len(rows)}
- Expected configuration runs: {len(rows) * 2}
- Completed pairs: {paired}
- Paired test cases: {paired_tests}
- Exact failed-side tasks in this package: {len(tasks)}
- Workers: {workers}
- Heap per JVM: `{heap}`
- FlowDroid timeout: {timeout} seconds
- Full-process timeout: {process_timeout} seconds

Failure-side breakdown:

{reason_lines}

## Install

Extract the ZIP into the existing qilin-FD root:

```bash
cd ~/repo/qilin-FD
unzip /path/to/{output.name}.zip
(cd rerun/{output.name} && sha256sum -c SHA256SUMS)
```

The archive creates `rerun/{output.name}/`. It does not overwrite program JARs,
the benchmark, raw results, or existing logs.

## Start

```bash
cd ~/repo/qilin-FD
bash rerun/{output.name}/start-workers.sh
```

Every task checks its current raw result before running. A side that has already
completed successfully is skipped, so restarting these worker scripts is safe.
`--force` is used only for an exact side that is still missing or invalid.

For a high-memory retry after the default pass:

```bash
HEAP=128g FLOWDROID_TIMEOUT=21600 PROCESS_TIMEOUT=43200 \
  bash rerun/{output.name}/start-workers.sh
```

## Monitor

One snapshot:

```bash
python3 rerun/{output.name}/check_progress.py
```

Refresh every five minutes:

```bash
python3 rerun/{output.name}/check_progress.py --watch 300
```

Worker logs:

```bash
tail -f worker-logs/remaining-rerun-worker-*.log
```

## Completion target

The final target is:

```text
Completed batch pairs     : 851 / 851
Paired configuration runs : 1702
Paired OWASP test cases   : 1698
Failed sides to rerun     : 0
```
"""
    (output / "README-UBUNTU.md").write_text(
        text, encoding="utf-8", newline="\n"
    )


def write_checksums(output: Path) -> None:
    entries = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(f"{sha256(path)}  {path.name}")
    (output / "SHA256SUMS").write_text(
        "\n".join(entries) + "\n", encoding="utf-8", newline="\n"
    )


def write_archive(output: Path) -> Path:
    archive = output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(output.iterdir(), key=lambda item: item.name):
            if path.is_file():
                bundle.write(path, Path("rerun") / output.name / path.name)
    return archive


def main() -> None:
    args = parse_args()
    if args.workers <= 0:
        raise ValueError("--workers must be positive")
    if not args.status.exists():
        raise FileNotFoundError(args.status)
    if not SUMMARIZER.exists():
        raise FileNotFoundError(SUMMARIZER)

    rows = read_rows(args.status)
    tasks = build_tasks(rows, args.workers)
    args.output.mkdir(parents=True, exist_ok=True)

    write_manifest(args.output / f"rerun-manifest-{args.pta}.csv", tasks)
    shutil.copy2(
        args.status, args.output / f"source-run-status-{args.pta}.csv"
    )
    (args.output / "run_one_if_needed.py").write_text(
        helper_source(), encoding="utf-8", newline="\n"
    )
    (args.output / "run_one_if_needed.py").chmod(0o755)
    (args.output / "check_progress.py").write_text(
        progress_source(), encoding="utf-8", newline="\n"
    )
    (args.output / "check_progress.py").chmod(0o755)
    shutil.copy2(SUMMARIZER, args.output / SUMMARIZER.name)
    write_worker_scripts(
        args.output,
        tasks,
        args.workers,
        args.heap,
        args.timeout,
        args.process_timeout,
        args.pta,
    )
    write_start_script(args.output)
    write_readme(
        args.output,
        args.status,
        rows,
        tasks,
        args.workers,
        args.heap,
        args.timeout,
        args.process_timeout,
    )
    write_checksums(args.output)
    archive = write_archive(args.output)

    print(f"Generated tasks: {len(tasks)}")
    print(f"Workers: {args.workers}")
    print(f"Package directory: {args.output}")
    print(f"Archive: {archive}")
    print(f"Archive SHA-256: {sha256(archive)}")


if __name__ == "__main__":
    main()
