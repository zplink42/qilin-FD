#!/usr/bin/env python3
"""Run the OWASP/FlowDroid downstream case-study experiment.

This is a thin, paper-facing wrapper around ``scripts/run_owasp_fspec.py``.
It keeps the actual benchmark preparation and Qilin-FlowDroid invocation in the
main project script, but adds a convenient multi-worker interface for the
resource-bounded downstream case study.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_owasp_fspec.py"


def base_command(args: argparse.Namespace, action: str) -> list[str]:
    command = [
        sys.executable,
        "-u",
        str(RUNNER),
        action,
        "--categories",
        args.categories,
        "--modes",
        args.modes,
        "--pta",
        args.pta,
        "--heap",
        args.heap,
        "--timeout",
        str(args.timeout),
        "--process-timeout",
        str(args.process_timeout),
        "--batch-size",
        str(args.batch_size),
    ]
    if args.force:
        command.append("--force")
    if args.refresh_qilin and action in {"prepare", "all"}:
        command.append("--refresh-qilin")
    return command


def run_checked(command: list[str], dry_run: bool) -> None:
    print("+", " ".join(command), flush=True)
    if not dry_run:
        subprocess.run(command, cwd=ROOT, check=True)


def run_sharded(args: argparse.Namespace) -> None:
    timestamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = ROOT / "worker-logs" / f"owasp-downstream-{timestamp}"
    log_dir.mkdir(parents=True, exist_ok=True)

    processes: list[tuple[int, subprocess.Popen[bytes], object]] = []
    try:
        for index in range(args.workers):
            command = base_command(args, "run")
            command.extend(
                [
                    "--shard-count",
                    str(args.workers),
                    "--shard-index",
                    str(index),
                ]
            )
            log_path = log_dir / f"worker-{index}.log"
            print("+", " ".join(command), ">", log_path, flush=True)
            if args.dry_run:
                continue
            log_stream = log_path.open("wb")
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
            )
            processes.append((index, process, log_stream))

        if args.dry_run:
            return

        failures: list[tuple[int, int]] = []
        for index, process, log_stream in processes:
            return_code = process.wait()
            log_stream.close()
            if return_code != 0:
                failures.append((index, return_code))

        if failures:
            formatted = ", ".join(f"worker {i}: {code}" for i, code in failures)
            raise SystemExit(f"One or more workers failed: {formatted}")
    except KeyboardInterrupt:
        for _, process, _ in processes:
            process.terminate()
        raise
    finally:
        for _, _, log_stream in processes:
            try:
                log_stream.close()
            except Exception:
                pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the OWASP Benchmark Java downstream FlowDroid case study."
    )
    parser.add_argument(
        "action",
        choices=("prepare", "run", "compare", "all"),
        nargs="?",
        default="run",
    )
    parser.add_argument("--categories", default="all")
    parser.add_argument("--modes", default="baseline,fspec")
    parser.add_argument("--pta", default="1o")
    parser.add_argument("--heap", default="32g")
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--process-timeout", type=int, default=14400)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--refresh-qilin", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.workers <= 0:
        raise SystemExit("--workers must be positive")

    if args.action in {"prepare", "all"}:
        run_checked(base_command(args, "prepare"), args.dry_run)

    if args.action in {"run", "all"}:
        if args.workers == 1:
            run_checked(base_command(args, "run"), args.dry_run)
        else:
            run_sharded(args)

    if args.action in {"compare", "all"}:
        run_checked(base_command(args, "compare"), args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
