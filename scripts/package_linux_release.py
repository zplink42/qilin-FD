#!/usr/bin/env python3
"""Build reproducible Linux runtime and precompiled OWASP release archives."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = ROOT / "release"
RUNTIME_ROOT = RELEASE_ROOT / "linux-runtime"
BENCHMARK_ROOT = RELEASE_ROOT / "owasp-benchmark-qilinfd-v1.2"

QILIN_JAR = "Qilin-0.10.10.3-SNAPSHOT.jar"
FLOWDROID_JAR = "soot-infoflow-2.14.1.jar"


def gradle_wrapper() -> list[str]:
    wrapper = ROOT / ("gradlew.bat" if shutil.which("cmd.exe") else "gradlew")
    if wrapper.suffix == ".bat":
        return [str(wrapper)]
    return [str(wrapper)] if wrapper.stat().st_mode & 0o111 else ["sh", str(wrapper)]


def run_build() -> None:
    subprocess.run(
        [
            *gradle_wrapper(),
            "stageFlowDroidJar",
            "portableJar",
            "smokeJar",
            "owaspBenchmarkFullJar",
            "stageOwaspBenchmarkFullLibraries",
            "--no-daemon",
        ],
        cwd=ROOT,
        check=True,
    )


def reset_directory(path: Path) -> None:
    resolved = path.resolve()
    release = RELEASE_ROOT.resolve()
    if resolved == release or release not in resolved.parents:
        raise RuntimeError(f"Refusing to reset unexpected path: {resolved}")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise RuntimeError(f"Required release input is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise RuntimeError(f"Required release input is missing: {source}")
    shutil.copytree(source, destination, dirs_exist_ok=True)


def write_checksums(root: Path, filename: str) -> None:
    lines: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name == filename:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root).as_posix()}")
    (root / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_zip(source_root: Path, destination: Path) -> None:
    if destination.exists():
        destination.unlink()
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as archive:
        for path in sorted(item for item in source_root.rglob("*") if item.is_file()):
            archive.write(path, path.relative_to(source_root).as_posix())


def package_runtime() -> None:
    reset_directory(RUNTIME_ROOT)
    copy_file(ROOT / "build" / "portable" / "qilin-FD.jar", RUNTIME_ROOT / "qilin-FD.jar")
    copy_file(
        ROOT / "lib" / "qilin" / QILIN_JAR,
        RUNTIME_ROOT / "lib" / "qilin" / QILIN_JAR,
    )
    copy_file(
        ROOT / "lib" / "flowdroid" / FLOWDROID_JAR,
        RUNTIME_ROOT / "lib" / "flowdroid" / FLOWDROID_JAR,
    )
    write_checksums(RUNTIME_ROOT, "SHA256SUMS-runtime")
    make_zip(RUNTIME_ROOT, RELEASE_ROOT / "qilin-fd-linux-runtime.zip")


def package_benchmark() -> None:
    reset_directory(BENCHMARK_ROOT)
    copy_file(
        ROOT / "scripts" / "run_owasp_fspec.py",
        BENCHMARK_ROOT / "scripts" / "run_owasp_fspec.py",
    )
    copy_file(
        ROOT / "benchmarks" / "config" / "owasp-benchmark-qilin.properties",
        BENCHMARK_ROOT / "benchmarks" / "config" / "owasp-benchmark-qilin.properties",
    )
    copy_file(
        ROOT / "benchmarks" / "config" / "smoke-qilin.properties",
        BENCHMARK_ROOT / "benchmarks" / "config" / "smoke-qilin.properties",
    )
    copy_tree(
        ROOT / "benchmarks" / "definitions",
        BENCHMARK_ROOT / "benchmarks" / "definitions",
    )
    copy_tree(
        ROOT / "benchmarks" / "JREs" / "jre1.8.0_121_debug",
        BENCHMARK_ROOT / "benchmarks" / "JREs" / "jre1.8.0_121_debug",
    )
    for filename in (
        "batch-manifest.csv",
        "expected-taint-cases.csv",
        "owasp-benchmark-java-v1.2-analysis.jar",
    ):
        copy_file(
            ROOT / "build" / "owasp-benchmark" / filename,
            BENCHMARK_ROOT / "build" / "owasp-benchmark" / filename,
        )
    copy_tree(
        ROOT / "build" / "owasp-benchmark" / "lib",
        BENCHMARK_ROOT / "build" / "owasp-benchmark" / "lib",
    )
    copy_file(
        ROOT / "build" / "smoke" / "qilinfd-smoke.jar",
        BENCHMARK_ROOT / "build" / "smoke" / "qilinfd-smoke.jar",
    )
    copy_file(
        ROOT / "docs" / "linux-owasp-execution.md",
        BENCHMARK_ROOT / "README-LINUX.md",
    )
    copy_file(
        ROOT / "reports" / "owasp-fspec-preliminary.md",
        BENCHMARK_ROOT / "reports" / "owasp-fspec-preliminary.md",
    )
    write_checksums(BENCHMARK_ROOT, "SHA256SUMS-benchmark")
    make_zip(
        BENCHMARK_ROOT,
        RELEASE_ROOT / "owasp-benchmark-qilinfd-v1.2.zip",
    )


def main() -> None:
    RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
    run_build()
    package_runtime()
    package_benchmark()
    for archive in (
        RELEASE_ROOT / "qilin-fd-linux-runtime.zip",
        RELEASE_ROOT / "owasp-benchmark-qilinfd-v1.2.zip",
    ):
        print(f"{archive} ({archive.stat().st_size / 1024 / 1024:.1f} MiB)")


if __name__ == "__main__":
    main()
