#!/usr/bin/env python3
"""Plot the aggregate FlowDroid downstream case-study summary.

The paper-facing figure follows the optimization effect from projected call
edges, through IFDS propagation work, to end-to-end runtime. Finding
preservation is reported in the accompanying text because the two modes have
identical findings on the paired completed runs.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAPER_DATA = ROOT / "reports" / "owasp-paper" / "data"

# Match the muted palette and bar treatment used by the main paper figures.
PAPER_PALETTE = ("#4C72B0", "#DD8452")
BAR_ALPHA = 0.85
BAR_EDGE_COLOR = "white"
BAR_EDGE_WIDTH = 0.5
GRID_LINE_WIDTH = 0.5
GRID_ALPHA = 0.4

def as_float(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    return float(value) if value not in {"", None} else 0.0


def load_aggregate(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    try:
        return next(row for row in rows if row["category"] == "ALL")
    except StopIteration as error:
        raise ValueError(f"Missing aggregate ALL row in {path}") from error


def plot(summary_path: Path, output_dir: Path, stem: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 7,
            "axes.labelsize": 8,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "legend.fontsize": 7,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    all_row = load_aggregate(summary_path)
    # Aggregate paired-subset outcomes. The three metrics form the causal chain
    # from a smaller projected call graph, through less IFDS propagation work,
    # to lower end-to-end runtime. Normalizing makes unlike units comparable.
    metrics = [
        ("Call edges", "qilinCallEdgesProjectedMean"),
        ("IFDS props.", "flowDroidEdgePropagationCount"),
        ("Runtime", "totalRuntimeMs"),
    ]
    aggregate_labels = [label for label, _ in metrics]
    baseline = [1.0] * len(metrics)
    fspec = [
        as_float(all_row, f"fspec_{key}") / as_float(all_row, f"baseline_{key}")
        for _, key in metrics
    ]
    x_positions = range(len(aggregate_labels))
    width = 0.36
    fig, axis = plt.subplots(figsize=(5.0, 2.5))
    axis.bar(
        [x - width / 2 for x in x_positions],
        baseline,
        width=width,
        label="Baseline",
#         color="#E6E6E6",
        color=PAPER_PALETTE[0],
        alpha=BAR_ALPHA,
        edgecolor=BAR_EDGE_COLOR,
        linewidth=BAR_EDGE_WIDTH,
    )
    axis.bar(
        [x + width / 2 for x in x_positions],
        fspec,
        width=width,
        label="FSpec",
        color=PAPER_PALETTE[1],
        alpha=BAR_ALPHA,
        edgecolor=BAR_EDGE_COLOR,
        linewidth=BAR_EDGE_WIDTH,
    )
    axis.set_ylabel("Normalized to baseline", fontsize=9)
#     axis.set_xlabel("Aggregate metric", fontsize=9)
    axis.set_xticks(list(x_positions))
    axis.set_xticklabels(aggregate_labels, rotation=0, ha="center")
    axis.set_ylim(0, 1.15)
    axis.grid(
        axis="y",
        linestyle="--",
        linewidth=GRID_LINE_WIDTH,
        alpha=GRID_ALPHA,
    )
    axis.tick_params(axis="both", labelsize=8)
    axis.legend(frameon=False, fontsize=8, loc="upper right", ncol=2, columnspacing=0.9, handlelength=1.4)
    for x, value in zip(x_positions, fspec):
        delta = (value - 1.0) * 100.0
        axis.text(
            x + width / 2,
            value + 0.03,
            f"{delta:+.1f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    fig.tight_layout(pad=0.45)

    output_dir.mkdir(parents=True, exist_ok=True)
    for suffix in ("pdf", "png"):
        path = output_dir / f"{stem}.{suffix}"
        fig.savefig(path, bbox_inches="tight", pad_inches=0.02, dpi=300)
        print(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot paired OWASP downstream deltas.")
    parser.add_argument(
        "--summary",
        default="results/owasp/analysis/paired-summary-1o.csv",
        help="Path to paired-summary-*.csv",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/owasp-paper/data",
        help="Directory for generated figures",
    )
    parser.add_argument("--stem", default="FlowDroid")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_path = Path(args.summary)
    if not summary_path.is_absolute():
        summary_path = ROOT / summary_path
    if not summary_path.exists():
        fallback = PAPER_DATA / summary_path.name
        if fallback.exists():
            print(f"Using precomputed paper data: {fallback}")
            summary_path = fallback
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    plot(summary_path, output_dir, args.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
