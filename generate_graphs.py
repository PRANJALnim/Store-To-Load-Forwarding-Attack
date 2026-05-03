"""
generate_graphs.py

Produces two plots from the measurement data collected during the gem5 run:

  graph1_timing_histogram.png  -- distribution of L1 hit and cache miss
                                   latencies used to calibrate the threshold
  graph2_secret_histogram.png  -- vote counts across all 256 possible byte
                                   values after 50 attack trials

Both CSV files (timing_data.csv, byte_histogram.csv) come directly from the
gem5 simulation; no synthetic data is used.
"""

import sys
import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.family":    "DejaVu Sans",
    "font.size":      12,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "figure.facecolor": "white",
    "axes.facecolor":   "white",
    "axes.spines.top":  False,
    "axes.spines.right":False,
})


def load_csv(path):
    if not os.path.exists(path):
        print(f"[error] {path} not found. Run the gem5 simulation first.")
        sys.exit(1)
    return pd.read_csv(path)


def resolve_input_path(filename, input_dir=None):
    if os.path.isabs(filename) and os.path.exists(filename):
        return filename

    candidates = []
    if input_dir:
        candidates.append(os.path.join(input_dir, filename))
    candidates.append(filename)
    candidates.append(os.path.join("m5out", filename))

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return os.path.join(input_dir, filename) if input_dir else filename


def plot_timing(df):
    hits   = df[df["type"] == "hit"]["latency_cycles"]
    misses = df[df["type"] == "miss"]["latency_cycles"]

    hit_mean  = hits.mean()
    miss_mean = misses.mean()
    threshold = hit_mean + (miss_mean - hit_mean) * 2 / 5

    fig, ax = plt.subplots(figsize=(8, 5))

    ax.hist(hits,   bins=15, alpha=0.65, color="#1f77b4",
            edgecolor="white", linewidth=0.5, label="L1 hit")
    ax.hist(misses, bins=15, alpha=0.65, color="#d62728",
            edgecolor="white", linewidth=0.5, label="Cache miss (L2)")

    ax.axvline(threshold, color="#2ca02c", linestyle="--", linewidth=1.8,
               label=f"Threshold ({int(threshold)} cycles)")

    ax.set_title("Cache Timing Distribution")
    ax.set_xlabel("Latency (cycles)")
    ax.set_ylabel("Frequency")
    ax.legend(frameon=False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    fig.savefig("plots/graph1_timing_histogram.png", dpi=300)
    plt.close(fig)

    print(f"  L1 hit mean   : {hit_mean:.1f} cycles")
    print(f"  Miss mean     : {miss_mean:.1f} cycles")
    print(f"  Threshold     : {threshold:.1f} cycles")


def plot_secret(df):
    best_idx  = int(df["hits"].idxmax())
    best_byte = int(df.loc[best_idx, "byte_value"])
    best_hits = int(df.loc[best_idx, "hits"])

    colors = ["#aec7e8"] * len(df)
    colors[best_idx] = "#d62728"

    fig, ax = plt.subplots(figsize=(11, 5))

    ax.bar(df["byte_value"], df["hits"], color=colors, width=1.0)

    label_char = chr(best_byte) if 32 <= best_byte <= 126 else "?"
    ax.annotate(
        f"0x{best_byte:02X} ('{label_char}')  {best_hits} votes",
        xy=(best_byte, best_hits),
        xytext=(best_byte + 18, best_hits * 0.85),
        arrowprops=dict(arrowstyle="->", color="black", lw=1.2),
        fontsize=11,
    )

    ax.set_title("Probe Array Vote Histogram (50 trials)")
    ax.set_xlabel("Byte value (0-255)")
    ax.set_ylabel("Vote count")
    ax.set_xlim(-1, 256)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    fig.savefig("plots/graph2_secret_histogram.png", dpi=300)
    plt.close(fig)

    print(f"  Recovered byte: 0x{best_byte:02X} ('{label_char}') with {best_hits} votes")


def plot_secret_to_file(df, out_path, title_suffix=""):
    best_idx  = int(df["hits"].idxmax())
    best_byte = int(df.loc[best_idx, "byte_value"])
    best_hits = int(df.loc[best_idx, "hits"])

    colors = ["#aec7e8"] * len(df)
    colors[best_idx] = "#d62728"

    fig, ax = plt.subplots(figsize=(11, 5))

    ax.bar(df["byte_value"], df["hits"], color=colors, width=1.0)

    label_char = chr(best_byte) if 32 <= best_byte <= 126 else "?"
    ax.annotate(
        f"0x{best_byte:02X} ('{label_char}')  {best_hits} votes",
        xy=(best_byte, best_hits),
        xytext=(best_byte + 18, best_hits * 0.85),
        arrowprops=dict(arrowstyle="->", color="black", lw=1.2),
        fontsize=11,
    )

    ax.set_title(f"Probe Array Vote Histogram (50 trials){title_suffix}")
    ax.set_xlabel("Byte value (0-255)")
    ax.set_ylabel("Vote count")
    ax.set_xlim(-1, 256)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)

    print(f"  Recovered byte: 0x{best_byte:02X} ('{label_char}') with {best_hits} votes")


def main():
    parser = argparse.ArgumentParser(description="Generate graphs from gem5 CSV outputs")
    parser.add_argument("--input-dir", default=None, help="Directory containing the CSV files")
    parser.add_argument("--timing", default="timing_data.csv", help="Timing CSV filename or path")
    parser.add_argument("--byte", default="byte_histogram.csv", help="Byte histogram CSV filename or path")
    args = parser.parse_args()

    os.makedirs("plots", exist_ok=True)

    print("Loading measurement data...")
    timing_path = resolve_input_path(args.timing, input_dir=args.input_dir)
    df_timing = load_csv(timing_path)

    byte_paths = []
    for i in range(4):
        p = resolve_input_path(f"byte_histogram_{i}.csv", input_dir=args.input_dir)
        if os.path.exists(p):
            byte_paths.append((i, p))

    df_byte = None
    if not byte_paths:
        byte_path = resolve_input_path(args.byte, input_dir=args.input_dir)
        df_byte = load_csv(byte_path)

    print("\nGenerating graph1_timing_histogram.png")
    plot_timing(df_timing)

    print("\nGenerating graph2_secret_histogram.png")
    if byte_paths:
        for i, p in byte_paths:
            df = load_csv(p)
            print(f"  Using {p}")
            plot_secret_to_file(df, f"plots/graph2_secret_histogram_byte{i}.png", title_suffix=f" (byte {i})")
    else:
        plot_secret(df_byte)

    print("\nDone. Plots written to plots/")


if __name__ == "__main__":
    main()
