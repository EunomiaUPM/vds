"""Draw the paper's cost-against-history figure (bench_cost.pdf).

1. Run the benchmark:        cargo bench --bench benchmark -- cost_vs_history
2. Install matplotlib once:  pip install matplotlib
3. Run this script:          python scripts/plot_bench_cost.py

It reads the criterion estimates of the `cost_vs_history` group under
target/criterion/ and writes bench_cost.pdf at the repository root. It can be
run from any directory.
"""
import json
import os
import sys

try:
    import matplotlib
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is not installed for this Python. Install it with:\n"
             f"    {sys.executable} -m pip install matplotlib")

# Embed TrueType (Type 42) fonts instead of matplotlib's default Type 3,
# which journal production systems may reject.
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["font.size"] = 8

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "target", "criterion", "cost_vs_history")
OUT = os.path.join(ROOT, "bench_cost.pdf")
LENS = [1, 8, 64, 256]


def mean_us(group, n):
    path = os.path.join(BASE, group, str(n), "new", "estimates.json")
    if not os.path.exists(path):
        sys.exit(f"Missing {path}.\nRun the benchmark first:\n"
                 "    cargo bench --bench benchmark -- cost_vs_history")
    with open(path) as fh:
        return json.load(fh)["mean"]["point_estimate"] / 1000.0


onboarding = [mean_us("onboarding", n) for n in LENS]
verify = [mean_us("verify", n) for n in LENS]

# Okabe-Ito colours, readable by colour-blind readers.
BLUE, ORANGE = "#0072B2", "#E69F00"

fig, ax = plt.subplots(figsize=(3.4, 2.5))
ax.plot(LENS, onboarding, marker="o", markersize=4, color=BLUE, label="Onboarding (validate chain)")
ax.plot(LENS, verify, marker="s", markersize=4, color=ORANGE, label="Per-verification (warm)")
ax.set_xscale("log", base=2)
ax.set_yscale("log")
# Head-room above the top point so the legend does not cover the data.
ax.set_ylim(top=max(onboarding) * 3)
ax.set_xticks(LENS)
ax.set_xticklabels([str(n) for n in LENS])
# Unlabelled minor ticks at the other powers of two, for the dotted grid.
ax.set_xticks([2, 4, 16, 32, 128], minor=True)
ax.tick_params(axis="x", which="minor", labelbottom=False)
ax.set_xlabel("History length (versions)")
ax.set_ylabel(r"Time ($\mu$s)")
ax.grid(True, which="both", linestyle=":", linewidth=0.5, alpha=0.6)
ax.legend(loc="upper left", frameon=False)
fig.tight_layout()
fig.savefig(OUT)

for n, o, v in zip(LENS, onboarding, verify):
    print(f"V = {n:3d}   onboarding {o:10.1f} us   per-verification {v:6.1f} us")
print(f"wrote {OUT}")
