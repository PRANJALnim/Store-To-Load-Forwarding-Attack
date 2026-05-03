# Store-to-Load Forwarding Side-Channel Attack on RISC-V

## Overview

This repository implements a proof-of-concept micro-architectural attack on
RISC-V out-of-order cores using the gem5 simulator. It demonstrates how
store-to-load forwarding (STLF) in the RISC-V load-store unit can be abused
in speculative execution to leak sensitive data through cache timing.

The attack is implemented in `stlf_attack.c`, and the simulation is driven by
`run_stlf.py` with a small launcher wrapper in `run_stlf_launcher.py`.
The target environment is gem5 SE mode with a RISC-V O3 CPU.

## How the Attack Works

### Threat model

The attack assumes an attacker can execute code on the same processor and
use a covert timing channel to observe cache state. The attack runs entirely
in user mode inside the gem5 simulator, so it does not require privileged
access.

### Attack principle

Store-to-load forwarding allows a load to obtain data directly from a pending
store in the store buffer before the store updates the cache. For performance,
the CPU may perform an early address alias check using only the page offset.
If a load and an older store share the same page offset but reside on different
pages, the CPU may speculatively forward data incorrectly.

During this transient window, the wrong or secret-dependent value can be used
to index a probe array and warm a specific cache line. After the pipeline
squashes the mis-speculated execution, the architecturally visible state is
restored, but the cache state remains affected. The attacker recovers the
secret by timing accesses to the probe array.

### Attack flow

For each secret byte, the code performs:

1. Flush the probe array from L1/L2 by reading a large eviction buffer.
2. Evict the target address from L1 so the subsequent load stalls.
3. Write a controlled value to an aliasing address in the store buffer.
4. Execute the gadget that loads the secret byte and touches the probe array.
5. Scan the probe array in pseudo-random order and time each access.
6. Aggregate votes and choose the most likely byte value.

The probe array uses `PROBE_STRIDE = PAGE_SIZE + CACHE_LINE_SIZE` so each
possible byte index maps to a different L1 cache set and avoids self-eviction
during scanning.

## Repository Contents

- `stlf_attack.c` — Attack implementation in C with RISC-V inline assembly.
- `run_stlf.py` — gem5 configuration script for RISC-V O3 SE mode.
- `run_stlf_launcher.py` — Wrapper used by the Makefile to invoke gem5.
- `Makefile` — Build and run targets.
- `generate_graphs.py` — Generates plots from timing and histogram CSV output.
- `output.txt` — Example attack output from gem5.
- `timing_data.csv` — Calibration latency measurements.
- `byte_histogram_*.csv` — Per-byte vote histograms.
- `plots/` — Graphs generated from the CSV files.
- `m5out/` — gem5 simulation output and statistics.

## Prerequisites

- RISC-V cross-compiler toolchain.
- gem5 built with RISC-V support.
- Python 3 for graph generation.

On Ubuntu/Debian:

```bash
sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu python3
```

Build gem5 for RISC-V:

```bash
git clone https://gem5.googlesource.com/public/gem5
cd gem5
scons build/RISCV/gem5.opt -j$(nproc)
```

## Build

From this directory:

```bash
make
```

This compiles the `stlf_attack` binary with `-O1` and the configured
`TRIALS` and `SPIN_COUNT` values.

> Note: `-O1` is chosen intentionally. Higher optimization levels may move or
> eliminate the speculative probe access, breaking the covert channel.

## Run

Use the Makefile to run the attack in gem5:

```bash
make GEM5_HOME=/path/to/gem5 run
```

If your gem5 binary is located elsewhere:

```bash
make GEM5=/path/to/gem5/build/RISCV/gem5.opt run
```

If your cross compiler has a different name:

```bash
make CC_RISCV=<your-riscv-gcc> run
```

### Tuning

- Increase trial count for better accuracy:

```bash
make GEM5_HOME=/path/to/gem5 TRIALS=2000 run
```

- Increase the speculative window if the signal is weak:

```bash
make GEM5_HOME=/path/to/gem5 TRIALS=1000 SPIN_COUNT=1000 run
```

### Direct invocation

```bash
/path/to/gem5.opt run_stlf_launcher.py \
  --binary ./stlf_attack \
  --l1d_size 32kB \
  --l1i_size 32kB \
  --l2_size 256kB \
  --lsq_depth 16 \
  --cpu_freq 2GHz
```

## Output

- `output.txt` — attack summary and recovered bytes.
- `timing_data.csv` — hit/miss latency calibration data.
- `byte_histogram_*.csv` — vote counts for each recovered byte.
- `plots/` — generated graphs.
- `m5out/stats.txt` — full gem5 simulation statistics.

Generate graphs with:

```bash
make graphs
```


## Context

This implementation explores whether store-to-load forwarding in RISC-V
out-of-order cores can be manipulated to leak secrets in a way similar to
Spectre and Meltdown-style micro-architectural attacks.
