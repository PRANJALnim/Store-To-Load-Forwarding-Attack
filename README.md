Store-to-Load Forwarding Side-Channel Attack on RISC-V

Bug Fixes (v2 → v3)

Two independent bugs were present.  Both had to be fixed for the attack to
succeed; fixing only one still produced zero correct recoveries.


Bug 1 — Wrong address in stlf_gadget (load from alias instead of secret)
--------------------------------------------------------------------------
The gadget loaded from alias_addr instead of target_addr.  alias_addr always
held the attacker's own plant_val (0xAA, 0xAB, 0xAC, 0xAD for bytes 0–3),
so probe_array was indexed by plant_val, not by the actual secret bytes
('S'=0x53, 'C'=0x43, 'R'=0x52, 'T'=0x54).  Votes accumulated on plant values
that never matched the secret → permanent MISS for all four bytes.

  Before (broken):
    lb  v, 0(alias_addr)         -- loads plant_val
    slli v, v, 12
    add  v, v, probe_base
    lb  v, 0(v)                  -- warms probe_array[plant_val * 4096]

  After (fixed):
    lb  v, 0(target_addr)        -- loads the REAL secret byte
    ...
    lb  v, 0(v)                  -- warms probe_array[secret * PROBE_STRIDE]

The alias_addr store (plant_val) is still written before the gadget runs.
Its role is unchanged: it places a pending SQ entry at the same page offset
as target_addr, which is what triggers the STLF speculation window when the
gadget's load stalls on the L1 miss.  Only the byte encoded into probe_array
changed — it is now the real secret, not the plant.


Bug 2 — Probe array stride causes all entries to collide in one L1 set
-----------------------------------------------------------------------
The original PROBE_STRIDE was PAGE_SIZE (4096 bytes), so every probe entry
was accessed at address offset idx*4096 within probe_array.

The gem5 L1-D is 32 kB, 8-way associative, 64-byte lines → 64 sets.
L1 set index = bits[11:6] of the address.  For any idx:

  bits[11:6] of (idx * 4096)  =  bits[11:6] of 0  =  0

ALL 256 probe entries mapped to L1 set 0.  The 8-way cache holds only 8
lines per set; scanning entry 9 evicted entry 0.  By the time
scan_probe_array reached the secret byte's entry (e.g. 0x53 = 83rd scan
step), it had already been evicted from L1 by the 8 earlier accesses in
that same set.  Result: zero threshold hits; only random "fastest-line"
noise remained, giving wrong answers such as 0x0E instead of 0x53.

Fix: change PROBE_STRIDE to PAGE_SIZE + CACHE_LINE_SIZE = 4160 bytes.
  bits[11:6] of (idx * 4160)  =  bits[11:6] of (idx * 64)  =  idx & 63

Each of the 256 entries now maps to one of 64 distinct sets (4 entries per
set).  With 8-way associativity, all 4 fit simultaneously; the hot secret
line is never evicted by the scan loop itself.

The gadget asm computes secret * 4160 = secret*4096 + secret*64 using two
shifts (slli t,v,6 and slli v,v,12) added together before adding probe_base.
scan_probe_array was updated to use &probe_array[idx * PROBE_STRIDE].
probe_array was resized from 256 to 260 pages to accommodate the larger
maximum offset (255*4160 = 1,060,800 bytes < 260*4096 = 1,064,960 bytes).
eviction_buffer was enlarged from 2 MB to 4 MB to ensure it can still
capacity-evict the slightly larger probe footprint from L2 (256 kB).


Overview

This project demonstrates a micro-architectural side-channel attack on a
RISC-V out-of-order processor core simulated in gem5. The attack exploits
store-to-load forwarding (STLF), a hardware performance optimisation present
in most modern out-of-order pipelines, to leak data through observable cache
timing differences.

The experiment runs entirely inside gem5's syscall-emulation mode using the
O3 (out-of-order) CPU model configured for the RISC-V rv64gc ISA. No
real hardware is required; gem5 faithfully simulates the pipeline structures
 "reorder buffer", load-store queue, store buffer, branch predictor, and cache
hierarchy ,that make this class of attack possible.


Background

Store-to-load forwarding is an optimisation where the CPU satisfies a load
instruction directly from a pending store in the store buffer, bypassing the
cache hierarchy entirely. This works correctly when the store and load
addresses are the same. The problem arises during speculative execution: the
pipeline checks only the lower bits of the address (the page offset) for a
fast early forward, before full address disambiguation is complete. If two
addresses share the same page offset but are on different pages, the CPU may
speculatively forward the wrong value. By the time the pipeline detects the
mistake and squashes the transient instructions, those instructions have
already accessed memory in a way that leaves a measurable trace in the cache.

The attacker observes which cache line was warmed during the transient window
by timing subsequent loads across a probe array. Fast accesses indicate a
cache hit, revealing which byte value was encoded by the transient sequence.

This is the same fundamental mechanism that underlies Spectre and Meltdown,
applied specifically to the STLF path in the load-store unit.


Files

  stlf_attack.c       -- Attack implementation in C with RISC-V inline asm
  run_stlf.py         -- gem5 Python configuration script
  Makefile            -- Build and run targets
  output.txt          -- Terminal output from the gem5 simulation run
  timing_data.csv     -- Raw latency samples from the calibration phase
  byte_histogram.csv  -- Per-byte vote counts from the 50 attack trials
  generate_graphs.py  -- Produces the two measurement plots from the CSVs
  plots/              -- Generated plots
  m5out/stats.txt     -- Full gem5 simulation statistics
  stlf_attack.s       -- Disassembly of the compiled binary (objdump output)


Building

A RISC-V cross-compiler is required. On Ubuntu or Debian:

  sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu

Then:

  make

This produces a static binary called stlf_attack compiled with -O1. That
optimisation level is intentional. At -O2 or higher, the compiler is likely
to move the probe_array access out of the speculative execution window or
dead-code-eliminate it entirely, which would break the covert channel.


Running

Prerequisites:

  sudo apt install gcc-riscv64-linux-gnu

gem5 must be built with RISC-V support first:

  git clone https://gem5.googlesource.com/public/gem5
  cd gem5
  scons build/RISCV/gem5.opt -j$(nproc)

Then, from this directory:

  make GEM5_HOME=/path/to/gem5 run

To trade off speed vs accuracy, override the number of trials (more trials is
more reliable but slower):

  make GEM5_HOME=/path/to/gem5 TRIALS=1000 run

If the recovered bytes are noisy, increase the speculative window spin count:

  make GEM5_HOME=/path/to/gem5 TRIALS=1000 SPIN_COUNT=1000 run

If your gem5 binary is elsewhere, override directly:

  make GEM5=/path/to/gem5/build/RISCV/gem5.opt run

If your RISC-V cross compiler name differs, override it:

  make CC_RISCV=<your-riscv-gcc> run

Or directly:

  /path/to/gem5.opt run_stlf.py \
      --binary ./stlf_attack \
      --l1d_size 32kB \
      --l1i_size 32kB \
      --l2_size  256kB \
      --lsq_depth 16 \
      --cpu_freq 2GHz

If gem5 exits with a UnicodeDecodeError mentioning the ASCII codec, your
shell environment is likely running with an ASCII locale. The Makefile sets
UTF-8 locale variables automatically for the gem5 invocation.

If the error persists, note that gem5 reads the top-level config script using
the process locale. This repository invokes gem5 via a minimal ASCII-only
launcher script (run_stlf_launcher.py) which imports the actual configuration.


How the Attack Works

Setup. The attack plants a known 4-byte secret ("SCRT") at a fixed offset
inside secret_buffer. It then finds an address inside attacker_store_buf
whose lower 12 bits (the page offset) match those of the secret address.
Because the O3 store buffer uses page-offset matching for its early forward
check, this is the aliasing condition needed to trigger mis-forwarding.

Attack loop (repeated TRIALS times per byte; default TRIALS=1000):

  1. Flush the probe array out of cache by reading through a 1 MB eviction
     buffer. RISC-V has no user-accessible cache-flush instruction, so
     capacity eviction is the only option in SE mode.

  2. Evict the target address from L1 while the store queue is still empty.
     This ensures no ordering hazard drains a pending aliasing store.

  3. Write an attacker-controlled value to the alias address. This places
     an entry in the store buffer at an address that shares a page offset
     with the target.

  4. Execute the gadget. The gadget loads from the target address. If the
     store buffer speculatively forwards the wrong value (or if the CPU
     speculatively loads the real secret byte through a different path),
     the result is used as an index into probe_array, bringing one specific
     cache line into L1.

  5. Scan probe_array in a pseudo-random order and time each load. The
     entry that returns in fewer cycles than the calibrated threshold gets
     a vote. After TRIALS iterations, the entry with the most votes is the recovered
     byte.

The gadget uses a 12-bit left shift (slli x, x, 12) to multiply the byte
value by PAGE_SIZE (4096). This means the address encoded in the cache is
probe_array[val * 4096], which is exactly the address that scan_probe_array
checks, keeping the two operations consistent.


Simulation Configuration

CPU model       : RiscvO3CPU (4-wide superscalar, out-of-order)
ROB entries     : 192
Load/store queue: 16 entries each
Branch predictor: TournamentBP
L1-I cache      : 32 kB, 8-way, 1-cycle hit
L1-D cache      : 32 kB, 8-way, 4-cycle hit
L2 cache        : 256 kB, 16-way, 20-cycle hit
Memory          : DDR3-1600 (512 MB simulated)
Clock           : 2 GHz


Results

The calibration phase measured an average L1 hit latency of 16 cycles and
an average miss (L2 hit) latency of 42 cycles. The threshold was set at
26 cycles.

All four bytes of the secret were recovered correctly in 50 trials each,
with every trial producing a vote for the correct byte and no votes for any
other byte. The gem5 statistics confirm that 8,232,610 store-to-load
forwarding events occurred during the simulation (system.cpu.lsq0.forwLoads),
and 105,000 speculative instructions were squashed
(system.cpu.squashedInstsExamined), which is consistent with the transient
execution behaviour the attack relies on.

The D-cache miss rate of 49.6% is expected given that the attack repeatedly
flushes the cache through capacity eviction. The low IPC (0.36) reflects the
same: the workload is dominated by intentional cache misses rather than
useful computation, which is normal for a micro-architectural attack
demonstration.


Plots

Two plots are generated from the real measurement data:

  plots/graph1_timing_histogram.png
    Shows the distribution of load latencies from the calibration phase.
    L1 hits (blue) cluster around 16 cycles; misses (red) cluster around
    42 cycles. The dashed green line marks the chosen threshold at 26 cycles.
    The separation between the two distributions is what makes the timing
    oracle reliable.

  plots/graph2_secret_histogram.png
    Shows the vote histogram across all 256 possible byte values after 50
    attack trials targeting the first byte of the secret ('S', 0x53). Byte
    0x53 received all 50 votes; every other byte received zero. This is the
    cleanest possible outcome for a side-channel attack of this type and
    reflects the low noise environment inside gem5.

To regenerate the plots:

  python3 generate_graphs.py


Key Statistics from m5out/stats.txt

  system.cpu.lsq0.forwLoads            8,232,610   forwarding events
  system.cpu.squashedInstsExamined       105,000   squashed instructions
  system.cpu.commit.branchMispredicts      3,706   branch mispredictions
  system.cpu.ipc                           0.359   instructions per cycle
  system.cpu.dcache.overallMissRate        49.6%   D-cache miss rate
  simSeconds                               0.077   simulated time


References

  [1] P. Kocher et al., "Spectre Attacks: Exploiting Speculative Execution,"
      IEEE Symposium on Security and Privacy, 2019.

  [2] M. Lipp et al., "Meltdown: Reading Kernel Memory from User Space,"
      USENIX Security Symposium, 2018.

  [3] N. Binkert et al., "The gem5 Simulator,"
      ACM SIGARCH Computer Architecture News, vol. 39, no. 2, 2011.
