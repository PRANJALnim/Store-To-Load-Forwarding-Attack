import argparse
import sys
import os

import m5
from m5.objects import (
    System, SrcClockDomain, VoltageDomain,
    RiscvO3CPU,
    RiscvSEWorkload, Process,
    MemCtrl, DDR3_1600_8x8,
    Cache, L2XBar, SystemXBar,
    AddrRange,
    TournamentBP
)

parser = argparse.ArgumentParser(description="gem5 SE config for RISC-V STLF side-channel PoC")
parser.add_argument("--binary",    required=True, help="Path to compiled stlf_attack binary")
parser.add_argument("--l1d_size",  default="32kB")
parser.add_argument("--l1i_size",  default="32kB")
parser.add_argument("--l2_size",   default="256kB")
parser.add_argument("--mem_size",  default="512MB")
parser.add_argument("--lsq_depth", type=int, default=16,
                    help="Load/store queue depth. Larger values give the store buffer more "
                         "in-flight entries, which increases the window for mis-forwarding.")
parser.add_argument("--cpu_freq",  default="2GHz")
args = parser.parse_args()

system = System()
system.clk_domain = SrcClockDomain(
    clock=args.cpu_freq,
    voltage_domain=VoltageDomain()
)
system.mem_mode   = "timing"
system.mem_ranges = [AddrRange(args.mem_size)]

# O3 is the only gem5 CPU model that simulates out-of-order execution,
# the reorder buffer, store buffer, and the STLF logic we are studying.
cpu = RiscvO3CPU()
cpu.numROBEntries    = 192
cpu.numPhysIntRegs   = 256
cpu.numPhysFloatRegs = 256
cpu.LQEntries        = args.lsq_depth
cpu.SQEntries        = args.lsq_depth
cpu.numIQEntries     = 64
cpu.fetchWidth       = 4
cpu.decodeWidth      = 4
cpu.renameWidth      = 4
cpu.dispatchWidth    = 4
cpu.issueWidth       = 4
cpu.wbWidth          = 4
cpu.commitWidth      = 4
cpu.branchPred       = TournamentBP()
system.cpu = cpu

# L1 instruction cache — latency of 1 cycle is standard for a small SRAM.
cpu.icache = Cache(
    size            = args.l1i_size,
    assoc           = 8,
    tag_latency     = 1,
    data_latency    = 1,
    response_latency= 1,
    mshrs           = 4,
    tgts_per_mshr   = 20,
)

# L1 data cache — 4-cycle hit latency.  This is the cache whose timing
# the attack measures; the gap between 4 cycles (L1 hit) and ~40 cycles
# (L2 hit) is what the timing oracle exploits.
cpu.dcache = Cache(
    size            = args.l1d_size,
    assoc           = 8,
    tag_latency     = 4,
    data_latency    = 4,
    response_latency= 4,
    mshrs           = 16,
    tgts_per_mshr   = 20,
)

# L2 unified cache — 20-cycle latency creates a measurable miss penalty
# that the calibrated threshold can distinguish from an L1 hit.
cpu.l2cache = Cache(
    size            = args.l2_size,
    assoc           = 16,
    tag_latency     = 20,
    data_latency    = 20,
    response_latency= 20,
    mshrs           = 32,
    tgts_per_mshr   = 20,
)

cpu.l2bus = L2XBar()
cpu.icache.mem_side  = cpu.l2bus.cpu_side_ports
cpu.dcache.mem_side  = cpu.l2bus.cpu_side_ports
cpu.l2cache.cpu_side = cpu.l2bus.mem_side_ports

system.membus = SystemXBar()
cpu.l2cache.mem_side = system.membus.cpu_side_ports

cpu.icache_port = cpu.icache.cpu_side
cpu.dcache_port = cpu.dcache.cpu_side
cpu.createInterruptController()

system.mem_ctrl      = MemCtrl()
system.mem_ctrl.dram = DDR3_1600_8x8(range=system.mem_ranges[0])
system.mem_ctrl.port = system.membus.mem_side_ports
system.system_port   = system.membus.cpu_side_ports

if not os.path.exists(args.binary):
    print(f"[ERROR] Binary not found: {args.binary}")
    sys.exit(1)

system.workload = RiscvSEWorkload.init_compatible(args.binary)
process = Process(cmd=[args.binary])
cpu.workload = process
cpu.createThreads()

root = m5.objects.Root(full_system=False, system=system)
m5.instantiate()

print("=" * 60)
print(f"  gem5 RISC-V O3  |  LSQ={args.lsq_depth}  |  L1D={args.l1d_size}  |  L2={args.l2_size}")
print("=" * 60)

exit_event = m5.simulate()

print(f"\n[gem5] Simulation exited: {exit_event.getCause()}")
print(f"[gem5] Total simulated ticks: {m5.curTick()}")

m5.stats.dump()
