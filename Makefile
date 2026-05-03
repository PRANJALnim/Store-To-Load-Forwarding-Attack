# Makefile for stlf_attack
#
# Default target builds a static RISC-V binary suitable for gem5 SE mode.
# The -O1 flag is intentional: higher optimisation levels can move the
# probe_array access out of the speculative execution window, which would
# defeat the covert channel entirely.

CC_RISCV  ?= riscv64-linux-gnu-gcc
GEM5_HOME ?= $(HOME)/gem5
GEM5     ?= $(GEM5_HOME)/build/RISCV/gem5.opt
BINARY    = stlf_attack
TRIALS   ?= 1000
SPIN_COUNT ?= 300

CFLAGS_RISCV = -O1 -march=rv64gc -mabi=lp64d -static -Wall -g

.PHONY: all run clean

all: $(BINARY)

$(BINARY): stlf_attack.c
	@command -v $(CC_RISCV) >/dev/null 2>&1 || { \
		echo "[error] RISC-V cross compiler '$(CC_RISCV)' not found."; \
		echo "        On Ubuntu/Debian install: sudo apt install gcc-riscv64-linux-gnu"; \
		echo "        Or run: make CC_RISCV=<your-riscv-gcc>"; \
		exit 127; \
	}
	$(CC_RISCV) $(CFLAGS_RISCV) -DTRIALS=$(TRIALS) -DSPIN_COUNT=$(SPIN_COUNT) -o $@ $<

run: $(BINARY)
	@test -x "$(GEM5)" || { \
		echo "[error] gem5 binary not found/executable at: $(GEM5)"; \
		echo "        Set GEM5_HOME (or GEM5) and ensure gem5 is built for RISCV."; \
		echo "        Example: make GEM5_HOME=/path/to/gem5 run"; \
		exit 127; \
	}
	LC_ALL=C.UTF-8 LANG=C.UTF-8 PYTHONIOENCODING=UTF-8 PYTHONUTF8=1 \
	$(GEM5) run_stlf_launcher.py \
		--binary ./$(BINARY) \
		--l1d_size 32kB \
		--l1i_size 32kB \
		--l2_size  256kB \
		--lsq_depth 16 \
		--cpu_freq 2GHz

graphs:
	python3 generate_graphs.py

clean:
	rm -f $(BINARY)

.PHONY: all run graphs clean
