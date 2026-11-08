#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "fuzz_ucb.h"

/* ---- coverage reward via an *independent* SanitizerCoverage channel ----
 * We can't reuse libFuzzer's 8-bit counters (it already owns __sanitizer_cov_8bit_counters_init),
 * so we add our own `-fsanitize-coverage=trace-pc-guard` instrumentation (see build.sh). Each guard
 * starts non-zero; the first time an edge executes we count it as a brand-new global edge and zero
 * its guard, so after warm-up the callback is almost never entered. The number of new edges seen
 * since the last reset is exactly the payoff of the input that just ran.
 * These symbols are weak-defaulted by the sanitizer runtime, so defining them here is conflict-free
 * and a no-op in modes that don't enable trace-pc-guard (afl/cov/repro). */
static volatile long g_new_this_input;   /* new global edges since last fz_ucb_begin */
static long g_new_total;

/* These callbacks must NOT themselves be coverage-instrumented, or the guard callback would call
 * itself on its own branches (infinite recursion). The file is built with trace-pc-guard, so we
 * exempt exactly these two functions. */
#if defined(__clang__)
#define FZ_NOCOV __attribute__((no_sanitize("coverage")))
#else
#define FZ_NOCOV
#endif

FZ_NOCOV void __wrap___sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint32_t n;
    for (uint32_t *p = start; p < stop; p++) if (!*p) *p = ++n;   /* non-zero == "not yet hit" */
}
FZ_NOCOV void __wrap___sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard) return;        /* already counted this edge globally */
    *guard = 0;
    g_new_this_input++; g_new_total++;
}

/* Fallback definitions for modes without linker wrapping (e.g. repro, cov) */
FZ_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
    __attribute__((weak, alias("__wrap___sanitizer_cov_trace_pc_guard_init")));
FZ_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
    __attribute__((weak, alias("__wrap___sanitizer_cov_trace_pc_guard")));
static long new_edges(void) { long v = g_new_this_input; g_new_this_input = 0; return v; }

/* ---- UCB1 over arms ---- */
static double sum_r[FZ_ARM_COUNT];   /* summed reward per arm */
static double n_r[FZ_ARM_COUNT];     /* pulls per arm */
static double total_pulls;
static int    pending = -1;          /* arm credited with the next input's coverage */
static int    inited;

int fz_ucb_enabled(void) {
    static int v = -1;
    if (v < 0) { const char *e = getenv("FUZZ_UCB"); v = !(e && e[0] == '0'); }
    return v;
}

static void lazy_init(void) {
    if (inited) return; inited = 1;
    if (getenv("FZ_UCB_STATS")) atexit(fz_ucb_dump);
}

void fz_ucb_begin(int arm) {
    lazy_init();
    if (!fz_ucb_enabled()) return;
    if (pending >= 0) {
        /* reward in [0,1]: 1 - exp(-edges) saturates (one new edge is already a win, we don't want
         * a single jackpot input to dominate the mean). */
        long e = new_edges();
        double reward = e > 0 ? 1.0 - exp(-(double)e) : 0.0;
        sum_r[pending] += reward; n_r[pending] += 1.0; total_pulls += 1.0;
    } else {
        (void)new_edges();   /* prime the shadow on the very first call */
    }
    pending = arm;
}

int fz_ucb_select(const int *arms, int n) {
    if (!fz_ucb_enabled() || n <= 1) return arms[0];
    /* Pull any never-tried arm first (UCB1 convention: infinite bonus). */
    for (int i = 0; i < n; i++) if (n_r[arms[i]] < 1.0) return arms[i];
    static const double C = 1.4142135623730951;   /* sqrt(2) */
    double lt = log(total_pulls > 1.0 ? total_pulls : 1.0);
    int best = arms[0]; double bestv = -1e300;
    for (int i = 0; i < n; i++) {
        int a = arms[i];
        double mean = sum_r[a] / n_r[a];
        double v = mean + C * sqrt(lt / n_r[a]);
        if (v > bestv) { bestv = v; best = a; }
    }
    return best;
}

void fz_ucb_dump(void) {
    const char *path = getenv("FZ_UCB_STATS");
    FILE *f = path ? fopen(path, "w") : stderr;
    if (!f) return;
    static const char *nm[FZ_ARM_COUNT] = {
        "bin.libfuzzer", "bin.intedge", "bin.blockdup", "bin.fixup",
        "vfs.entry", "vfs.rename", "vfs.dup", "vfs.drop", "vfs.cross" };
    fprintf(f, "# total_new_edges %ld\n# arm pulls mean_reward\n", g_new_total);
    for (int a = 0; a < FZ_ARM_COUNT; a++)
        if (n_r[a] > 0) fprintf(f, "%-14s %10.0f %8.4f\n", nm[a], n_r[a], sum_r[a] / n_r[a]);
    if (f != stderr) fclose(f);
}
