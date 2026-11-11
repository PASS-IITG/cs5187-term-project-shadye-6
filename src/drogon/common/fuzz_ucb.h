/* UCB1-scheduled mutation rewards (shared by every harness via the mutator macros).
 *
 * Problem: fz_mutate_binary / fz_mutate_vfs each pick one of several *strategies* (libFuzzer
 * splice, integer-boundary injection, block duplication, length fixup; or for the VFS:
 * mutate-entry / rename / duplicate / drop / crossover). A fixed probability split wastes CPU on
 * strategies that stop paying off for a given target (e.g. block-dup on a format with no repeated
 * chunks). We instead treat strategy choice as a multi-armed bandit and let the payoff — *new
 * coverage* — steer it, per-harness and online.
 *
 * Reward signal (no harness changes needed): libFuzzer's own 8-bit coverage counters. We grab the
 * counter region from __sanitizer_cov_8bit_counters_init and keep a 1-byte "seen" shadow. Between
 * two calls to the custom mutator exactly one produced input has executed, so at the top of each
 * mutator call we scan for counters that went non-zero for the first time (= globally new edges),
 * credit that count to the arm we picked last time, then pick the next arm with UCB1. Everything
 * lives in the mutator, so any harness that uses FZ_USE_BINARY_MUTATOR / FZ_USE_VFS_MUTATOR gets it
 * for free. Disable with FUZZ_UCB=0 (falls back to the original fixed split).
 *
 * Under AFL++ (no 8-bit-counter callback, no LLVMFuzzerMutate) the selector still runs but every
 * reward is 0, so arms are explored round-robin — harmless, and AFL has its own scheduler anyway.
 */
#ifndef FUZZ_UCB_H
#define FUZZ_UCB_H
#include <stddef.h>
#include <stdint.h>

/* Named arms. The two mutators share one space so FZ_UCB_STATS dumps both tables. */
enum {
    /* binary mutator */
    FZ_ARM_BIN_LIBFUZZER = 0,   /* delegate to LLVMFuzzerMutate (havoc/splice/dictionary) */
    FZ_ARM_BIN_INTEDGE,         /* integer-boundary injection into the header region */
    FZ_ARM_BIN_BLOCKDUP,        /* duplicate a block (grow repeated chunks/frames/glyphs) */
    FZ_ARM_BIN_FIXUP,           /* libFuzzer mutate then force length-field fixup */
    /* vfs mutator */
    FZ_ARM_VFS_ENTRY,           /* mutate one entry's bytes (recursively, binary mutator) */
    FZ_ARM_VFS_RENAME,          /* rename: break / redirect cross-file references */
    FZ_ARM_VFS_DUP,             /* duplicate an entry */
    FZ_ARM_VFS_DROP,            /* drop an entry */
    FZ_ARM_VFS_CROSS,           /* (crossover path) graft/swap whole entries between items */
    FZ_ARM_COUNT
};

/* 1 unless FUZZ_UCB=0. Cached. */
int  fz_ucb_enabled(void);
/* Pick an arm from the given candidate set with UCB1. `arms`/`n` list the legal arms for this
 * mutator; `ctx` is 0 for the binary mutator, 1 for the VFS mutator (kept separate exploration
 * counts aren't needed — arms are globally unique — but ctx lets the picker ignore the other
 * mutator's arms). Returns one of `arms`. When UCB is disabled, returns arms[0] and the caller
 * should keep its original random split instead. */
int  fz_ucb_select(const int *arms, int n);
/* Commit the pending reward (new edges from the just-executed input) and remember `arm` as the one
 * that produced the *next* input. Call this once at the top of each custom-mutator invocation. */
void fz_ucb_begin(int arm);
/* Optional: dump the per-arm table to the file named by FZ_UCB_STATS (atexit, or on demand). */
void fz_ucb_dump(void);

#endif
