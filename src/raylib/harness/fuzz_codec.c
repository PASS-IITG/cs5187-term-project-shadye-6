/* Compression/encoding API (sinfl/sdefl DEFLATE, Base64, hashes).
 * Mode byte selects: raw inflate of attacker data, or differential round-trips (true oracles):
 *   Decompress(Compress(x)) == x      Decode64(Encode64(x)) == x      hash(x) deterministic */
#include "fuzz_common.h"
#include <stdlib.h>
FZ_USE_BINARY_MUTATOR

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(0);
    if (!n) return 0;
    uint8_t mode = d[0]; d++; n--;
    if (n > (1u << 20)) return 0;
    int out = 0;
    switch (mode & 3) {
    case 0: { unsigned char *p = DecompressData(d, (int)n, &out); MemFree(p); } break;   /* hostile inflate */
    case 1: { char *s = malloc(n + 1); memcpy(s, d, n); s[n] = 0;
              unsigned char *p = DecodeDataBase64(s, &out); MemFree(p); free(s); } break;
    case 2: { int cs = 0; unsigned char *c = CompressData(d, (int)n, &cs);
              if (c) { unsigned char *p = DecompressData(c, cs, &out);
                  FUZZ_ORACLE(p && out == (int)n && !memcmp(p, d, n), "DEFLATE round-trip mismatch");
                  MemFree(p); MemFree(c); } } break;
    case 3: { int es = 0; char *e = EncodeDataBase64(d, (int)n, &es);
              if (e) { unsigned char *p = DecodeDataBase64(e, &out);
                  FUZZ_ORACLE(p && out == (int)n && !memcmp(p, d, n), "Base64 round-trip mismatch");
                  MemFree(p); MemFree(e); } } break;
    }
    unsigned h1 = ComputeCRC32((unsigned char *)d, (int)n), h2 = ComputeCRC32((unsigned char *)d, (int)n);
    FUZZ_ORACLE(h1 == h2, "CRC32 nondeterministic");
    unsigned m[4]; memcpy(m, ComputeMD5((unsigned char *)d, (int)n), 16);
    FUZZ_ORACLE(!memcmp(m, ComputeMD5((unsigned char *)d, (int)n), 16), "MD5 nondeterministic (stale static state)");
    (void)ComputeSHA1((unsigned char *)d, (int)n); (void)ComputeSHA256((unsigned char *)d, (int)n);
    return 0;
}
