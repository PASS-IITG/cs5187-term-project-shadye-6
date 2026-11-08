/* Driver for repro/cov builds: ./fuzz_x file|dir ...  (runs each input once) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run(const char *p) {
    struct stat st; if (stat(p, &st)) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(p); struct dirent *e; char b[4096];
        while (d && (e = readdir(d))) if (e->d_name[0] != '.') { snprintf(b, sizeof b, "%s/%s", p, e->d_name); run(b); }
        if (d) closedir(d); return;
    }
    FILE *f = fopen(p, "rb"); if (!f) return;
    uint8_t *buf = (uint8_t *)malloc(st.st_size ? st.st_size : 1); size_t n = fread(buf, 1, st.st_size, f); fclose(f);
    fprintf(stderr, "[run] %s (%zu)\n", p, n); LLVMFuzzerTestOneInput(buf, n); free(buf);
}
int main(int argc, char **argv) { for (int i = 1; i < argc; i++) run(argv[i]); return 0; }
