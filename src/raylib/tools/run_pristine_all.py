import os, glob, subprocess

crashes = sorted(glob.glob('/mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_model_gltf/crash-*'))
bin_path = '/mnt/c/Users/dxksh/Desktop/swa/raylib/out/repro/fuzz_model_gltf'

for c in crashes:
    cname = os.path.basename(c)
    env = dict(os.environ, FUZZ_KNOWN='0', ASAN_OPTIONS='abort_on_error=0:symbolize=1', UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0')
    p = subprocess.run([bin_path, c], env=env, capture_output=True, text=True, errors='replace')
    print('='*70)
    print('CRASH:', cname)
    err_lines = [l.strip() for l in (p.stdout + p.stderr).splitlines() if any(k in l for k in ['ERROR:', 'SUMMARY:', 'SEGV', 'heap-buffer-overflow', 'rmodels.c:'])]
    for el in err_lines[:5]:
        print('  ', el)

