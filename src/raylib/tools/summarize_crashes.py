import glob, re, collections, os

W = "/mnt/c/Users/dxksh/Desktop/swa/raylib/work"

for log_path in sorted(glob.glob(f"{W}/logs/*.log")):
    name = os.path.basename(log_path).replace(".log", "")
    with open(log_path, errors="ignore") as f:
        content = f.read()

    asan_errors = collections.Counter()
    for line in content.splitlines():
        if "ERROR: AddressSanitizer:" in line or "SUMMARY: AddressSanitizer:" in line:
            cleaned = re.sub(r"0x[0-9a-f]+", "0x...", line)
            cleaned = re.sub(r"==\d+==", "", cleaned).strip()
            # simplify
            cleaned = re.sub(r"on address 0x\.\.\.", "", cleaned)
            cleaned = re.sub(r"at pc 0x\.\.\. bp 0x\.\.\. sp 0x\.\.\. T\d+", "", cleaned)
            asan_errors[cleaned] += 1

    print(f"=== {name} ASan Crashes (Distinct: {len(asan_errors)}) ===")
    for sig, count in asan_errors.most_common(8):
        print(f"  [{count} hits] {sig}")
    print()
