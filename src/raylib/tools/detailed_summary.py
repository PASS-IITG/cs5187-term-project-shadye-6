import glob, re, collections, os

W = "/mnt/c/Users/dxksh/Desktop/swa/raylib/work"

for log_path in sorted(glob.glob(f"{W}/logs/*.log")):
    name = os.path.basename(log_path).replace(".log", "")
    with open(log_path, errors="ignore") as f:
        content = f.read()

    asan_errors = collections.Counter()
    ubsan_errors = collections.Counter()
    
    for line in content.splitlines():
        if "ERROR: AddressSanitizer:" in line:
            cleaned = re.sub(r"0x[0-9a-f]+", "0x...", line)
            cleaned = re.sub(r"==\d+==", "", cleaned).strip()
            cleaned = re.sub(r"on address 0x\.\.\.", "", cleaned)
            cleaned = re.sub(r"at pc 0x\.\.\. bp 0x\.\.\. sp 0x\.\.\. T\d+", "", cleaned)
            asan_errors[cleaned] += 1
        elif "runtime error:" in line:
            cleaned = re.sub(r":\d+:\d+: runtime error:", " runtime error:", line)
            cleaned = re.sub(r"0x[0-9a-f]+", "0x...", cleaned)
            ubsan_errors[cleaned] += 1

    print(f"=== {name} Summary ===")
    print(f"  ASan Distinct Errors: {len(asan_errors)}")
    for sig, count in asan_errors.most_common(5):
        print(f"    [ASan {count} hits] {sig}")
    print(f"  UBSan Distinct Errors: {len(ubsan_errors)}")
    for sig, count in ubsan_errors.most_common(5):
        print(f"    [UBSan {count} hits] {sig}")
    print()

