import glob, re, os

W = "/mnt/c/Users/dxksh/Desktop/swa/raylib/work"

for log_path in sorted(glob.glob(f"{W}/logs/*.log")):
    name = os.path.basename(log_path).replace(".log", "")
    with open(log_path, errors="ignore") as f:
        content = f.read()

    print(f"==================================================")
    print(f"TARGET: {name}")
    print(f"==================================================")
    
    # Find crash blocks
    blocks = re.split(r"(?:==\d+==ERROR: AddressSanitizer:|runtime error:)", content)
    found = 0
    for b in blocks[1:]:
        header = b.splitlines()[0] if b.splitlines() else ""
        frames = [l.strip() for l in b.splitlines() if l.strip().startswith("#") and "raylib" in l][:3]
        if frames and found < 3:
            print(f"  * Type: {header[:80]}")
            for fr in frames:
                print(f"    {fr}")
            found += 1
            print()

