import os, struct, glob

crashes = sorted(glob.glob("/mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/fuzz_model_gltf/crash-*"))
print("Total crashes:", len(crashes))

for cp in crashes:
    fn = os.path.basename(cp)
    data = open(cp, "rb").read()
    print(f"\n--- {fn} (size: {len(data)}) ---")
    pos = 0
    file_idx = 0
    while pos < len(data):
        namelen = data[pos]
        pos += 1
        if pos + namelen > len(data):
            print(f"  [trunc] namelen {namelen} exceeds remaining data at pos {pos}")
            break
        name = data[pos:pos+namelen].decode("latin1", errors="replace")
        pos += namelen
        if pos + 4 > len(data):
            print(f"  [trunc] len field truncated at pos {pos}")
            break
        flen = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        file_data = data[pos:pos+flen]
        pos += flen
        print(f"  File #{file_idx}: name={name!r}, declared_len={flen}, actual_len={len(file_data)}")
        if file_idx == 0:
            preview = file_data[:120].decode("latin1", errors="replace").replace("\n", " ")
            print(f"    Preview: {preview}")
        file_idx += 1

