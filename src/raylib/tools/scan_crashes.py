import os

targets = ["fuzz_audio_wav", "fuzz_model_gltf", "fuzz_image_ops", "fuzz_render_vm", "fuzz_text", "fuzz_automation"]
for target in targets:
    p = f"/mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/{target}"
    crashes = []
    timeouts = []
    ooms = []
    if os.path.exists(p):
        for entry in os.scandir(p):
            if entry.name.startswith("crash-"):
                crashes.append(entry.name)
            elif entry.name.startswith("timeout-"):
                timeouts.append(entry.name)
            elif entry.name.startswith("oom-"):
                ooms.append(entry.name)
    print(f"{target}: {len(crashes)} crashes, {len(timeouts)} timeouts, {len(ooms)} ooms")
    if crashes:
        print(f"  sample crashes: {crashes[:5]}")

