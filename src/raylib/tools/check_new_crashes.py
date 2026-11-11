import os
import time

now = time.time()
cutoff = now - 4500  # last 75 minutes

targets = ["fuzz_audio_wav", "fuzz_model_gltf", "fuzz_image_ops", "fuzz_render_vm", "fuzz_text", "fuzz_automation"]
new_files = {}

for target in targets:
    p = f"/mnt/c/Users/dxksh/Desktop/swa/raylib/work/crashes/{target}"
    new_crashes = []
    new_timeouts = []
    new_ooms = []
    if os.path.exists(p):
        for entry in os.scandir(p):
            try:
                mtime = entry.stat().st_mtime
                if mtime >= cutoff:
                    if entry.name.startswith("crash-"):
                        new_crashes.append((entry.name, entry.path))
                    elif entry.name.startswith("timeout-"):
                        new_timeouts.append(entry.name)
                    elif entry.name.startswith("oom-"):
                        new_ooms.append(entry.name)
            except Exception:
                pass
    new_files[target] = {
        "crashes": new_crashes,
        "timeouts": new_timeouts,
        "ooms": new_ooms
    }
    print(f"{target}: {len(new_crashes)} new crashes, {len(new_timeouts)} new timeouts, {len(new_ooms)} new ooms")
    if new_crashes:
        print(f"  sample new crashes: {[c[0] for c in new_crashes[:3]]}")

