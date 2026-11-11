#!/usr/bin/env python3
"""Build per-harness seed corpora in seeds/<harness>/.
Sources: raylib's examples/**/resources (real assets), plus synthetic seeds for formats/APIs with
no shipped samples (PIL images, ffmpeg audio, hand-built glTF/OBJ/FNT/RAE/VFS containers).
Multi-file formats are packed into the VFS container understood by fuzz_model.c:
    repeat { u8 nameLen; name; u32le len; data }   (entry 0 = entry point)
Usage: tools/make_seeds.py [RAYLIB_DIR]"""
import io, os, re, struct, subprocess, sys, json, base64, random, shutil, hashlib
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
RL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "raylib"))
OUT = os.path.join(ROOT, "seeds"); MAXSZ = 1 << 20

def put(h, data, tag=""):
    if not data or len(data) > MAXSZ: return
    d = os.path.join(OUT, h); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, hashlib.sha1(data).hexdigest()[:16] + tag), "wb").write(data)

def vfs(entries):  # [(name, bytes)]
    b = b""
    for n, d in entries:
        n = n.encode()[:63]; b += bytes([len(n)]) + n + struct.pack("<I", len(d)) + d
    return b

res = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(RL, "examples")) for f in fs]
ext = lambda p: os.path.splitext(p)[1].lower()

# ---- 1. raw single-file assets ----
IMG = "png bmp tga jpg gif pic psd hdr qoi dds pkm ktx pvr astc pnm ppm pgm".split()
for p in res:
    e = ext(p)[1:]; data = open(p, "rb").read()
    if e in IMG: put("fuzz_image_" + ("pnm" if e in ("ppm", "pgm") else e), data)
    elif e in ("wav", "ogg", "mp3", "qoa", "flac", "xm", "mod"): put("fuzz_audio_" + e, data)
    elif e in ("ttf", "otf"): put("fuzz_font_" + e, data); put("fuzz_font_ttf" if e == "otf" else "fuzz_font_otf", data)
    elif e in ("iqm", "glb", "vox", "m3d"): put("fuzz_model_" + e, vfs([("main." + e, data)]))
    elif e == "png" and os.path.getsize(p) < 4096: put("fuzz_image_ops", b"\x0a\x40\x00\x00" + bytes([10, 1]) + struct.pack("<H", len(data)) + data)

# ---- 2. multi-file assets: OBJ(+MTL+textures), FNT(+pages) ----
for p in res:
    e = ext(p); d = os.path.dirname(p)
    if e == ".obj":
        txt = open(p, "rb").read(); ents = [("main.obj", txt)]
        for m in re.findall(rb"mtllib\s+(\S+)", txt):
            mp = os.path.join(d, m.decode(errors="ignore"))
            if os.path.exists(mp):
                mt = open(mp, "rb").read(); ents.append((os.path.basename(mp), mt))
                for t in re.findall(rb"map_\w+\s+(\S+)", mt)[:2]:
                    tp = os.path.join(d, t.decode(errors="ignore"))
                    if os.path.exists(tp) and os.path.getsize(tp) < 200000: ents.append((os.path.basename(tp), open(tp, "rb").read()))
        put("fuzz_model_obj", vfs(ents))
    elif e == ".fnt":
        txt = open(p, "rb").read(); ents = [("main.fnt", txt)]
        for pg in re.findall(rb'file="([^"]+)"', txt):
            pp = os.path.join(d, pg.decode(errors="ignore"))
            if os.path.exists(pp): ents.append((pg.decode(errors="ignore"), open(pp, "rb").read()))
        put("fuzz_font_fnt", vfs(ents))

# ---- 3. synthetic images (formats raylib ships no sample of) ----
try:
    from PIL import Image
    random.seed(1)
    for (w, h, mode) in [(1, 1, "RGBA"), (3, 2, "RGB"), (16, 9, "L"), (7, 5, "P"), (33, 17, "LA"), (8, 8, "1")]:
        im = Image.new(mode if mode != "LA" else "LA", (w, h))
        im.putdata([random.randrange(256) if mode in ("L", "P", "1") else tuple(random.randrange(256) for _ in mode) for _ in range(w * h)])
        for fmt, h_ in [("PNG", "png"), ("BMP", "bmp"), ("TGA", "tga"), ("GIF", "gif"), ("PPM", "pnm"), ("JPEG", "jpg"), ("PSD", None), ("DDS", "dds")]:
            if h_ is None: continue
            try:
                b = io.BytesIO(); src = im
                if fmt in ("JPEG", "PPM", "DDS") and mode not in ("RGB", "L"): src = im.convert("RGB" if fmt != "DDS" else "RGBA")
                if fmt == "BMP" and mode == "LA": src = im.convert("RGBA")
                src.save(b, fmt); put("fuzz_image_" + h_, b.getvalue())
            except Exception: pass
        b = io.BytesIO(); im.convert("RGB").save(b, "PPM"); put("fuzz_image_pnm", b.getvalue())
    # animated gif (multi-frame path)
    fr = [Image.new("P", (5, 4), i * 40) for i in range(4)]; b = io.BytesIO()
    fr[0].save(b, "GIF", save_all=True, append_images=fr[1:], duration=50, loop=0); put("fuzz_image_gif", b.getvalue())
except ImportError:
    print("PIL missing: skipping synthetic images")

put("fuzz_image_psd", b"8BPS" + struct.pack(">H", 1) + bytes(6) + struct.pack(">HIIHH", 3, 2, 2, 8, 3) + struct.pack(">IIIH", 0, 0, 0, 0) + bytes(12))
# Minimal Radiance HDR, PKM(ETC1), KTX1, PVR3, ASTC, QOI, DDS-DXT1 headers + payload
put("fuzz_image_hdr", b"#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 2 +X 2\n" + bytes(16))
put("fuzz_image_pkm", b"PKM 10" + struct.pack(">HHHHH", 0, 4, 4, 4, 4) + bytes(8))
put("fuzz_image_pkm", b"PKM 20" + struct.pack(">HHHHH", 1, 4, 4, 4, 4) + bytes(8))
ktx = b"\xabKTX 11\xbb\r\n\x1a\n" + struct.pack("<13I", 0x04030201, 0, 1, 0, 0x8D64, 0, 4, 4, 0, 0, 1, 1, 0)
put("fuzz_image_ktx", ktx + struct.pack("<I", 8) + bytes(8))
put("fuzz_image_pvr", struct.pack("<IIQIIIIIIII", 0x03525650, 0, 0x08080808_61626772, 0, 0, 2, 2, 1, 1, 1, 1) + struct.pack("<I", 0) + bytes(16))
put("fuzz_image_astc", bytes([0x13, 0xAB, 0xA1, 0x5C, 4, 4, 1]) + (4).to_bytes(3, "little") + (4).to_bytes(3, "little") + (1).to_bytes(3, "little") + bytes(16))
put("fuzz_image_qoi", b"qoif" + struct.pack(">II", 2, 2) + bytes([4, 0]) + bytes([0xfe, 1, 2, 3, 0xc0 | 2]) + bytes(7) + b"\x01")
dds = b"DDS " + struct.pack("<7I", 124, 0x1007, 4, 4, 8, 0, 1) + bytes(44) + struct.pack("<2I", 32, 4) + b"DXT1" + bytes(20) + struct.pack("<I", 0x1000) + bytes(16)
put("fuzz_image_dds", dds + bytes(8))

# ---- 4. synthetic audio via ffmpeg (FLAC/OGG/MP3/WAV variants), tiny MOD/XM headers ----
if shutil.which("ffmpeg"):
    for (codec, ext_, extra) in [("pcm_s16le", "wav", []), ("pcm_u8", "wav", []), ("pcm_f32le", "wav", []), ("pcm_s24le", "wav", []),
                                 ("flac", "flac", []), ("libvorbis", "ogg", []), ("libmp3lame", "mp3", [])]:
        for ch, sr in [(1, 8000), (2, 44100)]:
            try:
                r = subprocess.run(["ffmpeg", "-loglevel", "quiet", "-f", "lavfi", "-i", f"sine=f=440:r={sr}:d=0.05", "-ac", str(ch),
                                    "-c:a", codec, *extra, "-f", ext_ if ext_ != "ogg" else "ogg", "-"], capture_output=True, timeout=30)
                put("fuzz_audio_" + ext_, r.stdout)
            except Exception: pass
mod = bytearray(1084 + 1024); mod[0:4] = b"seed"; mod[950] = 1; mod[1080:1084] = b"M.K."; put("fuzz_audio_mod", bytes(mod))
xm = bytearray(b"Extended Module: seed".ljust(37, b" ") + b"\x1a" + b"raylib-fuzz".ljust(20) + b"\x04\x01")
xm += struct.pack("<IHHHHHHHH", 276, 1, 0, 1, 2, 0, 1, 6, 125) + bytes(256)
xm += struct.pack("<IBHH", 9, 0, 1, 2) + bytes([0x80, 0x80])
put("fuzz_audio_xm", bytes(xm))

# ---- 5. glTF: external .bin, data-URI buffer, skinned/animated variant ----
pos = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0); idx = struct.pack("<3H", 0, 1, 2) + b"\0\0"
binb = pos + idx
def gltf(uri, extra=None):
    g = {"asset": {"version": "2.0"}, "scenes": [{"nodes": [0]}], "nodes": [{"mesh": 0}],
         "buffers": [{"uri": uri, "byteLength": len(binb)}],
         "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": 36}, {"buffer": 0, "byteOffset": 36, "byteLength": 6}],
         "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3", "min": [0, 0, 0], "max": [1, 1, 0]},
                       {"bufferView": 1, "componentType": 5123, "count": 3, "type": "SCALAR"}],
         "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "indices": 1, "material": 0}]}],
         "materials": [{"pbrMetallicRoughness": {"baseColorTexture": {"index": 0}}}],
         "textures": [{"source": 0}], "images": [{"uri": "tex.png"}]}
    if extra: extra(g)
    return json.dumps(g).encode()
png1 = open(next(p for p in res if p.endswith(".png") and os.path.getsize(p) < 3000), "rb").read() if any(p.endswith(".png") for p in res) else b""
put("fuzz_model_gltf", vfs([("main.gltf", gltf("a.bin")), ("a.bin", binb), ("tex.png", png1)]))
put("fuzz_model_gltf", vfs([("main.gltf", gltf("data:application/octet-stream;base64," + base64.b64encode(binb).decode()))]))
def skin(g):
    g["nodes"] = [{"mesh": 0, "skin": 0}, {"name": "bone"}]; g["skins"] = [{"joints": [1]}]
    g["animations"] = [{"channels": [{"sampler": 0, "target": {"node": 1, "path": "rotation"}}],
                        "samplers": [{"input": 2, "output": 3, "interpolation": "LINEAR"}]}]
    g["accessors"] += [{"bufferView": 0, "componentType": 5126, "count": 2, "type": "SCALAR", "min": [0], "max": [1]},
                       {"bufferView": 0, "componentType": 5126, "count": 2, "type": "VEC4"}]
put("fuzz_model_gltf", vfs([("main.gltf", gltf("a.bin", skin)), ("a.bin", binb), ("tex.png", png1)]))
put("fuzz_model_obj", vfs([("main.obj", b"mtllib a.mtl\nv 0 0 0\nv 1 0 0\nv 0 1 0\nvt 0 0\nvn 0 0 1\nusemtl m\nf 1/1/1 2/1/1 3/1/1\no b\nf -1 -2 -3\n"),
                           ("a.mtl", b"newmtl m\nKd 1 0 0\nmap_Kd tex.png\n"), ("tex.png", png1)]))

# ---- 6. text-ish harnesses ----
put("fuzz_font_bdf", b"STARTFONT 2.1\nFONT test\nSIZE 8 75 75\nFONTBOUNDINGBOX 8 8 0 0\nCHARS 1\nSTARTCHAR A\nENCODING 65\nSWIDTH 500 0\nDWIDTH 8 0\nBBX 8 8 0 0\nBITMAP\n18\n24\n42\n42\n7E\n42\n42\n00\nENDCHAR\nENDFONT\n" + bytes(16))
for s in [b"c 3\ne 0 1 65 0 0 0 KEY_DOWN\ne 1 0 65 0 0 0 KEY_UP\ne 2 7 10 20 0 0 MOUSE_MOVE\n",
          b"c 2\ne 0 13 0 5 5 0 TOUCH\ne 1 17 0 1 0 0 GAMEPAD\n"]:
    put("fuzz_automation", s)
for s in [b"\x10\x02\x02Hello, \xe2\x82\xac world/dir/file.tar.gz,a,b\n\nline2\xf0\x9f\x98\x80\x02, \x01-", b"\x00\x00\x00" + "ÄÖÜ\U0001F600 x".encode() * 30]:
    put("fuzz_text", s)
for m in range(4): put("fuzz_codec", bytes([m]) + (zlibish := b"hello hello hello raylib " * 8))
import zlib
put("fuzz_codec", b"\x00" + zlib.compress(b"x" * 300)[2:-4])     # raw DEFLATE stream
put("fuzz_codec", b"\x01" + base64.b64encode(b"\x00\xff" * 20))
random.seed(7)
for _ in range(8):
    put("fuzz_render_vm", bytes(random.randrange(256) for _ in range(random.choice([64, 256, 1024]))))
    put("fuzz_image_ops", bytes(random.randrange(256) for _ in range(random.choice([32, 128, 512]))))
print("seeds:", {d: len(os.listdir(os.path.join(OUT, d))) for d in sorted(os.listdir(OUT))})
