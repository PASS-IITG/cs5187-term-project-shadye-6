#!/usr/bin/env python3
"""Crash triage: re-run every artifact under work/crashes/<harness>/ with the repro build, bucket by
(sanitizer kind, top-3 drogon/trantor-side frames), tag buckets that match a KNOWN signature,
minimise one representative per new bucket, and write work/triage.md.
Same engine as the raylib tree; only the frame filter (drogon/trantor source, not raylib) and the
KNOWN table differ. KNOWN is empty until a campaign confirms a bug — fill it as you report upstream,
so later campaigns don't re-triage it.
Usage: tools/triage.py [--minimize]     (needs ./build.sh repro and ./build.sh libfuzzer)"""
import os, re, subprocess, sys, hashlib, collections, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPRO, LF, W = f"{ROOT}/out/repro", f"{ROOT}/out/libfuzzer", f"{ROOT}/work"
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:symbolize=1",
           UBSAN_OPTIONS=f"print_stacktrace=1:halt_on_error=1:suppressions={ROOT}/tools/ubsan.supp",
           FUZZ_KNOWN="1")   # reproduce faithfully: known-bug guards OFF

# Fill as bugs are confirmed/reported, e.g.:
#   "D1 HttpRequestParser chunk-len overflow": r"HttpRequestParser::parseRequest",
KNOWN = {}

FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)")
KIND = re.compile(r"(ERROR: AddressSanitizer: [\w-]+(?: on address)?|runtime error: [^:\n]{0,60}|==FUZZ ORACLE== [^\n]+|ERROR: libFuzzer: [\w-]+|SEGV)")
# a frame is "target code" (not harness/third-party) if it lives in drogon's lib or trantor
TARGET = re.compile(r"(drogon/lib/|/trantor/trantor/)")

def run(binary, f, timeout=60):
    try:
        p = subprocess.run([binary, f], env=ENV, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"

def signature(log):
    kind = (KIND.search(log).group(1) if KIND.search(log) else "unknown").split(" on address")[0]
    kind = re.sub(r"0x[0-9a-f]+|-?\d+", "N", kind)          # bucket by class, not by offending value
    frames = [m.group(1) for m in FRAME.finditer(log)
              if TARGET.search(m.group(2)) and not m.group(1).startswith(("__", "fz_", "LLVMFuzzer"))][:3]
    return kind, tuple(frames)

def main():
    buckets = collections.OrderedDict()
    for h in sorted(os.listdir(f"{W}/crashes")) if os.path.isdir(f"{W}/crashes") else []:
        b = f"{REPRO}/{h}"
        if not os.path.exists(b): continue
        for a in sorted(os.listdir(f"{W}/crashes/{h}")):
            p = f"{W}/crashes/{h}/{a}"
            if not os.path.isfile(p): continue
            rc, log = run(b, p)
            if rc == 0: continue                                   # flaky / not reproducible
            kind, fr = signature(log)
            key = (kind, fr)
            known = next((k for k, rx in KNOWN.items() if re.search(rx, log)), None)
            e = buckets.setdefault(key, {"harness": set(), "files": [], "known": known, "log": log})
            e["harness"].add(h); e["files"].append(p)
    os.makedirs(f"{W}/triage", exist_ok=True)
    out = ["# Triage report", "", f"{len(buckets)} unique buckets", ""]
    for i, ((kind, fr), e) in enumerate(buckets.items()):
        bid = hashlib.sha1(repr((kind, fr)).encode()).hexdigest()[:10]
        rep = min(e["files"], key=os.path.getsize); dst = f"{W}/triage/{bid}"
        shutil.copy(rep, dst)
        if "--minimize" in sys.argv and not e["known"]:
            h = sorted(e["harness"])[0]
            subprocess.run([f"{LF}/{h}", "-minimize_crash=1", "-runs=20000", f"-exact_artifact_path={dst}.min", rep],
                           env=ENV, capture_output=True, timeout=900)
        out += [f"## {bid} — {kind}", f"- frames: {' <- '.join(fr) or '?'}", f"- harness: {', '.join(sorted(e['harness']))}",
                f"- hits: {len(e['files'])}   reproducer: work/triage/{bid}", f"- status: {e['known'] or '**NEW**'}", ""]
    open(f"{W}/triage.md", "w", encoding="utf-8").write("\n".join(out))
    new = sum(1 for e in buckets.values() if not e["known"])
    print(f"{len(buckets)} buckets ({new} new) -> work/triage.md")

if __name__ == "__main__":
    main()
