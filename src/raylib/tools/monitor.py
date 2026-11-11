#!/usr/bin/env python3
"""Automated coverage-plateau / saturation monitor for the libFuzzer ensemble.

It samples every work/logs/<harness>.log on a fixed cadence, keeps a rolling per-harness history of
(wall-clock, edges, features, total-execs, corpus-size), and classifies each target so a long
campaign doesn't silently waste CPU on a saturated harness:

  PROGRESSING  coverage still climbing (edges or features grew within the plateau window)
  PLATEAU      execs advancing but edges flat for >--plateau-min minutes (needs new inputs:
               seeds / dict tokens / VM ops, or hand it to AFL++ CMPLOG to crack a comparison)
  SATURATED    edges AND corpus flat for >--sat-min minutes at steady exec/s (diminishing returns:
               switch CPU to AFL++/other harnesses, or raise -max_len)
  STALLED      exec/s collapsed or log stale (crash loop / hang / OOM thrash — inspect the log)
  WARMUP       too little history yet to judge

It also reads <harness>.ucb (written when the harness runs with FZ_UCB_STATS) and flags when the
UCB mutation bandit has collapsed onto a single arm, which usually coincides with a plateau.

State persists in work/monitor/state.json, so it works whether you run it by hand periodically,
from cron/loop, or with --watch (its own sleep loop). Output: work/monitor.md + a stderr summary.
Exit status is nonzero when any harness is SATURATED/STALLED, so a wrapper can react.

Usage:
  tools/monitor.py [--watch SECONDS] [--plateau-min M] [--sat-min M] [--stale-min M] [--work DIR]
"""
import os, re, sys, json, time, glob, argparse

LINE = re.compile(r"#(\d+)\b")
def kv(log, key):            # last "key: <number>" (handles cov:/ft:/exec/s:)
    m = re.findall(re.escape(key) + r"\s*([0-9]+(?:\.[0-9]+)?)", log)
    return float(m[-1]) if m else None
def corp(log):               # last "corp: <count>/<size>"
    m = re.findall(r"corp:\s*(\d+)", log)
    return int(m[-1]) if m else None

def tail(path, n=16384):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); sz = f.tell(); f.seek(max(0, sz - n))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""

def read_ucb(path):
    """Parse <harness>.ucb: pick the arm with the highest pull count ('top arm') and count how many
    arms were used at all (arms==1 => the bandit collapsed onto a single strategy)."""
    rows, total = [], None
    try:
        for ln in open(path):
            if ln.startswith("# total_new_edges"):
                total = int(ln.split()[-1]); continue
            if ln.startswith("#") or not ln.strip():
                continue
            name, pulls, mean = ln.split()
            rows.append((name, float(pulls), float(mean)))
    except OSError:
        return None
    if not rows:
        return None
    top = max(rows, key=lambda r: r[1])
    return {"arms": len(rows), "best": (top[0], top[2]), "total_edges": total}

def sample(work):
    out = {}
    for log in sorted(glob.glob(f"{work}/logs/*.log")):
        h = os.path.basename(log)[:-4]
        t = tail(log)
        if "cov:" not in t:
            out[h] = {"mtime": os.path.getmtime(log)}
            continue
        execs = None
        mm = LINE.findall(t)
        if mm:
            execs = int(mm[-1])
        out[h] = {"edges": kv(t, "cov:"), "ft": kv(t, "ft:"),
                  "execs": execs, "corp": corp(t), "eps": kv(t, "exec/s:"),
                  "mtime": os.path.getmtime(log)}
        u = read_ucb(f"{work}/logs/{h}.ucb")
        if u:
            out[h]["ucb"] = u
    return out

def classify(hist, now, args):
    """hist: list of snapshots [{t, edges, ft, execs, corp}] oldest..newest for one harness."""
    cur = hist[-1]
    if cur.get("edges") is None:
        return "STALLED", "no coverage line yet / log has no cov:"
    span = now - hist[0]["t"]
    # find the oldest snapshot within each window
    def oldest_within(minutes):
        cutoff = now - minutes * 60
        c = [s for s in hist if s["t"] >= cutoff]
        return c[0] if c else hist[0]
    # exec/s health
    eps = cur.get("eps") or 0
    prev = hist[-2] if len(hist) > 1 else None
    if prev and cur.get("execs") is not None and prev.get("execs") is not None:
        dt = cur["t"] - prev["t"]
        dexec = cur["execs"] - prev["execs"]
        if dt > 60 and dexec <= 0 and (now - cur["mtime"]) > args.stale_min * 60:
            return "STALLED", f"execs not advancing and log stale {int(now-cur['mtime'])}s"
    if span < min(args.plateau_min, 5) * 60:
        return "WARMUP", f"only {int(span)}s of history"
    base_p = oldest_within(args.plateau_min)
    de = (cur["edges"] or 0) - (base_p.get("edges") or 0)
    df = (cur["ft"] or 0) - (base_p.get("ft") or 0)
    if de > 0 or df > 0:
        rate = de / max(1e-9, (cur["t"] - base_p["t"]) / 3600.0)
        return "PROGRESSING", f"+{int(de)} edges/+{int(df)} ft in window (~{rate:.0f} edges/h)"
    # edges flat over plateau window -> check saturation (longer window + corpus flat)
    base_s = oldest_within(args.sat_min)
    dcorp = (cur.get("corp") or 0) - (base_s.get("corp") or 0)
    flat_long = (cur["edges"] or 0) - (base_s.get("edges") or 0) <= 0
    if span >= args.sat_min * 60 and flat_long and dcorp <= 0 and eps > 1:
        return "SATURATED", f"edges+corpus flat {args.sat_min}m at {eps:.0f} exec/s"
    return "PLATEAU", f"edges flat {args.plateau_min}m (ft {'+' if df>0 else ''}{int(df)})"

REC = {
    "PLATEAU":   "add seeds/dict tokens or VM ops for 0% functions; or run tools/run_afl.sh <h> (CMPLOG cracks magic/length/checksum compares)",
    "SATURATED": "reallocate its CPU: lower this harness's weight in harness_table.sh, raise -max_len, or move cores to AFL++/other harnesses",
    "STALLED":   "inspect work/logs/<h>.log — crash loop, hang, or OOM thrash; check work/crashes/<h>",
    "PROGRESSING": "leave running",
    "WARMUP":    "keep sampling",
}

def run_once(args):
    work = args.work
    os.makedirs(f"{work}/monitor", exist_ok=True)
    statef = f"{work}/monitor/state.json"
    state = {}
    if os.path.exists(statef):
        try: state = json.load(open(statef))
        except Exception: state = {}
    now = time.time()
    snap = sample(work)
    hist = state.get("hist", {})
    for h, s in snap.items():
        s["t"] = now
        hl = hist.setdefault(h, [])
        hl.append(s)
        # cap history, but keep enough to cover the saturation window
        horizon = now - max(args.sat_min, args.plateau_min) * 60 * 3
        hist[h] = [x for x in hl if x["t"] >= horizon][-500:]
    json.dump({"hist": hist, "updated": now}, open(statef, "w"))

    rows, attention = [], 0
    for h in sorted(hist):
        st, why = classify(hist[h], now, args)
        cur = hist[h][-1]
        ucb = cur.get("ucb") or {}
        bestarm = (ucb.get("best") or ["-"])[0]
        if ucb.get("arms") == 1:
            why += "; UCB collapsed to one arm"
        rows.append((h, st, int(cur.get("edges") or 0), int(cur.get("ft") or 0),
                     int(cur.get("corp") or 0), f"{cur.get('eps') or 0:.0f}", bestarm, why))
        if st in ("SATURATED", "STALLED"):
            attention += 1

    md = ["# Fuzzing monitor", "", f"Updated {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}",
          f"(plateau>{args.plateau_min}m, saturation>{args.sat_min}m)", "",
          "| harness | status | edges | ft | corp | exec/s | top arm | note |",
          "|---|---|--:|--:|--:|--:|---|---|"]
    order = {"STALLED":0, "SATURATED":1, "PLATEAU":2, "WARMUP":3, "PROGRESSING":4}
    for r in sorted(rows, key=lambda r: order.get(r[1], 9)):
        md.append("| " + " | ".join(str(x) for x in r) + " |")
    md += ["", "## Recommendations", ""]
    seen = set()
    for r in sorted(rows, key=lambda r: order.get(r[1], 9)):
        if r[1] in ("PROGRESSING", "WARMUP") or r[1] in seen: continue
        seen.add(r[1]); md.append(f"- **{r[1]}** → {REC[r[1]]}")
    if not seen:
        md.append("- all harnesses progressing; no action")
    open(f"{work}/monitor.md", "w", encoding="utf-8").write("\n".join(md) + "\n")

    sys.stderr.write(f"[monitor] {time.strftime('%H:%M:%S')}  " +
                     "  ".join(f"{r[0]}:{r[1]}" for r in sorted(rows, key=lambda r: order.get(r[1],9))) +
                     f"   -> {work}/monitor.md\n")
    return attention

def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--work", default=f"{here}/work")
    ap.add_argument("--plateau-min", type=float, default=30)
    ap.add_argument("--sat-min", type=float, default=120)
    ap.add_argument("--stale-min", type=float, default=10)
    ap.add_argument("--watch", type=float, default=0, help="loop every N seconds")
    args = ap.parse_args()
    if args.watch:
        while True:
            try: run_once(args)
            except Exception as e: sys.stderr.write(f"[monitor] error: {e}\n")
            time.sleep(args.watch)
    else:
        sys.exit(1 if run_once(args) else 0)

if __name__ == "__main__":
    main()
