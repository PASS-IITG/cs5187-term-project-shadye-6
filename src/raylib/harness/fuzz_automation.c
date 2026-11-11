/* Automation-event (.rae) loader + replay. LoadAutomationEventList() uses fopen() directly (not the
 * VFS callbacks), so the input is written to a per-process tmpfs file. Replay matters most:
 * PlayAutomationEvent() indexes CORE.Input arrays with file-controlled params[] (key codes, mouse
 * buttons, touch ids, gamepad ids). Those arrays are fixed-size members of one big struct, so ASan
 * cannot see intra-struct overflows — UBSan -fsanitize=bounds (part of `undefined`) can. */
#include "fuzz_common.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

static char *g_saved;   /* ExportAutomationEventList() goes through SaveFileText(): capture it */
static bool capture(const char *fn, const char *t) { (void)fn; free(g_saved); g_saved = strdup(t ? t : ""); return true; }

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    fz_init(FZ_GL);
    static char path[64], out[64];
    if (!path[0]) { snprintf(path, sizeof path, "/dev/shm/rlfz_%d.rae", getpid()); snprintf(out, sizeof out, "/dev/shm/rlfz_%d_out.rae", getpid()); }
    FILE *f = fopen(path, "wb"); if (!f) return 0; fwrite(d, 1, n, f); fclose(f);

    AutomationEventList list = LoadAutomationEventList(path);
    FUZZ_ORACLE(list.count <= list.capacity, "automation count exceeds capacity");
    unsigned lim = list.count < list.capacity ? list.count : list.capacity;
    for (unsigned i = 0; i < lim && i < 1024; i++) {
        AutomationEvent ev = list.events[i];
        /* enum lives in rcore.c: 1-4 key*, 5-6 mouse btn, 9-13 gamepad, 14-16 touch, 23 SETTARGETFPS */
        if (ev.type == 23) continue;                       /* would make EndDrawing() sleep: DoS only */
        if (fz_avoid_known()) {                            /* KNOWN: unchecked params[] indices (rcore.c:3811..) */
            int p0 = ev.params[0], p1 = ev.params[1], t = (int)ev.type;
            if (t >= 1 && t <= 4 && (p0 < 0 || p0 >= 512)) continue;
            if (((t >= 5 && t <= 6) || (t >= 14 && t <= 16)) && (p0 < 0 || p0 >= 8)) continue;
            if (t >= 9 && t <= 13 && (p0 < 0 || p0 >= 4 || p1 < 0 || p1 >= 32)) continue;
        }
        PlayAutomationEvent(ev);
        if ((i & 15) == 15) { BeginDrawing(); EndDrawing(); }   /* swaps current->previous input state, gesture update */
    }
    SetSaveFileTextCallback(capture);
    free(g_saved); g_saved = NULL;
    if (ExportAutomationEventList(list, out) && g_saved) {      /* export -> reload: count must survive */
        FILE *o = fopen(out, "wb"); if (o) { fputs(g_saved, o); fclose(o); }
        AutomationEventList again = LoadAutomationEventList(out);
        FUZZ_ORACLE(again.count == lim, "automation export/import count mismatch");
        UnloadAutomationEventList(again);
    }
    UnloadAutomationEventList(list);
    return 0;
}
