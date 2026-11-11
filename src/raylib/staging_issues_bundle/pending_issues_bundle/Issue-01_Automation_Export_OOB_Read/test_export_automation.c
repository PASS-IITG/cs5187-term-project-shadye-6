#include "raylib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

int main(int argc, char **argv) {
    int test_case = (argc > 1) ? atoi(argv[1]) : 0;
    printf("=== Running ExportAutomationEventList Test (case %d) ===\n", test_case);

    if (test_case == 1 || test_case == 0) {
        printf("--- Test 1: Public API with boundary and out-of-bounds event types ---\n");
        AutomationEvent events[5] = { 0 };
        events[0].frame = 0; events[0].type = 0;          // Valid lower bound (EVENT_NONE)
        events[1].frame = 1; events[1].type = 23;         // Valid upper bound (ACTION_SETTARGETFPS)
        events[2].frame = 2; events[2].type = 24;         // Out of bounds (first invalid)
        events[3].frame = 3; events[3].type = 1000;       // Out of bounds
        events[4].frame = 4; events[4].type = UINT_MAX;   // Out of bounds (UINT_MAX)

        AutomationEventList list = { .capacity = 5, .count = 5, .events = events };
        const char *outFile = "/tmp/automation_test_api.rae";
        printf("Calling ExportAutomationEventList()...\n");
        bool result = ExportAutomationEventList(list, outFile);
        if (!result) {
            printf("FAIL: ExportAutomationEventList returned false\n");
            return 1;
        }

        // Read exported file and verify contents
        FILE *f = fopen(outFile, "rt");
        if (!f) { printf("FAIL: Cannot open exported file %s\n", outFile); return 1; }
        char line[512];
        int count_unknown = 0;
        int count_none = 0;
        int count_fps = 0;
        while (fgets(line, sizeof(line), f)) {
            printf("  Exported line: %s", line);
            if (strstr(line, "// Event: UNKNOWN")) count_unknown++;
            if (strstr(line, "// Event: EVENT_NONE")) count_none++;
            if (strstr(line, "// Event: ACTION_SETTARGETFPS")) count_fps++;
        }
        fclose(f);

        printf("Verification: count_none=%d, count_fps=%d, count_unknown=%d\n",
               count_none, count_fps, count_unknown);

        if (count_none != 1 || count_fps != 1 || count_unknown != 3) {
            printf("FAIL: Unexpected event names in export (expected 1 EVENT_NONE, 1 ACTION_SETTARGETFPS, 3 UNKNOWN)\n");
            return 1;
        }
        printf("RESULT: PASS - Test 1 (Public API boundary test)\n\n");
    }

    if (test_case == 2 || test_case == 0) {
        printf("--- Test 2: Untrusted .rae file load and re-export ---\n");
        const char *inFile = "/tmp/automation_untrusted.rae";
        const char *outFile = "/tmp/automation_reexported.rae";

        FILE *f = fopen(inFile, "wt");
        if (!f) { printf("FAIL: Cannot create %s\n", inFile); return 1; }
        fprintf(f, "c 3\n");
        fprintf(f, "e 0 0 10 20 30 40 // Event: EVENT_NONE\n");
        fprintf(f, "e 1 23 60 0 0 0 // Event: ACTION_SETTARGETFPS\n");
        fprintf(f, "e 2 24 99 88 77 66 // Event: MALFORMED_TYPE_24\n");
        fclose(f);

        printf("Loading untrusted .rae file %s...\n", inFile);
        AutomationEventList list = LoadAutomationEventList(inFile);
        printf("Loaded %u events (capacity %u)\n", list.count, list.capacity);
        if (list.count != 3) {
            printf("FAIL: Expected 3 events, got %u\n", list.count);
            UnloadAutomationEventList(list);
            return 1;
        }

        printf("Calling ExportAutomationEventList() on loaded list...\n");
        bool result = ExportAutomationEventList(list, outFile);
        if (!result) {
            printf("FAIL: ExportAutomationEventList returned false\n");
            UnloadAutomationEventList(list);
            return 1;
        }

        FILE *fout = fopen(outFile, "rt");
        if (!fout) { printf("FAIL: Cannot open %s\n", outFile); UnloadAutomationEventList(list); return 1; }
        char line[512];
        int count_unknown = 0;
        while (fgets(line, sizeof(line), fout)) {
            printf("  Exported line: %s", line);
            if (strstr(line, "// Event: UNKNOWN")) count_unknown++;
        }
        fclose(fout);

        UnloadAutomationEventList(list);

        if (count_unknown != 1) {
            printf("FAIL: Expected 1 UNKNOWN event, got %d\n", count_unknown);
            return 1;
        }
        printf("RESULT: PASS - Test 2 (Untrusted .rae file load and export)\n\n");
    }

    printf("ALL AUTOMATION EXPORT TESTS PASSED!\n");
    return 0;
}

