# Issue 01: Global Array Out-of-Bounds Read in ExportAutomationEventList()

- **Vulnerable File:** `src/rcore.c:3757`
- **Component:** Core / Automation System
- **Status:** Patched locally on branch `fix-export-automation-oob-read` (Commit `6aa7fad6`). Not in upstream master.
- **Vulnerability Type:** Out-of-bounds Read (CWE-125)

## Description
`ExportAutomationEventList()` iterates over `list.events` and exports event information to text format.
When generating human-readable comments for events:
```c
snprintf(txtData + byteCount, 256, "... // Event: %s\n", ..., autoEventTypeName[list.events[i].type]);
```
`autoEventTypeName` is a static global array of length 24 (`[0..23]`).
If `event.type >= 24` or `UINT_MAX`, the code performs an unvalidated subscript into `autoEventTypeName`, reading memory out of bounds and crashing the process with SEGV or leaking heap/global memory.

Additionally, `list.count`, `list.events[i].frame`, and `list.events[i].type` are unsigned integers, but the format strings used signed `%i` specifiers.

## Remediation
1. Validate `list.events[i].type < sizeof(autoEventTypeName)/sizeof(autoEventTypeName[0])` before subscripting.
2. Provide a safe fallback `"UNKNOWN"` string if the event type is invalid.
3. Update `%i` to `%u` for unsigned integer fields.
