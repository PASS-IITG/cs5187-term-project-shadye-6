# Issue 05: Heap Buffer Underflow in GetCodepointPrevious()

- **Vulnerable File:** `src/rtext.c:2590-2592`
- **Component:** Text / UTF-8 Decoding
- **Status:** Pending (discovered during parallel fuzzing campaign)
- **Vulnerability Type:** Heap Buffer Underflow (CWE-124)

## Description
In `GetCodepointPrevious(const char *text, int *codepointSize)`:
```c
do ptr--;
while (((0x80 & ptr[0]) != 0) && ((0xc0 & ptr[0]) ==  0x80));
```
When iterating backwards through a string where the start of the string or substring begins with an invalid/continuation UTF-8 byte (`0x80..0xBF`), the while condition remains true as `ptr` decrements past the start of the buffer.

## Remediation
UTF-8 codepoints are at most 4 bytes long. Guard the continuation loop with `count < 4` to prevent unbounded backward iteration into memory before the string buffer.
