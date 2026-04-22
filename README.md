# Apex One PML Dual-Detection Test  v2

## What This Tests

| Phase | Engine | Expected Alert | Action |
|---|---|---|---|
| File drop (no execution) | ATSE -> PML File Model | File Detection | Quarantine |
| Execution (chain runs) | CIE -> PML Process Model | Process Detection | Terminate + Clean |

## Detection Chain

```
pml_test.exe  (unsigned PE / IAT: VirtualAlloc+WPM+CRT / .payload entropy 7.95 / overlay)
  +-- cmd.exe                      [signal: abnormal parent-child]
       +-- powershell.exe          [signal: -NoProfile -Hidden -Bypass -EncodedCommand]
            +-- [decode + drop]    [signal: in-memory exec, %APPDATA% write]
                 +-- wscript.exe   [signal: PS->wscript cross-engine hop]
                      +-- pml_s3.vbs  [signal: HKCU Run key persistence]
                           +-- cscript.exe pml_s4.js  [signal: 3rd script engine]
```

## What Changed from v1

| Issue | v1 (broken) | v2 (fixed) |
|---|---|---|
| Suspicious APIs in IAT | Dynamic GetProcAddress — NOT in IAT | Direct calls — appear in static IAT |
| .payload section | #pragma section (MSVC-only, ignored by GCC) | __attribute__((section)) — GCC native |
| Overlay entropy pattern | os.urandom() — chi-sq 492k, mean 81 | RC4-keystream — chi-sq ~270, mean ~127 |
| .payload executable flag | Not set | Set via linker script (pml_sections.ld) |

## Prerequisites (build machine only)

- mingw-w64: `choco install mingw`  or  https://www.mingw-w64.org
- Python 3.x

## Step 1 — Generate source files

```bash
python build.py --build
```

## Step 2 — Compile (no warnings expected)

```bash
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \
    -mwindows -O2 -s -Wl,--strip-all \
    -T pml_sections.ld \
    -lkernel32 -luser32
```

## Step 3 — Append RC4-pattern overlay

```bash
python build.py --overlay pml_test.exe
```

## Step 4 — Verify entropy profile

```bash
ent pml_test.exe
# Target:
#   Entropy          > 7.0 bits/byte
#   Chi-square       ~300-600 (realistic for PE + encrypted sections)
#   Arithmetic mean  > 100
#   Serial corr.     < 0.15
```

## Step 5 — File Detection Test

1. Copy `pml_test.exe` to a watched directory on the test endpoint
2. Do NOT execute yet
3. Observe Apex One / Vision One for **File Detection alert**
4. Verify: malware type classification + Quarantine action

## Step 6 — Process Detection Test

1. Set PML **File action** to `Log only` in Apex One policy
2. Execute `pml_test.exe` (runs silently, all windows hidden)
3. Verify `%TEMP%\pml_done.txt` exists (Stage 4 completion marker)
4. Observe Vision One for **Process Detection alert**
5. Verify: behavioral malware type + Terminate action

## Step 7 — Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```

Restore PML File action to original setting.

## Tuning Tips

| Issue | Action |
|---|---|
| File detection not firing | Raise PML monitoring level; verify ATSE cloud connectivity |
| Process detection not firing | Confirm CIE active; check script engine monitoring policy |
| Chain killed by quarantine | Set File action = Log only before executing |
| Want different SHA256 | Change seed_key bytes in `gen_payload_section()` and rebuild |
