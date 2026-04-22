# Apex One PML Dual-Detection Test

## What This Tests

| Phase | Engine | Expected Alert | Action |
|---|---|---|---|
| File drop (no execution) | ATSE -> PML File Model | File Detection | Quarantine |
| Execution (chain runs) | CIE -> PML Process Model | Process Detection | Terminate + Clean |

## Detection Chain

```
pml_test.exe  (unsigned PE / high-entropy .payload / suspicious import table)
  +-- cmd.exe                      [signal: abnormal parent-child]
       +-- powershell.exe          [signal: -NoProfile -Hidden -Bypass -EncodedCommand]
            +-- [decode + drop]    [signal: in-memory exec, %APPDATA% write]
                 +-- wscript.exe   [signal: PS->wscript cross-engine hop]
                      +-- pml_s3.vbs  [signal: HKCU Run key persistence]
                           +-- cscript.exe pml_s4.js  [signal: 3rd engine]
```

## Prerequisites (build machine only - NOT the test endpoint)

- mingw-w64:  `choco install mingw`  or  https://www.mingw-w64.org
- Python 3.x

## Step 1 - Compile

```bat
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c ^
    -mwindows -O2 -s -Wl,--strip-all ^
    -lkernel32 -luser32
```

## Step 2 - Append Overlay (post-build)

```bat
python build.py --overlay pml_test.exe
```

## Step 3 - File Detection Test

1. Copy `pml_test.exe` to a watched directory on the test endpoint (e.g. Desktop)
2. Do NOT execute it yet
3. Watch Apex One / Vision One console for **File Detection alert**
4. Verify: malware type classification + Quarantine action triggered

## Step 4 - Process Detection Test

1. Temporarily set PML **File action** to `Log only` in Apex One policy
2. Execute `pml_test.exe` on test endpoint (all windows hidden, runs silently)
3. Verify `%TEMP%\pml_done.txt` exists (confirms Stage 4 completed)
4. Watch Vision One console for **Process Detection alert**
5. Verify: behavioral malware type + Terminate action triggered

## Step 5 - Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```

Restore PML File action to original setting.

## Tuning Tips

| Issue | Action |
|---|---|
| File detection not firing | Raise PML monitoring level; verify ATSE is enabled |
| Process detection missing | Verify CIE active; confirm script monitoring enabled |
| Chain killed by quarantine | Set File action to Log only before execution |
| Want a different file hash | Change `seed` param in `gen_entropy_section()` |
