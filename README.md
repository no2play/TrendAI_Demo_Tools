# Apex One PML Dual-Detection Test  v4

## Detection Chain
```
pml_test.exe  (unsigned / IAT: VirtualAlloc+WPM+CRT / .payload 7.95bpb / 64KB overlay)
  +-- cmd.exe                      [abnormal parent-child]
       +-- powershell.exe          [-NoProfile -Hidden -Bypass -EncodedCommand]
            +-- [decode + drop]    [IEX-equivalent, %APPDATA% write]
                 +-- wscript.exe   [engine hop]
                      +-- pml_s3.vbs  [HKCU Run persistence]
                           +-- cscript.exe pml_s4.js  [3rd script engine]
```

## Build (all-in-one)
```bash
python build.py --compile
```

## Build (manual steps)
```bash
# 1. Compile
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \
    -mwindows -O2 -s -Wl,--strip-all \
    -lkernel32 -luser32

# 2. Set .payload section executable
x86_64-w64-mingw32-objcopy \
    --set-section-flags .payload=code,readonly \
    pml_test.exe

# 3. Append 64 KB RC4 overlay
python build.py --overlay pml_test.exe
```

## Verify binary is correctly built
```bash
python build.py --verify pml_test.exe
```
Expected output:
- File size > 90 KB (PE ~30 KB + 64 KB overlay)
- .payload section found
- VirtualAlloc / WriteProcessMemory / CreateRemoteThread in IAT
- Whole-file entropy > 7.0 (64 KB overlay dominates)

## Why whole-file `ent` was low before

`ent` measures the entire file.  The PE structure (headers, aligned code,
import name strings) has entropy ~6.4.  With only an 8 KB overlay, RC4 data
was <20% of the file and PE structure dominated the blend (~6.7 bpb).

v4 uses a 64 KB overlay.  RC4 data is now ~67% of the file:
  (31744 x 6.4  +  65536 x 7.98) / 97280 = 7.45 bpb  <- passes ent check

ATSE measures per-section entropy (not whole-file), so the .payload section
at 7.95 bpb was always the correct signal — ent was never the right validator.

## Test Execution

**File Detection:**
1. Copy pml_test.exe to watched directory on test endpoint
2. Do NOT execute
3. Verify File Detection alert + Quarantine in Vision One

**Process Detection:**
1. Set PML File action to "Log only"
2. Execute pml_test.exe (silent, no windows)
3. Check %TEMP%\pml_done.txt exists
4. Verify Process Detection alert + Terminate in Vision One

## Cleanup
```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```
