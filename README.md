# Apex One PML Dual-Detection Test  v3

## Detection Chain

```
pml_test.exe  (unsigned PE / IAT: VirtualAlloc+WPM+CRT / .payload xr 7.95bpb / RC4 overlay)
  +-- cmd.exe                      [abnormal parent-child]
       +-- powershell.exe          [-NoProfile -Hidden -Bypass -EncodedCommand]
            +-- [decode + drop]    [IEX equivalent, %APPDATA% write]
                 +-- wscript.exe   [PS->wscript engine hop]
                      +-- pml_s3.vbs  [HKCU Run key persistence]
                           +-- cscript.exe pml_s4.js  [3rd script engine]
```

## Build (two commands, no linker script needed)

```bash
# 1. Compile
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \
    -mwindows -O2 -s -Wl,--strip-all \
    -lkernel32 -luser32

# 2. Set .payload section executable (PE section flag — no ELF phdr involved)
x86_64-w64-mingw32-objcopy \
    --set-section-flags .payload=code,readonly \
    pml_test.exe

# 3. Append overlay
python build.py --overlay pml_test.exe
```

Or run all three steps automatically:
```bash
python build.py --compile
```

## Why No Linker Script

v2 used a linker script with `:text` phdr syntax.
PE/COFF has no program headers (phdrs are an ELF concept).
mingw-ld refuses to assign a PE section to a non-existent phdr -> link error.

v3 solution: compile normally, then use `objcopy --set-section-flags` to
set `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ` on `.payload` post-build.
The PE loader maps code-flagged sections as executable.

## Verify entropy after build

```bash
ent pml_test.exe
# Target:
#   Entropy         > 7.0 bits/byte
#   Chi-square      < 1000
#   Arithmetic mean > 110
#   Serial corr.    < 0.15
```

## Test Execution

**File Detection:**
1. Copy `pml_test.exe` to watched directory on test endpoint
2. Do NOT execute
3. Verify File Detection alert + Quarantine in Vision One

**Process Detection:**
1. Set PML File action to `Log only`
2. Execute `pml_test.exe` (silent, no visible windows)
3. Check `%TEMP%\pml_done.txt` exists (Stage 4 completion marker)
4. Verify Process Detection alert + Terminate in Vision One

## Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```
