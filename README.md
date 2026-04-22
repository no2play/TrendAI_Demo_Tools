# Apex One PML Dual-Detection Test  v5

## Why UPX Packing is the Critical Step

PML's file model was trained on real malware. A GCC-compiled C program has
clean, structured opcodes that score low — it looks like legitimate software
with suspicious imports, not a real dropper.

UPX transforms the PE into an authentic packer:

```
Before UPX:                     After UPX:
  .text   clean GCC code    ->    UPX0  decompressor stub
  .rdata  strings               (PUSHAD / XOR loop / POPAD / JMP)
  .data   globals           ->    UPX1  LZMA-compressed original PE
  .payload RC4 data                     entropy ~8.0 bpb
                                        original IAT inside (recovered
                                        by ATSE deep analysis)
```

~60% of real-world malware uses UPX. PML's model is heavily weighted
toward UPX stub opcode patterns.

## Build (all-in-one)

```bash
python3 build.py --compile
```

## Build (manual)

```bash
# 1. Compile
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \
    -mwindows -O2 -s -Wl,--strip-all -lkernel32 -luser32

# 2. Set .payload flags
x86_64-w64-mingw32-objcopy --set-section-flags .payload=code,readonly pml_test.exe

# 3. UPX pack  <-- THE key step for PML file detection
upx --best --force -q pml_test.exe

# 4. Append RC4 overlay
python3 build.py --overlay pml_test.exe
```

## Verify

```bash
python3 build.py --verify pml_test.exe
# Should show: UPX0 + UPX1 sections, entropy > 7.5
```

## Install UPX (if not present)

```bash
apt-get install upx-ucl
# or
apt-get install upx
```

## Test Execution

**File Detection:**
1. Copy pml_test.exe to watched directory on test endpoint
2. Do NOT execute — ATSE scans on write
3. Verify File Detection alert + Quarantine in Vision One

**Process Detection:**
1. Set PML File action to "Log only"
2. Execute pml_test.exe (silent)
3. Check %TEMP%\pml_done.txt exists
4. Verify Process Detection alert + Terminate in Vision One

## Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```
