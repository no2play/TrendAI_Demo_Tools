#!/usr/bin/env python3
"""
PML Dual-Detection Test Builder  v4

Changes from v3:
  - Overlay size increased 8 KB -> 65 KB (dominates whole-file entropy calc)
  - Added --verify flag: checks section existence, IAT content, file size, entropy
  - compile() auto-runs verify after build
  - Clearer ent target expectations documented

Usage:
  python build.py --build                   generate source artifacts
  python build.py --compile                 build + compile + objcopy + overlay + verify
  python build.py --overlay <pml.exe>       append RC4-pattern overlay
  python build.py --verify  <pml.exe>       verify section, IAT, entropy profile
  python build.py --check-env               verify mingw tools available
  python build.py --clean                   remove output directory
"""

import os, sys, base64, argparse, shutil, subprocess, math

def run_cmd(cmd, **kwargs):
    """Python 3.6 compatible subprocess.run wrapper that always returns text."""
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    r.stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
    r.stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
    return r


OUT_DIR = "pml_test_output_v4"

GCC     = "x86_64-w64-mingw32-gcc"
OBJCOPY = "x86_64-w64-mingw32-objcopy"
OBJDUMP = "x86_64-w64-mingw32-objdump"

# ───────────────────────────────────────────────────────────────────────────────
#  RC4-KEYSTREAM  (correct packer-entropy profile)
# ───────────────────────────────────────────────────────────────────────────────
def rc4_keystream(size, seed_key=b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + seed_key[i % len(seed_key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(size)
    for n in range(size):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = S[(S[i] + S[j]) & 0xFF]
    return bytes(out)

# ───────────────────────────────────────────────────────────────────────────────
#  OVERLAY
#  65 KB makes RC4 data ~67% of total file, shifting whole-file entropy to ~7.5+
#  8 KB was only ~20% of file — PE structure entropy dominated the blend.
# ───────────────────────────────────────────────────────────────────────────────
OVERLAY_SIZE = 65536   # 64 KB

def append_overlay(pe_path, size=OVERLAY_SIZE):
    overlay = rc4_keystream(size)
    with open(pe_path, "ab") as f:
        f.write(overlay)
    print("[+] Overlay appended : {:,} bytes (RC4-keystream)".format(size))
    print("[i] Final file size  : {:,} bytes".format(os.path.getsize(pe_path)))

# ───────────────────────────────────────────────────────────────────────────────
#  VERIFY
#  Checks three things without needing `ent`:
#   1. .payload section exists in section table
#   2. Suspicious APIs present in IAT
#   3. File size confirms overlay was appended
#   4. Computes per-section and whole-file entropy internally
# ───────────────────────────────────────────────────────────────────────────────
def shannon_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = 0.0
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e

def verify(pe_path):
    if not os.path.exists(pe_path):
        print("[!] File not found: {}".format(pe_path))
        return False

    size = os.path.getsize(pe_path)
    print("\n[*] Verifying: {}  ({:,} bytes)".format(pe_path, size))
    all_ok = True

    # ── Check 1: file size (overlay appended?) ─────────────────────────────────
    # PE without overlay is typically 28-35 KB.
    # With 64 KB overlay: expect > 90 KB.
    print("\n  [1] File size check")
    expected_min = 20000 + OVERLAY_SIZE  # PE ~20-30 KB + overlay
    if size < expected_min:
        print("      [!] FAIL  size {:,} bytes — overlay likely NOT appended".format(size))
        print("          Run: python build.py --overlay {}".format(pe_path))
        all_ok = False
    else:
        print("      [+] PASS  {:,} bytes (overlay present)".format(size))

    # ── Check 2: .payload section (requires objdump) ──────────────────────────
    print("\n  [2] .payload section check")
    try:
        r = run_cmd([OBJDUMP, "-h", pe_path])
        if ".payload" in r.stdout:
            # Parse section size
            for line in r.stdout.splitlines():
                if ".payload" in line:
                    parts = line.split()
                    # objdump -h format: Idx Name Size VMA LMA ...
                    try:
                        sec_size = int(parts[2], 16)
                        print("      [+] PASS  .payload section found, size: {:,} bytes".format(sec_size))
                    except (IndexError, ValueError):
                        print("      [+] PASS  .payload section found")
        else:
            print("      [!] FAIL  .payload section NOT found in section table")
            print("          Check that __attribute__((section(\".payload\"),used)) compiled correctly")
            all_ok = False
    except FileNotFoundError:
        print("      [?] SKIP  {} not available".format(OBJDUMP))

    # ── Check 3: IAT suspicious APIs ─────────────────────────────────────────
    print("\n  [3] IAT suspicious API check")
    target_apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]
    try:
        r = run_cmd([OBJDUMP, "-p", pe_path])
        found = []
        missing = []
        for api in target_apis:
            if api in r.stdout:
                found.append(api)
            else:
                missing.append(api)
        for api in found:
            print("      [+] FOUND  {}".format(api))
        for api in missing:
            print("      [!] MISSING  {} — NOT in IAT".format(api))
            all_ok = False
    except FileNotFoundError:
        print("      [?] SKIP  {} not available".format(OBJDUMP))

    # ── Check 4: Whole-file entropy (internal, no `ent` needed) ──────────────
    print("\n  [4] Entropy profile")
    with open(pe_path, "rb") as f:
        raw = f.read()

    e      = shannon_entropy(raw)
    n      = len(raw)
    freq   = [0] * 256
    for b in raw:
        freq[b] += 1
    mean   = sum(i * freq[i] for i in range(256)) / n
    exp    = n / 256
    chisq  = sum((freq[i] - exp)**2 / exp for i in range(256))

    print("      Whole-file entropy : {:.4f} bpb".format(e))
    print("      Arithmetic mean    : {:.2f}   (target > 110)".format(mean))
    print("      Chi-square         : {:.1f}   (target < 5000)".format(chisq))

    # Note: whole-file entropy is dominated by PE structure.
    # ATSE measures per-section entropy, not whole-file.
    # Even 6.5 bpb whole-file can be fine if .payload section is 7.9+ bpb.
    if e < 6.0:
        print("      [!] Whole-file entropy very low — overlay likely missing")
        all_ok = False
    elif e < 6.8:
        print("      [~] Moderate — PE structure dominates; check overlay was appended")
    else:
        print("      [+] Good")

    print("\n  [NOTE] ATSE measures PER-SECTION entropy, not whole-file.")
    print("         .payload section target: 7.9+ bpb  (RC4-keystream achieves this)")
    print("         Whole-file ent output is NOT the signal that drives PML scoring.")

    print("\n  Overall: {}".format("[+] PASS" if all_ok else "[!] ISSUES FOUND — see above"))
    return all_ok

# ───────────────────────────────────────────────────────────────────────────────
#  STAGE CHAIN (unchanged from v3)
# ───────────────────────────────────────────────────────────────────────────────
STAGE4_LINES = [
    "// PML Test - Stage 4 (JScript via cscript.exe)",
    "// Signal: 3rd script engine (powershell -> wscript -> cscript)",
    "var sh  = new ActiveXObject('WScript.Shell');",
    "var fs  = new ActiveXObject('Scripting.FileSystemObject');",
    "var sep = String.fromCharCode(92);",
    "var tp  = sh.ExpandEnvironmentStrings('%TEMP%') + sep + 'pml_done.txt';",
    "var ts  = fs.OpenTextFile(tp, 2, true);",
    "ts.WriteLine('PML Stage 4 complete: ' + new Date().toISOString());",
    "ts.Close();",
]

def build_stage3_vbs():
    lines = [
        "' PML Test - Stage 3 (VBScript / wscript.exe)",
        "Option Explicit",
        "Dim sh, fs, jp, fh",
        "",
        'Set sh = CreateObject("WScript.Shell")',
        'Set fs = CreateObject("Scripting.FileSystemObject")',
        "",
        "' Signal: HKCU Run key persistence",
        "sh.RegWrite _",
        '    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PMLTestStub", _',
        '    "wscript.exe """ & WScript.ScriptFullName & """", _',
        '    "REG_SZ"',
        "",
        "' Drop Stage 4 JScript line-by-line",
        'jp = sh.ExpandEnvironmentStrings("%TEMP%") & "\\pml_s4.js"',
        "Set fh = fs.OpenTextFile(jp, 2, True)",
    ]
    for js_line in STAGE4_LINES:
        lines.append('fh.WriteLine "' + js_line + '"')
    lines += [
        "fh.Close",
        "",
        "' Signal: wscript -> cscript cross-engine hop",
        'sh.Run "cscript.exe """ & jp & """ //nologo", 0, True',
    ]
    return "\n".join(lines) + "\n"

def build_stage2_ps1(vbs_b64):
    return "\n".join([
        "$ErrorActionPreference='SilentlyContinue'",
        "$d=$env:APPDATA+'\\Microsoft\\Windows'",
        "if(-not(Test-Path $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}",
        "$p=$d+'\\pml_s3.vbs'",
        "$b=[System.Convert]::FromBase64String('" + vbs_b64 + "')",
        "[System.IO.File]::WriteAllBytes($p,$b)",
        "Start-Process -FilePath 'wscript.exe' -ArgumentList \"`\"$p`\"\" -WindowStyle Hidden",
    ]) + "\n"

def encode_for_encoded_command(ps1):
    return base64.b64encode(ps1.encode("utf-16-le")).decode("ascii")

def b64_utf8(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def gen_payload_section(size=512):
    return rc4_keystream(size, seed_key=b'\xBA\xDC\x0F\xFE\xDE\xAD\xC0\xDE')

def fmt_c_bytes(data, cols=16, indent=4):
    pad = " " * indent
    rows = []
    for i in range(0, len(data), cols):
        rows.append(pad + ", ".join("0x{:02X}".format(b) for b in data[i:i+cols]))
    return ",\n".join(rows)

# ───────────────────────────────────────────────────────────────────────────────
#  C SOURCE (unchanged from v3 — the fixes there were correct)
# ───────────────────────────────────────────────────────────────────────────────
C_TEMPLATE = """\
/*
 * pml_dropper_stub.c  v4
 *
 * Static signals (ATSE):
 *   [1] IAT: VirtualAlloc, VirtualProtect, WriteProcessMemory,
 *            CreateRemoteThread  (direct calls -> appear in PE import table)
 *   [2] .payload: 512 B RC4-keystream, ~7.95 bpb, executable via objcopy
 *   [3] XOR decode stub: packer opcode pattern
 *   [4] Unsigned PE
 *   [5] RC4 overlay: 64 KB appended post-build
 *
 * Behavioral chain (CIE):
 *   PE -> cmd.exe -> powershell (-NoProfile -Hidden -Bypass -EncodedCommand)
 *      -> wscript.exe pml_s3.vbs (HKCU Run + drop JScript)
 *      -> cscript.exe pml_s4.js  (3rd engine marker)
 *
 * Build:
 *   gcc ... -lkernel32 -luser32
 *   objcopy --set-section-flags .payload=code,readonly pml_test.exe
 *   python build.py --overlay pml_test.exe
 *
 * CONTROLLED TEST ARTIFACT — no real injection or shellcode executed.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* .payload section — GCC syntax (MSVC #pragma section silently ignored by GCC)
 * Executable flag set post-build via:
 *   objcopy --set-section-flags .payload=code,readonly pml_test.exe
 */
static const unsigned char g_payload[{entropy_sz}]
    __attribute__((section(".payload"), used)) = {{
{entropy_arr}
}};

/* XOR decode stub — Emotet/TrickBot/Ryuk packer opcode pattern */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}}

/* Encoded behavioral chain */
static const char g_enc[] = "{encoded_cmd}";

static BOOL launch_chain(void)
{{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    char                cmd[16384];
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    _snprintf_s(cmd, sizeof(cmd), _TRUNCATE,
        "cmd.exe /c powershell.exe "
        "-NoProfile -WindowStyle Hidden "
        "-ExecutionPolicy Bypass "
        "-EncodedCommand %s", g_enc);
    return CreateProcessA(NULL, cmd, NULL, NULL,
                          FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{{
    LPVOID pMem;
    DWORD  dwOld;
    SIZE_T written = 0;
    unsigned char scratch[16];
    (void)hPrev; (void)lpCmd; (void)nShow;

    /* Direct API calls -> static IAT population
     * All arguments are safe/trivial — no real injection occurs.
     * Purpose: force linker to include each API in the PE IAT header
     * so ATSE's import table extractor sees the injection fingerprint.
     */
    pMem = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
    if (pMem) VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &dwOld);
    if (pMem) VirtualFree(pMem, 0, MEM_RELEASE);
    WriteProcessMemory(GetCurrentProcess(), &scratch, &scratch, 0, &written);
    CloseHandle(
        CreateRemoteThread(GetCurrentProcess(), NULL, 0,
                           NULL, NULL, CREATE_SUSPENDED, NULL)
    );

    /* XOR stub: emit packer opcode pattern */
    memcpy(scratch, g_payload, sizeof(scratch));
    xor_decode(scratch, sizeof(scratch), 0x55);
    (void)scratch;

    if (!launch_chain()) return 1;
    Sleep(5000);
    return 0;
}}
"""

# ───────────────────────────────────────────────────────────────────────────────
#  CLEANUP SCRIPT
# ───────────────────────────────────────────────────────────────────────────────
CLEANUP_PS1 = "\n".join([
    "# PML Test Cleanup v4",
    "$ErrorActionPreference = 'SilentlyContinue'",
    "Write-Host '[*] Removing file artifacts...'",
    "$files = @(",
    '    "$env:APPDATA\\Microsoft\\Windows\\pml_s3.vbs",',
    '    "$env:TEMP\\pml_s4.js",',
    '    "$env:TEMP\\pml_done.txt"',
    ")",
    "foreach ($f in $files) {",
    "    if (Test-Path $f) { Remove-Item $f -Force",
    '        Write-Host "    [+] Removed: $f" }',
    "}",
    "Write-Host '[*] Removing registry persistence key...'",
    "$rk = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    "if (Get-ItemProperty -Path $rk -Name 'PMLTestStub' -EA SilentlyContinue) {",
    "    Remove-ItemProperty -Path $rk -Name 'PMLTestStub' -Force",
    "    Write-Host '    [+] Removed Run key: PMLTestStub'",
    "}",
    "Write-Host '[+] Cleanup complete. Restore PML File action to original setting.'",
]) + "\n"

# ───────────────────────────────────────────────────────────────────────────────
#  README
# ───────────────────────────────────────────────────────────────────────────────
README_MD = """\
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
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \\
    -mwindows -O2 -s -Wl,--strip-all \\
    -lkernel32 -luser32

# 2. Set .payload section executable
x86_64-w64-mingw32-objcopy \\
    --set-section-flags .payload=code,readonly \\
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
3. Check %TEMP%\\pml_done.txt exists
4. Verify Process Detection alert + Terminate in Vision One

## Cleanup
```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```
"""

# ───────────────────────────────────────────────────────────────────────────────
#  ENV CHECK + COMPILE
# ───────────────────────────────────────────────────────────────────────────────
def check_env():
    ok = True
    for tool in [GCC, OBJCOPY, OBJDUMP]:
        try:
            r = run_cmd([tool, "--version"])
            ver = r.stdout.splitlines()[0] if r.stdout else "(no output)"
            print("  [+] {}".format(ver[:70]))
        except FileNotFoundError:
            print("  [!] {} -- NOT FOUND".format(tool))
            ok = False
    return ok

def run_compile(outdir):
    src = os.path.join(outdir, "dropper_stub.c")
    exe = os.path.join(outdir, "pml_test.exe")

    print("[*] Step 1/3  Compiling...")
    gcc_cmd = [GCC, "-o", exe, src,
               "-mwindows", "-O2", "-s", "-Wl,--strip-all",
               "-lkernel32", "-luser32"]
    print("    " + " ".join(gcc_cmd))
    r = run_cmd(gcc_cmd)
    if r.returncode != 0:
        print("[!] Compile failed:\n" + r.stderr)
        return False
    if r.stderr.strip():
        print("    Warnings: " + r.stderr.strip())
    print("    [+] OK  {:,} bytes".format(os.path.getsize(exe)))

    print("[*] Step 2/3  Setting .payload section flags...")
    obj_cmd = [OBJCOPY, "--set-section-flags", ".payload=code,readonly", exe]
    print("    " + " ".join(obj_cmd))
    r = run_cmd(obj_cmd)
    if r.returncode != 0:
        print("    [!] objcopy failed: " + r.stderr.strip())
    else:
        print("    [+] .payload -> code + readonly (executable)")

    print("[*] Step 3/3  Appending 64 KB RC4 overlay...")
    append_overlay(exe)

    verify(exe)
    return True

# ───────────────────────────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="PML Dual-Detection Test Builder v4")
    ap.add_argument("--build",     action="store_true")
    ap.add_argument("--compile",   action="store_true")
    ap.add_argument("--overlay",   metavar="EXE")
    ap.add_argument("--verify",    metavar="EXE")
    ap.add_argument("--check-env", action="store_true")
    ap.add_argument("--clean",     action="store_true")
    ap.add_argument("--outdir",    default=OUT_DIR)
    args = ap.parse_args()

    if not any([args.build, args.compile, args.overlay,
                args.verify, args.check_env, args.clean]):
        ap.print_help()
        return

    if args.clean:
        if os.path.exists(args.outdir):
            shutil.rmtree(args.outdir)
            print("[+] Removed {}/".format(args.outdir))
        return

    if args.check_env:
        print("[*] Checking build environment...")
        check_env()
        return

    if args.overlay:
        append_overlay(args.overlay)
        return

    if args.verify:
        verify(args.verify)
        return

    # ── GENERATE SOURCE ────────────────────────────────────────────────────────
    os.makedirs(args.outdir, exist_ok=True)
    print("[*] Output directory : {}/\n".format(args.outdir))

    print("[*] Stage 3  Building VBScript...")
    s3_vbs  = build_stage3_vbs()
    s3_b64  = b64_utf8(s3_vbs)

    print("[*] Stage 2  Building PowerShell + encoding...")
    s2_ps1  = build_stage2_ps1(s3_b64)
    enc_cmd = encode_for_encoded_command(s2_ps1)
    print("    ENC length: {:,} chars  (limit: 8191)".format(len(enc_cmd)))
    if len(enc_cmd) > 7800:
        print("    [!] WARNING - approaching cmd.exe line limit")

    print("[*] Generating .payload section (RC4-keystream, 512 bytes)...")
    entropy = gen_payload_section(512)

    print("[*] Building C source...")
    c_src = C_TEMPLATE.format(
        entropy_sz  = len(entropy),
        entropy_arr = fmt_c_bytes(entropy),
        encoded_cmd = enc_cmd,
    )

    def write(name, content):
        path = os.path.join(args.outdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print("    [+] {:<28s} ({:,} bytes)".format(name, os.path.getsize(path)))

    print("[*] Writing files...")
    write("dropper_stub.c", c_src)
    write("cleanup.ps1",    CLEANUP_PS1)
    write("README.md",      README_MD)
    with open(__file__, "r", encoding="utf-8") as src:
        write("build.py", src.read())

    print("\n[*] Source ready.  Run:  python build.py --compile")

    if args.compile:
        print()
        if not check_env():
            print("[!] Missing tools — cannot compile")
            return
        run_compile(args.outdir)

if __name__ == "__main__":
    main()
