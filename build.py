#!/usr/bin/env python3
"""
PML Dual-Detection Test Builder  v3
Apex One Predictive Machine Learning - File + Process Detection Validation

Changes from v2:
  - Fixed: linker script removed (ELF phdr syntax invalid for PE targets)
  - Fixed: .payload executable flag now set via objcopy post-compile step
  - Added: --check-env  validates mingw + objcopy availability before build
  - Added: --compile    runs full compile + objcopy sequence automatically

Usage:
  python build.py --build                   generate source artifacts
  python build.py --compile                 build + compile + objcopy + overlay
  python build.py --overlay <pml.exe>       append RC4-pattern overlay to PE
  python build.py --check-env               verify mingw tools are available
  python build.py --clean                   remove output directory
"""

import os, sys, base64, argparse, shutil, subprocess

OUT_DIR = "pml_test_output_v3"

GCC     = "x86_64-w64-mingw32-gcc"
OBJCOPY = "x86_64-w64-mingw32-objcopy"

# ───────────────────────────────────────────────────────────────────────────────
#  RC4-KEYSTREAM  (correct packer-entropy profile)
#  Chi-sq ~270, mean ~129, serial corr ~-0.02  vs  os.urandom chi-sq 492k
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

def append_overlay(pe_path, size=8192):
    overlay = rc4_keystream(size)
    with open(pe_path, "ab") as f:
        f.write(overlay)
    print("[+] Overlay appended : {} bytes (RC4-keystream)".format(size))
    print("[i] Final file size  : {:,} bytes".format(os.path.getsize(pe_path)))

def gen_payload_section(size=512):
    return rc4_keystream(size, seed_key=b'\xBA\xDC\x0F\xFE\xDE\xAD\xC0\xDE')

def fmt_c_bytes(data, cols=16, indent=4):
    pad = " " * indent
    rows = []
    for i in range(0, len(data), cols):
        rows.append(pad + ", ".join("0x{:02X}".format(b) for b in data[i:i+cols]))
    return ",\n".join(rows)

# ───────────────────────────────────────────────────────────────────────────────
#  STAGE 4 — JScript (cscript.exe)
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

# ───────────────────────────────────────────────────────────────────────────────
#  STAGE 3 — VBScript (wscript.exe)
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
#  STAGE 2 — PowerShell (-EncodedCommand)
# ───────────────────────────────────────────────────────────────────────────────
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

# ───────────────────────────────────────────────────────────────────────────────
#  C SOURCE  v3
#
#  Section fix:
#    v2 used #pragma section (MSVC) → GCC warning + section not created
#    v2 also tried linker script with :text phdr → PE doesn't have phdrs → error
#
#    v3 solution:
#      Source:   __attribute__((section(".payload"), used))  → GCC creates section
#      Compile:  no linker script needed (plain gcc flags)
#      Post-build: objcopy --set-section-flags .payload=code,readonly
#                  → sets IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE
#                  → ATSE sees: high-entropy + executable section = shellcode staging
# ───────────────────────────────────────────────────────────────────────────────
C_TEMPLATE = """\
/*
 * pml_dropper_stub.c  v3
 * ─────────────────────────────────────────────────────────────────────────────
 * Static signals (ATSE feature extraction):
 *   [1] IAT: VirtualAlloc, VirtualProtect, WriteProcessMemory,
 *            CreateRemoteThread  --  direct calls, appear in PE import table
 *   [2] .payload section: 512 B RC4-keystream, entropy ~7.95 bpb
 *            executable flag set post-build via objcopy (shellcode staging)
 *   [3] XOR decode stub: tight loop matching packer opcode signatures
 *   [4] Unsigned PE: no Authenticode, no version info, no manifest
 *   [5] Overlay: 8 KB RC4-keystream appended post-build
 *
 * Behavioral chain (CIE telemetry):
 *   PE -> cmd.exe -> powershell.exe
 *      (-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand)
 *      -> wscript.exe pml_s3.vbs  (HKCU Run persistence + drop JScript)
 *      -> cscript.exe pml_s4.js   (3rd engine: completion marker)
 *
 * Compile (no linker script needed in v3):
 *   x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c
 *       -mwindows -O2 -s -Wl,--strip-all -lkernel32 -luser32
 *
 * Post-build (set .payload executable flag):
 *   x86_64-w64-mingw32-objcopy
 *       --set-section-flags .payload=code,readonly pml_test.exe
 *
 * CONTROLLED TEST ARTIFACT - no real injection or shellcode executed.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * High-entropy .payload section
 *
 * GCC syntax: __attribute__((section(".payload"), used))
 *   - section(".payload")  creates a named PE section
 *   - used                 prevents the compiler from discarding the symbol
 *                          as unreferenced dead code
 *
 * Executable flag is set AFTER compilation by:
 *   objcopy --set-section-flags .payload=code,readonly pml_test.exe
 *
 * Do NOT use:
 *   #pragma section         -- MSVC-only, silently ignored by GCC
 *   __declspec(allocate)    -- MSVC-only, produces "allocate ignored" warning
 *   Linker script :phdr     -- ELF concept, PE has no phdrs, causes ld error
 */
static const unsigned char g_payload[{entropy_sz}]
    __attribute__((section(".payload"), used)) = {{
{entropy_arr}
}};

/*
 * XOR decode stub
 * Opcode: XOR byte ptr [reg+offset], imm8  (0x80 /6)
 * Matches Emotet / TrickBot / Ryuk packer entry stubs.
 * noinline preserves the loop opcode pattern.
 */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}}

/* Encoded behavioral chain (UTF-16LE base64 for -EncodedCommand) */
static const char g_enc[] = "{encoded_cmd}";

/* Process chain launcher */
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
        "-EncodedCommand %s",
        g_enc);

    return CreateProcessA(NULL, cmd, NULL, NULL,
                          FALSE, CREATE_NO_WINDOW,
                          NULL, NULL, &si, &pi);
}}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{{
    LPVOID  pMem;
    DWORD   dwOld;
    SIZE_T  written = 0;
    unsigned char scratch[16];

    (void)hPrev; (void)lpCmd; (void)nShow;

    /*
     * Static IAT population via direct calls
     * ───────────────────────────────────────
     * All four calls use safe/trivial arguments (no real injection occurs).
     * Purpose: force linker to add each API to the PE IAT so ATSE can read
     * the injection capability fingerprint from the import table header.
     *
     * Without direct calls, GetProcAddress resolution is invisible to ATSE
     * because it happens at runtime, not at PE parse time.
     */

    /* VirtualAlloc: reserve only (no MEM_COMMIT) — no real memory allocated */
    pMem = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);

    /* VirtualProtect: no-op if pMem is NULL */
    if (pMem)
        VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &dwOld);

    /* VirtualFree: release immediately */
    if (pMem)
        VirtualFree(pMem, 0, MEM_RELEASE);

    /* WriteProcessMemory: 0 bytes to own process — succeeds, writes nothing */
    WriteProcessMemory(GetCurrentProcess(), &scratch, &scratch, 0, &written);

    /* CreateRemoteThread: NULL entry point — will fail, handle closed safely */
    CloseHandle(
        CreateRemoteThread(GetCurrentProcess(), NULL, 0,
                           NULL, NULL, CREATE_SUSPENDED, NULL)
    );

    /* XOR stub: emit packer opcode pattern on 16 bytes of .payload data */
    memcpy(scratch, g_payload, sizeof(scratch));
    xor_decode(scratch, sizeof(scratch), 0x55);
    (void)scratch;

    /* Launch behavioral chain */
    if (!launch_chain())
        return 1;

    /* Stay alive so CIE records parent-child process linkage */
    Sleep(5000);
    return 0;
}}
"""

# ───────────────────────────────────────────────────────────────────────────────
#  ENV CHECK
# ───────────────────────────────────────────────────────────────────────────────
def check_env():
    ok = True
    for tool in [GCC, OBJCOPY]:
        try:
            r = subprocess.run([tool, "--version"],
                               capture_output=True, text=True)
            ver = r.stdout.splitlines()[0] if r.stdout else "(no output)"
            print("  [+] {} -- {}".format(tool, ver))
        except FileNotFoundError:
            print("  [!] {} -- NOT FOUND".format(tool))
            ok = False
    return ok

# ───────────────────────────────────────────────────────────────────────────────
#  FULL COMPILE SEQUENCE  (--compile flag)
# ───────────────────────────────────────────────────────────────────────────────
def run_compile(outdir):
    src  = os.path.join(outdir, "dropper_stub.c")
    exe  = os.path.join(outdir, "pml_test.exe")

    # Step 1: gcc
    gcc_cmd = [
        GCC, "-o", exe, src,
        "-mwindows", "-O2", "-s", "-Wl,--strip-all",
        "-lkernel32", "-luser32"
    ]
    print("[*] Compiling...")
    print("    " + " ".join(gcc_cmd))
    r = subprocess.run(gcc_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("[!] Compile failed:\n" + r.stderr)
        return False
    if r.stderr.strip():
        print("    Warnings: " + r.stderr.strip())
    print("    [+] Compiled: {:,} bytes".format(os.path.getsize(exe)))

    # Step 2: objcopy -- set .payload executable
    # code      = IMAGE_SCN_CNT_CODE       (marks as code section)
    # readonly  = IMAGE_SCN_MEM_READ       (readable)
    # Together these cause the linker/loader to also set MEM_EXECUTE on PE sections
    obj_cmd = [
        OBJCOPY,
        "--set-section-flags", ".payload=code,readonly",
        exe
    ]
    print("[*] Setting .payload section flags (executable)...")
    print("    " + " ".join(obj_cmd))
    r = subprocess.run(obj_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("[!] objcopy failed:\n" + r.stderr)
        print("    (continuing — section may not have executable flag)")
    else:
        print("    [+] .payload flags set: code + readonly (execute)")

    # Step 3: overlay
    print("[*] Appending RC4-keystream overlay (8192 bytes)...")
    append_overlay(exe)

    print("\n[+] Final binary: {}".format(exe))
    return True

# ───────────────────────────────────────────────────────────────────────────────
#  CLEANUP SCRIPT
# ───────────────────────────────────────────────────────────────────────────────
CLEANUP_PS1 = "\n".join([
    "# PML Test Cleanup v3",
    "$ErrorActionPreference = 'SilentlyContinue'",
    "",
    "Write-Host '[*] Removing file artifacts...'",
    "$files = @(",
    '    "$env:APPDATA\\Microsoft\\Windows\\pml_s3.vbs",',
    '    "$env:TEMP\\pml_s4.js",',
    '    "$env:TEMP\\pml_done.txt"',
    ")",
    "foreach ($f in $files) {",
    "    if (Test-Path $f) {",
    "        Remove-Item $f -Force",
    '        Write-Host "    [+] Removed: $f"',
    "    }",
    "}",
    "",
    "Write-Host '[*] Removing registry persistence key...'",
    "$rk = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    "if (Get-ItemProperty -Path $rk -Name 'PMLTestStub' -EA SilentlyContinue) {",
    "    Remove-ItemProperty -Path $rk -Name 'PMLTestStub' -Force",
    "    Write-Host '    [+] Removed Run key: PMLTestStub'",
    "}",
    "",
    "Write-Host '[+] Cleanup complete. Restore PML File action to original setting.'",
]) + "\n"

# ───────────────────────────────────────────────────────────────────────────────
#  README
# ───────────────────────────────────────────────────────────────────────────────
README_MD = """\
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
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \\
    -mwindows -O2 -s -Wl,--strip-all \\
    -lkernel32 -luser32

# 2. Set .payload section executable (PE section flag — no ELF phdr involved)
x86_64-w64-mingw32-objcopy \\
    --set-section-flags .payload=code,readonly \\
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
3. Check `%TEMP%\\pml_done.txt` exists (Stage 4 completion marker)
4. Verify Process Detection alert + Terminate in Vision One

## Cleanup

```powershell
powershell -ExecutionPolicy Bypass -File cleanup.ps1
```
"""

# ───────────────────────────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="PML Dual-Detection Test Builder v3")
    ap.add_argument("--build",     action="store_true", help="Generate source artifacts")
    ap.add_argument("--compile",   action="store_true", help="Build + compile + objcopy + overlay")
    ap.add_argument("--overlay",   metavar="EXE",       help="Append RC4 overlay to compiled PE")
    ap.add_argument("--check-env", action="store_true", help="Check mingw tools available")
    ap.add_argument("--clean",     action="store_true", help="Remove output directory")
    ap.add_argument("--outdir",    default=OUT_DIR)
    args = ap.parse_args()

    if not any([args.build, args.compile, args.overlay, args.check_env, args.clean]):
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

    # ── GENERATE SOURCE ────────────────────────────────────────────────────────
    os.makedirs(args.outdir, exist_ok=True)
    print("[*] Output directory : {}/\n".format(args.outdir))

    print("[*] Stage 3  Building VBScript...")
    s3_vbs  = build_stage3_vbs()
    s3_b64  = b64_utf8(s3_vbs)
    print("    VBS raw   : {:,} chars".format(len(s3_vbs)))

    print("[*] Stage 2  Building PowerShell + encoding...")
    s2_ps1  = build_stage2_ps1(s3_b64)
    enc_cmd = encode_for_encoded_command(s2_ps1)
    print("    ENC length: {:,} chars  (cmd.exe limit: 8191)".format(len(enc_cmd)))
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

    sep = "=" * 62
    print("\n" + sep)
    print("  Source generated.  Next steps:\n")
    print("  Compile + objcopy + overlay (all-in-one):")
    print("    python build.py --compile\n")
    print("  Or manually:")
    print("    {} -o pml_test.exe dropper_stub.c \\".format(GCC))
    print("        -mwindows -O2 -s -Wl,--strip-all \\")
    print("        -lkernel32 -luser32\n")
    print("    {} --set-section-flags .payload=code,readonly pml_test.exe\n".format(OBJCOPY))
    print("    python build.py --overlay pml_test.exe\n")
    print("  Verify: ent pml_test.exe  (target: entropy > 7.0, chi-sq < 1000)")
    print(sep)

    # ── AUTO COMPILE if --compile flag set ────────────────────────────────────
    if args.compile:
        print()
        if not check_env():
            print("[!] Missing tools — install mingw-w64 first")
            return
        run_compile(args.outdir)

if __name__ == "__main__":
    main()
