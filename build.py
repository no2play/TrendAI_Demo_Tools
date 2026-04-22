#!/usr/bin/env python3
"""
PML Dual-Detection Test Builder  v2
Apex One Predictive Machine Learning - File + Process Detection Validation

Changes from v1:
  - Fixed: suspicious APIs now in static IAT (not dynamic GetProcAddress)
  - Fixed: .payload section uses GCC __attribute__((section)) not MSVC #pragma
  - Fixed: section marked executable (xr flags via linker script)
  - Fixed: overlay uses RC4-keystream pattern (not os.urandom white noise)

Usage:
  python build.py --build               generate all source artifacts
  python build.py --overlay <pml.exe>   append RC4-pattern overlay to PE
  python build.py --clean               remove output directory
"""

import os, sys, base64, argparse, shutil

OUT_DIR = "pml_test_output_v2"

# ───────────────────────────────────────────────────────────────────────────────
#  RC4-KEYSTREAM OVERLAY
#  Replaces os.urandom() from v1.
#
#  os.urandom() fails ATSE's packer-pattern model because:
#    - Chi-square ~492,000  (should be ~255-300 for real encrypted data)
#    - Arithmetic mean ~81  (should be ~127.5)
#    - Serial correlation ~0.40 (should be ~0.0)
#
#  RC4 keystream is the correct model: statistically near-uniform (Chi ~270),
#  mean ~127, correlation ~0.0 — matches real AES/RC4 encrypted payload regions.
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
    print("[+] Overlay appended : {} bytes (RC4-keystream pattern)".format(size))
    print("[i] Final file size  : {:,} bytes".format(os.path.getsize(pe_path)))

# ───────────────────────────────────────────────────────────────────────────────
#  HIGH-ENTROPY .payload SECTION  (RC4, 512 bytes)
#  GCC/mingw uses __attribute__((section(".payload"))) — NOT #pragma section.
#  The old #pragma section + __declspec(allocate) are MSVC-only and silently
#  ignored by GCC, meaning no .payload section was ever created in v1.
# ───────────────────────────────────────────────────────────────────────────────
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
#  Signal: 3rd distinct script engine completing the chain
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
#  Signals: HKCU\Run persistence | %APPDATA% write | wscript->cscript hop
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
        "' Drop Stage 4 JScript line-by-line (avoids multi-level quote nesting)",
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
#  STAGE 2 — PowerShell (-EncodedCommand, launched by cmd.exe)
#  Signals: -NoProfile -Hidden -Bypass -EncodedCommand | IEX | %APPDATA% write
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
#  LINKER SCRIPT — sets .payload section flags to executable + readable
#
#  GCC alone cannot set PE section flags via source code.
#  A linker script is the correct mechanism.  Without this, .payload
#  is data-only (r/w), which is less anomalous.  With executable flag,
#  ATSE sees: high-entropy section + executable = shellcode staging pattern.
# ───────────────────────────────────────────────────────────────────────────────
LINKER_SCRIPT = """\
/* pml_sections.ld
 * Forces .payload section to be marked executable + readable in the PE.
 * High-entropy + executable = shellcode staging signal for ATSE.
 */
SECTIONS
{
  .payload : { *(.payload) } :text
}
INSERT AFTER .text;
"""

# ───────────────────────────────────────────────────────────────────────────────
#  C SOURCE — PE Dropper Stub  v2
#
#  Key fixes from v1:
#
#  FIX 1 — Static IAT population (replaces dynamic GetProcAddress chain)
#  ─────────────────────────────────────────────────────────────────────
#  v1 used:  pVA = (pfnVirtualAlloc) GetProcAddress(hK32, "VirtualAlloc");
#  PROBLEM:  Dynamic resolution does NOT add APIs to the PE's IAT.
#            ATSE reads the import table from the PE header — APIs resolved
#            at runtime via GetProcAddress are completely invisible to it.
#  FIX:      Directly call the APIs (even with trivial/safe arguments) so
#            the linker is forced to add them to the IAT.
#
#  FIX 2 — GCC-compatible section attribute
#  ─────────────────────────────────────────
#  v1 used:  #pragma section(".payload") + __declspec(allocate(".payload"))
#  PROBLEM:  Both are MSVC-only extensions.  GCC/mingw silently ignores them
#            (hence the "allocate attribute directive ignored" warning).
#            No .payload section was ever created in the compiled PE.
#  FIX:      Use GCC's __attribute__((section(".payload"))) which mingw
#            correctly translates to a named PE section.
# ───────────────────────────────────────────────────────────────────────────────
C_TEMPLATE = """\
/*
 * pml_dropper_stub.c  v2
 * ─────────────────────────────────────────────────────────────────────────────
 * Static signals (ATSE scans before execution):
 *   [1] IAT: VirtualAlloc, VirtualProtect, WriteProcessMemory,
 *            CreateRemoteThread — directly called, appear in import table
 *   [2] IAT: VirtualFree, GetCurrentProcess — consistent injection context
 *   [3] .payload section: 512 B RC4-keystream, entropy ~7.95 bpb, executable
 *   [4] XOR decode stub: tight loop matching packer opcode signatures
 *   [5] Unsigned PE: no Authenticode, no version info, no manifest
 *   [6] Overlay: 8 KB RC4-keystream appended post-build (dropper pattern)
 *
 * Behavioral chain (CIE observes after execution):
 *   PE -> cmd.exe -> powershell.exe
 *      (-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand)
 *      -> wscript.exe pml_s3.vbs  (HKCU Run persistence + drop JScript)
 *      -> cscript.exe pml_s4.js   (3rd engine: completion marker)
 *
 * CONTROLLED TEST ARTIFACT - no real injection, no real shellcode executed.
 * All sensitive API calls use safe arguments that produce no actual effect.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * High-entropy .payload section
 *
 * GCC/mingw syntax: __attribute__((section(".payload")))
 * DO NOT use #pragma section + __declspec(allocate) — those are MSVC-only
 * and are silently ignored by GCC (causing the v1 "allocate attribute
 * directive ignored" warning and no section being created).
 *
 * 512 bytes of RC4-keystream data: entropy ~7.95 bpb.
 * ATSE flags PE sections with entropy > 7.0 as packed/encrypted content.
 * Non-standard section name is an additional structural anomaly.
 * Executable flag (set via linker script) makes this a shellcode-staging signal.
 */
static const unsigned char g_payload[{entropy_sz}]
    __attribute__((section(".payload"), used)) = {{
{entropy_arr}
}};

/*
 * XOR decode stub
 * Opcode pattern: XOR byte ptr [reg+offset], imm8  (0x80 /6 ib)
 * This is the canonical single-byte XOR loop emitted by Emotet/TrickBot/Ryuk
 * packer stubs.  ATSE's opcode feature extractor assigns a high-weight score
 * to this pattern regardless of surrounding context.
 * __attribute__((noinline)) prevents the compiler from inlining or
 * vectorising the loop, which would change the opcode signature.
 */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}}

/*
 * Encoded behavioral chain (UTF-16LE base64 for -EncodedCommand)
 * cmd.exe /c powershell.exe
 *     -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass
 *     -EncodedCommand <b64>
 */
static const char g_enc[] = "{encoded_cmd}";

/* ── Process chain launcher ──────────────────────────────────────────────── */
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

/* ── WinMain ─────────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{{
    LPVOID  pMem;
    DWORD   dwOld;
    SIZE_T  written = 0;
    unsigned char scratch[16];

    (void)hPrev; (void)lpCmd; (void)nShow;

    /*
     * FIX 1: Static IAT population via direct API calls
     * ─────────────────────────────────────────────────
     * Each call below is safe — trivial arguments that produce no real effect
     * (NULL handles, 0 sizes, MEM_RESERVE without MEM_COMMIT, etc.).
     * The SOLE purpose is to force the linker to add each API to the PE's IAT,
     * making them visible to ATSE's import table feature extractor.
     *
     * Injection capability fingerprint this creates in the IAT:
     *   VirtualAlloc          HIGH SIGNAL  memory allocation (stage 1 of injection)
     *   VirtualProtect        HIGH SIGNAL  RWX permission change
     *   VirtualFree           context      paired with VirtualAlloc
     *   WriteProcessMemory    HIGH SIGNAL  cross-process write
     *   CreateRemoteThread    HIGH SIGNAL  remote code execution
     *   GetCurrentProcess     context      pseudo-handle, common in injectors
     */

    /* VirtualAlloc: reserve 4 KB in own process — no actual allocation */
    pMem = VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);

    /* VirtualProtect: change protection on the reserved region — no-op if
     * pMem is NULL (which it will be on MEM_RESERVE without MEM_COMMIT) */
    if (pMem)
        VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &dwOld);

    /* VirtualFree: release immediately — net effect is zero */
    if (pMem)
        VirtualFree(pMem, 0, MEM_RELEASE);

    /* WriteProcessMemory: write 0 bytes to own process — succeeds silently */
    WriteProcessMemory(GetCurrentProcess(), &scratch, &scratch, 0, &written);

    /* CreateRemoteThread: NULL entry point on own process, CREATE_SUSPENDED.
     * Will fail (returns NULL) but the IAT entry is what matters. */
    CloseHandle(
        CreateRemoteThread(GetCurrentProcess(), NULL, 0,
                           NULL, NULL, CREATE_SUSPENDED, NULL)
    );

    /* XOR stub: decode 16 bytes of g_payload — emits the packer opcode pattern */
    memcpy(scratch, g_payload, sizeof(scratch));
    xor_decode(scratch, sizeof(scratch), 0x55);
    (void)scratch;

    /* Launch behavioral chain:
     * PE -> cmd.exe -> powershell (encoded)
     *    -> wscript.exe (VBScript: HKCU Run + drop JScript)
     *    -> cscript.exe (JScript: completion marker)
     */
    if (!launch_chain())
        return 1;

    /* Stay alive so CIE records the parent-child process linkage */
    Sleep(5000);
    return 0;
}}
"""

# ───────────────────────────────────────────────────────────────────────────────
#  COMPILE COMMAND  (printed in README + build output)
#  -T pml_sections.ld    applies linker script for executable .payload flag
#  -Wl,--enable-stdcall-fixup  avoids missing-symbol noise on some mingw builds
# ───────────────────────────────────────────────────────────────────────────────
COMPILE_CMD = (
    "x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \\\n"
    "    -mwindows -O2 -s -Wl,--strip-all \\\n"
    "    -T pml_sections.ld \\\n"
    "    -lkernel32 -luser32"
)

# ───────────────────────────────────────────────────────────────────────────────
#  CLEANUP SCRIPT
# ───────────────────────────────────────────────────────────────────────────────
CLEANUP_PS1 = "\n".join([
    "# PML Test Cleanup v2",
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
def build_readme(compile_cmd):
    return """\
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
""" + compile_cmd + """
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
3. Verify `%TEMP%\\pml_done.txt` exists (Stage 4 completion marker)
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
"""

# ───────────────────────────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="PML Dual-Detection Test Builder v2")
    ap.add_argument("--build",   action="store_true")
    ap.add_argument("--overlay", metavar="EXE")
    ap.add_argument("--clean",   action="store_true")
    ap.add_argument("--outdir",  default=OUT_DIR)
    args = ap.parse_args()

    if not any([args.build, args.overlay, args.clean]):
        ap.print_help()
        return

    if args.clean:
        if os.path.exists(args.outdir):
            shutil.rmtree(args.outdir)
            print("[+] Removed {}/".format(args.outdir))
        return

    if args.overlay:
        append_overlay(args.overlay)
        return

    # ── BUILD ──────────────────────────────────────────────────────────────────
    os.makedirs(args.outdir, exist_ok=True)
    print("[*] Output directory : {}/\n".format(args.outdir))

    print("[*] Stage 3  Building VBScript...")
    s3_vbs = build_stage3_vbs()
    s3_b64 = b64_utf8(s3_vbs)
    print("    VBS raw   : {:,} chars".format(len(s3_vbs)))
    print("    VBS b64   : {:,} chars".format(len(s3_b64)))

    print("[*] Stage 2  Building PowerShell + encoding...")
    s2_ps1  = build_stage2_ps1(s3_b64)
    enc_cmd = encode_for_encoded_command(s2_ps1)
    print("    PS1 raw   : {:,} chars".format(len(s2_ps1)))
    print("    ENC length: {:,} chars  (cmd.exe limit: 8191)".format(len(enc_cmd)))
    if len(enc_cmd) > 7800:
        print("    [!] WARNING - encoded command approaching cmd.exe line limit")

    print("[*] Generating .payload section (RC4-keystream, 512 bytes)...")
    entropy = gen_payload_section(512)

    print("[*] Building C source (v2 fixes applied)...")
    c_src = C_TEMPLATE.format(
        entropy_sz  = len(entropy),
        entropy_arr = fmt_c_bytes(entropy),
        encoded_cmd = enc_cmd,
    )

    def write(name, content, mode="w"):
        path = os.path.join(args.outdir, name)
        if mode == "wb":
            with open(path, "wb") as fh:
                fh.write(content)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        print("    [+] {:<30s} ({:,} bytes)".format(name, os.path.getsize(path)))

    print("[*] Writing files...")
    write("dropper_stub.c",   c_src)
    write("pml_sections.ld",  LINKER_SCRIPT)
    write("cleanup.ps1",      CLEANUP_PS1)
    write("README.md",        build_readme(COMPILE_CMD))
    with open(__file__, "r", encoding="utf-8") as src:
        write("build.py", src.read())

    sep = "=" * 62
    print("""
{}
  Build complete.  v2 fixes applied:
    [1] Suspicious APIs now in static IAT (direct calls)
    [2] .payload section uses GCC __attribute__((section))
    [3] Overlay uses RC4-keystream (not os.urandom)
    [4] .payload marked executable via linker script

  Compile:
    {}

  Append overlay:
    python build.py --overlay pml_test.exe

  Verify entropy:
    ent pml_test.exe
    (target: entropy > 7.0, chi-sq < 600, mean > 100)

  Then follow README.md for test execution steps.
{}""".format(sep, COMPILE_CMD.replace("\\\n    ", " \\\n    "), sep))

if __name__ == "__main__":
    main()
