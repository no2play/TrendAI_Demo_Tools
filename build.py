#!/usr/bin/env python3
"""
PML Dual-Detection Test Builder
Apex One Predictive Machine Learning - File + Process Detection Validation
"""

import os, sys, base64, random, argparse, shutil

OUT_DIR = "pml_test_output"

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
        "' Signals: HKCU\\Run persistence | %APPDATA% drop | wscript->cscript hop",
        "Option Explicit",
        "Dim sh, fs, jp, fh",
        "",
        'Set sh = CreateObject("WScript.Shell")',
        'Set fs = CreateObject("Scripting.FileSystemObject")',
        "",
        "' -- Persistence: HKCU Run key --",
        "sh.RegWrite _",
        '    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\PMLTestStub", _',
        '    "wscript.exe """ & WScript.ScriptFullName & """", _',
        '    "REG_SZ"',
        "",
        "' -- Drop Stage 4 JScript line-by-line --",
        'jp = sh.ExpandEnvironmentStrings("%TEMP%") & "\\pml_s4.js"',
        "Set fh = fs.OpenTextFile(jp, 2, True)",
    ]
    for js_line in STAGE4_LINES:
        lines.append('fh.WriteLine "' + js_line + '"')
    lines += [
        "fh.Close",
        "",
        "' -- Cross-engine hop: wscript -> cscript --",
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

def gen_entropy_section(size=512, seed=0xDEADBEEF):
    rng = random.Random(seed)
    return bytes((rng.randint(0, 255) ^ 0x55) for _ in range(size))

def fmt_c_bytes(data, cols=16, indent=4):
    pad = " " * indent
    rows = []
    for i in range(0, len(data), cols):
        rows.append(pad + ", ".join("0x{:02X}".format(b) for b in data[i:i+cols]))
    return ",\n".join(rows)

C_TEMPLATE = """\
/*
 * pml_dropper_stub.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Purpose   : File-detection trigger for Apex One PML test
 * Role      : Stage-1 PE — triggers ATSE + PML File Model, then launches
 *             behavioral chain for CIE + PML Process Model
 *
 * Static signals (ATSE scans these before execution):
 *   [1] Import table  : VirtualAlloc, WriteProcessMemory, CreateRemoteThread
 *   [2] Dynamic import: LoadLibrary -> GetProcAddress resolution chain
 *   [3] .payload      : 512-byte section, Shannon entropy ~7.95 bpb
 *   [4] XOR opcode    : tight XOR loop matching packer stub signatures
 *   [5] Unsigned PE   : no Authenticode, no version resource, no manifest
 *   [7] Overlay bytes : appended post-build (dropper/binder pattern)
 *
 * Behavioral chain (CIE observes after execution):
 *   PE -> cmd.exe -> powershell.exe (-NoProfile -Hidden -Bypass -EncodedCommand)
 *      -> wscript.exe pml_s3.vbs (HKCU Run persistence + drop JScript)
 *      -> cscript.exe pml_s4.js  (3rd engine: completion marker)
 *
 * CONTROLLED TEST ARTIFACT - no actual injection or shellcode executed.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Suspicious API typedefs - presence in import resolution chain is the signal.
 * ATSE maps these against injection/loader capability fingerprints.
 * None are invoked with real targets.
 */
typedef LPVOID  (WINAPI *pfnVirtualAlloc)       (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pfnWriteProcessMemory) (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE  (WINAPI *pfnCreateRemoteThread) (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                                 LPTHREAD_START_ROUTINE, LPVOID,
                                                 DWORD, LPDWORD);
typedef BOOL    (WINAPI *pfnVirtualProtect)     (LPVOID, SIZE_T, DWORD, PDWORD);

/* High-entropy .payload section
 * 512 bytes XOR-scrambled pseudo-random data.
 * Shannon entropy: ~7.95 bpb.  ATSE flags sections > 7.0 as packed/encrypted.
 * Non-standard section name is a structural anomaly (packer artifact pattern).
 */
#pragma section(".payload", read, write)
__declspec(allocate(".payload"))
static const unsigned char g_payload[{entropy_sz}] = {{
{entropy_arr}
}};

/* XOR decode stub
 * Tight loop + XOR byte ptr [reg], key  (opcode 0x30/0x32 per iteration).
 * Matches packer stub signatures used by Emotet, TrickBot, Ryuk.
 * noinline preserves opcode sequence against compiler optimisation.
 */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}}

/* Encoded behavioral chain
 * cmd.exe /c powershell.exe -NoProfile -WindowStyle Hidden
 *                           -ExecutionPolicy Bypass -EncodedCommand <b64>
 * CIE signals: abnormal parent, hidden window, -BypassPolicy, -EncodedCommand.
 */
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
        "-EncodedCommand %s",
        g_enc);

    return CreateProcessA(NULL, cmd, NULL, NULL,
                          FALSE, CREATE_NO_WINDOW,
                          NULL, NULL, &si, &pi);
}}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{{
    HMODULE               hK32, hNt;
    pfnVirtualAlloc       pVA;
    pfnWriteProcessMemory pWPM;
    pfnCreateRemoteThread pCRT;
    pfnVirtualProtect     pVP;
    unsigned char         scratch[16];

    (void)hPrev; (void)lpCmd; (void)nShow;

    /* Dynamic import resolution
     * LoadLibraryA -> GetProcAddress(suspicious API) pattern.
     * CIE telemetry observes this as a reflective-loader / injector hallmark,
     * even when the resolved functions are not subsequently invoked.
     */
    hK32 = LoadLibraryA("kernel32.dll");
    hNt  = LoadLibraryA("ntdll.dll");
    pVA  = (pfnVirtualAlloc)       GetProcAddress(hK32, "VirtualAlloc");
    pWPM = (pfnWriteProcessMemory) GetProcAddress(hK32, "WriteProcessMemory");
    pCRT = (pfnCreateRemoteThread) GetProcAddress(hK32, "CreateRemoteThread");
    pVP  = (pfnVirtualProtect)     GetProcAddress(hK32, "VirtualProtect");

    /* Keep symbols reachable - prevent linker from stripping them */
    (void)hNt; (void)pVA; (void)pWPM; (void)pCRT; (void)pVP;

    /* XOR stub: decode 16 bytes of g_payload - emits opcode pattern */
    memcpy(scratch, g_payload, sizeof(scratch));
    xor_decode(scratch, sizeof(scratch), 0x55);
    (void)scratch;

    /* Launch behavioral chain */
    if (!launch_chain())
        return 1;

    /* Stay alive so CIE can record parent-child linkage */
    Sleep(5000);
    return 0;
}}
"""

CLEANUP_PS1 = "\n".join([
    "# PML Test Cleanup - removes all test artifacts",
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

README_MD = """\
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
3. Verify `%TEMP%\\pml_done.txt` exists (confirms Stage 4 completed)
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
"""

def append_overlay(pe_path, size=256):
    rng = random.Random(0xCAFEBABE)
    overlay = bytes(rng.randint(0, 255) ^ 0xAA for _ in range(size))
    with open(pe_path, "ab") as f:
        f.write(overlay)
    print("[+] Overlay appended : {} bytes".format(size))
    print("[i] Final file size  : {:,} bytes".format(os.path.getsize(pe_path)))

def main():
    ap = argparse.ArgumentParser(description="PML Dual-Detection Test Builder")
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

    os.makedirs(args.outdir, exist_ok=True)
    print("[*] Output directory : {}/\n".format(args.outdir))

    print("[*] Stage 3  Building VBScript (embeds Stage 4 inline)...")
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

    print("[*] Generating high-entropy .payload section (512 bytes)...")
    entropy = gen_entropy_section(512)

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
        print("    [+] {:<30s} ({:,} bytes)".format(name, os.path.getsize(path)))

    print("[*] Writing files...")
    write("dropper_stub.c", c_src)
    write("cleanup.ps1",    CLEANUP_PS1)
    write("README.md",      README_MD)
    with open(__file__, "r", encoding="utf-8") as src:
        write("build.py", src.read())

    sep = "=" * 62
    print("""
{}
  Build complete.

  1. Compile (requires mingw-w64):
     x86_64-w64-mingw32-gcc -o pml_test.exe dropper_stub.c \\
         -mwindows -O2 -s -Wl,--strip-all \\
         -lkernel32 -luser32

  2. Append overlay:  python build.py --overlay pml_test.exe

  3. Copy pml_test.exe to endpoint
     -> File Detection alert  (ATSE + PML File Model)

  4. Set File action to "Log only", then execute
     -> Process Detection alert  (CIE + PML Process Model)

  5. Verify: %TEMP%\\pml_done.txt should exist after chain runs

  6. Cleanup: powershell -ExecutionPolicy Bypass -File cleanup.ps1
{}""".format(sep, sep))

if __name__ == "__main__":
    main()
