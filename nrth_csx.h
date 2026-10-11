#pragma once
/**
 * ============================================================================
 * nrth_csx.h — CSX.exe FULL REVERSE ENGINEERING results + read-only audit
 * ============================================================================
 * SAMPLE: CSX.exe, SHA-256
 *   683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31
 *   PE32 native GUI "CSX Loader", requireAdministrator, 6,175,744 B,
 *   .text 0x376F9 (entropy 6.48), .rsrc 0x597638 (95% of file).
 *
 * LOADER CHAIN (all call sites verified by disassembly, capstone):
 *   - Resource load + decrypt : FindResourceW @0x409DB8 (id in cx, RCDATA),
 *     LockResource @0x409DDE, SizeofResource @0x409DED
 *   - DECRYPTION (loop @0x409E30): buf[i] ^= key[i & 15] with the 16-byte key
 *     stored at VA 0x4463FC = "C5x~Stealth!2026" (also derivable from the
 *     container header 0E6FE87E50746561"68746821"CDCF3236 XOR a standard DOS
 *     header). Plaintext must start with "MZ" (checked @0x409E48).
 *   - Drop to disk: CreateFileA CREATE_ALWAYS with 4 retries x Sleep(600)
 *     (@0x409E62..), WriteFile (@0x409EB6).
 *   - Injection suite: VirtualAllocEx @0x4021D6/370, WriteProcessMemory
 *     @0x40224B/2BD/3A5/3BE, CreateRemoteThread @0x4023D6, ResumeThread
 *     @0x40C8DC; target PID found via CreateToolhelp32Snapshot + Process32
 *     loop comparing against a name at 0x446254 (gta_sa.exe).
 *   - Spoofer ("reset MTA serial identity"): MachineGuid
 *     (HKLM\SOFTWARE\Microsoft\Cryptography) + the 8 MTA identity keys
 *     (SOFTWARE[\WOW6432Node]\Multi Theft Auto{...}\1.5/1.6) + clearing
 *     C:\ProgramData\MTA San Andreas All\Common\data\cache; own state under
 *     non-standard Explorer\CLSID2; revert log "your real hardware identity
 *     is back". License/C2 via WinHttp: /api/event, /api/heartbeat,
 *     /status?hwid=, {"banned":true}; updates from onlyyoussef/csx-update
 *     CDNs; ip-api.com; discord.gg/ehXCwMMFrM.
 *
 * DECRYPTED PAYLOADS (this analysis decrypted them statically with the key):
 *   PAYLOAD-102 (RCDATA 102, 3,744,256 B) = csxcheat.dll
 *     PE32 DLL, base 0x10000000, SHA-256
 *     1026d3be16e37ce8aefa62148da71fe54afd54c6ca7ef3d4381e7f34be78869e
 *     D3D9 overlay menu (imports Direct3DCreate9 + d3dx9; "##MainMenuBar",
 *     PT/EN settings UI). Cleartext capability logs:
 *       [SILENTAIM] ProcessLineOfSight hooked / SendBulletSyncFire hooked
 *       [CLIENT] SendBulletSync hook enabled! (bullet-sync packet tampering)
 *       [ANTISCREEN] Server screenshot blocked!  TakePlayerScreenShot @0x%X
 *       [TRIGGER] Block list is full (64)
 *     plus teleport/money/Lua-dump strings and Discord data access
 *     (\discord\sentry\scope_v3.json -> discord_id/name/email fingerprinting;
 *     CryptoAPI hashing for hwid).
 *   PAYLOAD-103 (RCDATA 103, 184,832 B) = CSXAgent (dropped as csxprobe.exe /
 *     version.dll proxy)
 *     PE32 DLL, base 0x10000000, SHA-256
 *     731854a7705d539eee41c47d22112f6e6aa34615b3b61723ec847a3ea0e269af
 *     Exports the 16 version.dll functions (DLL sideload proxy); imports
 *     dbghelp MiniDumpWriteDump/StackWalk64 + WriteProcessMemory +
 *     TerminateProcess + RemoveVectoredExceptionHandler; PDB path leaked:
 *     C:\Users\dell\Downloads\all\freeesp\CSXAgent\bin\x86\csxagent.pdb
 *
 * SCOPE (authorized blue-team lab only): read-only audit constants/helpers.
 * Nothing here modifies MachineGuid/MTA serials or injects into processes —
 * the live spoofer is ban-evasion tooling and is intentionally NOT rebuilt;
 * the value for the report verification is detection + documented evidence.
 * ============================================================================
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ---- Evidence constants (all verified in CSX.exe / decrypted payloads) ---- */
#define NRTH_CSX_CONTAINER_MAGIC "\x0E\x6F\xE8\x7E\x50\x74\x65\x61\x68\x74\x68\x21\xCD\xCF\x32\x36"
#define NRTH_CSX_XOR_KEY         "C5x~Stealth!2026"     /* @VA 0x4463FC, 16 bytes */
#define NRTH_CSX_KEY_VA          0x4463FCu

static const char *kNrthCsxSigs[] = {
    "csxcheat.dll",                                    /* 0  injected payload name   */
    "csxprobe.exe",                                    /* 1  dropped probe name      */
    NRTH_CSX_CONTAINER_MAGIC,                          /* 2  encrypted RCDATA header */
    NRTH_CSX_XOR_KEY,                                  /* 3  XOR-16 key in loader    */
    "/api/heartbeat",                                  /* 4  C2 heartbeat endpoint   */
    "{\"type\":\"rename\",\"hwid\":\"",                /* 5  spoofer rename request  */
    "Explorer\\CLSID2",                                /* 6  non-standard state key  */
    "[SILENTAIM] SendBulletSyncFire hooked",           /* 7  payload-102 capability  */
    "[ANTISCREEN] Server screenshot blocked!",         /* 8  payload-102 capability  */
    "csxagent.pdb",                                    /* 9  payload-103 PDB leak    */
    "scope_v3.json",                                   /* 10 Discord sentry path     */
    "[TRIGGER] Block list is full (64)",               /* 11 payload-102 triggerbot  */
    " resetting MTA serial identity",                  /* 12 loader spoofer log      */
};
#define NRTH_CSX_SIG_COUNT  (sizeof(kNrthCsxSigs) / sizeof(kNrthCsxSigs[0]))

/* signature bit flags (index i -> bit i) */
static uint32_t NrthCsx_ScanSignatures(const uint8_t *data, size_t len)
{
    if (!data || len == 0) {
        return 0;
    }
    uint32_t flags = 0;
    for (size_t i = 0; i < NRTH_CSX_SIG_COUNT; ++i) {
        const char *sig = kNrthCsxSigs[i];
        const size_t slen = strlen(sig);
        if (slen == 0 || slen > len) {
            continue;
        }
        for (size_t off = 0; off + slen <= len; ++off) {
            if (memcmp(data + off, sig, slen) == 0) {
                flags |= (1u << i);
                break;
            }
        }
    }
    return flags;
}

/* Parity builder for CSX's fingerprint JSON shape (subset without the
 * privacy-invasive Discord fields). Output is AUDIT-ONLY: nothing is sent
 * anywhere; the UI labels it "LOCAL READ-ONLY". */
static size_t NrthCsx_BuildFingerprintJson(const char *hwid, const char *computer,
                                           const char *user, const char *diskVol,
                                           char *out, size_t cap)
{
    if (!out || cap == 0) {
        return 0;
    }
    hwid     = hwid     ? hwid     : "";
    computer = computer ? computer : "";
    user     = user     ? user     : "";
    diskVol  = diskVol  ? diskVol  : "";
    return (size_t)snprintf(out, cap,
        "{\"type\":\"audit\",\"hwid\":\"%s\",\"computer\":\"%s\","
        "\"user\":\"%s\",\"disk\":\"%s\",\"version\":\"DARKANARCHY-audit\"}",
        hwid, computer, user, diskVol);
}

/* Deterministic display-only dry-run spoof: FNV-1a rounds then hex render.
 * Same (input, salt) -> same output; output never equals input; no state is
 * written anywhere (pure function). */
static void NrthCsx_SimulateSpoofId(const char *in, uint32_t salt, char *out, size_t cap)
{
    if (!out || cap == 0) {
        return;
    }
    if (!in || !in[0]) {
        out[0] = '\0';
        return;
    }
    uint32_t h = 0x811C9DC5u ^ salt;
    for (const char *p = in; *p; ++p) {
        h ^= (uint8_t)*p;
        h *= 0x01000193u;
        h ^= h >> 15;
    }
    /* 4 extra rounds for diffusion */
    for (int r = 0; r < 4; ++r) {
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h << 5;
    }
    /* 16 hex chars, formatted like an identity token */
    snprintf(out, cap, "SIM-%08X-%04X", h, (unsigned)((h >> 16) ^ salt));
}

/* Static decryptor port (for verification tests): XOR-16 with the recovered
 * key, in-place. Pure function over the caller's buffer. */
static void NrthCsx_DecryptXor16(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return;
    }
    static const uint8_t kKey[16] = {
        'C','5','x','~','S','t','e','a','l','t','h','!','2','0','2','6'
    };
    for (size_t i = 0; i < len; ++i) {
        buf[i] ^= kKey[i & 15];
    }
}

/* ---- Differential audit (A/B snapshots): prove what a real spoofer changed */
typedef struct NrthCsxSnapshot {
    char     machineGuid[128];
    uint32_t volSerial;
    int32_t  mtaKeys;
    uint32_t flags; /* NRTH_CSX_F_* */
} NrthCsxSnapshot;

#define NRTH_CSX_F_CLSID2    0x1u  /* Explorer\CLSID2 key present      */
#define NRTH_CSX_F_MODULE    0x2u  /* csxcheat.dll loaded in-process   */
#define NRTH_CSX_F_PROBE     0x4u  /* csxprobe.exe dropped on disk     */
#define NRTH_CSX_F_CACHEDIR  0x8u  /* MTA cache dir present            */

/* identity inputs a spoofer rotates: MachineGuid + volume serial */
static int NrthCsx_SnapIdentityChanged(const NrthCsxSnapshot *a, const NrthCsxSnapshot *b)
{
    if (!a || !b) {
        return 0;
    }
    return strcmp(a->machineGuid, b->machineGuid) != 0 ||
           a->volSerial != b->volSerial;
}

/* artifacts that APPEARED in b (bitmask of NRTH_CSX_F_*) */
static uint32_t NrthCsx_SnapNewArtifacts(const NrthCsxSnapshot *a, const NrthCsxSnapshot *b)
{
    if (!a || !b) {
        return 0;
    }
    return b->flags & ~a->flags;
}
