#pragma once
/**
 * ============================================================================
 * nrth_csx.h — CSX.exe spoofer analysis constants + read-only audit helpers
 * ============================================================================
 * EVIDENCE BASE (static analysis of CSX.exe, SHA-256
 * 683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31,
 * PE32 GUI "CSX Loader", requireAdministrator, 2026-09-22):
 *   - Fingerprint JSON template in .rdata:
 *       {"type":"%s","hwid":"%s","computer":"%s","user":"%s","gpu":"%s",
 *        "mb":"%s","disk":"%s","version":"%s","discord_id":"%s",
 *        "discord_name":"%s","discord_email":"%s"}
 *   - WMI (ROOT\CIMV2): Win32_VideoController.Name, Win32_BaseBoard.SerialNumber,
 *     Win32_DiskDrive.SerialNumber, Win32_ComputerSystem.Manufacturer/Model,
 *     Win32_BIOS.Manufacturer; MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography.
 *   - Spoofer ("reset MTA serial identity") touches: MachineGuid; the MTA
 *     registry identity keys (SOFTWARE[\\WOW6432Node]\Multi Theft Auto{...}\1.5/1.6);
 *     clears C:\ProgramData\MTA San Andreas All\Common\data\cache; persists its
 *     own state under the NON-standard Explorer\CLSID2 key; logs
 *     "[ok] done - your real hardware identity is back" (revert capability).
 *   - Injection: csxcheat.dll mapped into gta_sa.exe before resume (suspended
 *     process); drops csxprobe.exe (incl. via RDP \\tsclient paths); encrypted
 *     RCDATA payloads (0x0E6FE87E50746561 'Ptea hth!' header, entropy ~7.9).
 *   - Network: WinHttp to /api/event, /api/heartbeat, /status?hwid=; update CDN
 *     raw.githubusercontent.com + cdn.jsdelivr.net (onlyyoussef/csx-update);
 *     ip-api.com geolocation; discord.gg invite.
 *
 * SCOPE (authorized blue-team lab only): this header provides READ-ONLY audit
 * helpers. It does NOT and will NOT modify MachineGuid/MTA registry/serials —
 * a live serial spoofer is ban-evasion tooling and is out of scope. The
 * "simulator" is a display-only deterministic dry run for UI illustration.
 * ============================================================================
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ---- Evidence constants (strings/paths/keys found in CSX.exe) ------------- */
#define NRTH_CSX_MAGIC_BYTES "\x0E\x6F\xE8\x7E\x50\x74\x65\x61\x68\x74\x68\x21" /* payload header */

static const char *kNrthCsxSigs[] = {
    "csxcheat.dll",                                   /* injected payload name        */
    "csxprobe.exe",                                   /* dropped probe binary         */
    NRTH_CSX_MAGIC_BYTES,                             /* encrypted RCDATA container   */
    "/api/heartbeat",                                 /* C2 heartbeat endpoint        */
    "{\"type\":\"rename\",\"hwid\":\"",               /* spoofer rename request JSON  */
    " resetting MTA serial identity",                 /* loader log line              */
    "Explorer\\CLSID2",                               /* non-standard state key       */
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
