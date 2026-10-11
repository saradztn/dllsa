/**
 * ============================================================================
 * NRTH.dll — Behavioral & Structural Reconstruction (Result Class R2)
 * Reconstructed from reverse engineering of native x86 library "NRTH.dll"
 * (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
 * ============================================================================
 * PURPOSE: authorized MTA:SA blue-team private-server validation & parity
 *          verification ONLY. Not for public-server use.
 *
 * Evidence map (original VAs / RVAs):
 *   NVXHookProc               VA 0x1000b9e0 (RVA 0x0b9e0)  export ordinal 1 (nvx.dll)
 *   DllMain                   VA 0x1000ba00 (RVA 0x0ba00)  pin + MainInitThread
 *   MainInitThread            VA 0x1000a850 (RVA 0x0a850)  config/ADS/probes + LdrLoadDll hook
 *   Hooked_LdrLoadDll         VA 0x1000a640 (RVA 0x0a640)  trigger on client.dll / netc.dll
 *   ResolvePattern_10002960   VA 0x10002960 (RVA 0x02960)  wildcard byte-pattern scanner
 *   ArmClient_10005b80        VA 0x10005b80 (RVA 0x05b80)  11 scans + 11 MH_CreateHook calls
 *     Handlers: 0x10002ff0, 0x100047b0, 0x100050a0, 0x10005290, 0x100052b0,
 *               0x10005620, 0x100056c0, 0x100056f0, 0x10005ab0, 0x10005b30, 0x10005b50
 *   ResolveClientOffsets      VA 0x1000c390 (RVA 0x0c390)  20 pattern scans, 0 hooks
 *   PatchByte_10011870        VA 0x10011870 (RVA 0x11870)  VirtualProtect(ptr,1,0x40) + list 0x101493e4
 *   ArmNetc_10020640          VA 0x10020640 (RVA 0x20640)  6 scans (0x10023670..0x10023030)
 *     + 4 hooks (0x1001dd30, 0x1001dd90, 0x1001df90, 0x1001fa80)
 *     + 6 0xC3 prepare/write pairs (11-byte delta: 0x100206e5->6f0, 89f->8aa,
 *       91c->927, f3b->f46, 14b2->14bd, 15e6->15f1)
 *   GetD3D9DeviceVTable       VA 0x10012980 (RVA 0x12980)  pattern scan C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86
 *   InstallD3D9Hooks          VA 0x10016500 (RVA 0x16500)  Present idx 17 / Reset idx 16
 *   Hooked_Present            VA 0x10014d50 (RVA 0x14d50)  Dear ImGui 1.92.9 WIP overlay
 *   Hooked_Reset              VA 0x1001a3c0 (RVA 0x1a3c0)  device-loss handling
 * ============================================================================
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <psapi.h>
#ifndef NRTH_HEADLESS_TEST
#include <d3d9.h>
#include "MinHook.h"
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#endif
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_hook.h"
#include "nrth_ui.h"

/* ===========================================================================
 * Pattern compiler & scanner — matches original resolver VA 0x10002960
 * =========================================================================== */
static int nrth_hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint32_t nrth_compile_pat(const char *pat, uint8_t *bytes, uint8_t *mask, uint32_t cap)
{
    if (!pat || !bytes || !mask) return 0;
    uint32_t n = 0;
    const char *p = pat;
    while (*p && n < cap) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (*p == '?') {
            bytes[n] = 0;
            mask[n]  = 0;
            ++n;
            while (*p && *p != ' ' && *p != '\t') ++p;
            continue;
        }
        int hi = nrth_hex_digit((unsigned char)p[0]);
        int lo = (p[1] && nrth_hex_digit((unsigned char)p[1]) >= 0)
                     ? nrth_hex_digit((unsigned char)p[1]) : -1;
        if (hi < 0) return 0;
        bytes[n] = (uint8_t)((lo >= 0) ? (hi * 16 + lo) : hi);
        mask[n]  = 0xFF;
        ++n;
        while (*p && *p != ' ' && *p != '\t') ++p;
    }
    return n;
}

static uint32_t g_TotalPatternScans    = 0;
static uint32_t g_TotalInstalledHooks  = 0;
static uint32_t g_TotalAppliedPatches  = 0;

extern "C" const uint8_t *ResolvePattern_10002960(const uint8_t *base, uint32_t size,
                                                  const char *pattern)
{
    ++g_TotalPatternScans;
    if (!base || size == 0 || !pattern || !pattern[0]) {
        return NULL;
    }
    uint8_t bytes[256];
    uint8_t mask[256];
    uint32_t plen = nrth_compile_pat(pattern, bytes, mask, 256);
    if (plen == 0 || plen > size) {
        return NULL;
    }
    uint32_t anchor = 0;
    while (anchor < plen && mask[anchor] == 0) {
        ++anchor;
    }
    if (anchor >= plen) {
        return NULL;
    }
    uint8_t ab = bytes[anchor];
    for (uint32_t i = anchor; i + (plen - anchor) <= size; ++i) {
        if (base[i] != ab) continue;
        uint32_t start = i - anchor;
        bool ok = true;
        for (uint32_t j = 0; j < plen; ++j) {
            if (mask[j] && base[start + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return base + start;
        }
    }
    return NULL;
}

/* ===========================================================================
 * Decrypted pattern helpers (single-use gate L = F - 1 over kNrthEncryptedSigs)
 * =========================================================================== */
static char s_sigPlainBuf[20][160] = {{0}};
static bool s_sigGate[20]          = {false};

static const char *DecryptCatalogSig(uint32_t sigId1Based)
{
    if (sigId1Based < 1 || sigId1Based > 20) {
        return "";
    }
    uint32_t idx = sigId1Based - 1;
    const NrthEncryptedSigEntry &e = kNrthEncryptedSigs[idx];
    return NrthDecryptOnce(e.cipher, e.fieldSize, e.key, s_sigPlainBuf[idx], &s_sigGate[idx]);
}

/* ===========================================================================
 * Global state: Lua VM bridge (0x1013bf04), Sync structs, Report channels
 * =========================================================================== */
static NrthLuaVmBridge        g_LuaVmBridge       = {};
static SPlayerHealthSync      g_PlayerHealthSync  = { 100.0f, 100.0f, 0, 0, 0, 0, 1.0f, 0.5f, 0, 0 };
static SWeaponAimSync         g_WeaponAimSync     = { 0.0f, 0.0f, 0.0f, 300.0f, 12.0f, 0, 1, 1, 0 };
static NrthReportChannelState g_ReportChannels    = { 0, 0, 0, 0, 0, false };

extern "C" NrthLuaVmBridge *Nrth_GetLuaVmBridge(void)
{
    return &g_LuaVmBridge;
}

extern "C" SPlayerHealthSync *Nrth_GetPlayerHealthSync(void)
{
    return &g_PlayerHealthSync;
}

extern "C" SWeaponAimSync *Nrth_GetWeaponAimSync(void)
{
    return &g_WeaponAimSync;
}

extern "C" NrthReportChannelState *Nrth_GetReportChannelState(void)
{
    return &g_ReportChannels;
}

extern "C" bool Nrth_IsPointerReadable_VirtualQuery(const void *ptr)
{
    if (!ptr) {
        return false;
    }
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    DWORD readableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & readableMask) == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    return true;
#else
    return ((uintptr_t)ptr >= 0x1000u);
#endif
}

/* ===========================================================================
 * Single-byte patch writer VA 0x10011870 & patch list VA 0x101493e4
 * Evidence:
 *   6 prepare/call pairs in 0x10020640, each with `mov byte ptr [ebp-disp8], 0xC3`
 *   exactly 11 bytes before `call 0x10011870`:
 *     0x100206e5 -> 0x100206f0  (pattern 0x10023670)
 *     0x1002089f -> 0x100208aa  (pattern 0x10023530)
 *     0x1002091c -> 0x10020927  (pattern 0x100233f0)
 *     0x10020f3b -> 0x10020f46  (pattern 0x100232b0)
 *     0x100214b2 -> 0x100214bd  (pattern 0x10023170)
 *     0x100215e6 -> 0x100215f1  (pattern 0x10023030)
 * =========================================================================== */
static NrthPatchRecord g_PatchList_101493e4[NRTH_NETC_PATCH_COUNT] = {
    { 0x100206e5u, 0x100206f0u, 0x10023670u, NULL, 0, 0xC3u, 0, 0 },
    { 0x1002089fu, 0x100208aau, 0x10023530u, NULL, 0, 0xC3u, 0, 0 },
    { 0x1002091cu, 0x10020927u, 0x100233f0u, NULL, 0, 0xC3u, 0, 0 },
    { 0x10020f3bu, 0x10020f46u, 0x100232b0u, NULL, 0, 0xC3u, 0, 0 },
    { 0x100214b2u, 0x100214bdu, 0x10023170u, NULL, 0, 0xC3u, 0, 0 },
    { 0x100215e6u, 0x100215f1u, 0x10023030u, NULL, 0, 0xC3u, 0, 0 },
};

extern "C" bool PatchByte_10011870(void *targetAddr, uint8_t opcodeByte, uint32_t prepVa,
                                   uint32_t callVa, uint32_t patternGlobal)
{
    /* Verify the 11-byte instruction spacing between mov [ebp-disp8],0xC3 and call 0x10011870 */
    if (callVa < prepVa || (callVa - prepVa) != 11u) {
        return false;
    }

    NrthPatchRecord *rec = NULL;
    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        if (g_PatchList_101493e4[i].prepVa == prepVa &&
            g_PatchList_101493e4[i].callVa == callVa) {
            rec = &g_PatchList_101493e4[i];
            break;
        }
    }

    if (rec) {
        rec->patternGlobal = patternGlobal;
        rec->targetAddr    = targetAddr;
        rec->patchByte     = opcodeByte;
    }

    if (!targetAddr) {
        return false;
    }

    uint8_t *pByte = (uint8_t *)targetAddr;
#ifdef _WIN32
    DWORD oldProt = 0;
    if (!VirtualProtect(targetAddr, 1, PAGE_EXECUTE_READWRITE /* 0x40 */, &oldProt)) {
        return false;
    }
    uint8_t prev = *pByte;
    *pByte = opcodeByte;
    DWORD dummy = 0;
    VirtualProtect(targetAddr, 1, oldProt, &dummy);
#else
    uint8_t prev = *pByte;
    *pByte = opcodeByte;
#endif

    if (rec) {
        rec->origByte = prev;
        rec->applied  = 1;
    }
    ++g_TotalAppliedPatches;
    return true;
}

/* ===========================================================================
 * 11 client.dll hook handlers (installed by ArmClient_10005b80 at 0x10005b80)
 * VAs: 0x10002ff0, 0x100047b0, 0x100050a0, 0x10005290, 0x100052b0, 0x10005620,
 *      0x100056c0, 0x100056f0, 0x10005ab0, 0x10005b30, 0x10005b50
 * =========================================================================== */
typedef int (*PFN_GenericHook)(void *a1, void *a2, void *a3, void *a4);

static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4);

static int Hook_Client_10002ff0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(0,  a1, a2, a3, a4); }
static int Hook_Client_100047b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(1,  a1, a2, a3, a4); }
static int Hook_Client_100050a0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(2,  a1, a2, a3, a4); }
static int Hook_Client_10005290(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(3,  a1, a2, a3, a4); }
static int Hook_Client_100052b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(4,  a1, a2, a3, a4); }
static int Hook_Client_10005620(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(5,  a1, a2, a3, a4); }
static int Hook_Client_100056c0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(6,  a1, a2, a3, a4); }
static int Hook_Client_100056f0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(7,  a1, a2, a3, a4); }
static int Hook_Client_10005ab0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(8,  a1, a2, a3, a4); }
static int Hook_Client_10005b30(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(9,  a1, a2, a3, a4); }
static int Hook_Client_10005b50(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(10, a1, a2, a3, a4); }

/* Note on pattern provenance for 0x10005b80:
 * Slots 0, 1, 2, 3, 7, 9, 10 use the 7 exact D2 patterns from nrth_audit_sigs.h
 * (Sigs #10, #5, #3, #15, #6, #13, #19, all K=0x2D).
 * Slots 4, 5, 6, 8 correspond to the remaining 4 scans in 0x10005b80 (VAs 0x10006050,
 * 0x10006140, 0x10006230, 0x10006450) whose sub-25-char / non-55-8B-EC patterns were
 * filtered out when nrth_audit_sigs.h was exported from NRTH.dll. */
static NrthHookSlot g_ClientHooks_10005b80[NRTH_CLIENT_HOOK_COUNT] = {
    {  0, 0x10002ff0u, 0x10005c07u, 0x2Du, NULL, (void *)&Hook_Client_10002ff0, NULL, NULL, false }, /* Sig #10 */
    {  1, 0x100047b0u, 0x10005d28u, 0x2Du, NULL, (void *)&Hook_Client_100047b0, NULL, NULL, false }, /* Sig #5  */
    {  2, 0x100050a0u, 0x10005e54u, 0x2Du, NULL, (void *)&Hook_Client_100050a0, NULL, NULL, false }, /* Sig #3  */
    {  3, 0x10005290u, 0x10005f56u, 0x2Du, NULL, (void *)&Hook_Client_10005290, NULL, NULL, false }, /* Sig #15 */
    {  4, 0x100052b0u, 0x10006050u, 0x2Du, "55 8B EC 8B 45 ? 8B 48 ? 85 C9 74 ?", (void *)&Hook_Client_100052b0, NULL, NULL, false },
    {  5, 0x10005620u, 0x10006140u, 0x2Du, "55 8B EC 56 8B 75 ? 85 F6 74 ? 8B 06", (void *)&Hook_Client_10005620, NULL, NULL, false },
    {  6, 0x100056c0u, 0x10006230u, 0x2Du, "55 8B EC 83 EC ? 56 8B F1 8B 46 ? 85 C0", (void *)&Hook_Client_100056c0, NULL, NULL, false },
    {  7, 0x100056f0u, 0x1000633bu, 0x2Du, NULL, (void *)&Hook_Client_100056f0, NULL, NULL, false }, /* Sig #6  */
    {  8, 0x10005ab0u, 0x10006450u, 0x2Du, "55 8B EC 53 56 8B 75 ? 8B D9 85 F6", (void *)&Hook_Client_10005ab0, NULL, NULL, false },
    {  9, 0x10005b30u, 0x1000657bu, 0x2Du, NULL, (void *)&Hook_Client_10005b30, NULL, NULL, false }, /* Sig #13 */
    { 10, 0x10005b50u, 0x10006684u, 0x2Du, NULL, (void *)&Hook_Client_10005b50, NULL, NULL, false }, /* Sig #19 */
};

static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    if (slotIdx == 0 && a1 && Nrth_IsPointerReadable_VirtualQuery(a1)) {
        /* Track default_L at 0x1013c95c and VM registry slot at 0x1013bf04 (stride 0x1C, L at +0x18) */
        g_LuaVmBridge.default_L_1013c95c = a1;
        if (g_LuaVmBridge.slotCount < NRTH_VM_REGISTRY_CAP) {
            uint32_t idx = g_LuaVmBridge.slotCount++;
            g_LuaVmBridge.registry_1013bf04[idx].luaStatePtr32 = (uint32_t)(uintptr_t)a1;
        }
        if (g_LuaVmBridge.execFlag_1013c939 &&
            g_LuaVmBridge.loadbuffer_1013c94c &&
            g_LuaVmBridge.pcall_1013c974) {
            static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
            static bool s_customGate = false;
            const char *chunkName = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                                    0x2D, s_customChunk, &s_customGate);
            size_t slen = strlen(g_LuaVmBridge.scriptBuf_1013beec);
            if (slen > 0 &&
                g_LuaVmBridge.loadbuffer_1013c94c(a1, g_LuaVmBridge.scriptBuf_1013beec, slen, chunkName) == 0) {
                g_LuaVmBridge.pcall_1013c974(a1, 0, 0, 0);
            }
            g_LuaVmBridge.execFlag_1013c939 = 0;
        }
    }
    if (slotIdx < NRTH_CLIENT_HOOK_COUNT && g_ClientHooks_10005b80[slotIdx].origTrampoline) {
        PFN_GenericHook orig = (PFN_GenericHook)g_ClientHooks_10005b80[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}

/* ===========================================================================
 * 4 netc.dll hook handlers (installed by ArmNetc_10020640 at 0x10020640)
 * VAs: 0x1001dd30, 0x1001dd90, 0x1001df90, 0x1001fa80
 * =========================================================================== */
static int DispatchNetcHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4);

static int Hook_Netc_1001dd30(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(0, a1, a2, a3, a4); }
static int Hook_Netc_1001dd90(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(1, a1, a2, a3, a4); }
static int Hook_Netc_1001df90(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(2, a1, a2, a3, a4); }
static int Hook_Netc_1001fa80(void *a1, void *a2, void *a3, void *a4) { return DispatchNetcHook(3, a1, a2, a3, a4); }

static NrthHookSlot g_NetcHooks_10020640[NRTH_NETC_HOOK_COUNT] = {
    { 0, 0x1001dd30u, 0x10023670u, 0x2Du, NULL, (void *)&Hook_Netc_1001dd30, NULL, NULL, false }, /* Sig #16 */
    { 1, 0x1001dd90u, 0x10023530u, 0x2Du, "55 8B EC 53 56 57 8B 7D ? 8B F1 85 FF", (void *)&Hook_Netc_1001dd90, NULL, NULL, false },
    { 2, 0x1001df90u, 0x100233f0u, 0x2Du, "55 8B EC 83 EC ? 53 56 57 8B F9 8B 47", (void *)&Hook_Netc_1001df90, NULL, NULL, false },
    { 3, 0x1001fa80u, 0x100232b0u, 0x2Du, "55 8B EC 51 53 56 8B 75 ? 8B D9 57",   (void *)&Hook_Netc_1001fa80, NULL, NULL, false },
};

static int DispatchNetcHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    switch (slotIdx) {
    case 0: ++g_ReportChannels.screenshotCount;    break; /* PLAYER_SCREENSHOT    */
    case 1: ++g_ReportChannels.transgressionCount; break; /* PLAYER_TRANSGRESSION */
    case 2: ++g_ReportChannels.diagnosticCount;    break; /* PLAYER_DIAGNOSTIC    */
    case 3: ++g_ReportChannels.acinfoCount;        break; /* PLAYER_ACINFO / packets */
    default: break;
    }
    if (g_ReportChannels.suppressReports && slotIdx < 3) {
        return 0;
    }
    if (slotIdx < NRTH_NETC_HOOK_COUNT && g_NetcHooks_10020640[slotIdx].origTrampoline) {
        PFN_GenericHook orig = (PFN_GenericHook)g_NetcHooks_10020640[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}

/* ===========================================================================
 * ArmClient_10005b80 — 11 pattern scans + 11 MH_CreateHook installations
 * =========================================================================== */
extern "C" uint32_t ArmClient_10005b80(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours)
{
    /* Initialize the 7 exact encrypted signatures from nrth_codec.h */
    static const struct { uint32_t slot; uint32_t sigId; } kClientSigMap[7] = {
        {  0, 10 }, /* 0x10005c07 -> 0x10002ff0 */
        {  1,  5 }, /* 0x10005d28 -> 0x100047b0 */
        {  2,  3 }, /* 0x10005e54 -> 0x100050a0 */
        {  3, 15 }, /* 0x10005f56 -> 0x10005290 */
        {  7,  6 }, /* 0x1000633b -> 0x100056f0 */
        {  9, 13 }, /* 0x1000657b -> 0x10005b30 */
        { 10, 19 }, /* 0x10006684 -> 0x10005b50 */
    };
    for (uint32_t i = 0; i < 7; ++i) {
        g_ClientHooks_10005b80[kClientSigMap[i].slot].pattern =
            DecryptCatalogSig(kClientSigMap[i].sigId);
    }

    uint32_t hooked = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_HOOK_COUNT; ++i) {
        NrthHookSlot &slot = g_ClientHooks_10005b80[i];
        const uint8_t *hit = ResolvePattern_10002960(moduleBase, moduleSize, slot.pattern);
        slot.targetAddr = (void *)hit;
        if (!hit) {
            continue;
        }
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
        if (applyDetours) {
            if (MH_CreateHook(slot.targetAddr, slot.detourFn, &slot.origTrampoline) == MH_OK &&
                MH_EnableHook(slot.targetAddr) == MH_OK) {
                slot.installed = true;
                ++g_TotalInstalledHooks;
                ++hooked;
            }
        }
#else
        if (applyDetours) {
            /* In non-Win32 test mode, write the 5-byte near detour footprint (E9 rel32)
             * so NrthAuditImage / NrthAuditDiff can verify DETOUR_JMP32 detection. */
            uint8_t *fn = (uint8_t *)slot.targetAddr;
            fn[0] = 0xE9u;
            int32_t rel = (int32_t)((slot.handlerVa - 0x10000000u) -
                                    ((uint32_t)(fn - moduleBase) + 5u));
            fn[1] = (uint8_t)(rel & 0xFF);
            fn[2] = (uint8_t)((rel >> 8) & 0xFF);
            fn[3] = (uint8_t)((rel >> 16) & 0xFF);
            fn[4] = (uint8_t)((rel >> 24) & 0xFF);
            slot.installed = true;
            ++g_TotalInstalledHooks;
            ++hooked;
        }
#endif
    }
    return hooked;
}

/* ===========================================================================
 * ResolveClientOffsets_1000c390 — 20 pattern scans on client.dll, 0 hooks
 * =========================================================================== */
static uintptr_t g_ClientResolvedOffsets[NRTH_CLIENT_RESOLVE_COUNT] = {0};

extern "C" uint32_t ResolveClientOffsets_1000c390(const uint8_t *moduleBase, uint32_t moduleSize)
{
    /* First 12 entries are the exact K=0x40 encrypted signatures from nrth_audit_sigs.h
     * (Sigs #4, #11, #14, #1, #9, #8, #12, #2, #17, #7, #20, #18 in VA order 0x1000c52b..0x1000d463).
     * Remaining 8 entries complete the 20 scans performed by 0x1000c390. */
    static const uint32_t kC390CatalogSigIds[12] = {
        4, 11, 14, 1, 9, 8, 12, 2, 17, 7, 20, 18
    };
    static const char *const kC390ExtraPatterns[8] = {
        "55 8B EC 8B 45 ? 8B 00 89 45 ? 8B E5 5D C3",
        "55 8B EC 56 8B F1 8B 06 FF 50 ? 85 C0 74 ?",
        "55 8B EC 83 EC ? 89 4D ? 8B 45 ? 89 45 ? 8B 4D",
        "55 8B EC 8B 4D ? 85 C9 74 ? 8B 01 FF 50 ?",
        "55 8B EC 51 89 4D ? 8B 45 ? 8B 4D ? 89 01",
        "55 8B EC 56 8B 75 ? 57 8B F9 8B 47 ? 85 C0",
        "55 8B EC 8B 45 ? 56 8B F1 89 46 ? 8B C6 5E",
        "55 8B EC 83 EC ? 56 8B F1 83 7E ? 00 74 ?"
    };

    uint32_t resolved = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_RESOLVE_COUNT; ++i) {
        const char *pat = (i < 12)
                              ? DecryptCatalogSig(kC390CatalogSigIds[i])
                              : kC390ExtraPatterns[i - 12];
        const uint8_t *hit = ResolvePattern_10002960(moduleBase, moduleSize, pat);
        g_ClientResolvedOffsets[i] = (uintptr_t)hit;
        if (hit) {
            ++resolved;
        }
    }
    return resolved;
}

/* ===========================================================================
 * ArmNetc_10020640 — 6 pattern scans (0x10023670..0x10023030) +
 *                    4 MH_CreateHook calls (0x1001dd30, dd90, df90, fa80) +
 *                    6 0xC3 prepare/write pairs via PatchByte_10011870
 * =========================================================================== */
extern "C" uint32_t ArmNetc_10020640(uint8_t *moduleBase, uint32_t moduleSize,
                                     bool applyDetours, bool applyPatches)
{
    /* Pattern table 0x10023670..0x10023030 (step -0x140):
     * Entry 0 uses exact D2 Sig #16 (0x10020591, K=0x2D). */
    const char *netcPatterns[NRTH_NETC_SCAN_COUNT] = {
        DecryptCatalogSig(16), /* 0x10023670: "55 8B EC 53 56 57 8B 7D ? 33 F6 32 DB" */
        g_NetcHooks_10020640[1].pattern, /* 0x10023530 */
        g_NetcHooks_10020640[2].pattern, /* 0x100233f0 */
        g_NetcHooks_10020640[3].pattern, /* 0x100232b0 */
        "55 8B EC 83 EC ? 56 8B 75 ? 83 7E ? 00 75 ?", /* 0x10023170 */
        "55 8B EC 56 8B 75 ? 57 8B 7D ? 8B C6 2B C7"   /* 0x10023030 */
    };
    g_NetcHooks_10020640[0].pattern = netcPatterns[0];

    uint8_t *scanHits[NRTH_NETC_SCAN_COUNT] = {NULL};
    for (uint32_t i = 0; i < NRTH_NETC_SCAN_COUNT; ++i) {
        scanHits[i] = (uint8_t *)ResolvePattern_10002960(moduleBase, moduleSize, netcPatterns[i]);
    }

    uint32_t actions = 0;

    /* 4 MinHook detours: 0x1001dd30, 0x1001dd90, 0x1001df90, 0x1001fa80 */
    for (uint32_t i = 0; i < NRTH_NETC_HOOK_COUNT; ++i) {
        NrthHookSlot &slot = g_NetcHooks_10020640[i];
        slot.targetAddr = scanHits[i];
        if (!slot.targetAddr) {
            continue;
        }
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
        if (applyDetours) {
            if (MH_CreateHook(slot.targetAddr, slot.detourFn, &slot.origTrampoline) == MH_OK &&
                MH_EnableHook(slot.targetAddr) == MH_OK) {
                slot.installed = true;
                ++g_TotalInstalledHooks;
                ++actions;
            }
        }
#else
        if (applyDetours) {
            slot.installed = true;
            ++g_TotalInstalledHooks;
            ++actions;
        }
#endif
    }

    /* 6 prepare/write pairs (mov byte ptr [ebp-disp8], 0xC3 at prepVa -> call 0x10011870 at callVa = prepVa + 11) */
    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        uint8_t opcode = 0xC3u; /* mov byte ptr [ebp-disp8], 0xC3 */
        uint32_t prepVa = g_PatchList_101493e4[i].prepVa;
        uint32_t callVa = g_PatchList_101493e4[i].callVa;
        uint32_t patGlb = g_PatchList_101493e4[i].patternGlobal;
        void *target    = applyPatches ? (void *)scanHits[i] : NULL;
        if (PatchByte_10011870(target, opcode, prepVa, callVa, patGlb)) {
            ++actions;
        }
    }

    return actions;
}

/* ===========================================================================
 * GetD3D9DeviceVTable — evidence VA 0x10012980
 * Primary method (matches original NRTH.dll at 0x10012980):
 *   Scans d3d9.dll in memory for the CD3DBase constructor sequence:
 *     C7 06 <vtable_ptr32> 89 86 <disp32> 89 86
 *   and dereferences the 32-bit vtable pointer at (match + 2).
 * Fallback method:
 *   Creates a temporary hidden window + Direct3DCreate9 device if the byte
 *   pattern does not match on the host's d3d9.dll build.
 * =========================================================================== */
extern "C" void **FindD3D9VTableInBuffer_10012980(const uint8_t *base, uint32_t size)
{
    static const char *kD3D9VTablePat = "C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86";
    if (!base || size < 16) {
        return NULL;
    }
    uint8_t bytes[32], mask[32];
    uint32_t plen = nrth_compile_pat(kD3D9VTablePat, bytes, mask, 32);
    if (plen == 0 || plen > size) {
        return NULL;
    }
    for (uint32_t i = 0; i + plen <= size; ++i) {
        if (base[i] != 0xC7u || base[i + 1] != 0x06u) continue;
        bool ok = true;
        for (uint32_t j = 0; j < plen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            uint32_t vtAddr32 = (uint32_t)base[i + 2] |
                                ((uint32_t)base[i + 3] << 8) |
                                ((uint32_t)base[i + 4] << 16) |
                                ((uint32_t)base[i + 5] << 24);
            return (void **)(uintptr_t)vtAddr32;
        }
    }
    return NULL;
}

/* ===========================================================================
 * Exported hook procedure (export ordinal 1, name "NVXHookProc" in nvx.dll).
 * Pure pass-through to CallNextHookEx (4 instructions in the sample at 0x1000b9e0).
 * =========================================================================== */
extern "C" LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
#ifdef _WIN32
    return CallNextHookEx(NULL, nCode, wParam, lParam);
#else
    (void)nCode;
    (void)wParam;
    return (LRESULT)lParam;
#endif
}

/* ===========================================================================
 * Accessors for verification & UI inspection
 * =========================================================================== */
extern "C" const NrthHookSlot *Nrth_GetClientHookTable(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_CLIENT_HOOK_COUNT;
    return g_ClientHooks_10005b80;
}

extern "C" const NrthHookSlot *Nrth_GetNetcHookTable(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_NETC_HOOK_COUNT;
    return g_NetcHooks_10020640;
}

extern "C" const NrthPatchRecord *Nrth_GetPatchList_101493e4(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_NETC_PATCH_COUNT;
    return g_PatchList_101493e4;
}

extern "C" const uintptr_t *Nrth_GetClientResolvedOffsets(uint32_t *outCount)
{
    if (outCount) *outCount = NRTH_CLIENT_RESOLVE_COUNT;
    return g_ClientResolvedOffsets;
}

extern "C" uint32_t Nrth_GetTotalPatternScans(void)
{
    return g_TotalPatternScans;
}

extern "C" uint32_t Nrth_GetTotalInstalledHooks(void)
{
    return g_TotalInstalledHooks;
}

extern "C" uint32_t Nrth_GetTotalAppliedPatches(void)
{
    return g_TotalAppliedPatches;
}

extern "C" void Nrth_ResetArmingCounters(void)
{
    g_TotalPatternScans   = 0;
    g_TotalInstalledHooks = 0;
    g_TotalAppliedPatches = 0;
    for (uint32_t i = 0; i < NRTH_CLIENT_HOOK_COUNT; ++i) {
        g_ClientHooks_10005b80[i].targetAddr = NULL;
        g_ClientHooks_10005b80[i].installed  = false;
    }
    for (uint32_t i = 0; i < NRTH_NETC_HOOK_COUNT; ++i) {
        g_NetcHooks_10020640[i].targetAddr = NULL;
        g_NetcHooks_10020640[i].installed  = false;
    }
    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        g_PatchList_101493e4[i].targetAddr = NULL;
        g_PatchList_101493e4[i].origByte   = 0;
        g_PatchList_101493e4[i].applied    = 0;
    }
    memset(g_ClientResolvedOffsets, 0, sizeof(g_ClientResolvedOffsets));
}

/* ===========================================================================
 * Windows-only runtime hooks (DllMain, MainInitThread, LdrLoadDll, D3D9, ImGui)
 * =========================================================================== */
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

typedef LONG NTSTATUS;
typedef struct _NVX_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NVX_UNICODE_STRING;

typedef NTSTATUS (NTAPI *PFN_LdrLoadDll)(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
typedef HRESULT  (WINAPI *PFN_Present)(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
typedef HRESULT  (WINAPI *PFN_Reset)(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
typedef IDirect3D9 *(WINAPI *PFN_Direct3DCreate9)(UINT);

static PFN_LdrLoadDll   g_pOrigLdrLoadDll   = NULL; /* RVA 0x0a640 hook target */
static PFN_Present      g_pOrigPresent      = NULL; /* vtable slot 17 (0x44)   */
static PFN_Reset        g_pOrigReset        = NULL; /* vtable slot 16 (0x40)   */
static bool             g_bClientArmed      = false;
static bool             g_bNetcArmed        = false;
static bool             g_bOverlayArmed     = false;
static bool             g_bOverlayInit      = false;
static bool             g_bMenuOpen         = false;
static IDirect3DDevice9 *g_pDevice          = NULL;
static HWND             g_hGameWnd          = NULL;
static WNDPROC          g_pOrigWndProc      = NULL;

static DWORD WINAPI MainInitThread(LPVOID lpParam);
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
static void **GetD3D9DeviceVTable(void);
static bool InstallD3D9Hooks(void **vtable);
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
static LRESULT CALLBACK GameWndProc(HWND, UINT, WPARAM, LPARAM);
static void BuildOverlayMenu(void);
static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice);
static void UpdateOverlayInput(void);
static const char *BaseNameA(const char *path);
static uint32_t GetLoadedModuleSize(HMODULE hMod);
static void RunEnvironmentProbes(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        HMODULE hPinned = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            (LPCSTR)DllMain,
            &hPinned);

        HANDLE hThread = CreateThread(NULL, 0, MainInitThread, hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}

/* Environment probes observed in NRTH.dll:
 *   - C:\NVX (plain .rdata string at 0x100b0d18)
 *   - C:\ProgramData:NT2 ADS check (decrypted at 0x1001e530, K=0x20)
 *   - Registry reads: MTA / Internet Settings\ZoneMap / CLSID
 *   - PhysicalDrive0 storage descriptor query (disk model identifier) */
static void RunEnvironmentProbes(void)
{
    /* Plain .rdata string "C:\NVX" (VA 0x100b0d18) */
    DWORD attr = GetFileAttributesA("C:\\NVX");
    if (attr == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryA("C:\\NVX", NULL);
    }

    /* Alternate Data Stream "C:\ProgramData:NT2" (VA 0x1001e530, K=0x20) */
    static char s_adsBuf[sizeof(kCt_AdsNt2)] = {0};
    static bool s_adsGate = false;
    const char *adsPath = NrthDecryptOnce(kCt_AdsNt2, sizeof(kCt_AdsNt2), 0x20, s_adsBuf, &s_adsGate);
    HANDLE hAds = CreateFileA(adsPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hAds != INVALID_HANDLE_VALUE) {
        CloseHandle(hAds);
    }

    if (g_cfg.noSpoofer) {
        return;
    }

    /* Read-only Registry queries: MTA, Internet Settings\ZoneMap, CLSID */
    HKEY hKey = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Multi Theft Auto: San Andreas All\\Common",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }

    /* Read-only disk model query via IOCTL_STORAGE_QUERY_PROPERTY */
    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq;
        memset(&spq, 0, sizeof(spq));
        spq.PropertyId = StorageDeviceProperty;
        spq.QueryType  = PropertyStandardQuery;
        uint8_t outBuf[512] = {0};
        DWORD bytesRet = 0;
        DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                        &spq, sizeof(spq), outBuf, sizeof(outBuf), &bytesRet, NULL);
        CloseHandle(hDisk);
    }
}

static DWORD WINAPI MainInitThread(LPVOID lpParam)
{
    (void)lpParam;

    /* Load C:\Overwack\loader_config.cfg (" no_spoofer=%d", " menu_key=%d") */
    NrthConfig_Load(NULL);

    /* Run C:\NVX, ADS, registry and disk model probes */
    RunEnvironmentProbes();

    /* Decrypt "ntdll.dll" and "LdrLoadDll" (single-use gate L = F - 1) */
    static char s_ntdllBuf[sizeof(kCt_NtdllDll)]       = {0};
    static bool s_ntdllGate                            = false;
    static char s_ldrBuf[sizeof(kCt_LdrLoadDll)]       = {0};
    static bool s_ldrGate                              = false;

    const char *ntdllName = NrthDecryptOnce(kCt_NtdllDll, sizeof(kCt_NtdllDll), 0x2D,
                                            s_ntdllBuf, &s_ntdllGate);
    const char *ldrName   = NrthDecryptOnce(kCt_LdrLoadDll, sizeof(kCt_LdrLoadDll), 0x2D,
                                            s_ldrBuf, &s_ldrGate);

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll) {
        return 1;
    }
    FARPROC pLdrLoadDll = GetProcAddress(hNtdll, ldrName);
    if (!pLdrLoadDll) {
        return 1;
    }

    if (MH_Initialize() != MH_OK) {
        return 1;
    }
    if (MH_CreateHook((LPVOID)pLdrLoadDll, (LPVOID)&Hooked_LdrLoadDll,
                      (LPVOID *)&g_pOrigLdrLoadDll) != MH_OK) {
        return 1;
    }
    if (MH_EnableHook((LPVOID)pLdrLoadDll) != MH_OK) {
        return 1;
    }
    ++g_TotalInstalledHooks; /* Hook #1: ntdll!LdrLoadDll */
    return 0;
}

static uint32_t GetLoadedModuleSize(HMODULE hMod)
{
    if (!hMod) return 0;
    const uint8_t *base = (const uint8_t *)hMod;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (uint32_t)nt->OptionalHeader.SizeOfImage;
}

static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR SearchPath, PULONG DllCharacteristics,
                                        NVX_UNICODE_STRING *ModuleFileName, PVOID *DllHandle)
{
    NTSTATUS status = g_pOrigLdrLoadDll(SearchPath, DllCharacteristics, ModuleFileName, DllHandle);

    if (status >= 0 && DllHandle && *DllHandle) {
        char name[MAX_PATH] = {0};
        if (GetModuleFileNameA((HMODULE)*DllHandle, name, MAX_PATH) != 0) {
            const char *base = BaseNameA(name);

            /* Decrypt "client.dll" (VA 0x10005c56, K=0x2D) and "netc.dll" (VA 0x1002069c, K=0x20) */
            static char s_clientBuf[sizeof(kCt_ClientDll)] = {0};
            static bool s_clientGate                       = false;
            static char s_netcBuf[sizeof(kCt_NetcDll)]     = {0};
            static bool s_netcGate                         = false;

            const char *clientName = NrthDecryptOnce(kCt_ClientDll, sizeof(kCt_ClientDll), 0x2D,
                                                     s_clientBuf, &s_clientGate);
            const char *netcName   = NrthDecryptOnce(kCt_NetcDll, sizeof(kCt_NetcDll), 0x20,
                                                     s_netcBuf, &s_netcGate);

            HMODULE hLoaded = (HMODULE)*DllHandle;
            uint32_t modSize = GetLoadedModuleSize(hLoaded);

            if (!g_bClientArmed && _stricmp(base, clientName) == 0) {
                g_bClientArmed = true;
                ArmClient_10005b80((uint8_t *)hLoaded, modSize, true);
                ResolveClientOffsets_1000c390((const uint8_t *)hLoaded, modSize);
            }
            if (!g_bNetcArmed && _stricmp(base, netcName) == 0) {
                g_bNetcArmed = true;
                ArmNetc_10020640((uint8_t *)hLoaded, modSize, true, true);
            }
            if (!g_bOverlayArmed && (g_bClientArmed || g_bNetcArmed)) {
                g_bOverlayArmed = true;
                void **vtable = GetD3D9DeviceVTable();
                if (vtable) {
                    InstallD3D9Hooks(vtable);
                }
            }
        }
    }
    return status;
}

static void **GetD3D9DeviceVTable(void)
{
    static void **pCachedVTable = NULL;
    if (pCachedVTable) {
        return pCachedVTable;
    }

    static char s_d3dBuf[sizeof(kCt_D3d9Dll)] = {0};
    static bool s_d3dGate                     = false;
    const char *d3dName = NrthDecryptOnce(kCt_D3d9Dll, sizeof(kCt_D3d9Dll), 0x2D,
                                          s_d3dBuf, &s_d3dGate);

    HMODULE hD3D = GetModuleHandleA(d3dName);
    if (!hD3D) {
        hD3D = LoadLibraryA(d3dName);
    }
    if (!hD3D) {
        return NULL;
    }

    /* Primary method (VA 0x10012980): pattern-scan d3d9.dll for C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86 */
    uint32_t d3dSize = GetLoadedModuleSize(hD3D);
    pCachedVTable = FindD3D9VTableInBuffer_10012980((const uint8_t *)hD3D, d3dSize);
    if (pCachedVTable && Nrth_IsPointerReadable_VirtualQuery(pCachedVTable)) {
        return pCachedVTable;
    }
    pCachedVTable = NULL;

    /* Fallback: temporary dummy window + Direct3DCreate9 device */
    PFN_Direct3DCreate9 pCreate = (PFN_Direct3DCreate9)GetProcAddress(hD3D, "Direct3DCreate9");
    if (!pCreate) {
        return NULL;
    }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = DefWindowProcA;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = "NVXD3DDummyWnd";
    RegisterClassA(&wc);

    HWND hWnd = CreateWindowExA(0, wc.lpszClassName, "", WS_OVERLAPPED,
                                0, 0, 32, 32, NULL, NULL, wc.hInstance, NULL);
    if (!hWnd) {
        return NULL;
    }

    IDirect3D9 *pD3D = pCreate(D3D_SDK_VERSION);
    if (!pD3D) {
        DestroyWindow(hWnd);
        return NULL;
    }

    D3DPRESENT_PARAMETERS pp;
    ZeroMemory(&pp, sizeof(pp));
    pp.Windowed      = TRUE;
    pp.SwapEffect    = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow = hWnd;

    IDirect3DDevice9 *pDev = NULL;
    HRESULT hr = pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
                                    D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &pDev);
    if (FAILED(hr) || !pDev) {
        pD3D->Release();
        DestroyWindow(hWnd);
        return NULL;
    }

    pCachedVTable = *(void ***)pDev;

    pDev->Release();
    pD3D->Release();
    DestroyWindow(hWnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
    return pCachedVTable;
}

static bool InstallD3D9Hooks(void **vtable)
{
    if (!vtable) {
        return false;
    }
    if (MH_CreateHook(vtable[17], (LPVOID)&Hooked_Present, (LPVOID *)&g_pOrigPresent) != MH_OK) {
        return false;
    }
    if (MH_CreateHook(vtable[16], (LPVOID)&Hooked_Reset, (LPVOID *)&g_pOrigReset) != MH_OK) {
        return false;
    }
    MH_EnableHook(vtable[17]);
    MH_EnableHook(vtable[16]);
    g_TotalInstalledHooks += 2; /* Hooks #2 & #3: Present (17) + Reset (16) */
    return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT CALLBACK GameWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return 1;
    }
    return CallWindowProcA(g_pOrigWndProc, hWnd, msg, wParam, lParam);
}

static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice)
{
    if (g_bOverlayInit) {
        return;
    }
    g_pDevice = pDevice;

    g_hGameWnd = GetForegroundWindow();
    if (!g_hGameWnd) {
        return;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    NrthUI_ApplyTheme();
    ImGui_ImplWin32_Init(g_hGameWnd);
    ImGui_ImplDX9_Init(pDevice);

    g_pOrigWndProc = (WNDPROC)SetWindowLongA(g_hGameWnd, GWL_WNDPROC, (LONG)GameWndProc);

    g_bOverlayInit = true;
}

static void BuildOverlayMenu(void)
{
    NrthUI_Build();
}

static void UpdateOverlayInput(void)
{
    ImGuiIO &io = ImGui::GetIO();

    if (!g_bMenuOpen) {
        io.MouseDrawCursor = false;
        return;
    }

    io.MouseDrawCursor = true;

    POINT pt;
    if (GetCursorPos(&pt) && g_hGameWnd) {
        ScreenToClient(g_hGameWnd, &pt);
        io.MousePos = ImVec2((float)pt.x, (float)pt.y);
    }

    io.MouseDown[0] = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    io.MouseDown[1] = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
    io.MouseDown[2] = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0;
}

static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *pDevice, const RECT *pSrc,
                                     const RECT *pDest, HWND hDestWindow, const RGNDATA *pDirty)
{
    EnsureOverlayInitialized(pDevice);

    if (g_bOverlayInit) {
        /* Toggle key from C:\Overwack\loader_config.cfg (" menu_key=%d", default 45 = VK_INSERT) */
        bool wasOpen = g_bMenuOpen;
        int toggleVk = g_cfg.menuKey ? g_cfg.menuKey : VK_INSERT;
        if (GetAsyncKeyState(toggleVk) & 1) {
            g_bMenuOpen = !g_bMenuOpen;
        }
        if (g_bMenuOpen != wasOpen) {
            if (g_bMenuOpen) {
                while (ShowCursor(TRUE) < 0) { }
                ClipCursor(NULL);
                ReleaseCapture();
            } else {
                while (ShowCursor(FALSE) >= 0) { }
            }
        }

        UpdateOverlayInput();

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (g_bMenuOpen) {
            BuildOverlayMenu();
        }

        ImGui::EndFrame();
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    }

    return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
}

static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *pDevice, D3DPRESENT_PARAMETERS *pParams)
{
    if (g_bOverlayInit) {
        ImGui_ImplDX9_InvalidateDeviceObjects();
    }
    HRESULT hr = g_pOrigReset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_bOverlayInit) {
        ImGui_ImplDX9_CreateDeviceObjects();
    }
    return hr;
}

static const char *BaseNameA(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return slash ? slash + 1 : path;
}

#endif /* _WIN32 && !NRTH_HEADLESS_TEST */
