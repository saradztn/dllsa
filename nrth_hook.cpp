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
 *   MainInitThread            VA 0x1000a850 (RVA 0x0a850)  config/ADS/probes + LdrLoadDll + D3D9 hook
 *   Hooked_LdrLoadDll         VA 0x1000a640 (RVA 0x0a640)  trigger on client.dll / netc.dll
 *   ResolvePattern_10002960   VA 0x10002960 (RVA 0x02960)  wildcard byte-pattern scanner
 *   ArmClient_10005b80        VA 0x10005b80 (RVA 0x05b80)  11 scans + 11 MH_CreateHook calls
 *     Handlers: 0x10002ff0, 0x100047b0, 0x100050a0, 0x10005290, 0x100052b0,
 *               0x10005620, 0x100056c0, 0x100056f0, 0x10005ab0, 0x10005b30, 0x10005b50
 *   ResolveClientOffsets      VA 0x1000c400 (RVA 0x0c400)  20 pattern scans, 0 hooks
 *   PatchByte_10011870        VA 0x10011870 (RVA 0x11870)  VirtualProtect(ptr,1,0x40) + list 0x101493e4
 *   ArmNetc_10020640          VA 0x10020640 (RVA 0x20640)  netc.dll scans + hooks + 0xC3 patches
 *   GetD3D9DeviceVTable       VA 0x10012980 (RVA 0x12980)  pattern scan C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86
 *   InstallD3D9Hooks          VA 0x10016300 (RVA 0x16300)  Present idx 17 / Reset idx 16 + Cursor hooks
 *   Hooked_Present            VA 0x10014d50 (RVA 0x14d50)  Dear ImGui 1.92.9 WIP overlay
 *   Hooked_Reset              VA 0x1001a3c0 (RVA 0x1a3c0)  device-loss handling
 *   Hooked_WndProc            VA 0x10015ed0 (RVA 0x15ed0)  SetWindowLongW subclass + VK_INSERT toggle
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
 * Exported hook procedure (export ordinal 1, name "NVXHookProc" in nvx.dll).
 * Placed at exact RVA 0x0000B9E0 (VA 0x1000B9E0) in the PE32 build when
 * nrth_hook.o is linked first after dllcrt2.o (0x10001010 + 0xA9D0 = 0x1000B9E0).
 * =========================================================================== */
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
__asm__(
    ".section .text\n"
    ".balign 16, 0x90\n"
    ".fill 0xA9E0, 1, 0x90\n"
);
#endif

extern "C"
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
__attribute__((aligned(16)))
#endif
LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam)
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
 * Decoded from NRTH.dll (0x10002ff0..0x10005b50) with exact calling conventions:
 *   #00 0x10002ff0: __thiscall (ret 0x18) — captures 6 client interface pointers
 *   #01 0x100047b0: __cdecl    (ret)      — luaL_loadbuffer / script loader hook
 *   #02 0x100050a0: __cdecl    (ret)      — TriggerServerEvent / event filter
 *   #03 0x100056f0: __cdecl    (ret)      — Lua debug / state hook
 *   #04 0x10005290: __thiscall (ret 0x1c) — captures CResourceManager thisPtr
 *   #05 0x100052b0: __thiscall (ret 0x1c) — CResource creation tracker
 *   #06 0x10005620: __thiscall (ret 0x04) — CResource removal tracker
 *   #07 0x100056c0: __thiscall (ret 0x20) — Anti-ScreenShot / screen capture guard
 *   #08 0x10005ab0: __thiscall (ret 0x18) — World/projectile Vec3 override
 *   #09 0x10005b30: __thiscall (ret 0x08) — Client pass-through hook
 *   #10 0x10005b50: __cdecl    (ret)      — Anti-ScreenShot secondary guard
 * =========================================================================== */
static void RecordLuaVmAndRunPending(void *L)
{
    if (!L || !Nrth_IsPointerReadable_VirtualQuery(L)) {
        return;
    }
    g_LuaVmBridge.default_L_1013c95c = L;
    bool already = false;
    for (uint32_t i = 0; i < g_LuaVmBridge.slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
        if (g_LuaVmBridge.registry_1013bf04[i].luaStatePtr32 == (uint32_t)(uintptr_t)L) {
            already = true;
            break;
        }
    }
    if (!already && g_LuaVmBridge.slotCount < NRTH_VM_REGISTRY_CAP) {
        uint32_t idx = g_LuaVmBridge.slotCount++;
        g_LuaVmBridge.registry_1013bf04[idx].luaStatePtr32 = (uint32_t)(uintptr_t)L;
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
            g_LuaVmBridge.loadbuffer_1013c94c(L, g_LuaVmBridge.scriptBuf_1013beec, slen, chunkName) == 0) {
            g_LuaVmBridge.pcall_1013c974(L, 0, 0, 0);
        }
        g_LuaVmBridge.execFlag_1013c939 = 0;
    }
}

static void *g_ClientIfaces_10148ed4[6] = { NULL };
static void *g_ResourceMgr_1013c948     = NULL;

#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

typedef void (__thiscall *PFN_Client_10002ff0)(void *, void *, void *, void *, void *, void *, void *);
typedef int  (__cdecl    *PFN_Client_100047b0)(void *, const char *, size_t, const char *);
typedef unsigned char (__cdecl *PFN_Client_100050a0)(void *, const char *, void *, void *, void *, void *, float);
typedef void *(__thiscall *PFN_Client_10005290)(void *, void *, void *, void *, void *, void *, void *, void *);
typedef void *(__thiscall *PFN_Client_100052b0)(void *, void *, const char *, void *, void *, void *, void *, void *);
typedef void (__thiscall *PFN_Client_10005620)(void *, void *);
typedef int  (__thiscall *PFN_Client_100056c0)(void *, void *, void *, void *, void *, void *, void *, void *, void *);
typedef unsigned char (__cdecl *PFN_Client_100056f0)(void *, void *, void *);
typedef void (__thiscall *PFN_Client_10005ab0)(void *, void *, float *, void *, float, void *, void *);
typedef int  (__thiscall *PFN_Client_10005b30)(void *, void *, void *);
typedef int  (__cdecl    *PFN_Client_10005b50)(void *);

extern NrthHookSlot g_ClientHooks_10005b80[NRTH_CLIENT_HOOK_COUNT];

/* #00 0x10002ff0: __thiscall with 6 stack args (ret 0x18) */
static void __fastcall Hook_Client_10002ff0(void *thisPtr, void *edxUnused,
                                            void *a1, void *a2, void *a3, void *a4, void *a5, void *a6)
{
    (void)edxUnused;
    if (thisPtr && a1 && a2 && a3 && a4 && a5 && a6) {
        g_ClientIfaces_10148ed4[0] = a1;
        g_ClientIfaces_10148ed4[1] = a2;
        g_ClientIfaces_10148ed4[2] = a3;
        g_ClientIfaces_10148ed4[3] = a4;
        g_ClientIfaces_10148ed4[4] = a5;
        g_ClientIfaces_10148ed4[5] = a6;
    }
    PFN_Client_10002ff0 orig = (PFN_Client_10002ff0)g_ClientHooks_10005b80[0].origTrampoline;
    if (orig) {
        orig(thisPtr, a1, a2, a3, a4, a5, a6);
    }
}

/* #01 0x100047b0: __cdecl with 4 stack args (ret) — luaL_loadbuffer hook */
static int __cdecl Hook_Client_100047b0(void *L, const char *buff, size_t sz, const char *name)
{
    RecordLuaVmAndRunPending(L);
    PFN_Client_100047b0 orig = (PFN_Client_100047b0)g_ClientHooks_10005b80[1].origTrampoline;
    if (orig) {
        if (!g_LuaVmBridge.loadbuffer_1013c94c) {
            g_LuaVmBridge.loadbuffer_1013c94c = (PFN_NrthLuaLoadBuffer)orig;
        }
        return orig(L, buff, sz, name);
    }
    return 0;
}

/* #02 0x100050a0: __cdecl with 7 stack args (ret) — TriggerServerEvent hook */
static unsigned char __cdecl Hook_Client_100050a0(void *a1, const char *eventName,
                                                  void *a3, void *a4, void *a5, void *a6, float a7)
{
    PFN_Client_100050a0 orig = (PFN_Client_100050a0)g_ClientHooks_10005b80[2].origTrampoline;
    if (orig) {
        return orig(a1, eventName, a3, a4, a5, a6, a7);
    }
    return 1;
}

/* #03 0x10005290: __thiscall with 7 stack args (ret 0x1c) */
static void *__fastcall Hook_Client_10005290(void *thisPtr, void *edxUnused,
                                             void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    (void)edxUnused;
    if (thisPtr) {
        g_ResourceMgr_1013c948 = thisPtr;
    }
    PFN_Client_10005290 orig = (PFN_Client_10005290)g_ClientHooks_10005b80[4].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2, a3, a4, a5, a6, a7);
    }
    return NULL;
}

/* #04 0x100052b0: __thiscall with 7 stack args (ret 0x1c) */
static void *__fastcall Hook_Client_100052b0(void *thisPtr, void *edxUnused,
                                             void *a1, const char *resName, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    (void)edxUnused;
    PFN_Client_100052b0 orig = (PFN_Client_100052b0)g_ClientHooks_10005b80[5].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, resName, a3, a4, a5, a6, a7);
    }
    return NULL;
}

/* #05 0x10005620: __thiscall with 1 stack arg (ret 0x4) */
static void __fastcall Hook_Client_10005620(void *thisPtr, void *edxUnused, void *resPtr)
{
    (void)edxUnused;
    PFN_Client_10005620 orig = (PFN_Client_10005620)g_ClientHooks_10005b80[6].origTrampoline;
    if (orig) {
        orig(thisPtr, resPtr);
    }
}

/* #06 0x100056c0: __thiscall with 8 stack args (ret 0x20) — Anti-ScreenShot guard */
static int __fastcall Hook_Client_100056c0(void *thisPtr, void *edxUnused,
                                           void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    (void)edxUnused;
    if (g_ReportChannels.suppressReports) {
        ++g_ReportChannels.screenshotCount;
        return 0;
    }
    PFN_Client_100056c0 orig = (PFN_Client_100056c0)g_ClientHooks_10005b80[7].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    return 0;
}

/* #07 0x100056f0: __cdecl with 3 stack args (ret) */
static unsigned char __cdecl Hook_Client_100056f0(void *a1, void *a2, void *a3)
{
    RecordLuaVmAndRunPending(a1);
    PFN_Client_100056f0 orig = (PFN_Client_100056f0)g_ClientHooks_10005b80[3].origTrampoline;
    if (orig) {
        return orig(a1, a2, a3);
    }
    return 1;
}

/* #08 0x10005ab0: __thiscall with 6 stack args (ret 0x18) */
static void __fastcall Hook_Client_10005ab0(void *thisPtr, void *edxUnused,
                                            void *a1, float *posVec3, void *a3, float a4, void *a5, void *a6)
{
    (void)edxUnused;
    PFN_Client_10005ab0 orig = (PFN_Client_10005ab0)g_ClientHooks_10005b80[8].origTrampoline;
    if (!orig) {
        return;
    }
    float localVec[3] = { 0.0f, 0.0f, 0.0f };
    if (posVec3) {
        localVec[0] = posVec3[0];
        localVec[1] = posVec3[1];
        localVec[2] = posVec3[2];
    }
    orig(thisPtr, a1, posVec3 ? localVec : posVec3, a3, a4, a5, a6);
}

/* #09 0x10005b30: __thiscall with 2 stack args (ret 0x8) */
static int __fastcall Hook_Client_10005b30(void *thisPtr, void *edxUnused, void *a1, void *a2)
{
    (void)edxUnused;
    PFN_Client_10005b30 orig = (PFN_Client_10005b30)g_ClientHooks_10005b80[9].origTrampoline;
    if (orig) {
        return orig(thisPtr, a1, a2);
    }
    return 0;
}

/* #10 0x10005b50: __cdecl with 1 stack arg (ret) */
static int __cdecl Hook_Client_10005b50(void *a1)
{
    if (g_ReportChannels.suppressReports) {
        ++g_ReportChannels.screenshotCount;
        return 0;
    }
    PFN_Client_10005b50 orig = (PFN_Client_10005b50)g_ClientHooks_10005b80[10].origTrampoline;
    if (orig) {
        return orig(a1);
    }
    return 0;
}

#else /* Headless / Linux verification mode */

typedef int (*PFN_GenericHook)(void *a1, void *a2, void *a3, void *a4);
static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4);

static int Hook_Client_10002ff0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(0,  a1, a2, a3, a4); }
static int Hook_Client_100047b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(1,  a1, a2, a3, a4); }
static int Hook_Client_100050a0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(2,  a1, a2, a3, a4); }
static int Hook_Client_10005290(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(4,  a1, a2, a3, a4); }
static int Hook_Client_100052b0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(5,  a1, a2, a3, a4); }
static int Hook_Client_10005620(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(6,  a1, a2, a3, a4); }
static int Hook_Client_100056c0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(7,  a1, a2, a3, a4); }
static int Hook_Client_100056f0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(3,  a1, a2, a3, a4); }
static int Hook_Client_10005ab0(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(8,  a1, a2, a3, a4); }
static int Hook_Client_10005b30(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(9,  a1, a2, a3, a4); }
static int Hook_Client_10005b50(void *a1, void *a2, void *a3, void *a4) { return DispatchClientHook(10, a1, a2, a3, a4); }

#endif

/* All 11 patterns from 0x10005b80 in NRTH.dll (7 from kNrthEncryptedSigs + 4 full patterns) */
NrthHookSlot g_ClientHooks_10005b80[NRTH_CLIENT_HOOK_COUNT] = {
    {  0, 0x10002ff0u, 0x10005c07u, 0x2Du, NULL, (void *)&Hook_Client_10002ff0, NULL, NULL, false }, /* Sig #10 */
    {  1, 0x100047b0u, 0x10005d28u, 0x2Du, NULL, (void *)&Hook_Client_100047b0, NULL, NULL, false }, /* Sig #5  */
    {  2, 0x100050a0u, 0x10005e54u, 0x2Du, NULL, (void *)&Hook_Client_100050a0, NULL, NULL, false }, /* Sig #3  */
    {  3, 0x100056f0u, 0x10005f56u, 0x2Du, NULL, (void *)&Hook_Client_100056f0, NULL, NULL, false }, /* Sig #15 */
    {  4, 0x10005290u, 0x10006050u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 89 5D ? 68 ? ? ? ? E8 ? ? ? ? 83 C4",
       (void *)&Hook_Client_10005290, NULL, NULL, false },
    {  5, 0x100052b0u, 0x10006140u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 7D ? 89 7D ? 0F B7 45",
       (void *)&Hook_Client_100052b0, NULL, NULL, false },
    {  6, 0x10005620u, 0x10006230u, 0x2Du, NULL, (void *)&Hook_Client_10005620, NULL, NULL, false }, /* Sig #6  */
    {  7, 0x100056c0u, 0x1000633bu, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 4D ? 8B 45 ? 89 45 ? 8B 45",
       (void *)&Hook_Client_100056c0, NULL, NULL, false },
    {  8, 0x10005ab0u, 0x10006450u, 0x2Du, NULL, (void *)&Hook_Client_10005ab0, NULL, NULL, false }, /* Sig #13 */
    {  9, 0x10005b30u, 0x1000657bu, 0x2Du, NULL, (void *)&Hook_Client_10005b30, NULL, NULL, false }, /* Sig #19 */
    { 10, 0x10005b50u, 0x10006684u, 0x2Du,
       "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 7D ? 8D 8D ? ? ? ? 57 C7 85 ? ? ? ? 00 00 00 00 C7 85 ? ? ? ? 00 00 00 00 E8",
       (void *)&Hook_Client_10005b50, NULL, NULL, false },
};

#if !defined(_WIN32) || defined(NRTH_HEADLESS_TEST)
static int DispatchClientHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    if (slotIdx == 0 && a1 && Nrth_IsPointerReadable_VirtualQuery(a1)) {
        RecordLuaVmAndRunPending(a1);
    }
    if (slotIdx < NRTH_CLIENT_HOOK_COUNT && g_ClientHooks_10005b80[slotIdx].origTrampoline) {
        PFN_GenericHook orig = (PFN_GenericHook)g_ClientHooks_10005b80[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}
#endif

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
    { 1, 0x1001dd90u, 0x10023530u, 0x2Du,
      "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 45 ? 0F 57 C0 89 85 ? ? ? ? 33 FF",
      (void *)&Hook_Netc_1001dd90, NULL, NULL, false },
    { 2, 0x1001df90u, 0x100233f0u, 0x2Du,
      "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 8D ? ? ? ? C7 85",
      (void *)&Hook_Netc_1001df90, NULL, NULL, false },
    { 3, 0x1001fa80u, 0x100232b0u, 0x2Du,
      "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B 4D ? 8D 51 ? ? ? ? ? ? 41 84 C0 75 ? 2B CA 83 F9",
      (void *)&Hook_Netc_1001fa80, NULL, NULL, false },
};

static int DispatchNetcHook(uint32_t slotIdx, void *a1, void *a2, void *a3, void *a4)
{
    switch (slotIdx) {
    case 0: ++g_ReportChannels.screenshotCount;    break;
    case 1: ++g_ReportChannels.transgressionCount; break;
    case 2: ++g_ReportChannels.diagnosticCount;    break;
    case 3: ++g_ReportChannels.acinfoCount;        break;
    default: break;
    }
    if (g_ReportChannels.suppressReports && slotIdx < 3) {
        return 0;
    }
    if (slotIdx < NRTH_NETC_HOOK_COUNT && g_NetcHooks_10020640[slotIdx].origTrampoline) {
        typedef int (*PFN_NetcGeneric)(void *, void *, void *, void *);
        PFN_NetcGeneric orig = (PFN_NetcGeneric)g_NetcHooks_10020640[slotIdx].origTrampoline;
        return orig(a1, a2, a3, a4);
    }
    return 0;
}

/* ===========================================================================
 * ArmClient_10005b80 — 11 pattern scans + 11 MH_CreateHook installations
 * =========================================================================== */
extern "C" uint32_t ArmClient_10005b80(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours)
{
    static const struct { uint32_t slot; uint32_t sigId; } kClientSigMap[7] = {
        { 0, 10 }, /* 0x10005c07 -> 0x10002ff0 */
        { 1,  5 }, /* 0x10005d28 -> 0x100047b0 */
        { 2,  3 }, /* 0x10005e54 -> 0x100050a0 */
        { 3, 15 }, /* 0x10005f56 -> 0x100056f0 */
        { 6,  6 }, /* 0x10006230 -> 0x10005620 */
        { 8, 13 }, /* 0x10006450 -> 0x10005ab0 */
        { 9, 19 }, /* 0x1000657b -> 0x10005b30 */
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
 * ResolveClientOffsets_1000c390 (VA 0x1000c400) — 20 pattern scans on client.dll
 * =========================================================================== */
static uintptr_t g_ClientResolvedOffsets[NRTH_CLIENT_RESOLVE_COUNT] = {0};

extern "C" uint32_t ResolveClientOffsets_1000c390(const uint8_t *moduleBase, uint32_t moduleSize)
{
    static const uint32_t kC390CatalogSigIds[12] = {
        4, 11, 14, 1, 9, 8, 12, 2, 17, 7, 20, 18
    };
    /* Exact 8 additional patterns decoded from 0x1000c400 in NRTH.dll (K=0xC0) */
    static const char *const kC390ExtraPatterns[8] = {
        "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8 ? ? ? ? 8B C8",
        "55 8B EC 57 8B 7D ? 8B 4F ? 8B 41 ? 3B 41 ? 72 ? 57 E8 ? ? ? ? 83 C4 ? 56 FF 75 ? 8B 77 ? FF 75 ? 57 E8 ? ? ? ? ? ? 83 C4 ? C7 46 ? ? ? ? ? 8B 4F ? 8B 47 ? 5E 3B 41 ? 72 ? C7 05 ? ? ? ? ? ? ? ? 83 47 ? ? 5F 5D C3 ? ? ? ? ? ? ? ? ? ? ? ? 55 8B EC 8B 4D",
        "55 8B EC 56 57 FF 75 ? 8B 7D",
        "55 8B EC 83 EC ? 56 8B 75 ? 57 FF 75",
        "55 8B EC 8B 55 ? 8B 42 ? C7 40",
        "55 8B EC 57 FF 75 ? 8B 7D ? 57 E8 ? ? ? ? 83 C4 ? 83 78",
        "55 8B EC 53 57 8B 7D ? 8B 47 ? 2B 47 ? 83 E0 ? 83 F8 ? 7D ? C7 05 ? ? ? ? ? ? ? ? FF 75 ? 57 E8 ? ? ? ? 8B D8 83 C4 ? 83 7B ? ? 74 ? C7 05 ? ? ? ? ? ? ? ? 56 FF 75",
        "55 8B EC 8B 55 ? F2 0F 10 45"
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
    if (g_ClientResolvedOffsets[6]) {
        g_LuaVmBridge.pcall_1013c974 = (PFN_NrthLuaPcall)g_ClientResolvedOffsets[6];
    }
    return resolved;
}

/* ===========================================================================
 * ArmNetc_10020640 — 6 pattern scans (0x10023670..0x10023030) +
 *                    4 MH_CreateHook calls + 6 0xC3 prepare/write pairs
 * =========================================================================== */
extern "C" uint32_t ArmNetc_10020640(uint8_t *moduleBase, uint32_t moduleSize,
                                     bool applyDetours, bool applyPatches)
{
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

    for (uint32_t i = 0; i < NRTH_NETC_PATCH_COUNT; ++i) {
        uint8_t opcode = 0xC3u;
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
 * Scans d3d9.dll in memory for the CD3DBase constructor sequence:
 *   C7 06 <vtable_ptr32> 89 86 <disp32> 89 86
 * and dereferences the 32-bit vtable pointer at (match + 2).
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

typedef NTSTATUS (NTAPI  *PFN_LdrLoadDll)(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
typedef HRESULT  (WINAPI *PFN_Present)(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
typedef HRESULT  (WINAPI *PFN_Reset)(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
typedef IDirect3D9 *(WINAPI *PFN_Direct3DCreate9)(UINT);
typedef BOOL     (WINAPI *PFN_SetCursorPos)(int, int);
typedef int      (WINAPI *PFN_ShowCursor)(BOOL);
typedef BOOL     (WINAPI *PFN_ClipCursor)(const RECT *);

static PFN_LdrLoadDll   g_pOrigLdrLoadDll   = NULL; /* RVA 0x0a640 hook target */
static PFN_Present      g_pOrigPresent      = NULL; /* vtable slot 17 (0x44)   */
static PFN_Reset        g_pOrigReset        = NULL; /* vtable slot 16 (0x40)   */
static PFN_SetCursorPos g_pOrigSetCursorPos = NULL; /* RVA 0x162c0             */
static PFN_ShowCursor   g_pOrigShowCursor   = NULL; /* RVA 0x16290             */
static PFN_ClipCursor   g_pOrigClipCursor   = NULL; /* RVA 0x16260             */

static volatile LONG    g_lClientArmed      = 0;
static volatile LONG    g_lNetcArmed        = 0;
static volatile LONG    g_lOverlayArmed     = 0;
static volatile LONG    g_lCursorArmed      = 0;
static bool             g_bOverlayInit      = false;
static bool             g_bMenuOpen         = false;
static ULONGLONG        g_lastToggleTick    = 0;
static POINT            g_savedCursorPos    = { 0, 0 };
static IDirect3DDevice9 *g_pDevice          = NULL;
static HWND             g_hGameWnd          = NULL;
static WNDPROC          g_pOrigWndProc      = NULL;

static DWORD WINAPI MainInitThread(LPVOID lpParam);
static NTSTATUS NTAPI Hooked_LdrLoadDll(PWSTR, PULONG, NVX_UNICODE_STRING *, PVOID *);
static void **GetD3D9DeviceVTable(void);
static bool InstallD3D9Hooks(void **vtable);
static void InstallCursorHooks_100165ee(void);
static HRESULT WINAPI Hooked_Present(IDirect3DDevice9 *, const RECT *, const RECT *, HWND, const RGNDATA *);
static HRESULT WINAPI Hooked_Reset(IDirect3DDevice9 *, D3DPRESENT_PARAMETERS *);
static LRESULT CALLBACK GameWndProc(HWND, UINT, WPARAM, LPARAM);
static void BuildOverlayMenu(void);
static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice, HWND hDestWindow);
static void UpdateOverlayInput(void);
static void ToggleMenuState(void);
static const char *BaseNameA(const char *path);
static uint32_t GetLoadedModuleSize(HMODULE hMod);
static void RunEnvironmentProbes(void);
static void TryArmLoadedModules(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        /* If loaded locally inside NORTH LOADER.exe, do not spawn game hook threads */
        char hostExe[MAX_PATH] = {0};
        if (GetModuleFileNameA(NULL, hostExe, MAX_PATH) != 0) {
            const char *exeBase = BaseNameA(hostExe);
            if (_stricmp(exeBase, "NORTH LOADER.exe") == 0) {
                return TRUE;
            }
        }

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

static void RunEnvironmentProbes(void)
{
    CreateDirectoryA("C:\\NVX", NULL);
    CreateDirectoryA("C:\\NVX\\logs", NULL);
    CreateDirectoryA("C:\\NVX\\dump", NULL);

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

/* ===========================================================================
 * Cursor lock hooks (VA 0x10016260, 0x10016290, 0x100162c0 in NRTH.dll)
 * While the menu is open (g_bMenuOpen == true), block GTA:SA / MTA from
 * recentering, hiding, or clipping the cursor.
 * =========================================================================== */
static BOOL WINAPI Hooked_SetCursorPos(int X, int Y)
{
    if (g_bMenuOpen) {
        return TRUE;
    }
    return g_pOrigSetCursorPos ? g_pOrigSetCursorPos(X, Y) : TRUE;
}

static int WINAPI Hooked_ShowCursor(BOOL bShow)
{
    if (g_bMenuOpen) {
        return 1;
    }
    return g_pOrigShowCursor ? g_pOrigShowCursor(bShow) : (bShow ? 1 : -1);
}

static BOOL WINAPI Hooked_ClipCursor(const RECT *lpRect)
{
    if (g_bMenuOpen) {
        return TRUE;
    }
    return g_pOrigClipCursor ? g_pOrigClipCursor(lpRect) : TRUE;
}

static void InstallCursorHooks_100165ee(void)
{
    if (InterlockedCompareExchange(&g_lCursorArmed, 1, 0) != 0) {
        return;
    }
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        hUser32 = LoadLibraryA("user32.dll");
    }
    if (!hUser32) {
        InterlockedExchange(&g_lCursorArmed, 0);
        return;
    }
    FARPROC pSetCursorPos = GetProcAddress(hUser32, "SetCursorPos");
    FARPROC pShowCursor   = GetProcAddress(hUser32, "ShowCursor");
    FARPROC pClipCursor   = GetProcAddress(hUser32, "ClipCursor");

    if (pSetCursorPos) {
        if (MH_CreateHook((LPVOID)pSetCursorPos, (LPVOID)&Hooked_SetCursorPos,
                          (LPVOID *)&g_pOrigSetCursorPos) == MH_OK) {
            MH_EnableHook((LPVOID)pSetCursorPos);
        }
    }
    if (pShowCursor) {
        if (MH_CreateHook((LPVOID)pShowCursor, (LPVOID)&Hooked_ShowCursor,
                          (LPVOID *)&g_pOrigShowCursor) == MH_OK) {
            MH_EnableHook((LPVOID)pShowCursor);
        }
    }
    if (pClipCursor) {
        if (MH_CreateHook((LPVOID)pClipCursor, (LPVOID)&Hooked_ClipCursor,
                          (LPVOID *)&g_pOrigClipCursor) == MH_OK) {
            MH_EnableHook((LPVOID)pClipCursor);
        }
    }
}

/* ===========================================================================
 * Live netc.dll SendPacket & anti-cheat report detours (VA 0x1001da80..0x10020640)
 * =========================================================================== */
typedef unsigned char (__thiscall *PFN_Netc_SendPacket_1001da80)(
    void *thisPtr, unsigned char packetId, void *bitStream,
    int priority, int reliability, char orderingChannel);

static PFN_Netc_SendPacket_1001da80 g_pOrigNetcSendPacket = NULL;
static void *g_pNetcInstance_10148ed0 = NULL;

static unsigned char __fastcall Hook_Netc_SendPacket_1001da80(
    void *thisPtr, void *edxUnused,
    unsigned char packetId, void *bitStream,
    int priority, int reliability, char orderingChannel)
{
    (void)edxUnused;
    g_pNetcInstance_10148ed0 = thisPtr;

    /* Match 0x1001dbf6..0x1001dc2a in NRTH.dll: block packet IDs 0x5B, 0x5C, 0x5D */
    if (packetId == 0x5Bu || packetId == 0x5Cu || packetId == 0x5Du) {
        ++g_ReportChannels.transgressionCount;
        return 1;
    }
    if (g_ReportChannels.suppressReports &&
        (packetId == 80u || packetId == 81u || packetId == 82u || packetId == 83u)) {
        ++g_ReportChannels.diagnosticCount;
        return 1;
    }
    if (g_pOrigNetcSendPacket) {
        return g_pOrigNetcSendPacket(thisPtr, packetId, bitStream, priority, reliability, orderingChannel);
    }
    return 1;
}

static unsigned char __cdecl Hook_Netc_RetFalse_1001dc30(void) { return 0; }
static void __stdcall Hook_Netc_Ret4_1001dc40(void *a1) { (void)a1; }
static int  __cdecl Hook_Netc_RetZero_1001f500(void) { return 0; }
static int  __stdcall Hook_Netc_RetZero8_1001dc50(void *a1, void *a2) { (void)a1; (void)a2; return 0; }
static void __cdecl Hook_Netc_RetVoid_10001d20(void) { }

static bool PatchBytes_Live(void *addr, const uint8_t *bytes, size_t len)
{
    if (!addr || !bytes || len == 0) return false;
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    memcpy(addr, bytes, len);
    DWORD dummy = 0;
    VirtualProtect(addr, len, oldProt, &dummy);
    return true;
}

static void ArmNetc_Live_10020640(uint8_t *moduleBase, uint32_t moduleSize)
{
    if (!moduleBase || moduleSize == 0) return;

    /* 6 direct patch patterns from 0x1013b750..0x1013bc50 in NRTH.dll */
    static const char *const kNetcPatchPats[6] = {
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 8D ? ? ? ? C7 45",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 75 ? 8B 7D",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 89 5D ? 8B 7D",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? E8",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B 45 ? C7 45 ? ? ? ? ? 89 45 ? 8B 58",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 C7 45 ? ? ? ? ? 8B 0D"
    };
    const uint8_t kRet1[1]  = { 0xC3 };
    const uint8_t kRet10[3] = { 0xC2, 0x10, 0x00 };
    for (int i = 0; i < 6; ++i) {
        uint8_t *hit = (uint8_t *)ResolvePattern_10002960(moduleBase, moduleSize, kNetcPatchPats[i]);
        if (hit) {
            if (i < 5) PatchBytes_Live(hit, kRet1, 1);
            else       PatchBytes_Live(hit, kRet10, 3);
        }
    }

    /* 7 guard detours + SendPacket detour (0x1001da80) from 0x10020640 */
    struct LiveNetcDetour { const char *pat; void *detour; void **orig; };
    static void *s_dummyOrig[7] = { NULL };
    LiveNetcDetour detours[8] = {
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B F1 E8",
          (void *)&Hook_Netc_RetFalse_1001dc30, &s_dummyOrig[0] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 83 7B",
          (void *)&Hook_Netc_Ret4_1001dc40, &s_dummyOrig[1] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B F1 C7 45 ? ? ? ? ? 8D 4D",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[2] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B D9 C7 45 ? ? ? ? ? 83 7B",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[3] },
        { "55 8B EC 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 56 8B F1 6A",
          (void *)&Hook_Netc_RetZero_1001f500, &s_dummyOrig[4] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 89 8D ? ? ? ? 8B 45",
          (void *)&Hook_Netc_RetZero8_1001dc50, &s_dummyOrig[5] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 83 EC ? 53 56 57 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B F1 89 75 ? 8B 06",
          (void *)&Hook_Netc_RetVoid_10001d20, &s_dummyOrig[6] },
        { "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F1 89 75 ? 8B 46 ? 89 45 ? 8B 45 ? 83 EC",
          (void *)&Hook_Netc_SendPacket_1001da80, (void **)&g_pOrigNetcSendPacket },
    };
    for (int i = 0; i < 8; ++i) {
        void *hit = (void *)ResolvePattern_10002960(moduleBase, moduleSize, detours[i].pat);
        if (hit) {
            if (MH_CreateHook(hit, detours[i].detour, detours[i].orig) == MH_OK) {
                MH_EnableHook(hit);
                ++g_TotalInstalledHooks;
            }
        }
    }
}

static void TryArmLoadedModules(void)
{
    static char s_clientBuf[sizeof(kCt_ClientDll)] = {0};
    static bool s_clientGate                       = false;
    static char s_netcBuf[sizeof(kCt_NetcDll)]     = {0};
    static bool s_netcGate                         = false;

    const char *clientName = NrthDecryptOnce(kCt_ClientDll, sizeof(kCt_ClientDll), 0x2D,
                                             s_clientBuf, &s_clientGate);
    const char *netcName   = NrthDecryptOnce(kCt_NetcDll, sizeof(kCt_NetcDll), 0x20,
                                             s_netcBuf, &s_netcGate);

    if (g_lClientArmed == 0) {
        HMODULE hClient = GetModuleHandleA(clientName);
        if (hClient && InterlockedCompareExchange(&g_lClientArmed, 1, 0) == 0) {
            uint32_t modSize = GetLoadedModuleSize(hClient);
            ArmClient_10005b80((uint8_t *)hClient, modSize, true);
            ResolveClientOffsets_1000c390((const uint8_t *)hClient, modSize);
        }
    }

    if (g_lNetcArmed == 0) {
        HMODULE hNetc = GetModuleHandleA(netcName);
        if (hNetc && InterlockedCompareExchange(&g_lNetcArmed, 1, 0) == 0) {
            uint32_t modSize = GetLoadedModuleSize(hNetc);
            ArmNetc_Live_10020640((uint8_t *)hNetc, modSize);
        }
    }

    if (g_lOverlayArmed == 0) {
        void **vtable = GetD3D9DeviceVTable();
        if (vtable && InterlockedCompareExchange(&g_lOverlayArmed, 1, 0) == 0) {
            if (!InstallD3D9Hooks(vtable)) {
                InterlockedExchange(&g_lOverlayArmed, 0);
            } else {
                InstallCursorHooks_100165ee();
            }
        }
    }
}

static DWORD WINAPI MainInitThread(LPVOID lpParam)
{
    (void)lpParam;

    /* Load C:\NVX\loader_config.cfg or C:\Overwack\loader_config.cfg */
    if (!NrthConfig_Load("C:\\NVX\\loader_config.cfg")) {
        NrthConfig_Load(NULL);
    }

    /* Run C:\NVX, ADS, registry and disk model probes */
    RunEnvironmentProbes();

    if (MH_Initialize() != MH_OK) {
        return 1;
    }

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
    if (hNtdll) {
        FARPROC pLdrLoadDll = GetProcAddress(hNtdll, ldrName);
        if (pLdrLoadDll) {
            if (MH_CreateHook((LPVOID)pLdrLoadDll, (LPVOID)&Hooked_LdrLoadDll,
                              (LPVOID *)&g_pOrigLdrLoadDll) == MH_OK &&
                MH_EnableHook((LPVOID)pLdrLoadDll) == MH_OK) {
                ++g_TotalInstalledHooks;
            }
        }
    }

    /* Immediately arm D3D9 Present/Reset + Cursor hooks + any already-loaded client.dll/netc.dll
     * (matches 0x1000ace9..0x1000ad80 in NRTH.dll) */
    TryArmLoadedModules();

    /* Background watch loop (matches 0x1000a820 in NRTH.dll) */
    while (!(GetAsyncKeyState(VK_END) & 1)) {
        if (g_lOverlayArmed == 0 || g_lClientArmed == 0 || g_lNetcArmed == 0) {
            TryArmLoadedModules();
        }
        Sleep(50);
    }
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
        TryArmLoadedModules();
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
        char sysDir[MAX_PATH] = {0};
        if (GetSystemDirectoryA(sysDir, MAX_PATH) > 0) {
            char fullD3D[MAX_PATH] = {0};
            snprintf(fullD3D, sizeof(fullD3D), "%s\\d3d9.dll", sysDir);
            hD3D = LoadLibraryA(fullD3D);
        }
        if (!hD3D) {
            hD3D = LoadLibraryA(d3dName);
        }
    }
    if (!hD3D) {
        return NULL;
    }

    /* Primary method (VA 0x10012980): pattern-scan d3d9.dll .text for C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86 */
    uint32_t d3dSize = GetLoadedModuleSize(hD3D);
    if (d3dSize > 0x1000u) {
        uint32_t scanLen = d3dSize - 0x1000u;
        if (scanLen > 0x128000u) {
            scanLen = 0x128000u;
        }
        void **cand = FindD3D9VTableInBuffer_10012980((const uint8_t *)hD3D + 0x1000u, scanLen);
        if (cand &&
            Nrth_IsPointerReadable_VirtualQuery(cand) &&
            Nrth_IsPointerReadable_VirtualQuery(cand[16]) &&
            Nrth_IsPointerReadable_VirtualQuery(cand[17])) {
            pCachedVTable = cand;
            return pCachedVTable;
        }
    }

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
    if (!vtable || !vtable[16] || !vtable[17]) {
        return false;
    }
    if (MH_CreateHook(vtable[17], (LPVOID)&Hooked_Present, (LPVOID *)&g_pOrigPresent) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(vtable[17]) != MH_OK) {
        MH_RemoveHook(vtable[17]);
        g_pOrigPresent = NULL;
        return false;
    }
    if (MH_CreateHook(vtable[16], (LPVOID)&Hooked_Reset, (LPVOID *)&g_pOrigReset) != MH_OK) {
        MH_DisableHook(vtable[17]);
        MH_RemoveHook(vtable[17]);
        g_pOrigPresent = NULL;
        return false;
    }
    if (MH_EnableHook(vtable[16]) != MH_OK) {
        MH_RemoveHook(vtable[16]);
        MH_DisableHook(vtable[17]);
        MH_RemoveHook(vtable[17]);
        g_pOrigReset   = NULL;
        g_pOrigPresent = NULL;
        return false;
    }
    g_TotalInstalledHooks += 2; /* Hooks #2 & #3: Present (17) + Reset (16) */
    return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void ToggleMenuState(void)
{
    ULONGLONG now = GetTickCount64();
    if (now - g_lastToggleTick < 250ULL) {
        return;
    }
    g_lastToggleTick = now;
    g_bMenuOpen = !g_bMenuOpen;

    if (g_bMenuOpen) {
        GetCursorPos(&g_savedCursorPos);
        if (g_pOrigClipCursor) g_pOrigClipCursor(NULL);
        else ClipCursor(NULL);
        if (g_pOrigShowCursor) g_pOrigShowCursor(TRUE);
        else ShowCursor(TRUE);
        ReleaseCapture();
    } else {
        if (g_pOrigSetCursorPos) {
            g_pOrigSetCursorPos(g_savedCursorPos.x, g_savedCursorPos.y);
        } else {
            SetCursorPos(g_savedCursorPos.x, g_savedCursorPos.y);
        }
    }
}

/* Matches Hooked_WndProc at VA 0x10015ed0 in NRTH.dll */
static LRESULT CALLBACK GameWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int toggleVk = g_cfg.menuKey ? g_cfg.menuKey : VK_INSERT;
    if (msg == WM_KEYDOWN && (int)wParam == toggleVk && (lParam & 0x40000000L) == 0) {
        ToggleMenuState();
        return 0;
    }

    if (g_bMenuOpen) {
        ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);

        /* Block mouse input from reaching GTA:SA while the menu is open (0x100161cb..0x10016220) */
        if ((msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || msg == WM_INPUT) {
            return 1;
        }
        if (msg == WM_SETCURSOR) {
            SetCursor(LoadCursorA(NULL, IDC_ARROW));
            return TRUE;
        }
    }

    if (g_pOrigWndProc) {
        return CallWindowProcW(g_pOrigWndProc, hWnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static BOOL CALLBACK FindOwnProcessWindowProc(HWND hwnd, LPARAM lParam)
{
    DWORD wPid = 0;
    GetWindowThreadProcessId(hwnd, &wPid);
    if (wPid == GetCurrentProcessId() && IsWindowVisible(hwnd)) {
        *(HWND *)lParam = hwnd;
        return FALSE;
    }
    return TRUE;
}

static void EnsureOverlayInitialized(IDirect3DDevice9 *pDevice, HWND hDestWindow)
{
    if (g_bOverlayInit || !pDevice) {
        return;
    }

    /* Matches 0x10014e8d..0x100154df in NRTH.dll: obtain focus window from D3DDEVICE_CREATION_PARAMETERS */
    HWND hWnd = NULL;
    D3DDEVICE_CREATION_PARAMETERS cp;
    memset(&cp, 0, sizeof(cp));
    if (SUCCEEDED(pDevice->GetCreationParameters(&cp)) && cp.hFocusWindow && IsWindow(cp.hFocusWindow)) {
        hWnd = cp.hFocusWindow;
    }
    if (!hWnd && hDestWindow && IsWindow(hDestWindow)) {
        hWnd = hDestWindow;
    }
    if (!hWnd) {
        EnumWindows(FindOwnProcessWindowProc, (LPARAM)&hWnd);
    }
    if (!hWnd) {
        return;
    }

    g_pDevice  = pDevice;
    g_hGameWnd = hWnd;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = NULL;
    NrthUI_ApplyTheme();
    if (!ImGui_ImplWin32_Init(g_hGameWnd)) {
        return;
    }
    if (!ImGui_ImplDX9_Init(pDevice)) {
        ImGui_ImplWin32_Shutdown();
        return;
    }

    /* Subclass game window with SetWindowLongW (matches 0x100154df in NRTH.dll) */
    g_pOrigWndProc = (WNDPROC)SetWindowLongW(g_hGameWnd, GWL_WNDPROC, (LONG)GameWndProc);

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
    if (!pDevice) {
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }

    /* Matches 0x100155bf..0x100155d6 in NRTH.dll: check TestCooperativeLevel before rendering */
    HRESULT coop = pDevice->TestCooperativeLevel();
    if (coop == D3DERR_DEVICELOST) {
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }
    if (coop == D3DERR_DEVICENOTRESET) {
        if (g_bOverlayInit) {
            ImGui_ImplDX9_InvalidateDeviceObjects();
        }
        return g_pOrigPresent(pDevice, pSrc, pDest, hDestWindow, pDirty);
    }

    EnsureOverlayInitialized(pDevice, hDestWindow);

    if (g_bOverlayInit) {
        int toggleVk = g_cfg.menuKey ? g_cfg.menuKey : VK_INSERT;
        if (GetAsyncKeyState(toggleVk) & 1) {
            ToggleMenuState();
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
