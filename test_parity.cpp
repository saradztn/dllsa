/**
 * ============================================================================
 * test_parity.cpp — End-to-end verification suite for NRTH reconstruction
 * ============================================================================
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "nrth_audit.h"
#include "nrth_audit_sigs.h"
#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_arabic.h"
#include "nrth_assets.h"
#include "nrth_csx.h"

#ifdef NRTH_UI_HEADLESS
/* harness-only hook implemented inside nrth_ui.cpp's UI region */
extern "C" void NrthUI_TestSetLanguage(int lang);
extern "C" void NrthUI_TestSetTab(int tab);
#endif

/* defined in nrth_hook.cpp (C++ linkage); read through NrthHook_IsInGame */
extern void *g_pClientGame_10148ee8;
#include "nrth_hook.h"
#include "nrth_ui.h"
#include "imgui.h"

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, desc)                                                  \
    do {                                                                   \
        if (cond) {                                                        \
            ++g_passed;                                                    \
            printf("  [PASS] %s\n", desc);                                 \
        } else {                                                           \
            ++g_failed;                                                    \
            printf("  [FAIL] %s (line %d)\n", desc, __LINE__);             \
        }                                                                  \
    } while (0)

/* Helper: build a minimal valid PE32 image with a .text section and .rdata section */
static void BuildSyntheticPe32(uint8_t *img, uint32_t imgSize,
                               const uint8_t *textData, uint32_t textLen,
                               const uint8_t *rdataData, uint32_t rdataLen)
{
    memset(img, 0, imgSize);
    /* DOS header */
    img[0] = 'M';
    img[1] = 'Z';
    uint32_t peOff = 0x80;
    img[0x3C] = (uint8_t)(peOff & 0xFF);

    /* NT headers at 0x80 */
    uint8_t *nt = img + peOff;
    nt[0] = 'P'; nt[1] = 'E'; nt[2] = 0; nt[3] = 0;
    /* FileHeader: Machine=0x014C (i386), NumberOfSections=2, SizeOfOptionalHeader=0xE0, Characteristics=0x2102 */
    nt[4] = 0x4C; nt[5] = 0x01;
    nt[6] = 0x02; nt[7] = 0x00;
    nt[20] = 0xE0; nt[21] = 0x00;
    nt[22] = 0x02; nt[23] = 0x21;

    /* OptionalHeader32 at peOff + 24 */
    uint8_t *opt = nt + 24;
    opt[0] = 0x0B; opt[1] = 0x01; /* PE32 magic 0x10B */
    /* EntryPoint RVA = 0x1000 */
    opt[16] = 0x00; opt[17] = 0x10;
    /* ImageBase = 0x10000000 */
    opt[28] = 0x00; opt[29] = 0x00; opt[30] = 0x00; opt[31] = 0x10;

    /* Section headers at opt + 0xE0 */
    uint8_t *sh = opt + 0xE0;
    /* Section 0: .text at RVA 0x1000, raw 0x400, size 0x2000 */
    memcpy(sh, ".text\0\0\0", 8);
    uint32_t textSecSize = 0x2000;
    memcpy(sh + 8,  &textSecSize, 4); /* VirtualSize */
    uint32_t textRva = 0x1000;
    memcpy(sh + 12, &textRva, 4);
    memcpy(sh + 16, &textSecSize, 4); /* SizeOfRawData */
    uint32_t textRaw = 0x400;
    memcpy(sh + 20, &textRaw, 4);

    /* Section 1: .rdata at RVA 0x3000, raw 0x2400, size 0x2000 */
    uint8_t *sh1 = sh + 40;
    memcpy(sh1, ".rdata\0\0", 8);
    uint32_t rdataSecSize = 0x2000;
    memcpy(sh1 + 8,  &rdataSecSize, 4);
    uint32_t rdataRva = 0x3000;
    memcpy(sh1 + 12, &rdataRva, 4);
    memcpy(sh1 + 16, &rdataSecSize, 4);
    uint32_t rdataRaw = 0x2400;
    memcpy(sh1 + 20, &rdataRaw, 4);

    if (textData && textLen <= textSecSize) {
        memcpy(img + textRaw, textData, textLen);
    }
    if (rdataData && rdataLen <= rdataSecSize) {
        memcpy(img + rdataRaw, rdataData, rdataLen);
    }
}

/* Instantiateconcrete bytes matching a wildcard pattern ("55 8B ? ...") */
static uint32_t MaterializePattern(const char *pat, uint8_t *out, uint32_t cap)
{
    uint8_t bytes[256], mask[256];
    uint32_t plen = 0;
    if (NrthPatCompile(pat, bytes, mask, 256, &plen) < 0) return 0;
    if (plen > cap) return 0;
    for (uint32_t i = 0; i < plen; ++i) {
        out[i] = mask[i] ? bytes[i] : (uint8_t)(0x10 + (i & 0x7F));
    }
    return plen;
}

/* Mock Lua callbacks for testing NrthUI_ExecuteLuaViaBridge */
static int         s_mockLuaLoadCalled = 0;
static int         s_mockLuaPcallCalled = 0;
static std::string s_mockLuaLastChunk;
static std::string s_mockLuaLastScript;

static int MockLuaLoadBuffer(void *L, const char *buff, size_t sz, const char *name)
{
    (void)L;
    ++s_mockLuaLoadCalled;
    s_mockLuaLastScript.assign(buff, sz);
    s_mockLuaLastChunk = name ? name : "";
    return 0;
}

static int MockLuaPcall(void *L, int nargs, int nresults, int errfunc)
{
    (void)L; (void)nargs; (void)nresults; (void)errfunc;
    ++s_mockLuaPcallCalled;
    return 0;
}

int main(void)
{
    printf("=== NRTH Parity & Mechanism Verification Suite ===\n");
#ifdef NRTH_UI_HEADLESS
    printf("  mode: NRTH_UI_HEADLESS (full ImGui UI compiled, frame tests active)\n");
#else
    printf("  mode: core-only (UI stubbed; build with -DNRTH_UI_HEADLESS for UI frame tests)\n");
#endif

    /* 1. Built-in nrth_audit self-test */
    char auditReport[4096] = {0};
    int auditRc = NrthAuditSelfTest(auditReport, sizeof(auditReport));
    CHECK(auditRc == 0, "nrth_audit self-test (21 checks)");

    /* 2. Verify nrth_dll.def exports LIBRARY nvx.dll and NVXHookProc @1 */
    {
        FILE *fp = fopen("nrth_dll.def", "rb");
        char defBuf[1024] = {0};
        if (fp) {
            fread(defBuf, 1, sizeof(defBuf) - 1, fp);
            fclose(fp);
        }
        CHECK(strstr(defBuf, "LIBRARY nvx.dll") != NULL &&
              strstr(defBuf, "NVXHookProc=NVXHookProc@12 @1") != NULL,
              "nrth_dll.def: LIBRARY nvx.dll and NVXHookProc @1");
    }

    /* 3. Verify nrth_codec.h single-use gate (L = F - 1) and all 20 encrypted sigs */
    {
        char buf[64] = {0};
        bool gate = false;
        const char *dec = NrthDecryptOnce(kCt_ClientDll, sizeof(kCt_ClientDll), 0x2D, buf, &gate);
        CHECK(gate && strcmp(dec, "client.dll") == 0 && strlen(dec) == sizeof(kCt_ClientDll) - 1,
              "nrth_codec: kCt_ClientDll (K=0x2D, L=F-1=10) -> 'client.dll'");

        gate = false;
        dec = NrthDecryptOnce(kCt_NetcDll, sizeof(kCt_NetcDll), 0x20, buf, &gate);
        CHECK(gate && strcmp(dec, "netc.dll") == 0 && strlen(dec) == sizeof(kCt_NetcDll) - 1,
              "nrth_codec: kCt_NetcDll (K=0x20, L=F-1=8) -> 'netc.dll'");

        gate = false;
        dec = NrthDecryptOnce(kCt_AdsNt2, sizeof(kCt_AdsNt2), 0x20, buf, &gate);
        CHECK(gate && strcmp(dec, "C:\\ProgramData:NT2") == 0,
              "nrth_codec: kCt_AdsNt2 (VA 0x1001e530, K=0x20) -> 'C:\\ProgramData:NT2'");

        bool all20Match = true;
        for (uint32_t i = 0; i < 20; ++i) {
            const NrthSignature *cat = NrthSigAt(i + 1);
            const NrthEncryptedSigEntry &enc = kNrthEncryptedSigs[i];
            char pbuf[256] = {0};
            bool sgate = false;
            const char *p = NrthDecryptOnce(enc.cipher, enc.fieldSize, enc.key, pbuf, &sgate);
            if (!cat || !sgate || strcmp(p, cat->pattern) != 0 ||
                enc.fieldSize != cat->pattern_len + 1 || enc.key != cat->xor_key) {
                all20Match = false;
                break;
            }
        }
        CHECK(all20Match, "nrth_codec: all 20 encrypted signatures match nrth_audit_sigs.h (L=F-1)");
    }

    /* 4. Verify NrthFindHiddenSignatures discovers all 20 encrypted signatures in .rdata */
    {
        uint8_t rdata[0x2000];
        memset(rdata, 0, sizeof(rdata));
        uint32_t off = 0;
        for (uint32_t i = 0; i < 20; ++i) {
            off = (off + 3u) & ~3u; /* 4-byte align */
            memcpy(rdata + off, kNrthEncryptedSigs[i].cipher, kNrthEncryptedSigs[i].fieldSize);
            off += kNrthEncryptedSigs[i].fieldSize + 4u;
        }
        uint8_t peImg[0x4400];
        BuildSyntheticPe32(peImg, sizeof(peImg), NULL, 0, rdata, sizeof(rdata));
        char foundText[8192] = {0};
        uint32_t foundVas[32] = {0};
        int32_t nHidden = NrthFindHiddenSignatures(peImg, sizeof(peImg), 20,
                                                   foundText, sizeof(foundText), foundVas, 32);
        CHECK(nHidden == 20, "NrthFindHiddenSignatures discovers all 20 XOR-encrypted signatures in .rdata");
    }

    /* 5. Verify nrth_config.cpp: C:\Overwack\loader_config.cfg, menu_key=%d (45), no_spoofer=%d */
    {
        CHECK(strcmp(NrthConfig_GetPrimaryPath(), "C:\\Overwack\\loader_config.cfg") == 0 &&
              strcmp(NrthConfig_GetMenuKeyFmt(), " menu_key=%d") == 0 &&
              strcmp(NrthConfig_GetNoSpooferFmt(), " no_spoofer=%d") == 0,
              "nrth_config: decrypted path & format tokens (0x1001fcff, 0x1001fd7b, 0x1001fdc5)");

        g_cfg.menuKey   = 45;
        g_cfg.noSpoofer = 1;
        const char *tmpCfg = "/tmp/test_loader_config.cfg";
        const char *tmpOvr = "/tmp/test_profile.ovr";
        bool saved = NrthConfig_SaveOvr(tmpOvr, tmpCfg);
        g_cfg.menuKey   = 0;
        g_cfg.noSpoofer = 0;
        bool loaded = NrthConfig_Load(tmpCfg);
        CHECK(saved && loaded && g_cfg.menuKey == 45 && g_cfg.noSpoofer == 1,
              "nrth_config: round-trip SaveOvr/Load preserves menu_key=45 (VK_INSERT) & no_spoofer=1");
        remove(tmpCfg);
        remove(tmpOvr);
        remove("loader_config.cfg");
    }

    /* 6. Verify D3D9 vtable pattern scanner (VA 0x10012980: C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86) */
    {
        uint8_t fakeD3D9[256];
        memset(fakeD3D9, 0x90, sizeof(fakeD3D9));
        uint8_t seq[] = {
            0xC7, 0x06, 0x78, 0x56, 0x34, 0x12, /* mov dword ptr [esi], 0x12345678 */
            0x89, 0x86, 0x10, 0x00, 0x00, 0x00, /* mov [esi+10h], eax              */
            0x89, 0x86                          /* mov [esi+...], eax              */
        };
        memcpy(fakeD3D9 + 64, seq, sizeof(seq));
        void **vt = FindD3D9VTableInBuffer_10012980(fakeD3D9, sizeof(fakeD3D9));
        CHECK((uintptr_t)vt == 0x12345678u,
              "GetD3D9DeviceVTable (0x10012980): pattern scan extracts vtable pointer 0x12345678");
    }

    /* 7. Verify 37 pattern scans, 18 hooks, 6 0xC3 patches, and A/B audit detection */
    {
        Nrth_ResetArmingCounters();

        uint32_t nClientHooks = 0, nNetcHooks = 0, nPatches = 0;
        const NrthHookSlot    *clientHooks = Nrth_GetClientHookTable(&nClientHooks);
        const NrthHookSlot    *netcHooks   = Nrth_GetNetcHookTable(&nNetcHooks);
        const NrthPatchRecord *patches     = Nrth_GetPatchList_101493e4(&nPatches);

        CHECK(nClientHooks == 11 && nNetcHooks == 4 && nPatches == 6,
              "table sizes: 11 client hooks (0x10005b80), 4 netc hooks (0x10020640), 6 patches (0x101493e4)");

        /* Verify all 6 prepare/call pairs have exact 11-byte delta and pattern VAs 0x10023670..0x10023030 */
        bool pairsOk = true;
        for (uint32_t i = 0; i < 6; ++i) {
            if ((patches[i].callVa - patches[i].prepVa) != 11u ||
                patches[i].patternGlobal != (0x10023670u - i * 0x140u) ||
                patches[i].patchByte != 0xC3u) {
                pairsOk = false;
                break;
            }
        }
        CHECK(pairsOk, "6 prepare/write pairs: callVa - prepVa == 11, patterns 0x10023670..0x10023030, byte 0xC3");

        /* Build synthetic client.dll and netc.dll PE32 images containing all 20 catalog signatures
         * plus the additional patterns so all 37 scans resolve and patch/detour cleanly. */
        uint8_t clientText[0x2000];
        memset(clientText, 0xCC, sizeof(clientText));
        uint32_t cur = 0x40;
        for (uint32_t i = 1; i <= 20; ++i) {
            const NrthSignature *s = NrthSigAt(i);
            cur += MaterializePattern(s->pattern, clientText + cur, 256) + 0x20;
        }
        for (uint32_t i = 0; i < nClientHooks; ++i) {
            if (clientHooks[i].pattern) {
                cur += MaterializePattern(clientHooks[i].pattern, clientText + cur, 256) + 0x20;
            }
        }
        static const char *const kExtraC400[8] = {
            "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8 ? ? ? ? 8B C8",
            "55 8B EC 57 8B 7D ? 8B 4F ? 8B 41 ? 3B 41 ? 72 ? 57 E8 ? ? ? ? 83 C4 ? 56 FF 75 ? 8B 77 ? FF 75 ? 57 E8 ? ? ? ? ? ? 83 C4 ? C7 46 ? ? ? ? ? 8B 4F ? 8B 47 ? 5E 3B 41 ? 72 ? C7 05 ? ? ? ? ? ? ? ? 83 47 ? ? 5F 5D C3 ? ? ? ? ? ? ? ? ? ? ? ? 55 8B EC 8B 4D",
            "55 8B EC 56 57 FF 75 ? 8B 7D",
            "55 8B EC 83 EC ? 56 8B 75 ? 57 FF 75",
            "55 8B EC 8B 55 ? 8B 42 ? C7 40",
            "55 8B EC 57 FF 75 ? 8B 7D ? 57 E8 ? ? ? ? 83 C4 ? 83 78",
            "55 8B EC 53 57 8B 7D ? 8B 47 ? 2B 47 ? 83 E0 ? 83 F8 ? 7D ? C7 05 ? ? ? ? ? ? ? ? FF 75 ? 57 E8 ? ? ? ? 8B D8 83 C4 ? 83 7B ? ? 74 ? C7 05 ? ? ? ? ? ? ? ? 56 FF 75",
            "55 8B EC 8B 55 ? F2 0F 10 45"
        };
        uintptr_t expectedCreatetableOff = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            if (i == 1) {
                expectedCreatetableOff = cur;
            }
            cur += MaterializePattern(kExtraC400[i], clientText + cur, 256) + 0x20;
        }

        uint8_t cleanClientPe[0x4400], armedClientPe[0x4400];
        BuildSyntheticPe32(cleanClientPe, sizeof(cleanClientPe), clientText, sizeof(clientText), NULL, 0);
        memcpy(armedClientPe, cleanClientPe, sizeof(armedClientPe));

        uint8_t netcText[0x2000];
        memset(netcText, 0xCC, sizeof(netcText));
        uint32_t ncur = 0x40;
        ncur += MaterializePattern(NrthSigAt(16)->pattern, netcText + ncur, 256) + 0x20;
        for (uint32_t i = 1; i < nNetcHooks; ++i) {
            ncur += MaterializePattern(netcHooks[i].pattern, netcText + ncur, 256) + 0x20;
        }
        ncur += MaterializePattern("55 8B EC 83 EC ? 56 8B 75 ? 83 7E ? 00 75 ?", netcText + ncur, 256) + 0x20;
        ncur += MaterializePattern("55 8B EC 56 8B 75 ? 57 8B 7D ? 8B C6 2B C7",   netcText + ncur, 256) + 0x20;

        uint8_t cleanNetcPe[0x4400], armedNetcPe[0x4400];
        BuildSyntheticPe32(cleanNetcPe, sizeof(cleanNetcPe), netcText, sizeof(netcText), NULL, 0);
        memcpy(armedNetcPe, cleanNetcPe, sizeof(armedNetcPe));

        /* Execute the 3 arming/resolver blocks on the .text section of armedClientPe and armedNetcPe */
        uint32_t cHooked   = ArmClient_10005b80(armedClientPe + 0x400, 0x2000, true);
        uint32_t cResolved = ResolveClientOffsets_1000c390(armedClientPe + 0x400, 0x2000);
        uint32_t nActions  = ArmNetc_10020640(armedNetcPe + 0x400, 0x2000, true, true);
        uint32_t nResCount = 0;
        const uintptr_t *resOffs = Nrth_GetClientResolvedOffsets(&nResCount);

        CHECK(cHooked == 11 && cResolved == 20 && nActions == 10 &&
              resOffs[4] == (uintptr_t)(armedClientPe + 0x400 + expectedCreatetableOff) &&
              resOffs[4] != resOffs[6],
              "ArmClient_10005b80 (11 hooks), ResolveClientOffsets_1000c390 (20/20 ordered scans, lua_createtable != Sig #9), ArmNetc_10020640 (4 hooks + 6 patches)");
        CHECK(Nrth_GetTotalPatternScans() == 37,
              "Total pattern scans across 0x10005b80 (11) + 0x1000c390 (20) + 0x10020640 (6) == 37");
        CHECK(Nrth_GetTotalInstalledHooks() == 15 && (Nrth_GetTotalInstalledHooks() + 3) == 18,
              "Total hooks: 11 client + 4 netc (+ 1 LdrLoadDll + 2 D3D9) == 18");
        CHECK(Nrth_GetTotalAppliedPatches() == 6,
              "Total 0xC3 patches applied via PatchByte_10011870 == 6");

        /* Verify NrthAuditDiff detects the 7 client.dll DETOUR_JMP32 footprints and 1 netc.dll KILL_RET footprint */
        NrthAuditDiffRow diffClient[NRTH_SIG_COUNT];
        int32_t clientAlerts = NrthAuditDiff(cleanClientPe, sizeof(cleanClientPe),
                                             armedClientPe, sizeof(armedClientPe),
                                             diffClient, NRTH_SIG_COUNT);
        NrthAuditDiffRow diffNetc[NRTH_SIG_COUNT];
        int32_t netcAlerts = NrthAuditDiff(cleanNetcPe, sizeof(cleanNetcPe),
                                           armedNetcPe, sizeof(armedNetcPe),
                                           diffNetc, NRTH_SIG_COUNT);
        CHECK(clientAlerts == 7 && netcAlerts == 1 && diffNetc[15].susState == NRTH_PRO_KILL_RET,
              "NrthAuditDiff A/B verification: 7 DETOUR_JMP32 alerts on client.dll + 1 KILL_RET (0xC3) alert on netc.dll");
    }

    /* 8. Verify Packet Catalogue, Report Channels, Sync Structs, and Lua VM Bridge */
    {
        uint32_t pktCount = 0;
        const NrthPacketDef *pkts = NrthUI_GetPacketCatalog(&pktCount);
        bool foundChallenge = false;
        int reportChannels = 0;
        for (uint32_t i = 0; i < pktCount; ++i) {
            if (strcmp(pkts[i].name, "PACKET_ID_CHEAT_CHALLENGEMEMORY") == 0) {
                foundChallenge = true;
            }
            if (pkts[i].isReportChannel) {
                ++reportChannels;
            }
        }
        CHECK(pktCount >= 70 && foundChallenge && reportChannels == 4,
              "Packet catalog: PACKET_ID_CHEAT_CHALLENGEMEMORY + 4 report channels (SCREENSHOT/DIAGNOSTIC/ACINFO/TRANSGRESSION)");

        NrthUI_SyncFeaturesToState();
        CHECK(Nrth_GetPlayerHealthSync()->fHealth == 100.0f &&
              Nrth_GetWeaponAimSync()->fClickWarpMaxDist == 300.0f,
              "Feature state sync: SPlayerHealthSync & SWeaponAimSync initialized and synced");

        /* Exercise in-game feature tick & GTA:SA/MTA action helpers */
        Nrth_TickGameFeatures_10015812();
        Nrth_AirbreakTick_10001d80();
        Nrth_TriggerAllWeapons_1002a5a7();
        Nrth_TriggerJetpack_1002a86c();
        bool vehAct = Nrth_RepairCurrentVehicle_1002f070() ||
                      Nrth_StartCurrentVehicleEngine_1002f0f0() ||
                      Nrth_UnlockNearestVehicle_1002eea0() ||
                      Nrth_StopCurrentVehicle() ||
                      Nrth_DestroyCurrentVehicle();
        CHECK(!vehAct && Nrth_GetPlayerHealthSync()->bVehGodMode == 0 &&
              Nrth_GetPlayerHealthSync()->bDriveWater == 0 &&
              Nrth_GetPlayerHealthSync()->bFlyingCar == 0,
              "In-game feature tick (0x10015812) & GTA:SA/MTA action helpers (0x10001d80..0x1002f0f0) guarded safely");

        /* Live hook callbacks (0x10004220, 0x100050a0, 0x100052b0, 0x100054a0, 0x1001da80) */
        NrthUI_OnClientScriptLoaded("@:hud/client.lua", "outputChatBox('hi')", 19);
        NrthUI_OnResourceStarted("hud");
        bool stopResOk = Nrth_StopClientResource_100054a0("hud");
        bool evNotBlocked = !NrthUI_ShouldBlockServerEvent("onPlayerJoin");
        bool pktReportBlocked = NrthUI_OnPacketSent(80); /* PACKET_ID_PLAYER_SCREENSHOT blocked by default */
        bool pktNormalAllowed = !NrthUI_OnPacketSent(37); /* PACKET_ID_COMMAND allowed by default */
        CHECK(stopResOk && evNotBlocked && pktReportBlocked && pktNormalAllowed,
              "Live hook callbacks: script dumper (0x10004220), resource stop (0x100054a0), event filter (0x100050a0), packet filter (0x1001da80)");

        NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
        uint32_t dummyState = 0xCAFEBABEu;
        bridge->default_L_1013c95c  = &dummyState;
        bridge->loadbuffer_1013c94c = MockLuaLoadBuffer;
        bridge->pcall_1013c974      = MockLuaPcall;
        bool luaOk = NrthUI_ExecuteLuaViaBridge("print('hello')", 14, 0);
        CHECK(luaOk && s_mockLuaLoadCalled == 1 && s_mockLuaPcallCalled == 1 &&
              s_mockLuaLastChunk == "@custom" && bridge->execFlag_1013c939 == 0,
              "Lua VM bridge (0x1013bf04 / 0x1013c95c): executes via loadbuffer_1013c94c with '@custom' + pcall_1013c974");
    }

    /* 9. Verify built PE32 x86 binaries on disk (bin/NRTH.dll, bin/NORTH LOADER.exe, bin/NRTH_audit.dll) */
    {
        FILE *fDll = fopen("bin/NRTH.dll", "rb");
        FILE *fExe = fopen("bin/NORTH LOADER.exe", "rb");
        FILE *fAud = fopen("bin/NRTH_audit.dll", "rb");
        CHECK(fDll != NULL && fExe != NULL && fAud != NULL,
              "built binaries exist: bin/NRTH.dll, bin/NORTH LOADER.exe, bin/NRTH_audit.dll");
        if (fDll && fExe && fAud) {
            fseek(fDll, 0, SEEK_END);
            uint32_t dllSz = (uint32_t)ftell(fDll);
            rewind(fDll);
            uint8_t *dllBuf = (uint8_t *)malloc(dllSz);
            fread(dllBuf, 1, dllSz, fDll);

            fseek(fExe, 0, SEEK_END);
            uint32_t exeSz = (uint32_t)ftell(fExe);
            rewind(fExe);
            uint8_t *exeBuf = (uint8_t *)malloc(exeSz);
            fread(exeBuf, 1, exeSz, fExe);

            NrthPeView peDll, peExe;
            int rcDll = NrthPeMap(dllBuf, dllSz, &peDll);
            int rcExe = NrthPeMap(exeBuf, exeSz, &peExe);
            CHECK(rcDll == NVXA_OK && peDll.machine == 0x014Cu && peDll.imageBase == 0x10000000u &&
                  rcExe == NVXA_OK && peExe.machine == 0x014Cu && peExe.imageBase == 0x00400000u,
                  "PE32 x86 verification: bin/NRTH.dll (0x014C, base 0x10000000) & bin/NORTH LOADER.exe (0x014C, base 0x00400000)");

            char hidText[8192] = {0};
            uint32_t hidVas[32] = {0};
            int32_t nHid = NrthFindHiddenSignatures(dllBuf, dllSz, 20, hidText, sizeof(hidText), hidVas, 32);
            CHECK(nHid == 20, "bin/NRTH.dll: NrthFindHiddenSignatures recovers all 20 hidden signatures from built DLL");

            /* Verify NVXHookProc export RVA in bin/NRTH.dll matches original NRTH.dll (0x0000B9E0) */
            uint32_t e_lfanew = *(const uint32_t *)(dllBuf + 0x3C);
            uint32_t expRva   = *(const uint32_t *)(dllBuf + e_lfanew + 0x78);
            const uint8_t *expPtr = NrthPeRvaToPtr(&peDll, expRva, 0x28);
            uint32_t eatRva   = expPtr ? *(const uint32_t *)(expPtr + 0x1C) : 0;
            const uint8_t *eatPtr = eatRva ? NrthPeRvaToPtr(&peDll, eatRva, 4) : NULL;
            uint32_t hookProcRva = eatPtr ? *(const uint32_t *)eatPtr : 0;
            CHECK(hookProcRva == 0x0000B9E0u, "bin/NRTH.dll: Export NVXHookProc at exact RVA 0x0000B9E0 (matches original NRTH.dll)");

            free(dllBuf);
            free(exeBuf);
        }
        if (fDll) fclose(fDll);
        if (fExe) fclose(fExe);
        if (fAud) fclose(fAud);
    }

    /* 10. Verify the merged DARKANARCHY design: embedded assets, Arabic
     * shaper/BiDi engine (nrth_arabic.h), shaper->font coverage closure, and
     * headless full-UI frame renders (NRTH_UI_HEADLESS) */
    {
        /* 10a. Embedded TTF payloads are valid TrueType fonts */
        CHECK(sizeof(kDarkAnarchyEnglishTtf) == 78604u &&
              kDarkAnarchyEnglishTtf[0] == 0x00 && kDarkAnarchyEnglishTtf[1] == 0x01 &&
              kDarkAnarchyEnglishTtf[2] == 0x00 && kDarkAnarchyEnglishTtf[3] == 0x00,
              "nrth_assets: kDarkAnarchyEnglishTtf (78,604 B) has TTF magic");
        CHECK(sizeof(kDarkAnarchyArabicTtf) == 58876u &&
              kDarkAnarchyArabicTtf[0] == 0x00 && kDarkAnarchyArabicTtf[1] == 0x01 &&
              kDarkAnarchyArabicTtf[2] == 0x00 && kDarkAnarchyArabicTtf[3] == 0x00,
              "nrth_assets: kDarkAnarchyArabicTtf (58,876 B) has TTF magic");

        /* 10b. QOI texture assets: magic + declared dimensions */
        {
            auto qoiDims = [](const unsigned char *d, size_t sz, uint32_t *w, uint32_t *h) {
                if (sz < 22 || d[0] != 'q' || d[1] != 'o' || d[2] != 'i' || d[3] != 'f')
                    return false;
                *w = ((uint32_t)d[4] << 24) | ((uint32_t)d[5] << 16) | ((uint32_t)d[6] << 8) | d[7];
                *h = ((uint32_t)d[8] << 24) | ((uint32_t)d[9] << 16) | ((uint32_t)d[10] << 8) | d[11];
                return d[12] == 3 || d[12] == 4; /* channels */
            };
            uint32_t w = 0, h = 0;
            CHECK(qoiDims(kDarkAnarchyLogoQoi, sizeof(kDarkAnarchyLogoQoi), &w, &h) &&
                  w == (uint32_t)DARKANARCHY_LOGO_WIDTH && h == (uint32_t)DARKANARCHY_LOGO_HEIGHT,
                  "nrth_assets: logo QOI valid, 320x180 RGB");
            CHECK(qoiDims(kDarkAnarchyBgQoi, sizeof(kDarkAnarchyBgQoi), &w, &h) &&
                  w == (uint32_t)DARKANARCHY_BG_WIDTH && h == (uint32_t)DARKANARCHY_BG_HEIGHT,
                  "nrth_assets: background QOI valid, 480x270 RGB");
        }

        /* 10c. Contextual shaping + lam-alef ligatures + BiDi visual order via
         * Nrth_ShapeArabicUTF8 (expected outputs derived from the standard
         * Arabic Presentation Forms-B algorithm, verified independently) */
        {
            auto utf8Of = [](std::initializer_list<uint32_t> cps) {
                std::string s;
                for (uint32_t cp : cps) {
                    if (cp < 0x80) s += (char)cp;
                    else if (cp < 0x800) { s += (char)(0xC0 | (cp >> 6)); s += (char)(0x80 | (cp & 0x3F)); }
                    else { s += (char)(0xE0 | (cp >> 12)); s += (char)(0x80 | ((cp >> 6) & 0x3F)); s += (char)(0x80 | (cp & 0x3F)); }
                }
                return s;
            };
            CHECK(Nrth_ShapeArabicUTF8("\xD8\xB3\xD9\x84\xD8\xA7\xD9\x85") == utf8Of({0xFEE1, 0xFEFC, 0xFEB3}),
                  "shaper: salam -> visual FEE1 FEFC FEB3 (lam-alef + seen initial)");
            CHECK(Nrth_ShapeArabicUTF8("\xD9\x84\xD8\xA7") == utf8Of({0xFEFB}),
                  "shaper: lam-alef isolated -> FEFB");
            CHECK(Nrth_ShapeArabicUTF8("\xD9\x85\xD9\x84\xD8\xA7") == utf8Of({0xFEFC, 0xFEE3}),
                  "shaper: meem+lam-alef -> visual FEFC FEE3");
            CHECK(Nrth_ShapeArabicUTF8("\xD8\xA3\xD8\xA8") == utf8Of({0xFE8F, 0xFE83}),
                  "shaper: alef-hamza+beh (right-joining) -> visual FE8F FE83");
            CHECK(Nrth_ShapeArabicUTF8("\xD8\xA8\xD8\xA8") == utf8Of({0xFE90, 0xFE91}),
                  "shaper: beh+beh -> visual FE90 FE91 (initial + final)");
            CHECK(Nrth_ShapeArabicUTF8("DARKANARCHY 123") == "DARKANARCHY 123",
                  "shaper: pure ASCII passes through unchanged");
            CHECK(Nrth_ShapeArabicUTF8("\xD9\x85\xD8\xB1\xD8\xAD\xD8\xA8\xD8\xA7##tab1") ==
                                      utf8Of({0xFE8E, 0xFE92, 0xFEA3, 0xFEAE, 0xFEE3}) + "##tab1",
                  "shaper: ImGui ##id suffix preserved untouched");
            CHECK(Nrth_ShapeArabicUTF8("\xD8\xB4\xD8\xAC\xD8\xB1\xD8\xA9 abc") ==
                                      "abc " + utf8Of({0xFE93, 0xFEAE, 0xFEA0, 0xFEB7}),
                  "shaper/BiDi: mixed line -> Latin run first, Arabic run reversed");
        }

        /* 10d. Coverage closure: EVERY presentation form the shaper can emit
         * exists in the embedded Arabic font cmap (format 4 + 12 parser) */
        {
            /* --- minimal TTF cmap parser --- */
            auto rd16 = [](const unsigned char *d, size_t o) -> int {
                return (int)((unsigned)d[o] << 8 | d[o + 1]); };
            auto ru16 = [](const unsigned char *d, size_t o) -> unsigned {
                return (unsigned)d[o] << 8 | d[o + 1]; };
            auto ru32 = [](const unsigned char *d, size_t o) -> uint32_t {
                return ((uint32_t)d[o] << 24) | ((uint32_t)d[o+1] << 16) |
                       ((uint32_t)d[o+2] << 8) | d[o+3]; };
            const unsigned char *d = kDarkAnarchyArabicTtf;
            const size_t dlen = sizeof(kDarkAnarchyArabicTtf);
            bool hasAll = dlen > 1024;
            if (hasAll) {
                size_t cmapOff = 0;
                unsigned nTables = ru16(d, 4);
                for (unsigned i = 0; i < nTables; ++i) {
                    if (memcmp(d + 12 + i * 16, "cmap", 4) == 0) {
                        cmapOff = ru32(d, 12 + i * 16 + 8);
                        break;
                    }
                }
                hasAll = cmapOff != 0;
                if (hasAll) {
                    unsigned nSub = ru16(d, cmapOff + 2);
                    size_t sub = 0, sub12 = 0;
                    for (unsigned i = 0; i < nSub; ++i) {
                        /* encoding record: pid u16, eid u16, offset u32 (+4) */
                        size_t toff = cmapOff + ru32(d, cmapOff + 4 + i * 8 + 4);
                        unsigned fmt = ru16(d, toff);
                        if (fmt == 4 && !sub) sub = toff;
                        if (fmt == 12) sub12 = toff;
                    }
                    if (!sub && !sub12) hasAll = false;
                    auto inFont = [&](uint32_t c) -> bool {
                        if (sub12) {
                            uint32_t ng = ru32(d, sub12 + 12);
                            for (uint32_t g = 0; g < ng; ++g) {
                                uint32_t s = ru32(d, sub12 + 16 + g * 12);
                                uint32_t e = ru32(d, sub12 + 16 + g * 12 + 4);
                                if (c >= s && c <= e) return true;
                            }
                            return false;
                        }
                        /* format 4 with full glyph-id lookup (not just ranges) */
                        unsigned segX2 = ru16(d, sub + 6);
                        unsigned segs = segX2 / 2;
                        size_t endsO   = sub + 14;
                        size_t startsO = endsO + segX2 + 2;
                        size_t deltaO  = startsO + segX2;
                        size_t rosO    = deltaO + segX2;
                        for (unsigned sgi = 0; sgi < segs; ++sgi) {
                            unsigned e = ru16(d, endsO + sgi * 2);
                            unsigned s = ru16(d, startsO + sgi * 2);
                            if (c < s || c > e) continue;
                            int      delta = (int)(short)ru16(d, deltaO + sgi * 2);
                            unsigned ro    = ru16(d, rosO + sgi * 2);
                            unsigned glyph;
                            if (ro == 0) {
                                glyph = (unsigned)(c + delta) & 0xFFFFu;
                            } else {
                                size_t addr = rosO + sgi * 2 + ro + (c - s) * 2;
                                if (addr + 1 >= dlen) return false;
                                glyph = ru16(d, addr);
                                glyph = glyph ? ((unsigned)((int)glyph + delta) & 0xFFFFu) : 0u;
                            }
                            return glyph != 0;
                        }
                        return false;
                    };
                    /* every isolated/initial/medial/final form of all 37 letters */
                    for (const NrthArabicLetterMap &m : kNrthArabicLetters) {
                        const uint32_t forms[4] = { m.isolated, m.finalForm, m.initial, m.medial };
                        for (uint32_t f : forms) {
                            if (!inFont(f)) { hasAll = false; break; }
                        }
                        if (!hasAll) break;
                    }
                    /* lam-alef ligatures FEF5..FEFC (both joined variants) */
                    if (hasAll) {
                        for (uint32_t f = 0xFEF5; f <= 0xFEFC; ++f)
                            if (!inFont(f)) { hasAll = false; break; }
                    }
                }
            }
            CHECK(hasAll,
                  "coverage: Arabic font cmap contains every form the shaper emits (all letter forms + FEF5..FEFC)");
        }

        /* 10e. Feature state untouched by shaping calls */
        {
            (void)Nrth_ShapeArabicUTF8("\xD8\xAA\xD8\xB3\xD8\xAA \xD8\xA7\xD9\x84\xD9\x84\xD8\xBA\xD8\xA9");
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "Feature state intact after shaper calls");
        }

        /* 10f. Headless full-UI frame render (AR default + EN via test hook) */
#ifdef NRTH_UI_HEADLESS
        {
            ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.DisplaySize = ImVec2(880.0f, 570.0f);
            io.DeltaTime   = 1.0f / 60.0f;
            io.IniFilename = NULL;

            NrthUI_ApplyTheme();
            NrthUI_InitFonts();
            CHECK(io.Fonts->Fonts.size() >= 2 && io.Fonts->Build(),
                  "headless UI: font atlas builds with the embedded fonts");
            {
                bool arCov = false, enCov = false;
                for (ImFont *f : io.Fonts->Fonts) {
                    if (!f) continue;
                    if (f->IsGlyphInFont((ImWchar)0xFEB3) && f->IsGlyphInFont((ImWchar)0xFEFC)) arCov = true;
                    if (f->IsGlyphInFont((ImWchar)'D') && f->IsGlyphInFont((ImWchar)'3')) enCov = true;
                }
                CHECK(arCov, "headless UI: a baked font covers Arabic forms (FEB3/FEFC)");
                CHECK(enCov, "headless UI: a baked font covers Latin ('D'/'3')");
            }

            /* Arabic frame (s_lang == 0 is the shipped default) */
            NrthUI_TestSetLanguage(0);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            ImDrawData *dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "headless UI: Arabic frame produces draw data (>100 vtx)");

            /* English frame through the same live UI object */
            NrthUI_TestSetLanguage(1);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "headless UI: English frame produces draw data (>100 vtx)");
            NrthUI_TestSetLanguage(0);

            /* device-texture lifecycle must be NULL-safe headless */
            NrthUI_InitTextures(NULL);
            NrthUI_ReleaseTextures();
            CHECK(true, "headless UI: InitTextures(NULL)/ReleaseTextures no-crash");

            ImGui::DestroyContext();
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "Feature state intact after headless UI frames");
        }
#endif /* NRTH_UI_HEADLESS */
    }

    /* 11. SESSION LAB: in-game detection + stay-mode state (ped-deploy
     * feature was removed by design; server-visible bots live server-side) */
    {
        /* 11a. in-game detection reads the real client-game pointer */
        {
            CHECK(NrthHook_IsInGame() == 0, "session: not in game by default");
            void *saved = g_pClientGame_10148ee8;
            g_pClientGame_10148ee8 = (void *)&saved; /* simulate joining a server */
            CHECK(NrthHook_IsInGame() == 1, "session: IsInGame true when client-game ptr set");
            g_pClientGame_10148ee8 = saved;
            CHECK(NrthHook_IsInGame() == 0, "session: IsInGame false again after clear");
        }
        /* 11b. stay-mode state round-trips and leaves feature state intact */
        {
            NrthUI_SetStayMode(1);
            CHECK(NrthUI_IsStayModeOn() == 1, "session: stay mode round-trip");
            NrthUI_SetStayMode(0);
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "session: feature state intact after stay-mode changes");
        }
        /* 11c. read-only session probe chunk (runs via the Lua VM bridge) */
        {
            static char lua[2048];
            NrthUI_BuildSessionProbeLua(lua, sizeof(lua));
            CHECK(strstr(lua, "getLocalPlayer") != NULL &&
                  strstr(lua, "getPlayerSerial") != NULL &&
                  strstr(lua, "getPlayerPing") != NULL &&
                  strstr(lua, "#getElementsByType('player')") != NULL &&
                  strstr(lua, "outputChatBox") != NULL,
                  "session: probe chunk reads own nick/serial/ping/player-count");
            NrthUI_BuildSessionProbeLua(NULL, 0); /* must not crash */
            CHECK(1, "session: probe builder NULL/0-safe");
        }
        /* 11d. headless render of the Session Lab tab (AR default + EN) */
#ifdef NRTH_UI_HEADLESS
        {
            ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.DisplaySize = ImVec2(880.0f, 570.0f);
            io.DeltaTime   = 1.0f / 60.0f;
            io.IniFilename = NULL;
            NrthUI_ApplyTheme();
            NrthUI_InitFonts();
            CHECK(io.Fonts->Build(), "session UI: font atlas builds");

            NrthUI_TestSetTab(4); /* Session Lab */
            NrthUI_TestSetLanguage(0);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            ImDrawData *dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "session UI: Arabic Session frame renders (>100 vtx)");
            NrthUI_TestSetLanguage(1);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "session UI: English Session frame renders (>100 vtx)");
            NrthUI_TestSetLanguage(0);
            NrthUI_TestSetTab(0);
            ImGui::DestroyContext();
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "session UI: feature state intact after Session frames");
        }
#endif /* NRTH_UI_HEADLESS */
    }

    /* 12. CSX AUDIT: spoofer-analysis constants + pure audit helpers */
    {
        /* 12a. signature scanner detects CSX artifacts in a synthetic buffer */
        {
            const char *synthetic =
                "sample loader log: resetting MTA serial identity... "
                "payload csxcheat.dll mapped; dropped csxprobe.exe; "
                "beacon /api/heartbeat; req {\"type\":\"rename\",\"hwid\":\"\"}";
            const uint32_t f = NrthCsx_ScanSignatures((const uint8_t *)synthetic,
                                                      strlen(synthetic));
            CHECK((f & (1u << 0)) && (f & (1u << 1)) && (f & (1u << 4)) && (f & (1u << 5)),
                  "csx: scanner flags csxcheat.dll/csxprobe.exe/rename-JSON/reset-log");
            CHECK(NrthCsx_ScanSignatures((const uint8_t *)"nothing here", 12) == 0,
                  "csx: scanner reports zero on clean buffer");
            CHECK(NrthCsx_ScanSignatures(NULL, 0) == 0, "csx: scanner NULL-safe");
        }
        /* 12b. encrypted-container magic from the real binary is detectable */
        {
            const uint8_t container[] = {
                0x0E, 0x6F, 0xE8, 0x7E, 0x50, 0x74, 0x65, 0x61,
                0x68, 0x74, 0x68, 0x21, 0xCD, 0xCF, 0x32, 0x36
            };
            CHECK((NrthCsx_ScanSignatures(container, sizeof(container)) & (1u << 2)) != 0,
                  "csx: Ptea-hth RCDATA container magic flagged (blob 102/103 header)");
        }
        /* 12c. fingerprint JSON builder parity (audit-only shape) */
        {
            char js[512];
            const size_t n = NrthCsx_BuildFingerprintJson("AABBCCDD", "LAB-PC", "tester",
                                                          "1234ABCD", js, sizeof(js));
            CHECK(n > 0 && strstr(js, "\"hwid\":\"AABBCCDD\"") &&
                  strstr(js, "\"computer\":\"LAB-PC\"") &&
                  strstr(js, "\"user\":\"tester\"") &&
                  strstr(js, "\"disk\":\"1234ABCD\"") &&
                  strstr(js, "DARKANARCHY-audit"),
                  "csx: fingerprint JSON matches CSX shape (audit-labeled)");
            CHECK(NrthCsx_BuildFingerprintJson("x", "y", "z", "w", NULL, 0) == 0,
                  "csx: JSON builder NULL/0-safe");
        }
        /* 12d. dry-run spoof simulator: deterministic, distinct, pure */
        {
            char a[64], b[64], c[64];
            NrthCsx_SimulateSpoofId("9f3b1c2a-44d5", 7, a, sizeof(a));
            NrthCsx_SimulateSpoofId("9f3b1c2a-44d5", 7, b, sizeof(b));
            NrthCsx_SimulateSpoofId("9f3b1c2a-44d5", 8, c, sizeof(c));
            CHECK(a[0] && strcmp(a, b) == 0, "csx: simulator deterministic for (id,salt)");
            CHECK(strcmp(a, c) != 0, "csx: simulator changes with salt");
            CHECK(strcmp(a, "9f3b1c2a-44d5") != 0 && strncmp(a, "SIM-", 4) == 0,
                  "csx: simulator output distinct and SIM-prefixed");
            NrthCsx_SimulateSpoofId("", 1, c, sizeof(c));
            CHECK(c[0] == '\0', "csx: simulator empty-safe");
            NrthCsx_SimulateSpoofId("x", 1, NULL, 0);
            CHECK(1, "csx: simulator NULL/0-safe");
        }
        /* 12e. headless render of the CSX Audit tab (AR default + EN) */
#ifdef NRTH_UI_HEADLESS
        {
            ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.DisplaySize = ImVec2(880.0f, 570.0f);
            io.DeltaTime   = 1.0f / 60.0f;
            io.IniFilename = NULL;
            NrthUI_ApplyTheme();
            NrthUI_InitFonts();
            CHECK(io.Fonts->Build(), "csx UI: font atlas builds");

            NrthUI_TestSetTab(5); /* CSX Audit */
            NrthUI_TestSetLanguage(0);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            ImDrawData *dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "csx UI: Arabic CSX frame renders (>100 vtx)");
            NrthUI_TestSetLanguage(1);
            ImGui::NewFrame();
            NrthUI_RenderFrame(true);
            ImGui::Render();
            dd = ImGui::GetDrawData();
            CHECK(dd && dd->Valid && dd->TotalVtxCount > 100,
                  "csx UI: English CSX frame renders (>100 vtx)");
            NrthUI_TestSetLanguage(0);
            NrthUI_TestSetTab(0);
            ImGui::DestroyContext();
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "csx UI: feature state intact after CSX frames");
        }
#endif /* NRTH_UI_HEADLESS */
    }

    /* 13. CSX full-RE parity: recovered key, decryptor, payload signatures */
    {
        /* 13a. the recovered XOR-16 key is embedded in nrth_csx.h and matches
         * the known-plaintext derivation from the container header + DOS hdr */
        {
            static const uint8_t cont[16] = {
                0x0E,0x6F,0xE8,0x7E,0x50,0x74,0x65,0x61,
                0x68,0x74,0x68,0x21,0xCD,0xCF,0x32,0x36
            };
            static const uint8_t dos[16] = {
                0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
                0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00
            };
            uint8_t dec[16];
            memcpy(dec, cont, 16);
            NrthCsx_DecryptXor16(dec, 16);
            CHECK(memcmp(dec, dos, 16) == 0,
                  "csx-re: XOR16 decryptor turns the container header into a DOS header");
            CHECK(strcmp(NRTH_CSX_XOR_KEY, "C5x~Stealth!2026") == 0,
                  "csx-re: recovered key 'C5x~Stealth!2026' (VA 0x4463FC) embedded");
        }
        /* 13b. decryptor on a synthetic encrypted PE: MZ hidden then restored */
        {
            static const char *plain = "MZ\x90\x00 DARKANARCHY csx-re synthetic payload";
            uint8_t buf[64];
            const size_t n = strlen(plain);
            memcpy(buf, plain, n);
            NrthCsx_DecryptXor16(buf, n);   /* symmetric: encrypt */
            CHECK(!(buf[0] == 'M' && buf[1] == 'Z'), "csx-re: encrypted form hides MZ");
            NrthCsx_DecryptXor16(buf, n);   /* decrypt back */
            CHECK(memcmp(buf, plain, n) == 0, "csx-re: decryptor round-trips the payload");
        }
        /* 13c. decrypted-payload signature coverage in the scanner table */
        {
            const char *synthetic =
                "csxcheat.dll log: [SILENTAIM] SendBulletSyncFire hooked ; "
                "[ANTISCREEN] Server screenshot blocked! ; triggerbot "
                "[TRIGGER] Block list is full (64) ; discord scope_v3.json ; "
                "agent csxagent.pdb";
            const uint32_t f = NrthCsx_ScanSignatures((const uint8_t *)synthetic,
                                                      strlen(synthetic));
            CHECK((f & (1u << 0)) && (f & (1u << 7)) && (f & (1u << 8)) &&
                  (f & (1u << 9)) && (f & (1u << 10)) && (f & (1u << 11)),
                  "csx-re: scanner flags all decrypted-payload capability sigs");
            const uint32_t k = NrthCsx_ScanSignatures((const uint8_t *)"x C5x~Stealth!2026 y", 21);
            CHECK((k & (1u << 3)) != 0, "csx-re: embedded XOR key is itself detectable");
        }
        /* 13d. signature table size parity */
        CHECK(NRTH_CSX_SIG_COUNT == 13, "csx-re: signature table has 13 evidence sigs");
        /* 13e. differential A/B snapshot helpers (pure) */
        {
            NrthCsxSnapshot a, b;
            memset(&a, 0, sizeof(a));
            memset(&b, 0, sizeof(b));
            strncpy(a.machineGuid, "guid-1", sizeof(a.machineGuid) - 1);
            strncpy(b.machineGuid, "guid-1", sizeof(b.machineGuid) - 1);
            a.volSerial = 0x11223344;
            b.volSerial = 0x11223344;
            a.flags = 0;
            b.flags = 0;
            CHECK(!NrthCsx_SnapIdentityChanged(&a, &b) &&
                  NrthCsx_SnapNewArtifacts(&a, &b) == 0,
                  "csx-ab: identical snapshots -> no change, no new artifacts");
            strncpy(b.machineGuid, "guid-2", sizeof(b.machineGuid) - 1);
            b.volSerial = 0xAABBCCDD;
            CHECK(NrthCsx_SnapIdentityChanged(&a, &b),
                  "csx-ab: MachineGuid/volume change is flagged as identity change");
            b.machineGuid[0] = 'g'; /* restore guid, keep vol change covered above */
            strncpy(b.machineGuid, "guid-1", sizeof(b.machineGuid) - 1);
            b.volSerial = 0x11223344;
            b.flags = NRTH_CSX_F_CLSID2 | NRTH_CSX_F_PROBE;
            CHECK(NrthCsx_SnapNewArtifacts(&a, &b) == (NRTH_CSX_F_CLSID2 | NRTH_CSX_F_PROBE),
                  "csx-ab: new CLSID2+probe artifacts detected in B");
            CHECK(!NrthCsx_SnapIdentityChanged(&a, &b),
                  "csx-ab: artifact-only change is not reported as identity change");
            CHECK(!NrthCsx_SnapIdentityChanged(NULL, &b) &&
                  NrthCsx_SnapNewArtifacts(NULL, &b) == 0,
                  "csx-ab: helpers NULL-safe");
        }
    }

    printf("---------------------------------------------------\n");
    printf("Summary: %d passed, %d failed\n", g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
