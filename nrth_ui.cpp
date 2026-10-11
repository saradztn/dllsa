/**
 * ============================================================================
 * nrth_ui.cpp — UI, Packet Catalogue, Feature Sync & Lua VM Bridge (R2)
 * ============================================================================
 * Evidence sources (see analysis/strings_catalog.txt + runtime screenshot):
 *   - Window title "North Cheat"                         (VA 0x100ea0d8)
 *   - Top tabs  "%s##nvx_top_%d"  -> Scripts | Dumper | Cheat | Vehicle | Config
 *   - Scripts sub-tabs "%s##nvx_ssub_%d" -> Editor | Scripts | Resources |
 *             Events | Events Table | Packets   (off 0xe94a8-0xe94dc)
 *   - Cheat sub-tabs  "%s##nvx_csub_%d"  -> Player | Other | Markers (off 0xe94ec-0xe950c)
 *   - Editor: "##lua_editor", "Default VM" off 0xe9884, "@custom" off 0xe9890,
 *             "Execute" off 0xe9898, "Script executed" off 0xe98b8
 *   - Lua VM bridge: registry 0x1013bf04 (stride 0x1C, L at +0x18), default_L 0x1013c95c,
 *             loadbuffer 0x1013c94c (L, ..., "@custom"), pcall 0x1013c974,
 *             flag 0x1013c939, script buffer 0x1013beec, VirtualQuery guard.
 *   - Packets: full MTA PACKET_ID_* table (.rdata off 0xe9be4-0xeaaa4, including
 *             PACKET_ID_CHEAT_CHALLENGEMEMORY at VA 0x100eb6a8) and report channels
 *             PLAYER_SCREENSHOT, PLAYER_TRANSGRESSION, PLAYER_DIAGNOSTIC, PLAYER_ACINFO.
 *   - Feature sync: SPlayerHealthSync & SWeaponAimSync (RTTI in .data).
 *   - Config: C:\Overwack\loader_config.cfg (" no_spoofer=%d", " menu_key=%d") + .ovr ("OVRCFG").
 * ============================================================================
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_hook.h"
#include "nrth_ui.h"
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
#include "nrth_vehicle_names.inc"
#endif

/* ===========================================================================
 * MTA PACKET_ID_* catalogue (.rdata 0x100e9be4..0x100eaaa4 & 0x100eb6a8)
 * Includes PACKET_ID_CHEAT_CHALLENGEMEMORY (VA 0x100eb6a8) and the 4 report
 * channels PLAYER_SCREENSHOT, PLAYER_TRANSGRESSION, PLAYER_DIAGNOSTIC, PLAYER_ACINFO.
 * =========================================================================== */
static const NrthPacketDef kMtaPacketCatalog[] = {
    {   0, "PACKET_ID_SERVER_JOIN",                 false },
    {   1, "PACKET_ID_SERVER_JOIN_DATA",            false },
    {   2, "PACKET_ID_SERVER_JOIN_COMPLETE",        false },
    {   3, "PACKET_ID_PLAYER_JOIN",                 false },
    {   4, "PACKET_ID_PLAYER_JOINDATA",             false },
    {   5, "PACKET_ID_PLAYER_QUIT",                 false },
    {   6, "PACKET_ID_PLAYER_TIMEOUT",              false },
    {   7, "PACKET_ID_MOD_NAME",                    false },
    {   8, "PACKET_ID_PACKET_PROGRESS",             false },
    {   9, "PACKET_ID_MTA_RESERVED_03",             false },
    {  10, "PACKET_ID_MTA_RESERVED_04",             false },
    {  11, "PACKET_ID_GAME_STARTED",                false },
    {  12, "PACKET_ID_ GHOST_SYNC",                 false },
    {  19, "PACKET_ID_PLAYER_LIST",                 false },
    {  20, "PACKET_ID_PLAYER_SPAWN",                false },
    {  21, "PACKET_ID_PLAYER_WASTED",               false },
    {  22, "PACKET_ID_PLAYER_CHANGE_NICK",          false },
    {  23, "PACKET_ID_PLAYER_STATS",                false },
    {  24, "PACKET_ID_PLAYER_CLOTHES",              false },
    {  25, "PACKET_ID_PLAYER_KEYSYNC",              false },
    {  26, "PACKET_ID_PLAYER_PURESYNC",             false },
    {  27, "PACKET_ID_PLAYER_VEHICLE_PURESYNC",     false },
    {  28, "PACKET_ID_LIGHTSYNC",                   false },
    {  29, "PACKET_ID_VEHICLE_RESYNC",              false },
    {  30, "PACKET_ID_RETURN_SYNC",                 false },
    {  31, "PACKET_ID_EXPLOSION",                   false },
    {  32, "PACKET_ID_FIRE",                        false },
    {  33, "PACKET_ID_PROJECTILE",                  false },
    {  34, "PACKET_ID_DETONATE_SATCHELS",           false },
    {  35, "PACKET_ID_DESTROY_SATCHELS",            false },
    {  36, "PACKET_ID_COMMAND",                     false },
    {  37, "PACKET_ID_CHAT_ECHO",                   false },
    {  38, "PACKET_ID_CONSOLE_ECHO",                false },
    {  39, "PACKET_ID_DEBUG_ECHO",                  false },
    {  40, "PACKET_ID_MAP_INFO",                    false },
    {  41, "PACKET_ID_MAP_START",                   false },
    {  42, "PACKET_ID_MAP_RESTART",                 false },
    {  43, "PACKET_ID_MAP_STOP",                    false },
    {  44, "PACKET_ID_ENTITY_ADD",                  false },
    {  45, "PACKET_ID_ENTITY_REMOVE",               false },
    {  46, "PACKET_ID_PICKUP_HIDESHOW",             false },
    {  47, "PACKET_ID_PICKUP_HIT_CONFIRM",          false },
    {  48, "PACKET_ID_UNOCCUPIED_VEHICLE_STARTSYNC",false },
    {  49, "PACKET_ID_UNOCCUPIED_VEHICLE_STOPSYNC", false },
    {  50, "PACKET_ID_UNOCCUPIED_VEHICLE_SYNC",     false },
    {  51, "PACKET_ID_PED_STARTSYNC",               false },
    {  52, "PACKET_ID_PED_STOPSYNC",                false },
    {  53, "PACKET_ID_PED_SYNC",                    false },
    {  54, "PACKET_ID_CAMERA_SYNC",                 false },
    {  55, "PACKET_ID_OBJECT_STARTSYNC",            false },
    {  56, "PACKET_ID_OBJECT_STOPSYNC",             false },
    {  57, "PACKET_ID_OBJECT_SYNC",                 false },
    {  58, "PACKET_ID_LUA",                         false },
    {  59, "PACKET_ID_LUA_ELEMENT_RPC",             false },
    {  60, "PACKET_ID_TEXT_ITEM",                   false },
    {  61, "PACKET_ID_SCOREBOARD",                  false },
    {  62, "PACKET_ID_TEAMS",                       false },
    {  63, "PACKET_ID_LUA_EVENT",                   false },
    {  64, "PACKET_ID_RESOURCE_START",              false },
    {  65, "PACKET_ID_RESOURCE_STOP",               false },
    {  66, "PACKET_ID_CUSTOM_DATA",                 false },
    {  67, "PACKET_ID_VOICE_DATA",                  false },
    {  68, "PACKET_ID_VOICE_END",                   false },
    {  69, "PACKET_ID_CHEAT_CHALLENGEMEMORY",       false }, /* VA 0x100eb6a8 */
    {  70, "PACKET_ID_CHEAT_RETURN",                false },
    {  71, "PACKET_ID_MAP_LIST",                    false },
    {  72, "PACKET_ID_LUA_TIMERS",                  false },
    {  73, "PACKET_ID_LATENT_TRANSFER",             false },
    {  74, "PACKET_ID_PLAYER_BULLETSYNC",           false },
    {  75, "PACKET_ID_SYNC_SETTINGS",               false },
    {  76, "PACKET_ID_WEAPON_BULLETSYNC",           false },
    {  77, "PACKET_ID_PED_TASK",                    false },
    {  78, "PACKET_ID_PLAYER_NO_SOCKET",            false },
    {  79, "PACKET_ID_PLAYER_NETWORK_STATUS",       false },
    {  80, "PACKET_ID_PLAYER_SCREENSHOT",           true  }, /* Report channel #1 */
    {  81, "PACKET_ID_PLAYER_DIAGNOSTIC",           true  }, /* Report channel #2 */
    {  82, "PACKET_ID_PLAYER_ACINFO",               true  }, /* Report channel #3 */
    {  83, "PACKET_ID_PLAYER_TRANSGRESSION",        true  }, /* Report channel #4 */
    {  84, "PACKET_ID_RESEND_REQUEST",              false },
};

extern "C" const NrthPacketDef *NrthUI_GetPacketCatalog(uint32_t *outCount)
{
    if (outCount) {
        *outCount = (uint32_t)(sizeof(kMtaPacketCatalog) / sizeof(kMtaPacketCatalog[0]));
    }
    return kMtaPacketCatalog;
}

/* ===========================================================================
 * Feature state & sliders (shared between UI and SPlayerHealthSync/SWeaponAimSync)
 * =========================================================================== */
struct Feature { const char *label; const char *settings; bool on; int key; int mode; };
static Feature s_cheatFeatures[] = {
    {"GodMode",        "GodMode Settings",        false, 0, 1},
    {"Give HP",        "Give HP Settings",        false, 0, 1},
    {"Give Armor",     "Give Armor Settings",     false, 0, 1},
    {"Infinite Ammo",  "Infinite Ammo Settings",  false, 0, 1},
    {"Anti-Spread",    "Anti-Spread Settings",    false, 0, 1},
    {"Anti-ScreenShot","Anti-ScreenShot Settings",false, 0, 1},
    {"Crasher",        "Crasher Settings",        false, 0, 1},
    {"Anti-AFK",       "Anti-AFK Settings",       false, 0, 1},
    {"AirBreak",       "AirBreak Settings",       false, 0, 1},
    {"Click Warp",     "Click Warp Settings",     false, 0, 1},
    {"High Jump",      "High Jump Settings",      false, 0, 1},
    {"Money Exploit",  "Money Exploit Settings",  false, 0, 1},
    {"Jetpack",        "Jetpack Settings",        false, 0, 1},
    {"All Weapons",    "All Weapons Settings",    false, 0, 1},
};

static Feature s_vehicleFeatures[] = {
    {"Vehicle GodMode", "Vehicle GodMode Settings", false, 0, 1},
    {"Vehicle Chaos",   "Vehicle Chaos Settings",   false, 0, 1},
    {"Drive Water",     "Drive Water Settings",     false, 0, 1},
    {"Fast Stop",       "Fast Stop Settings",       false, 0, 1},
    {"Fall Bike",       "Fall Bike Settings",       false, 0, 1},
    {"Flying Car",      "Flying Car Settings",      false, 0, 1},
    {"Start Engine",    "Start Engine Settings",    false, 0, 1},
    {"Repair Car",      "Repair Car Settings",      false, 0, 1},
    {"Unlock Car",      "Unlock Car Settings",      false, 0, 1},
};

static float s_hpValue = 100.f, s_armorValue = 100.f, s_abSpeed = 1.f, s_abIncr = 0.5f;
static float s_maxDist = 300.f, s_crossSize = 12.f;
static bool  s_groundWarp = true, s_enterVehicle = true;
static bool  s_hideObsDiscord = false, s_antiAfk = false;

extern "C" void NrthUI_SyncFeaturesToState(void)
{
    SPlayerHealthSync *hs = Nrth_GetPlayerHealthSync();
    if (hs) {
        hs->bGodMode       = s_cheatFeatures[0].on ? 1 : 0;
        hs->bGiveHp        = s_cheatFeatures[1].on ? 1 : 0;
        hs->fHealth        = s_cheatFeatures[1].on ? s_hpValue : 100.0f;
        hs->bGiveArmor     = s_cheatFeatures[2].on ? 1 : 0;
        hs->fArmor         = s_cheatFeatures[2].on ? s_armorValue : 100.0f;
        hs->bInfiniteAmmo  = s_cheatFeatures[3].on ? 1 : 0;
        hs->bAntiSpread    = s_cheatFeatures[4].on ? 1 : 0;
        hs->bAirBreak      = s_cheatFeatures[8].on ? 1 : 0;
        hs->fAirBreakSpeed = s_abSpeed;
        hs->fAirBreakIncr  = s_abIncr;
        hs->bHighJump      = s_cheatFeatures[10].on ? 1 : 0;
        hs->bJetpack       = s_cheatFeatures[12].on ? 1 : 0;

        /* Vehicle features (0x10148f10..0x10149110 in NRTH.dll) */
        hs->bVehGodMode    = s_vehicleFeatures[0].on ? 1 : 0;
        hs->bVehicleChaos  = s_vehicleFeatures[1].on ? 1 : 0;
        hs->bDriveWater    = s_vehicleFeatures[2].on ? 1 : 0;
        hs->bFastStop      = s_vehicleFeatures[3].on ? 1 : 0;
        hs->bFallBike      = s_vehicleFeatures[4].on ? 1 : 0;
        hs->bFlyingCar     = s_vehicleFeatures[5].on ? 1 : 0;
        hs->bStartEngine   = s_vehicleFeatures[6].on ? 1 : 0;
        hs->bRepairCar     = s_vehicleFeatures[7].on ? 1 : 0;
        hs->bUnlockCar     = s_vehicleFeatures[8].on ? 1 : 0;
    }

    SWeaponAimSync *ws = Nrth_GetWeaponAimSync();
    if (ws) {
        ws->bClickWarp        = s_cheatFeatures[9].on ? 1 : 0;
        ws->fClickWarpMaxDist = s_maxDist;
        ws->fCrosshairSize    = s_crossSize;
        ws->bGroundWarp       = s_groundWarp ? 1 : 0;
        ws->bEnterVehicle     = s_enterVehicle ? 1 : 0;
        ws->bAllWeapons       = s_cheatFeatures[13].on ? 1 : 0;
    }

    NrthReportChannelState *rc = Nrth_GetReportChannelState();
    if (rc) {
        rc->suppressReports = s_cheatFeatures[5].on || s_hideObsDiscord;
    }
    (void)s_antiAfk;
}

/* ===========================================================================
 * Lua VM Bridge execution (0x1013bf04 registry stride 0x1C, L at +0x18,
 * default_L 0x1013c95c, loadbuffer 0x1013c94c with "@custom", pcall 0x1013c974,
 * flag 0x1013c939, script buffer 0x1013beec, VirtualQuery guard)
 * =========================================================================== */
extern "C" bool NrthUI_ExecuteLuaViaBridge(const char *code, size_t len, int vmMode)
{
    if (!code || len == 0) {
        return false;
    }
    NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
    if (!bridge) {
        return false;
    }

    size_t copyLen = len < (sizeof(bridge->scriptBuf_1013beec) - 1)
                         ? len
                         : (sizeof(bridge->scriptBuf_1013beec) - 1);
    memcpy(bridge->scriptBuf_1013beec, code, copyLen);
    bridge->scriptBuf_1013beec[copyLen] = '\0';
    bridge->execFlag_1013c939 = 1;

    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *chunkName = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                            0x2D, s_customChunk, &s_customGate);

    void *targetL = NULL;
    if (vmMode == 0 && bridge->default_L_1013c95c) {
        targetL = bridge->default_L_1013c95c;
    } else if (bridge->slotCount > 0) {
        for (uint32_t i = 0; i < bridge->slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
            void *cand = (void *)(uintptr_t)bridge->registry_1013bf04[i].luaStatePtr32;
            if (cand && Nrth_IsPointerReadable_VirtualQuery(cand)) {
                targetL = cand;
                break;
            }
        }
    }

    if (targetL &&
        Nrth_IsPointerReadable_VirtualQuery(targetL) &&
        bridge->loadbuffer_1013c94c &&
        bridge->pcall_1013c974) {
        int rc = bridge->loadbuffer_1013c94c(targetL, bridge->scriptBuf_1013beec,
                                             copyLen, chunkName);
        if (rc == 0) {
            rc = bridge->pcall_1013c974(targetL, 0, 0, 0);
        }
        bridge->execFlag_1013c939 = 0;
        return (rc == 0);
    }

    return false;
}

/* ===========================================================================
 * Full Dear ImGui + Embedded Lua 5.4.6 UI (Windows build)
 * =========================================================================== */
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

#include "imgui.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

static lua_State *s_L = nullptr;
static std::string s_console;

static int LuaPrint(lua_State *L)
{
    int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char *s = luaL_tolstring(L, i, &len);
        s_console.append(s ? s : "nil", s ? len : 3);
        lua_pop(L, 1);
        if (i < n) s_console += "\t";
    }
    s_console += "\n";
    return 0;
}

static void EnsureLuaVM()
{
    if (s_L) return;
    s_L = luaL_newstate();
    if (!s_L) return;
    luaL_openlibs(s_L);
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "print");
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "log");
}

static bool RunLuaBuffer(const char *code, size_t len, const char *chunkName, int vmMode)
{
    /* First try the MTA Lua VM bridge (0x1013bf04 / default_L 0x1013c95c with "@custom") */
    if (NrthUI_ExecuteLuaViaBridge(code, len, vmMode)) {
        return true;
    }

    /* Fallback to the embedded Lua 5.4.6 VM using "@custom" chunk name */
    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *effectiveChunk = chunkName ? chunkName :
        NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk), 0x2D, s_customChunk, &s_customGate);

    EnsureLuaVM();
    if (!s_L) {
        s_console += "[error] Lua VM unavailable\n";
        return false;
    }
    lua_settop(s_L, 0);
    int rc = luaL_loadbuffer(s_L, code, len, effectiveChunk);
    if (rc == LUA_OK) rc = lua_pcall(s_L, 0, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        const char *err = lua_tostring(s_L, -1);
        s_console += "[error] ";
        s_console += err ? err : "?";
        s_console += "\n";
        lua_pop(s_L, 1);
        return false;
    }
    return true;
}

static int  s_topTab     = 0;
static int  s_scriptsSub = 0;
static int  s_cheatSub   = 0;
static bool s_menuOpen   = true;

static char s_editorBuf[65536] = "-- North Cheat editor\n";
static int  s_vmIndex     = 0;  /* "Default VM", "@custom" */

static std::string s_status = "No connected server.";
static std::string s_lastAction;

struct ScriptItem { std::string name; bool autoInject; };
static std::vector<ScriptItem> s_scripts;
static int  s_scriptSel = -1;
static bool s_scriptsScanned = false;

static std::vector<std::string> s_resources;
static std::vector<std::string> s_blockedEvents;
static std::vector<std::string> s_recentTriggers;
struct PacketRow { std::string name; int id; bool blocked; std::string time; };
static std::vector<PacketRow> s_packets;
static bool s_packetsPopulated = false;
static char s_packetSearch[64] = "";
static int  s_packetSel = -1;

struct PlayerRow { std::string name; bool isYou; };
static std::vector<PlayerRow> s_players;
static std::vector<std::string> s_friends;
static std::string s_playerFilter;
static int  s_playerSel = 0;
struct MarkerRow { std::string name; float x, y, z; };
static std::vector<MarkerRow> s_markers;
static char s_markerName[64] = "";

struct ConfigItem { std::string name; };
static std::vector<ConfigItem> s_configs;
static bool s_configsScanned = false;
static char s_cfgName[64] = "default";
static int  s_cfgSel = -1;
static bool s_waitingForKey = false;

struct Bind { std::string action; int key; int mode; };
static std::vector<Bind> s_binds;
static int  s_bindCapture = -1;

static int s_vehicleSel = 0;

static const ImVec4 kAccent      = ImVec4(0.48f, 0.22f, 0.85f, 1.00f);
static const ImVec4 kAccentHover = ImVec4(0.56f, 0.30f, 0.92f, 1.00f);
static const ImVec4 kTabIdle     = ImVec4(0.16f, 0.10f, 0.24f, 1.00f);
static const ImVec4 kPanelBg     = ImVec4(0.09f, 0.06f, 0.14f, 1.00f);
static const ImVec4 kWindowBg    = ImVec4(0.07f, 0.04f, 0.11f, 1.00f);

void NrthUI_ApplyTheme()
{
    ImGuiStyle &st = ImGui::GetStyle();
    st.WindowRounding = 8.f;
    st.ChildRounding  = 6.f;
    st.FrameRounding  = 4.f;
    st.GrabRounding   = 4.f;
    st.WindowBorderSize = 1.f;
    st.FrameBorderSize  = 0.f;
    st.WindowPadding = ImVec2(12, 12);
    st.ItemSpacing   = ImVec2(8, 6);

    ImVec4 *c = st.Colors;
    c[ImGuiCol_WindowBg]        = kWindowBg;
    c[ImGuiCol_ChildBg]         = kPanelBg;
    c[ImGuiCol_PopupBg]         = ImVec4(0.11f, 0.07f, 0.17f, 1.f);
    c[ImGuiCol_Border]          = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_FrameBg]         = ImVec4(0.14f, 0.09f, 0.22f, 1.f);
    c[ImGuiCol_FrameBgHovered]  = kAccentHover;
    c[ImGuiCol_FrameBgActive]   = kAccent;
    c[ImGuiCol_Button]          = kTabIdle;
    c[ImGuiCol_ButtonHovered]   = kAccentHover;
    c[ImGuiCol_ButtonActive]    = kAccent;
    c[ImGuiCol_Header]          = kTabIdle;
    c[ImGuiCol_HeaderHovered]   = kAccentHover;
    c[ImGuiCol_HeaderActive]    = kAccent;
    c[ImGuiCol_Tab]             = kTabIdle;
    c[ImGuiCol_TabHovered]      = kAccentHover;
    c[ImGuiCol_TabActive]       = kAccent;
    c[ImGuiCol_TitleBg]         = kWindowBg;
    c[ImGuiCol_TitleBgActive]   = kWindowBg;
    c[ImGuiCol_Separator]       = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_CheckMark]       = kAccent;
    c[ImGuiCol_SliderGrab]      = kAccent;
    c[ImGuiCol_SliderGrabActive]= kAccentHover;
    c[ImGuiCol_Text]            = ImVec4(0.93f, 0.91f, 0.98f, 1.f);
}

struct ToastNotification {
    std::string text;
    ULONGLONG   createdTick;
};
static std::vector<ToastNotification> s_notifications;
static bool s_showKeybindWindow = false;
static Feature *s_capturingFeature = nullptr;

static void AddNotification_10002cd0(const char *msg)
{
    if (!msg || !msg[0] || !g_cfg.notifications) {
        return;
    }
    if (s_notifications.size() >= 6) {
        s_notifications.erase(s_notifications.begin());
    }
    s_notifications.push_back({ msg, GetTickCount64() });
}

static void FeatureAction(const char *msg)
{
    s_lastAction = msg ? msg : "";
    NrthUI_SyncFeaturesToState();
    AddNotification_10002cd0(msg);
}

static void EnsurePacketsPopulated()
{
    if (s_packetsPopulated) return;
    uint32_t count = 0;
    const NrthPacketDef *defs = NrthUI_GetPacketCatalog(&count);
    for (uint32_t i = 0; i < count; ++i) {
        s_packets.push_back({defs[i].name, defs[i].id, defs[i].isReportChannel, "00:00:00"});
    }
    s_packetsPopulated = true;
}

static void ScanLuaScripts()
{
    s_scripts.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("lua\\*.*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                s_scripts.push_back({fd.cFileName, false});
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_scriptsScanned = true;
}

static void ScanConfigs()
{
    s_configs.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*.ovr", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                s_configs.push_back({fd.cFileName});
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_configsScanned = true;
}

static bool TabButton(const char *label, const char *hiddenId, bool active, const ImVec2 &size)
{
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentHover);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, kTabIdle);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccent);
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "%s##%s", label, hiddenId);
    bool clicked = ImGui::Button(buf, size);
    ImGui::PopStyleColor(3);
    return clicked;
}

static void StatusLine()
{
    ImGui::TextColored(kAccentHover, "%s", s_status.c_str());
    if (!s_lastAction.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", s_lastAction.c_str());
    }
}

static void DrawEditor()
{
    ImGui::BeginChild("##lua_gutter", ImVec2(48, -140), true);
    int lines = 1;
    for (const char *p = s_editorBuf; *p; ++p) if (*p == '\n') ++lines;
    for (int i = 1; i <= lines && i < 2000; ++i) {
        ImGui::TextDisabled("%d", i);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::PushItemWidth(-1);
    ImGui::InputTextMultiline("##lua_editor", s_editorBuf, sizeof(s_editorBuf),
                              ImVec2(-1, -140), ImGuiInputTextFlags_AllowTabInput);
    ImGui::PopItemWidth();

    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *customLabel = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                              0x2D, s_customChunk, &s_customGate);

    if (ImGui::Button("Execute", ImVec2(110, 34))) {
        s_console.clear();
        if (RunLuaBuffer(s_editorBuf, strlen(s_editorBuf), customLabel, s_vmIndex)) {
            FeatureAction("Script executed");
        } else {
            FeatureAction("Script error (see console)");
        }
    }
    ImGui::SameLine();
    const char *vms[] = {"Default VM", customLabel};
    ImGui::SetNextItemWidth(160);
    ImGui::Combo("##vm_combo", &s_vmIndex, vms, 2);
    ImGui::SameLine();
    if (ImGui::Button("Clear##console")) s_console.clear();
    ImGui::SameLine();
    ImGui::TextDisabled("Output:");

    ImGui::BeginChild("##lua_console", ImVec2(-1, -1), true);
    if (s_console.empty()) {
        ImGui::TextDisabled("print(...) output appears here");
    } else {
        ImGui::TextUnformatted(s_console.c_str());
    }
    ImGui::EndChild();
}

static void DrawScriptsList()
{
    if (!s_scriptsScanned) ScanLuaScripts();
    ImGui::TextDisabled("Path: .\\lua\\   (evidence: \"%%s\\\\lua\\\\%%s\")");
    ImGui::BeginChild("##scripts_list", ImVec2(-1, -80), true);
    if (s_scripts.empty()) {
        ImGui::TextDisabled("No scripts found");
    }
    for (int i = 0; i < (int)s_scripts.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_scripts[i].name.c_str(), s_scriptSel == i)) s_scriptSel = i;
        ImGui::SameLine(220);
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "Inject##%d", i);
        if (ImGui::SmallButton(lbl)) FeatureAction(("Injected: " + s_scripts[i].name).c_str());
        ImGui::SameLine();
        snprintf(lbl, sizeof(lbl), "Auto-inj##%d", i);
        ImGui::Checkbox(lbl, &s_scripts[i].autoInject);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (ImGui::Button("Dump")) {
        if (s_scriptSel >= 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Dump script saved: %s", s_scripts[s_scriptSel].name.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Dump all")) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Dump all scripts saved (%d)", (int)s_scripts.size());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button("Run##script") && s_scriptSel >= 0) {
        std::string path = "lua\\" + s_scripts[s_scriptSel].name;
        FILE *fp = fopen(path.c_str(), "rb");
        if (fp) {
            std::string code;
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) code.append(buf, n);
            fclose(fp);
            s_console.clear();
            if (RunLuaBuffer(code.c_str(), code.size(), s_scripts[s_scriptSel].name.c_str(), s_vmIndex))
                FeatureAction("Script executed");
            else
                FeatureAction("Script error (see console)");
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("view: ##script_editor_view | \"File big, no view script\"");
}

static void DrawResources()
{
    if (s_resources.empty()) {
        static const char *kRoots[] = {
            "mods\\deathmatch\\resources",
            "mods\\deathmatch\\cache",
        };
        for (const char *root : kRoots) {
            WIN32_FIND_DATAA fd;
            std::string pattern = std::string(root) + "\\*";
            HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, ".."))
                        s_resources.push_back(fd.cFileName);
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
    ImGui::TextDisabled("Source: .\\mods\\deathmatch\\resources / cache (disk)");
    static char search[64] = "";
    ImGui::InputTextWithHint("##res_search", "Search...", search, sizeof(search));
    static int resSel = 0;
    std::string preview = s_resources.empty() ? "Select Resource" : s_resources[resSel];
    ImGui::SetNextItemWidth(260);
    if (ImGui::BeginCombo("##res_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_resources.size(); ++i) {
            if (search[0] && s_resources[i].find(search) == std::string::npos) continue;
            if (ImGui::Selectable(s_resources[i].c_str(), resSel == i)) resSel = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%d found)", (int)s_resources.size());
    if (ImGui::Button("Stop Resource")) {
        if (!s_resources.empty()) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Resource stopped: %s", s_resources[resSel].c_str());
            FeatureAction(msg);
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("Block list (\" (blocked)\"):");
    for (auto &e : s_blockedEvents) ImGui::BulletText("%s (blocked)", e.c_str());
}

static void DrawEvents()
{
    static int evSel = 0;
    static const char *kEvents[] = {"onClientRender", "onClientPlayerDamage", "onClientVehicleEnter",
                                    "onClientChatMessage", "onClientElementDataChange", "onClientPreRender"};
    ImGui::SetNextItemWidth(280);
    ImGui::BeginCombo("##event_combo", kEvents[evSel]);
    for (int i = 0; i < 6; ++i) if (ImGui::Selectable(kEvents[i], evSel == i)) evSel = i;
    ImGui::EndCombo();
    ImGui::SameLine();
    if (ImGui::Button("Block##event")) {
        s_blockedEvents.push_back(kEvents[evSel]);
        FeatureAction(("Event blocked: " + std::string(kEvents[evSel])).c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Unblock##event") && !s_blockedEvents.empty()) {
        FeatureAction(("Event unblocked: " + s_blockedEvents.back()).c_str());
        s_blockedEvents.pop_back();
    }
    static char trig[96] = "";
    ImGui::InputTextWithHint("##trigger_input", "triggerServerEvent name...", trig, sizeof(trig));
    ImGui::SameLine();
    if (ImGui::Button("Add to Block List") && trig[0]) {
        s_blockedEvents.push_back(trig);
        trig[0] = 0;
    }
    ImGui::Separator();
    ImGui::Text("Recent Triggers:");
    if (s_recentTriggers.empty()) ImGui::TextDisabled("No triggers");
    for (auto &t : s_recentTriggers) ImGui::BulletText("%s", t.c_str());
}

static void DrawEventsTable()
{
    ImGui::TextDisabled("Events Table (live event registry view)");
    if (ImGui::BeginTable("##events_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Event");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("State");
        ImGui::TableHeadersRow();
        for (auto &e : s_recentTriggers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextDisabled("tracked");
        }
        for (auto &e : s_blockedEvents) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextColored(kAccentHover, "(blocked)");
        }
        ImGui::EndTable();
    }
}

static void DrawPackets()
{
    EnsurePacketsPopulated();
    if (ImGui::Button("Refresh")) {
        s_packetsPopulated = false;
        s_packets.clear();
        EnsurePacketsPopulated();
        FeatureAction("Refresh");
    }
    ImGui::SameLine();
    ImGui::Text("Packets: %zu", s_packets.size());
    ImGui::SameLine();
    if (ImGui::Button("Clear All")) s_packets.clear();
    ImGui::SameLine();
    if (ImGui::Button("Unblock All"))
        for (auto &p : s_packets) p.blocked = false;
    ImGui::SameLine();
    ImGui::InputTextWithHint("##packet_search", "Search packet...", s_packetSearch, sizeof(s_packetSearch));

    ImGui::BeginChild("packets_left", ImVec2(-320, -1), true);
    if (s_packets.empty()) {
        ImGui::TextDisabled("No packets detected.");
    }
    for (int i = 0; i < (int)s_packets.size(); ++i) {
        if (s_packetSearch[0] && s_packets[i].name.find(s_packetSearch) == std::string::npos) {
            continue;
        }
        ImGui::PushID(i);
        if (ImGui::Selectable(s_packets[i].name.c_str(), s_packetSel == i)) s_packetSel = i;
        ImGui::SameLine();
        ImGui::TextDisabled("%s", s_packets[i].blocked ? "BLOCKED" : "UNBLOCKED");
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("packets_right", ImVec2(0, -1), true);
    if (s_packetSel >= 0 && s_packetSel < (int)s_packets.size()) {
        const PacketRow &p = s_packets[s_packetSel];
        ImGui::Text("Name: %s", p.name.c_str());
        ImGui::Text("Time: %s", p.time.c_str());
        ImGui::Text("ID: %d", p.id);
        ImGui::TextColored(kAccentHover, "%s", p.blocked ? "BLOCKED" : "UNBLOCKED");
        if (ImGui::Button("Block Packet"))
            s_packets[s_packetSel].blocked = !s_packets[s_packetSel].blocked;
        ImGui::SameLine();
        if (ImGui::Button("Resend")) {
            char msg[160];
            snprintf(msg, sizeof(msg), "Resending packet: %s", p.name.c_str());
            FeatureAction(msg);
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy Name")) {
            ImGui::SetClipboardText(p.name.c_str());
            char msg[160];
            snprintf(msg, sizeof(msg), "Packet name copied: %s", p.name.c_str());
            FeatureAction(msg);
        }
    } else {
        ImGui::TextDisabled("Select a packet");
    }
    ImGui::EndChild();
}

static void DrawDumper()
{
    ImGui::TextDisabled("Memory / class dumper (resolved offsets from 0x1000c390)");
    ImGui::BeginChild("##dumper", ImVec2(-1, -1), true);
    uint32_t count = 0;
    const uintptr_t *offsets = Nrth_GetClientResolvedOffsets(&count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t addr = offsets[i] ? (uint32_t)offsets[i] : (0x10000000u + i * 0x10u);
        ImGui::Text("Address: 0x%08X", addr);
        ImGui::SameLine(180);
        ImGui::TextDisabled("slot #%02u (%s)", i + 1, offsets[i] ? "resolved" : "pending");
    }
    ImGui::EndChild();
}

static void DrawPlayerTab()
{
    ImGui::InputTextWithHint("##player_filter", "filter...", (char *)s_playerFilter.c_str(), 64);
    ImGui::SetNextItemWidth(280);
    std::string preview = s_players.empty() ? "Select player..." :
        (s_players[s_playerSel].name + (s_players[s_playerSel].isYou ? " (you)" : ""));
    if (ImGui::BeginCombo("##player_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_players.size(); ++i) {
            std::string lbl = s_players[i].name + (s_players[i].isYou ? " (you)" : "");
            if (ImGui::Selectable(lbl.c_str(), s_playerSel == i)) s_playerSel = i;
        }
        if (s_players.empty()) ImGui::TextDisabled("No players found");
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport")) FeatureAction("Teleport");
    ImGui::SameLine();
    if (ImGui::Button("Bomb")) FeatureAction("Bomb");
    ImGui::SameLine();
    if (ImGui::Button("Add Friend")) {
        if (!s_players.empty()) s_friends.push_back(s_players[s_playerSel].name);
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete Friend") && !s_friends.empty())
        s_friends.pop_back();
    ImGui::Separator();
    ImGui::Text("Friend's list");
    if (s_friends.empty()) ImGui::TextDisabled("No friends added");
    for (auto &f : s_friends) ImGui::BulletText("%s", f.c_str());
}

static void TriggerFeatureImmediateAction(Feature &f)
{
    if (strcmp(f.label, "All Weapons") == 0 && f.on) {
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction("All weapons given (1000 ammo)");
        return;
    }
    if (strcmp(f.label, "Jetpack") == 0) {
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(f.on ? "Jetpack enabled" : "Jetpack disabled");
        return;
    }
    if (strcmp(f.label, "Repair Car") == 0 && f.on) {
        if (Nrth_RepairCurrentVehicle_1002f070()) {
            FeatureAction("Vehicle repaired");
        } else {
            FeatureAction("You must be in a vehicle");
        }
        return;
    }
    if (strcmp(f.label, "Start Engine") == 0 && f.on) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) {
            FeatureAction("Engine started");
        } else {
            FeatureAction("You must be in a vehicle");
        }
        return;
    }
    if (strcmp(f.label, "Unlock Car") == 0 && f.on) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) {
            FeatureAction("Unlocked nearest vehicle");
        } else {
            FeatureAction("No vehicle found nearby");
        }
        return;
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "%s %s", f.label, f.on ? "enabled" : "disabled");
    FeatureAction(msg);
}

static void FeatureRow(Feature &f, const char *id)
{
    ImGui::PushID(id);
    if (ImGui::Checkbox(f.label, &f.on)) {
        NrthUI_SyncFeaturesToState();
        TriggerFeatureImmediateAction(f);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("##gear")) ImGui::OpenPopup("##settings_panel");
    if (ImGui::BeginPopup("##settings_panel")) {
        ImGui::TextUnformatted(f.settings);
        ImGui::Separator();
        if (strcmp(f.label, "Give HP") == 0) {
            if (ImGui::SliderFloat("HP Value##sp", &s_hpValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Give Armor") == 0) {
            if (ImGui::SliderFloat("Armor Value##sp", &s_armorValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "AirBreak") == 0) {
            if (ImGui::SliderFloat("Speed: %.2f", &s_abSpeed, 0.1f, 10.f)) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat("Increment: %.2f", &s_abIncr, 0.05f, 2.f)) NrthUI_SyncFeaturesToState();
            ImGui::Separator();
            ImGui::Text("Keybinds");
            ImGui::BulletText("Forward: W"); ImGui::BulletText("Back: S");
            ImGui::BulletText("Left: A");    ImGui::BulletText("Right: D");
            ImGui::BulletText("Up: Space / Down: LCtrl");
        } else if (strcmp(f.label, "Click Warp") == 0) {
            if (ImGui::SliderFloat("Max Distance##sp", &s_maxDist, 10, 1000)) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat("Crosshair Size##sp", &s_crossSize, 2, 40)) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox("Ground Warp##sp", &s_groundWarp)) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox("Enter Vehicle##sp", &s_enterVehicle)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-ScreenShot") == 0) {
            if (ImGui::Checkbox("Hide obs/discord", &s_hideObsDiscord)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-AFK") == 0) {
            ImGui::Checkbox("Anti-AFK", &s_antiAfk);
        } else {
            ImGui::TextDisabled("settings synced to SPlayerHealthSync/SWeaponAimSync");
        }
        ImGui::Separator();
        if (s_capturingFeature == &f) {
            ImGui::Button("Press a key...");
            for (int vk = 1; vk < 256; ++vk) {
                if (vk == VK_LBUTTON || vk == VK_RBUTTON) continue;
                if (GetAsyncKeyState(vk) & 1) {
                    f.key = (vk == VK_ESCAPE) ? 0 : vk;
                    s_capturingFeature = nullptr;
                    break;
                }
            }
        } else {
            char keyBtn[64];
            if (f.key > 0) snprintf(keyBtn, sizeof(keyBtn), "Key: %d (click to change)", f.key);
            else           snprintf(keyBtn, sizeof(keyBtn), "Press a key...");
            if (ImGui::Button(keyBtn)) {
                s_capturingFeature = &f;
            }
        }
        ImGui::SameLine();
        const char *modes[] = { "Hold", "Toggle" };
        ImGui::SetNextItemWidth(90);
        ImGui::Combo("##mode", &f.mode, modes, 2);
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

static void DrawOtherTab()
{
    ImGui::TextDisabled("Feature toggles (synced to SPlayerHealthSync / SWeaponAimSync)");
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureRow(s_cheatFeatures[i], id);
    }
    ImGui::Separator();
    /* Action buttons matching 0x1002a580..0x1002a880 in NRTH.dll */
    if (ImGui::Button("All Weapons")) {
        s_cheatFeatures[13].on = true;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction("All weapons given (1000 ammo)");
    }
    ImGui::SameLine();
    if (ImGui::Button("High Jump")) {
        s_cheatFeatures[10].on = !s_cheatFeatures[10].on;
        NrthUI_SyncFeaturesToState();
        FeatureAction(s_cheatFeatures[10].on ? "High Jump enabled" : "High Jump disabled");
    }
    ImGui::SameLine();
    if (ImGui::Button("Money Exploit")) {
        s_cheatFeatures[11].on = !s_cheatFeatures[11].on;
        if (s_cheatFeatures[11].on) {
            static const char kMoneyLua[] = "givePlayerMoney(50000)";
            NrthUI_ExecuteLuaViaBridge(kMoneyLua, sizeof(kMoneyLua) - 1, 0);
        }
        FeatureAction(s_cheatFeatures[11].on ? "Money Exploit enabled" : "Money Exploit disabled");
    }
    ImGui::SameLine();
    if (ImGui::Button("Jetpack")) {
        s_cheatFeatures[12].on = !s_cheatFeatures[12].on;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(s_cheatFeatures[12].on ? "Jetpack enabled" : "Jetpack disabled");
    }
    if (!s_lastAction.empty()) ImGui::TextDisabled("last: %s", s_lastAction.c_str());
}

static void DrawMarkersTab()
{
    ImGui::InputTextWithHint("##marker_name", "marker name...", s_markerName, sizeof(s_markerName));
    ImGui::SameLine();
    if (ImGui::Button("Save") && s_markerName[0]) {
        MarkerRow m = {s_markerName, 0.f, 0.f, 0.f};
        s_markers.push_back(m);
        s_markerName[0] = 0;
    }
    if (s_markers.empty()) ImGui::TextDisabled("No markers saved");
    for (auto &m : s_markers) {
        char line[128];
        snprintf(line, sizeof(line), "%s (%.1f, %.1f, %.1f)", m.name.c_str(), m.x, m.y, m.z);
        ImGui::BulletText("%s", line);
        ImGui::SameLine(280);
        if (ImGui::SmallButton("Teleport")) FeatureAction("Teleport");
        ImGui::SameLine();
        if (ImGui::SmallButton("Delete")) m.name.clear();
    }
}

static void DrawVehicleTab()
{
    ImGui::Columns(2, "##vehcols", false);
    ImGui::SetColumnWidth(0, 300);
    ImGui::Text("Vehicle's");
    ImGui::Separator();
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "vf%d", i);
        FeatureRow(s_vehicleFeatures[i], id);
    }
    ImGui::NextColumn();

    ImGui::Text("Vehicles List");
    ImGui::SetNextItemWidth(-1);
    std::string prev = std::string(kVehicleNames[s_vehicleSel]) + " (HP: 1000)";
    if (ImGui::BeginCombo("##vehicles_combo", s_vehicleSel >= 0 ? prev.c_str() : "Select vehicle...")) {
        for (int i = 0; i < (int)(sizeof(kVehicleNames) / sizeof(kVehicleNames[0])); ++i) {
            if (ImGui::Selectable(kVehicleNames[i], s_vehicleSel == i)) s_vehicleSel = i;
        }
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport to Vehicle")) FeatureAction("Teleport to Vehicle");
    ImGui::SameLine();
    if (ImGui::Button("Teleport Vehicle")) FeatureAction("Vehicle teleported to you");
    ImGui::SameLine();
    if (ImGui::Button("Bomb Car")) {
        if (Nrth_DestroyCurrentVehicle()) FeatureAction("Vehicle destroyed");
        else FeatureAction("You must be in a vehicle");
    }
    if (ImGui::Button("Repair Car")) {
        if (Nrth_RepairCurrentVehicle_1002f070()) FeatureAction("Vehicle repaired");
        else FeatureAction("You must be in a vehicle");
    }
    ImGui::SameLine();
    if (ImGui::Button("Start Engine")) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) FeatureAction("Engine started");
        else FeatureAction("You must be in a vehicle");
    }
    ImGui::SameLine();
    if (ImGui::Button("Stop")) {
        if (Nrth_StopCurrentVehicle()) FeatureAction("Vehicle stopped");
        else FeatureAction("You must be in a vehicle");
    }
    ImGui::SameLine();
    if (ImGui::Button("Unlock Car")) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) FeatureAction("Unlocked nearest vehicle");
        else FeatureAction("No vehicle found nearby");
    }
    ImGui::Columns(1);
}

static void DrawColorSettings()
{
    if (ImGui::TreeNode("Color Settings")) {
        static char filter[64] = "";
        ImGui::InputTextWithHint("##filter", "Search color...", filter, sizeof(filter));
        static const struct { const char *name; ImGuiCol col; } kColors[] = {
            {"Text", ImGuiCol_Text}, {"Text Disabled", ImGuiCol_TextDisabled},
            {"Window BG", ImGuiCol_WindowBg}, {"Child BG", ImGuiCol_ChildBg},
            {"Popup BG", ImGuiCol_PopupBg}, {"Border", ImGuiCol_Border},
            {"Border Shadow", ImGuiCol_BorderShadow},
            {"Frame BG", ImGuiCol_FrameBg}, {"Frame BG Hovered", ImGuiCol_FrameBgHovered},
            {"Frame BG Active", ImGuiCol_FrameBgActive},
            {"Title BG", ImGuiCol_TitleBg}, {"Title BG Active", ImGuiCol_TitleBgActive},
            {"Title BG Collapsed", ImGuiCol_TitleBgCollapsed},
            {"Menu Bar BG", ImGuiCol_MenuBarBg},
            {"Scrollbar BG", ImGuiCol_ScrollbarBg},
            {"Scrollbar Grab", ImGuiCol_ScrollbarGrab},
            {"Scrollbar Grab Hovered", ImGuiCol_ScrollbarGrabHovered},
            {"Scrollbar Grab Active", ImGuiCol_ScrollbarGrabActive},
            {"Check Mark", ImGuiCol_CheckMark}, {"Slider Grab", ImGuiCol_SliderGrab},
            {"Slider Grab Active", ImGuiCol_SliderGrabActive},
            {"Button", ImGuiCol_Button}, {"Button Hovered", ImGuiCol_ButtonHovered},
            {"Button Active", ImGuiCol_ButtonActive},
            {"Header", ImGuiCol_Header}, {"Header Hovered", ImGuiCol_HeaderHovered},
            {"Header Active", ImGuiCol_HeaderActive},
            {"Separator Hovered", ImGuiCol_SeparatorHovered},
            {"Separator Active", ImGuiCol_SeparatorActive},
            {"Tab", ImGuiCol_Tab}, {"Tab Hovered", ImGuiCol_TabHovered},
            {"Tab Active", ImGuiCol_TabActive},
            {"Resize Grip", ImGuiCol_ResizeGrip},
            {"Resize Grip Hovered", ImGuiCol_ResizeGripHovered},
            {"Resize Grip Active", ImGuiCol_ResizeGripActive},
            {"Text Selected BG", ImGuiCol_TextSelectedBg},
        };
        if (ImGui::BeginTable("##ColorTable", 2, ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Color");
            ImGui::TableHeadersRow();
            for (auto &k : kColors) {
                if (filter[0] && !strstr(k.name, filter)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(k.name);
                ImGui::TableNextColumn();
                ImVec4 c = ImGui::GetStyle().Colors[k.col];
                if (ImGui::ColorEdit4("##col", (float *)&c, ImGuiColorEditFlags_NoInputs))
                    ImGui::GetStyle().Colors[k.col] = c;
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Reset Colors")) {
            ImGui::StyleColorsDark();
            NrthUI_ApplyTheme();
            FeatureAction("Colors reset");
        }
        ImGui::TreePop();
    }
}

static void DrawConfigTab()
{
    if (!s_configsScanned) ScanConfigs();
    ImGui::Columns(2, "##cfgcols", false);
    ImGui::SetColumnWidth(0, 260);
    ImGui::Text("Configs");
    ImGui::BeginChild("##cfgitem", ImVec2(-1, -1), true);
    if (s_configs.empty()) ImGui::TextDisabled("No configs found");
    for (int i = 0; i < (int)s_configs.size(); ++i) {
        if (ImGui::Selectable(s_configs[i].name.c_str(), s_cfgSel == i)) s_cfgSel = i;
    }
    ImGui::EndChild();
    ImGui::NextColumn();

    ImGui::BeginChild("##cfg_right", ImVec2(0, -1), true);
    ImGui::InputText("Name##sa", s_cfgName, sizeof(s_cfgName));
    if (ImGui::Button("Save")) {
        std::string f = std::string(s_cfgName) + ".ovr";
        /* Writes both <name>.ovr ("OVRCFG") and C:\Overwack\loader_config.cfg */
        NrthConfig_SaveOvr(f.c_str(), NULL);
        char msg[128];
        snprintf(msg, sizeof(msg), "Config saved: %s", f.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Save As...")) {
        s_cfgName[0] = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("Load") && s_cfgSel >= 0) {
        NrthConfig_Load(s_configs[s_cfgSel].name.c_str());
        NrthConfig_Save(NULL);
        char msg[128];
        snprintf(msg, sizeof(msg), "Config loaded: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete") && s_cfgSel >= 0) {
        DeleteFileA(s_configs[s_cfgSel].name.c_str());
        char msg[128];
        snprintf(msg, sizeof(msg), "Config deleted: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset to Default")) {
        g_cfg.menuKey   = NRTH_VK_INSERT;
        g_cfg.noSpoofer = 0;
        NrthConfig_Save(NULL);
        FeatureAction("Reset to default style");
    }
    ImGui::Separator();
    ImGui::Checkbox("Watermark", &g_cfg.watermark);
    ImGui::SameLine();
    ImGui::Checkbox("Notifications", &g_cfg.notifications);
    ImGui::SameLine();
    ImGui::Checkbox("Show Keybind's", &s_showKeybindWindow);
    ImGui::Separator();

    ImGui::Text("Menu Toggle Key");
    ImGui::SameLine();
    if (s_waitingForKey) {
        ImGui::Button("Press...");
        for (int k = 1; k < 256; ++k) {
            if (k == VK_LBUTTON || k == VK_RBUTTON) continue;
            if (GetAsyncKeyState(k) & 1) {
                g_cfg.menuKey = k;
                NrthConfig_Save(NULL);
                s_waitingForKey = false;
                break;
            }
        }
    } else if (ImGui::Button("Set")) {
        s_waitingForKey = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(current: %d / Insert=45)", g_cfg.menuKey);

    ImGui::Separator();
    ImGui::Text("Keybind's");
    bool anyBind = false;
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        if (s_cheatFeatures[i].key > 0) {
            anyBind = true;
            ImGui::PushID(1000 + i);
            ImGui::Text("%s -> key %d (%s)", s_cheatFeatures[i].label, s_cheatFeatures[i].key,
                        s_cheatFeatures[i].mode ? "Toggle" : "Hold");
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                s_cheatFeatures[i].key = 0;
                FeatureAction((std::string("Bind cleared: ") + s_cheatFeatures[i].label).c_str());
            }
            ImGui::PopID();
        }
    }
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        if (s_vehicleFeatures[i].key > 0) {
            anyBind = true;
            ImGui::PushID(2000 + i);
            ImGui::Text("%s -> key %d (%s)", s_vehicleFeatures[i].label, s_vehicleFeatures[i].key,
                        s_vehicleFeatures[i].mode ? "Toggle" : "Hold");
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                s_vehicleFeatures[i].key = 0;
                FeatureAction((std::string("Bind cleared: ") + s_vehicleFeatures[i].label).c_str());
            }
            ImGui::PopID();
        }
    }
    if (!anyBind && s_binds.empty()) ImGui::TextDisabled("No binds");
    for (int i = 0; i < (int)s_binds.size(); ++i) {
        ImGui::Text("Bind: %s -> key %d", s_binds[i].action.c_str(), s_binds[i].key);
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) {
            FeatureAction(("Bind cleared: " + s_binds[i].action).c_str());
            s_binds.erase(s_binds.begin() + i);
            break;
        }
    }
    DrawColorSettings();
    ImGui::EndChild();
    ImGui::Columns(1);
}

/* Matches PollHotkeys at VA 0x10012250 in NRTH.dll */
static void PollHotkeys_10012250(void)
{
    if (s_capturingFeature || s_waitingForKey) {
        return;
    }
    auto pollFeatureArray = [](Feature *arr, int count) {
        for (int i = 0; i < count; ++i) {
            Feature &f = arr[i];
            if (f.key <= 0) continue;
            if (f.mode == 1) { /* Toggle */
                if (GetAsyncKeyState(f.key) & 1) {
                    f.on = !f.on;
                    NrthUI_SyncFeaturesToState();
                    TriggerFeatureImmediateAction(f);
                }
            } else { /* Hold */
                bool down = (GetAsyncKeyState(f.key) & 0x8000) != 0;
                if (f.on != down) {
                    f.on = down;
                    NrthUI_SyncFeaturesToState();
                }
            }
        }
    };
    pollFeatureArray(s_cheatFeatures, (int)(sizeof(s_cheatFeatures) / sizeof(Feature)));
    pollFeatureArray(s_vehicleFeatures, (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)));
}

/* Matches DrawWatermark at VA 0x10012bc0 in NRTH.dll */
static void DrawWatermark_10012bc0(void)
{
    if (!g_cfg.watermark) {
        return;
    }
    ImGuiIO &io = ImGui::GetIO();
    float fps = io.Framerate > 0.0f ? io.Framerate : 60.0f;
    char wmBuf[256];
    snprintf(wmBuf, sizeof(wmBuf), "NORTH  |  FPS: %.0f  |  Server: %s", fps, s_status.c_str());

    ImVec2 textSz = ImGui::CalcTextSize(wmBuf);
    float winW = textSz.x + 24.0f;
    float posX = (io.DisplaySize.x > winW + 16.0f) ? (io.DisplaySize.x - winW - 14.0f) : 10.0f;
    ImGui::SetNextWindowPos(ImVec2(posX, 12.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.75f);
    if (ImGui::Begin("##Watermark", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove)) {
        ImGui::TextColored(kAccentHover, "NORTH");
        ImGui::SameLine();
        ImGui::Text("|  FPS: %.0f  |  Server: %s", fps, s_status.c_str());
    }
    ImGui::End();
}

/* Matches DrawKeybindList at VA 0x100130a0 in NRTH.dll */
static void DrawKeybindList_100130a0(void)
{
    if (!s_showKeybindWindow) {
        return;
    }
    ImGui::SetNextWindowPos(ImVec2(14.0f, 60.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(230.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.80f);
    if (ImGui::Begin("Keybind's##floating", &s_showKeybindWindow,
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings)) {
        bool any = false;
        auto listFeatureArray = [&](Feature *arr, int count) {
            for (int i = 0; i < count; ++i) {
                if (arr[i].key > 0) {
                    any = true;
                    ImGui::Text("%s [%s]", arr[i].label, arr[i].mode ? "Toggle" : "Hold");
                    ImGui::SameLine(175.0f);
                    if (arr[i].on) {
                        ImGui::TextColored(kAccentHover, "ON");
                    } else {
                        ImGui::TextDisabled("OFF");
                    }
                }
            }
        };
        listFeatureArray(s_cheatFeatures, (int)(sizeof(s_cheatFeatures) / sizeof(Feature)));
        listFeatureArray(s_vehicleFeatures, (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)));
        if (!any) {
            ImGui::TextDisabled("No active binds");
        }
    }
    ImGui::End();
}

/* Matches DrawNotifications at VA 0x10016990 in NRTH.dll */
static void DrawNotifications_10016990(void)
{
    if (!g_cfg.notifications || s_notifications.empty()) {
        return;
    }
    ULONGLONG now = GetTickCount64();
    const ULONGLONG kDurationMs = 3500ULL;
    for (int i = (int)s_notifications.size() - 1; i >= 0; --i) {
        if (now - s_notifications[i].createdTick > kDurationMs) {
            s_notifications.erase(s_notifications.begin() + i);
        }
    }
    ImGuiIO &io = ImGui::GetIO();
    float baseY = (io.DisplaySize.y > 100.0f ? io.DisplaySize.y : 720.0f) - 70.0f;
    float baseX = (io.DisplaySize.x > 300.0f ? io.DisplaySize.x : 1280.0f) - 275.0f;
    for (int i = 0; i < (int)s_notifications.size(); ++i) {
        char winId[32];
        snprintf(winId, sizeof(winId), "##toast_%d", i);
        ImGui::SetNextWindowPos(ImVec2(baseX, baseY - i * 58.0f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(260.0f, 50.0f), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.88f);
        if (ImGui::Begin(winId, nullptr,
                         ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings |
                         ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoMove)) {
            ImGui::TextColored(kAccentHover, "Notification");
            ImGui::TextUnformatted(s_notifications[i].text.c_str());
        }
        ImGui::End();
    }
}

void NrthUI_Build()
{
    ImGui::SetNextWindowSize(ImVec2(860, 560), ImGuiCond_FirstUseEver);
    if (!s_menuOpen) return;
    if (!ImGui::Begin("North Cheat", &s_menuOpen)) {
        ImGui::End();
        return;
    }

    ImGui::TextColored(kAccentHover, "N O R T H");
    ImGui::SameLine();
    StatusLine();
    ImGui::Separator();

    static const char *kTop[] = {"Scripts", "Dumper", "Cheat", "Vehicle", "Config"};
    float w = (ImGui::GetContentRegionAvail().x - 4 * 8.f) / 5.f;
    for (int i = 0; i < 5; ++i) {
        char hid[32];
        snprintf(hid, sizeof(hid), "nvx_top_%d", i);
        if (TabButton(kTop[i], hid, s_topTab == i, ImVec2(w, 34))) s_topTab = i;
        if (i < 4) ImGui::SameLine();
    }
    ImGui::Spacing();

    if (s_topTab == 0) {
        static const char *kSub[] = {"Editor", "Scripts", "Resources", "Events", "Events Table", "Packets"};
        float sw = (ImGui::GetContentRegionAvail().x - 5 * 6.f) / 6.f;
        for (int i = 0; i < 6; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_ssub_%d", i);
            if (TabButton(kSub[i], hid, s_scriptsSub == i, ImVec2(sw, 26))) s_scriptsSub = i;
            if (i < 5) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_scriptsSub) {
            case 0: DrawEditor();       break;
            case 1: DrawScriptsList();  break;
            case 2: DrawResources();    break;
            case 3: DrawEvents();       break;
            case 4: DrawEventsTable();  break;
            case 5: DrawPackets();      break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 1) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawDumper();
        ImGui::EndChild();
    } else if (s_topTab == 2) {
        static const char *kCSub[] = {"Player", "Other", "Markers"};
        float sw = (ImGui::GetContentRegionAvail().x - 2 * 6.f) / 3.f;
        for (int i = 0; i < 3; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_csub_%d", i);
            if (TabButton(kCSub[i], hid, s_cheatSub == i, ImVec2(sw, 26))) s_cheatSub = i;
            if (i < 2) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_cheatSub) {
            case 0: DrawPlayerTab();  break;
            case 1: DrawOtherTab();   break;
            case 2: DrawMarkersTab(); break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 3) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawVehicleTab();
        ImGui::EndChild();
    } else {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawConfigTab();
        ImGui::EndChild();
    }

    ImGui::End();
}

extern "C" void NrthUI_RenderFrame(bool menuOpen)
{
    PollHotkeys_10012250();
    DrawWatermark_10012bc0();
    DrawKeybindList_100130a0();
    if (menuOpen) {
        s_menuOpen = true;
        NrthUI_Build();
    }
    DrawNotifications_10016990();
}

#else /* Headless / non-Win32 build for verification tests */

extern "C" void NrthUI_ApplyTheme(void) {}
extern "C" void NrthUI_Build(void) {}
extern "C" void NrthUI_RenderFrame(bool menuOpen) { (void)menuOpen; }

#endif
