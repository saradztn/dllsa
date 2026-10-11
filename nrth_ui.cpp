/**
 * ============================================================================
 * nrth_ui.cpp — DARKANARCHY (Developed by XRAOUF)
 *               Bilingual (Arabic + English) Dear ImGui Overlay, Custom TTF
 *               Fonts, AI Logo & Background Textures, Packet Catalogue & Sync
 * ============================================================================
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef NRTH_HEADLESS_TEST
#include <d3d9.h>
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>

#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_hook.h"
#include "nrth_ui.h"
#include "nrth_arabic.h"
#if (defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)) || defined(NRTH_UI_HEADLESS)
#include "nrth_vehicle_names.inc"
#include "nrth_assets.h"
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
struct Feature {
    const char *label;
    const char *arLabel;
    const char *settings;
    const char *arSettings;
    bool        on;
    int         key;
    int         mode;
};

static Feature s_cheatFeatures[] = {
    {"GodMode",         "وضع الخلود (GodMode)",   "GodMode Settings",         "إعدادات وضع الخلود",         false, 0, 1},
    {"Give HP",         "إعطاء صحة (HP)",         "Give HP Settings",         "إعدادات الصحة",              false, 0, 1},
    {"Give Armor",      "إعطاء درع (Armor)",      "Give Armor Settings",      "إعدادات الدرع",              false, 0, 1},
    {"Infinite Ammo",   "ذخيرة لا نهائية",        "Infinite Ammo Settings",   "إعدادات الذخيرة اللانهائية", false, 0, 1},
    {"Anti-Spread",     "ثبات السلاح",            "Anti-Spread Settings",     "إعدادات ثبات السلاح",        false, 0, 1},
    {"Anti-ScreenShot", "حماية الشاشة (Anti-SS)", "Anti-ScreenShot Settings", "إعدادات حماية الشاشة",       false, 0, 1},
    {"Crasher",         "كراشر السيرفر",          "Crasher Settings",         "إعدادات الكراشر",            false, 0, 1},
    {"Anti-AFK",        "مانع الخمول (AFK)",      "Anti-AFK Settings",        "إعدادات منع الخمول",         false, 0, 1},
    {"AirBreak",        "طيران حر (AirBreak)",    "AirBreak Settings",        "إعدادات الطيران الحر",       false, 0, 1},
    {"Click Warp",      "انتقال بالماوس",         "Click Warp Settings",      "إعدادات الانتقال بالماوس",   false, 0, 1},
    {"High Jump",       "قفزة خارقة",             "High Jump Settings",       "إعدادات القفزة الخارقة",     false, 0, 1},
    {"Money Exploit",   "ثغرة الأموال (Money)",   "Money Exploit Settings",   "إعدادات ثغرة الأموال",       false, 0, 1},
    {"Jetpack",         "حقيبة نفاثة (Jetpack)",  "Jetpack Settings",         "إعدادات الحقيبة النفاثة",    false, 0, 1},
    {"All Weapons",     "جميع الأسلحة",           "All Weapons Settings",     "إعدادات جميع الأسلحة",       false, 0, 1},
};

static Feature s_vehicleFeatures[] = {
    {"Vehicle GodMode", "خلود المركبة",          "Vehicle GodMode Settings", "إعدادات خلود المركبة",     false, 0, 1},
    {"Vehicle Chaos",   "فوضى المركبات",         "Vehicle Chaos Settings",   "إعدادات فوضى المركبات",    false, 0, 1},
    {"Drive Water",     "القيادة على الماء",     "Drive Water Settings",     "إعدادات القيادة على الماء",false, 0, 1},
    {"Fast Stop",       "توقف فوري سريع",        "Fast Stop Settings",       "إعدادات التوقف السريع",    false, 0, 1},
    {"Fall Bike",       "عدم السقوط من الدراجة", "Fall Bike Settings",       "إعدادات ثبات الدراجة",     false, 0, 1},
    {"Flying Car",      "طيران المركبة",         "Flying Car Settings",      "إعدادات طيران المركبة",    false, 0, 1},
    {"Start Engine",    "تشغيل المحرك",          "Start Engine Settings",    "إعدادات تشغيل المحرك",     false, 0, 1},
    {"Repair Car",      "إصلاح المركبة",         "Repair Car Settings",      "إعدادات إصلاح المركبة",    false, 0, 1},
    {"Unlock Car",      "فتح قفل المركبات",      "Unlock Car Settings",      "إعدادات فتح المركبات",     false, 0, 1},
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
        hs->bCrasher       = s_cheatFeatures[6].on ? 1 : 0;
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
 * Shared live hook state (Resources, Events, Packets, Dumper, Markers)
 * =========================================================================== */
struct DumperFileEntry {
    std::string name;
    std::string code;
};
struct PacketRow { std::string name; int id; bool blocked; std::string time; };
struct MarkerRow { std::string name; float x, y, z; };

static std::vector<std::string>     s_resources;
static std::vector<std::string>     s_blockedEvents;
static std::vector<std::string>     s_recentTriggers;
static bool                         s_blockAllEvents = false;
static std::vector<PacketRow>       s_packets;
static bool                         s_packetsPopulated = false;
static std::vector<DumperFileEntry> s_dumperEntries;
static std::vector<MarkerRow>       s_markers;
static std::string                  s_status = "No connected server.";

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

/* Matches RecordCapturedScript (VA 0x10004220..0x10004473 in NRTH.dll) */
extern "C" void NrthUI_OnClientScriptLoaded(const char *chunkName, const char *code, size_t len)
{
    if (!chunkName || !chunkName[0] || !code || len == 0) {
        return;
    }
    if (chunkName[0] == '&' ||
        (chunkName[0] == '-' && chunkName[1] == '-') ||
        strstr(chunkName, "custom") != nullptr) {
        return;
    }
    s_status = "Server connected.";

    const char *p = chunkName;
    while (*p == '@' || *p == ':' || *p == '\\' || *p == '/') ++p;
    const char *sep = p;
    while (*sep && *sep != '\\' && *sep != '/') ++sep;
    if (*sep && sep > p && (size_t)(sep - p) < 64) {
        std::string resName(p, (size_t)(sep - p));
        NrthUI_OnResourceStarted(resName.c_str());
    }

    for (auto &entry : s_dumperEntries) {
        if (entry.name == chunkName) {
            entry.code.assign(code, len);
            return;
        }
    }
    if (s_dumperEntries.size() < 512) {
        s_dumperEntries.push_back({ chunkName, std::string(code, len) });
    }
}

/* Matches Hook_Client_100050a0 & Hook_Client_100056f0 */
extern "C" bool NrthUI_ShouldBlockServerEvent(const char *eventName)
{
    if (!eventName || !eventName[0]) {
        return false;
    }
    bool seen = false;
    for (const auto &ev : s_recentTriggers) {
        if (ev == eventName) {
            seen = true;
            break;
        }
    }
    if (!seen && s_recentTriggers.size() < 256) {
        s_recentTriggers.push_back(eventName);
    }
    if (s_blockAllEvents) {
        char msg[160];
        snprintf(msg, sizeof(msg), "Trigger blocked: %s", eventName);
        NrthUI_PushToastNotification(msg);
        return true;
    }
    for (const auto &blk : s_blockedEvents) {
        if (blk == eventName) {
            char msg[160];
            snprintf(msg, sizeof(msg), "Trigger blocked: %s", eventName);
            NrthUI_PushToastNotification(msg);
            return true;
        }
    }
    return false;
}

/* Matches Hook_Client_100052b0 */
extern "C" void NrthUI_OnResourceStarted(const char *resName)
{
    if (!resName || !resName[0]) {
        return;
    }
    s_status = "Server connected.";
    for (const auto &r : s_resources) {
        if (r == resName) {
            return;
        }
    }
    if (s_resources.size() < 256) {
        s_resources.push_back(resName);
    }
}

/* Matches Hook_Netc_SendPacket_1001da80 packet table lookup */
extern "C" bool NrthUI_OnPacketSent(unsigned char packetId)
{
    EnsurePacketsPopulated();
    bool blocked = false;
    for (auto &p : s_packets) {
        if (p.id == (int)packetId) {
            p.time = "live";
            if (p.blocked) {
                blocked = true;
            }
        }
    }
    return blocked;
}

extern "C" uint32_t NrthUI_GetMarkerCount(void)
{
    return (uint32_t)s_markers.size();
}

extern "C" bool NrthUI_GetMarkerAt(uint32_t idx, float *outX, float *outY, float *outZ)
{
    if (idx >= s_markers.size()) {
        return false;
    }
    if (outX) *outX = s_markers[idx].x;
    if (outY) *outY = s_markers[idx].y;
    if (outZ) *outZ = s_markers[idx].z;
    return true;
}

/* ===========================================================================
 * Lua VM Bridge execution
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
    } else if (vmMode > 0 && (uint32_t)(vmMode - 1) < bridge->slotCount &&
               (uint32_t)(vmMode - 1) < NRTH_VM_REGISTRY_CAP) {
        void *cand = (void *)(uintptr_t)bridge->registry_1013bf04[vmMode - 1].luaStatePtr32;
        if (cand && Nrth_IsPointerReadable_VirtualQuery(cand)) {
            targetL = cand;
        }
    }
    if (!targetL && bridge->slotCount > 0) {
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
 * BOT LAB core — pure, ImGui-free, testable in both suite modes.
 * Local-bot feature (by XRAOUF request): client-side peds created through the
 * game's own client-side Lua (createPed) — visible ONLY to the local player.
 * This cannot and does not create server-side players: in MTA:SA only the
 * server can add players, so nothing here joins/forges network sessions
 * (authorized blue-team lab use on the operator's own server).
 * =========================================================================== */
extern void *g_pClientGame_10148ee8; /* defined in nrth_hook.cpp */

extern "C" uint8_t NrthHook_IsInGame(void)
{
    return g_pClientGame_10148ee8 != NULL;
}

static uint32_t s_botLabDeployed = 0;
static uint32_t s_stayModeOn     = 0;

extern "C" uint32_t NrthUI_GetBotLabDeployed(void)    { return s_botLabDeployed; }
extern "C" void     NrthUI_SetBotLabDeployed(uint32_t n) { s_botLabDeployed = n; }
extern "C" uint32_t NrthUI_IsStayModeOn(void)         { return s_stayModeOn; }
extern "C" void     NrthUI_SetStayMode(uint32_t on)   { s_stayModeOn = on ? 1u : 0u; }

extern "C" void NrthUI_BuildBotsDeployLua(int count, char *buf, size_t cap)
{
    if (!buf || cap == 0) {
        return;
    }
    if (count < 1)   count = 1;
    if (count > 64)  count = 64;
    snprintf(buf, cap,
        "-- DARKANARCHY BOT LAB | DEV: XRAOUF (local peds, this client only)\n"
        "daBots = daBots or {}\n"
        "local n = %d\n"
        "local lp = getLocalPlayer()\n"
        "local px, py, pz = getElementPosition(lp)\n"
        "local skins = {7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30}\n"
        "for i = 1, n do\n"
        "    local a  = (i / n) * math.pi * 2\n"
        "    local bx = px + 3.0 * math.cos(a)\n"
        "    local by = py + 3.0 * math.sin(a)\n"
        "    local ped = createPed(skins[(i %% #skins) + 1], bx, by, pz)\n"
        "    if ped then\n"
        "        setElementHealth(ped, 100)\n"
        "        table.insert(daBots, ped)\n"
        "    end\n"
        "end\n"
        "if daBotTimer then killTimer(daBotTimer) end\n"
        "daBotTimer = setTimer(function()\n"
        "    for _, p in ipairs(daBots) do\n"
        "        if isElement(p) then\n"
        "            local x, y, z = getElementPosition(p)\n"
        "            setPedRotation(p, math.random(0, 359))\n"
        "            setElementPosition(p, x + math.random(-2, 2), y + math.random(-2, 2), z)\n"
        "        end\n"
        "    end\n"
        "end, 1500, 0)\n",
        count);
}

extern "C" void NrthUI_BuildBotsRemoveLua(char *buf, size_t cap)
{
    if (!buf || cap == 0) {
        return;
    }
    snprintf(buf, cap,
        "-- DARKANARCHY BOT LAB cleanup (local peds)\n"
        "if daBotTimer then killTimer(daBotTimer) daBotTimer = nil end\n"
        "if daBots then\n"
        "    for _, p in ipairs(daBots) do\n"
        "        if isElement(p) then destroyElement(p) end\n"
        "    end\n"
        "end\n"
        "daBots = nil\n");
}

extern "C" void NrthUI_BuildGhostTwinLua(char *buf, size_t cap)
{
    if (!buf || cap == 0) {
        return;
    }
    snprintf(buf, cap,
        "-- DARKANARCHY STAY MODE | local ghost twin (this client only)\n"
        "if daGhost and isElement(daGhost) then destroyElement(daGhost) end\n"
        "local lp = getLocalPlayer()\n"
        "local sk = getElementModel(lp)\n"
        "local x, y, z = getElementPosition(lp)\n"
        "daGhost = createPed((sk and sk ~= 0) and sk or 7, x, y - 1.5, z)\n"
        "if daGhost then setElementFrozen(daGhost, true) end\n");
}

/* ===========================================================================
 * Full Dear ImGui + Embedded Lua 5.4.6 UI (Windows build)
 * =========================================================================== */
#if (defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)) || defined(NRTH_UI_HEADLESS)

#include "imgui.h"

#ifndef _WIN32
/* NRTH_UI_HEADLESS (Linux verification harness): minimal Win32/D3D9 shims so
 * the real ImGui UI compiles and runs headless. Compiled out on Windows. */
#include <time.h>
#include "nrth_d3d9_headless.h"
typedef unsigned long long ULONGLONG;
typedef unsigned long       DWORD_;
typedef void               *HANDLE;
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)
#endif
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010u
#define TRUE  1
#define FALSE 0
#ifndef VK_LBUTTON
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_ESCAPE  0x1B
#endif
struct WIN32_FIND_DATAA {
    DWORD_ dwFileAttributes;
    char   cFileName[260];
};
static unsigned short GetAsyncKeyState(int /*vk*/) { return 0; }
static ULONGLONG GetTickCount64(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ULONGLONG)ts.tv_sec * 1000ull + (ULONGLONG)ts.tv_nsec / 1000000ull;
}
static HANDLE FindFirstFileA(const char * /*sz*/, WIN32_FIND_DATAA *fd)
{
    if (fd) { fd->dwFileAttributes = 0; fd->cFileName[0] = '\0'; }
    return INVALID_HANDLE_VALUE; /* no files visible in the headless harness */
}
static int FindNextFileA(HANDLE /*h*/, WIN32_FIND_DATAA * /*fd*/) { return FALSE; }
static int FindClose(HANDLE /*h*/) { return TRUE; }
static int CreateDirectoryA(const char * /*path*/, void * /*sa*/) { return FALSE; }
static int DeleteFileA(const char * /*path*/) { return FALSE; }
#endif /* !_WIN32 */


extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

/* ---- Language & Font / Texture state ---- */
static int                s_lang         = 0; /* 0 = Arabic (العربية), 1 = English */

#ifdef NRTH_UI_HEADLESS
/* Verification-harness-only hook (never compiled into the Windows DLL):
 * lets the headless test drive the live language switch like the UI button. */
extern "C" void NrthUI_TestSetLanguage(int lang) { s_lang = lang ? 1 : 0; }
#endif
static ImFont            *s_pFontMain    = nullptr;
static ImFont            *s_pFontTitle   = nullptr;
static ImFont            *s_pFontArabic  = nullptr;
static IDirect3DTexture9 *s_pLogoTexture = nullptr;
static IDirect3DTexture9 *s_pBgTexture   = nullptr;
static bool               s_showBgImage     = true;
static bool               s_showLogoImg     = true;
static bool               s_showParticles   = true;
static bool               s_customCrosshair = false;
static float              s_bgOpacity       = 0.34f;
static float              s_uiScale         = 1.00f;
static int                s_fontMode        = 0; /* 0 = Hybrid EN+AR TTF, 1 = Arabic-First TTF */
static int                s_themePreset     = 0;

/* Ring buffer for shaped Arabic UTF-8 strings so returned const char* stays valid all frame */
static const char *AR(const char *rawArabic)
{
    static std::string s_ring[128];
    static uint32_t    s_ringIdx = 0;
    uint32_t slot = (s_ringIdx++) & 127u;
    s_ring[slot] = Nrth_ShapeArabicUTF8(rawArabic);
    return s_ring[slot].c_str();
}

/* Bilingual string selector: returns shaped Arabic when s_lang == 0, English when s_lang == 1 */
static const char *TR(const char *en, const char *ar)
{
    if (s_lang == 0 && ar && ar[0]) {
        return AR(ar);
    }
    return en ? en : "";
}

/* ---- Self-contained QOI -> D3DFMT_A8R8G8B8 texture loader ---- */
static IDirect3DTexture9 *CreateTextureFromQoi(IDirect3DDevice9 *pDev,
                                               const unsigned char *data, size_t size)
{
    if (!pDev || !data || size < 22) return nullptr;
    if (data[0] != 'q' || data[1] != 'o' || data[2] != 'i' || data[3] != 'f') return nullptr;

    uint32_t w = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                 ((uint32_t)data[6] << 8)  | (uint32_t)data[7];
    uint32_t h = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                 ((uint32_t)data[10] << 8) | (uint32_t)data[11];
    if (w == 0 || h == 0 || w > 2048 || h > 2048) return nullptr;

    IDirect3DTexture9 *pTex = nullptr;
    if (FAILED(pDev->CreateTexture(w, h, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &pTex, NULL)) || !pTex) {
        return nullptr;
    }

    D3DLOCKED_RECT lr;
    if (FAILED(pTex->LockRect(0, &lr, NULL, 0))) {
        pTex->Release();
        return nullptr;
    }

    struct Rgba { uint8_t r, g, b, a; };
    Rgba index[64];
    memset(index, 0, sizeof(index));
    Rgba px = { 0, 0, 0, 255 };

    size_t pos = 14;
    size_t endPos = size - 8;
    int run = 0;

    for (uint32_t y = 0; y < h; ++y) {
        uint8_t *row = (uint8_t *)lr.pBits + y * lr.Pitch;
        for (uint32_t x = 0; x < w; ++x) {
            if (run > 0) {
                --run;
            } else if (pos < endPos) {
                uint8_t b1 = data[pos++];
                if (b1 == 0xFE && pos + 3 <= endPos) {
                    px.r = data[pos++];
                    px.g = data[pos++];
                    px.b = data[pos++];
                } else if (b1 == 0xFF && pos + 4 <= endPos) {
                    px.r = data[pos++];
                    px.g = data[pos++];
                    px.b = data[pos++];
                    px.a = data[pos++];
                } else if ((b1 & 0xC0) == 0x00) {
                    px = index[b1 & 63];
                } else if ((b1 & 0xC0) == 0x40) {
                    px.r = (uint8_t)(px.r + ((b1 >> 4) & 0x03) - 2);
                    px.g = (uint8_t)(px.g + ((b1 >> 2) & 0x03) - 2);
                    px.b = (uint8_t)(px.b + ( b1       & 0x03) - 2);
                } else if ((b1 & 0xC0) == 0x80 && pos < endPos) {
                    uint8_t b2 = data[pos++];
                    int vg = (b1 & 0x3F) - 32;
                    px.r = (uint8_t)(px.r + vg - 8 + ((b2 >> 4) & 0x0F));
                    px.g = (uint8_t)(px.g + vg);
                    px.b = (uint8_t)(px.b + vg - 8 + ( b2       & 0x0F));
                } else if ((b1 & 0xC0) == 0xC0) {
                    run = (b1 & 0x3F);
                }
                index[(px.r * 3 + px.g * 5 + px.b * 7 + px.a * 11) & 63] = px;
            }
            /* D3DFMT_A8R8G8B8 is B, G, R, A in little-endian memory */
            row[x * 4 + 0] = px.b;
            row[x * 4 + 1] = px.g;
            row[x * 4 + 2] = px.r;
            row[x * 4 + 3] = px.a;
        }
    }

    pTex->UnlockRect(0);
    return pTex;
}

extern "C" void NrthUI_InitFonts(void)
{
    ImGuiIO &io = ImGui::GetIO();
    io.Fonts->Clear();
    /* Clear() empties the atlas: cached ImFont* from a previous context/atlas
     * are dangling, and leaving them set would skip the first AddFont below
     * (breaking MergeMode's "first font" rule on a fresh atlas). */
    s_pFontMain = s_pFontTitle = s_pFontArabic = nullptr;

    static const ImWchar kArabicRanges[] = {
        0x0020, 0x00FF, /* Basic Latin + Supplement */
        0x0600, 0x06FF, /* Arabic */
        0x0750, 0x077F, /* Arabic Supplement */
        0x2000, 0x206F, /* General Punctuation */
        0xFB50, 0xFDFF, /* Arabic Presentation Forms-A */
        0xFE70, 0xFEFF, /* Arabic Presentation Forms-B */
        0,
    };

    /* 1. Main UI Font: English TTF (ChakraPetch SemiBold) + Merged Arabic TTF (Tajawal Bold) */
    ImFontConfig enCfg;
    enCfg.FontDataOwnedByAtlas = false;
    enCfg.OversampleH          = 2;
    enCfg.OversampleV          = 2;
    enCfg.PixelSnapH           = true;

    FILE *fEn = fopen("fonts\\DarkAnarchy-English.ttf", "rb");
    if (fEn) {
        fclose(fEn);
        s_pFontMain = io.Fonts->AddFontFromFileTTF("fonts\\DarkAnarchy-English.ttf", 16.5f, &enCfg, io.Fonts->GetGlyphRangesDefault());
    }
    if (!s_pFontMain) {
        s_pFontMain = io.Fonts->AddFontFromMemoryTTF((void *)kDarkAnarchyEnglishTtf,
                                                     (int)sizeof(kDarkAnarchyEnglishTtf),
                                                     16.5f, &enCfg, io.Fonts->GetGlyphRangesDefault());
    }

    ImFontConfig arMergeCfg;
    arMergeCfg.FontDataOwnedByAtlas = false;
    arMergeCfg.MergeMode            = true;
    arMergeCfg.OversampleH          = 2;
    arMergeCfg.OversampleV          = 2;
    arMergeCfg.PixelSnapH           = true;
    arMergeCfg.GlyphOffset          = ImVec2(0.0f, 1.0f);

    FILE *fAr = fopen("fonts\\DarkAnarchy-Arabic.ttf", "rb");
    if (fAr) {
        fclose(fAr);
        io.Fonts->AddFontFromFileTTF("fonts\\DarkAnarchy-Arabic.ttf", 18.5f, &arMergeCfg, kArabicRanges);
    } else {
        io.Fonts->AddFontFromMemoryTTF((void *)kDarkAnarchyArabicTtf,
                                       (int)sizeof(kDarkAnarchyArabicTtf),
                                       18.5f, &arMergeCfg, kArabicRanges);
    }

    /* 2. Large Title/Header Font (English 21px + Arabic 23px) */
    ImFontConfig titleEnCfg;
    titleEnCfg.FontDataOwnedByAtlas = false;
    titleEnCfg.OversampleH          = 2;
    titleEnCfg.OversampleV          = 2;
    s_pFontTitle = io.Fonts->AddFontFromMemoryTTF((void *)kDarkAnarchyEnglishTtf,
                                                  (int)sizeof(kDarkAnarchyEnglishTtf),
                                                  21.0f, &titleEnCfg, io.Fonts->GetGlyphRangesDefault());
    ImFontConfig titleArCfg;
    titleArCfg.FontDataOwnedByAtlas = false;
    titleArCfg.MergeMode            = true;
    titleArCfg.OversampleH          = 2;
    titleArCfg.OversampleV          = 2;
    titleArCfg.GlyphOffset          = ImVec2(0.0f, 1.0f);
    io.Fonts->AddFontFromMemoryTTF((void *)kDarkAnarchyArabicTtf,
                                   (int)sizeof(kDarkAnarchyArabicTtf),
                                   23.0f, &titleArCfg, kArabicRanges);

    /* 3. Dedicated Arabic-first Font */
    ImFontConfig arBaseCfg;
    arBaseCfg.FontDataOwnedByAtlas = false;
    arBaseCfg.OversampleH          = 2;
    arBaseCfg.OversampleV          = 2;
    s_pFontArabic = io.Fonts->AddFontFromMemoryTTF((void *)kDarkAnarchyArabicTtf,
                                                   (int)sizeof(kDarkAnarchyArabicTtf),
                                                   18.5f, &arBaseCfg, kArabicRanges);

    io.FontDefault = s_pFontMain;
}

extern "C" void NrthUI_InitTextures(void *pD3DDevice9)
{
    IDirect3DDevice9 *pDev = (IDirect3DDevice9 *)pD3DDevice9;
    if (!pDev) return;
    if (!s_pLogoTexture) {
        s_pLogoTexture = CreateTextureFromQoi(pDev, kDarkAnarchyLogoQoi, sizeof(kDarkAnarchyLogoQoi));
    }
    if (!s_pBgTexture) {
        s_pBgTexture = CreateTextureFromQoi(pDev, kDarkAnarchyBgQoi, sizeof(kDarkAnarchyBgQoi));
    }
}

extern "C" void NrthUI_ReleaseTextures(void)
{
    if (s_pLogoTexture) {
        s_pLogoTexture->Release();
        s_pLogoTexture = nullptr;
    }
    if (s_pBgTexture) {
        s_pBgTexture->Release();
        s_pBgTexture = nullptr;
    }
}

/* ---- Embedded Lua 5.4.6 state ---- */
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
    if (NrthUI_ExecuteLuaViaBridge(code, len, vmMode)) {
        return true;
    }

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
static int  s_cheatSub   = 1; /* Default to Features subtab in Cheat for instant access */
static bool s_menuOpen   = true;

#ifdef NRTH_UI_HEADLESS
/* harness-only: lets the headless test open any tab like a sidebar click */
extern "C" void NrthUI_TestSetTab(int tab) { s_topTab = tab; }
#endif

static char s_editorBuf[65536] =
    "-- ==========================================\n"
    "-- DARKANARCHY LUA EXECUTOR | DEV: XRAOUF\n"
    "-- ==========================================\n"
    "print('DARKANARCHY by XRAOUF initialized!')\n";
static int  s_vmIndex     = 0;

static std::string s_lastAction;

struct ScriptItem { std::string name; bool autoInject; };
static std::vector<ScriptItem> s_scripts;
static int  s_scriptSel = -1;
static bool s_scriptsScanned = false;

static char s_packetSearch[64] = "";
static int  s_packetSel = -1;

struct PlayerRow { std::string name; bool isYou; };
static std::vector<PlayerRow> s_players;
static std::vector<std::string> s_friends;
static char s_playerFilterBuf[64] = "";
static int  s_playerSel = 0;
static char s_markerName[64] = "";

struct ConfigItem { std::string name; };
static std::vector<ConfigItem> s_configs;
static bool s_configsScanned = false;
static char s_cfgName[64] = "darkanarchy_xraouf";
static int  s_cfgSel = -1;
static bool s_waitingForKey = false;

struct Bind { std::string action; int key; int mode; };
static std::vector<Bind> s_binds;

static int s_vehicleSel = 0;

/* ===========================================================================
 * Dynamic Theme Palette for DARKANARCHY (5 Presets + Custom Color Editor)
 * =========================================================================== */
static ImVec4 g_colAccent      = ImVec4(0.92f, 0.14f, 0.34f, 1.00f); /* Neon Crimson */
static ImVec4 g_colAccentHover = ImVec4(1.00f, 0.24f, 0.45f, 1.00f); /* Bright Crimson Glow */
static ImVec4 g_colSecondary   = ImVec4(0.62f, 0.18f, 0.88f, 1.00f); /* Cyber Anarchy Violet */
static ImVec4 g_colTabIdle     = ImVec4(0.12f, 0.08f, 0.17f, 0.90f);
static ImVec4 g_colPanelBg     = ImVec4(0.07f, 0.05f, 0.11f, 0.86f);
static ImVec4 g_colWindowBg    = ImVec4(0.04f, 0.03f, 0.07f, 0.96f);

static void ApplyThemePreset(int preset)
{
    s_themePreset = preset;
    switch (preset) {
        case 0: /* Dark Anarchy (Crimson & Cyber Violet - Matches AI Logo) */
            g_colAccent      = ImVec4(0.92f, 0.14f, 0.34f, 1.00f);
            g_colAccentHover = ImVec4(1.00f, 0.26f, 0.46f, 1.00f);
            g_colSecondary   = ImVec4(0.62f, 0.18f, 0.88f, 1.00f);
            g_colTabIdle     = ImVec4(0.13f, 0.07f, 0.18f, 0.90f);
            g_colPanelBg     = ImVec4(0.07f, 0.04f, 0.11f, 0.84f);
            g_colWindowBg    = ImVec4(0.04f, 0.02f, 0.07f, 0.96f);
            break;
        case 1: /* Blood Moon (Aggressive Crimson & Pitch Black) */
            g_colAccent      = ImVec4(0.95f, 0.08f, 0.18f, 1.00f);
            g_colAccentHover = ImVec4(1.00f, 0.22f, 0.30f, 1.00f);
            g_colSecondary   = ImVec4(0.60f, 0.04f, 0.12f, 1.00f);
            g_colTabIdle     = ImVec4(0.14f, 0.05f, 0.07f, 0.90f);
            g_colPanelBg     = ImVec4(0.08f, 0.03f, 0.05f, 0.86f);
            g_colWindowBg    = ImVec4(0.04f, 0.02f, 0.03f, 0.97f);
            break;
        case 2: /* Abyss Violet (Neon Amethyst & Deep Space) */
            g_colAccent      = ImVec4(0.58f, 0.22f, 0.96f, 1.00f);
            g_colAccentHover = ImVec4(0.70f, 0.36f, 1.00f, 1.00f);
            g_colSecondary   = ImVec4(0.92f, 0.18f, 0.64f, 1.00f);
            g_colTabIdle     = ImVec4(0.13f, 0.08f, 0.22f, 0.90f);
            g_colPanelBg     = ImVec4(0.07f, 0.05f, 0.14f, 0.86f);
            g_colWindowBg    = ImVec4(0.04f, 0.03f, 0.09f, 0.96f);
            break;
        case 3: /* XRAOUF Royal Gold (Luxury Gold & Obsidian) */
            g_colAccent      = ImVec4(0.95f, 0.68f, 0.14f, 1.00f);
            g_colAccentHover = ImVec4(1.00f, 0.78f, 0.28f, 1.00f);
            g_colSecondary   = ImVec4(0.85f, 0.32f, 0.12f, 1.00f);
            g_colTabIdle     = ImVec4(0.15f, 0.12f, 0.07f, 0.90f);
            g_colPanelBg     = ImVec4(0.08f, 0.07f, 0.05f, 0.86f);
            g_colWindowBg    = ImVec4(0.05f, 0.04f, 0.03f, 0.96f);
            break;
        case 4: /* Cyber Matrix (Neon Emerald & Dark Slate) */
            g_colAccent      = ImVec4(0.05f, 0.86f, 0.58f, 1.00f);
            g_colAccentHover = ImVec4(0.18f, 0.96f, 0.68f, 1.00f);
            g_colSecondary   = ImVec4(0.06f, 0.55f, 0.90f, 1.00f);
            g_colTabIdle     = ImVec4(0.06f, 0.15f, 0.14f, 0.90f);
            g_colPanelBg     = ImVec4(0.04f, 0.09f, 0.09f, 0.86f);
            g_colWindowBg    = ImVec4(0.02f, 0.05f, 0.06f, 0.96f);
            break;
    }

    ImGuiStyle &st = ImGui::GetStyle();
    st.WindowRounding    = 12.f;
    st.ChildRounding     = 9.f;
    st.FrameRounding     = 6.f;
    st.PopupRounding     = 8.f;
    st.GrabRounding      = 6.f;
    st.ScrollbarRounding = 8.f;
    st.WindowBorderSize  = 1.5f;
    st.ChildBorderSize   = 1.0f;
    st.FrameBorderSize   = 1.0f;
    st.WindowPadding     = ImVec2(14, 14);
    st.FramePadding      = ImVec2(10, 6);
    st.ItemSpacing       = ImVec2(9, 7);

    ImVec4 *c = st.Colors;
    c[ImGuiCol_WindowBg]             = g_colWindowBg;
    c[ImGuiCol_ChildBg]              = g_colPanelBg;
    c[ImGuiCol_PopupBg]              = ImVec4(0.08f, 0.05f, 0.13f, 0.97f);
    c[ImGuiCol_Border]               = ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.38f);
    c[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    c[ImGuiCol_FrameBg]              = ImVec4(0.11f, 0.07f, 0.16f, 0.92f);
    c[ImGuiCol_FrameBgHovered]       = ImVec4(g_colAccent.x * 0.45f, g_colAccent.y * 0.45f, g_colAccent.z * 0.45f, 0.95f);
    c[ImGuiCol_FrameBgActive]        = g_colAccent;
    c[ImGuiCol_Button]               = g_colTabIdle;
    c[ImGuiCol_ButtonHovered]        = g_colAccentHover;
    c[ImGuiCol_ButtonActive]         = g_colAccent;
    c[ImGuiCol_Header]               = ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.35f);
    c[ImGuiCol_HeaderHovered]        = g_colAccentHover;
    c[ImGuiCol_HeaderActive]         = g_colAccent;
    c[ImGuiCol_Tab]                  = g_colTabIdle;
    c[ImGuiCol_TabHovered]           = g_colAccentHover;
    c[ImGuiCol_TabActive]            = g_colAccent;
    c[ImGuiCol_TitleBg]              = g_colWindowBg;
    c[ImGuiCol_TitleBgActive]        = g_colWindowBg;
    c[ImGuiCol_Separator]            = ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.35f);
    c[ImGuiCol_CheckMark]            = g_colAccentHover;
    c[ImGuiCol_SliderGrab]           = g_colAccent;
    c[ImGuiCol_SliderGrabActive]     = g_colAccentHover;
    c[ImGuiCol_ScrollbarBg]          = ImVec4(0.04f, 0.02f, 0.07f, 0.60f);
    c[ImGuiCol_ScrollbarGrab]        = ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.55f);
    c[ImGuiCol_ScrollbarGrabHovered] = g_colAccentHover;
    c[ImGuiCol_ScrollbarGrabActive]  = g_colAccent;
    c[ImGuiCol_Text]                 = ImVec4(0.97f, 0.95f, 0.99f, 1.00f);
    c[ImGuiCol_TextDisabled]         = ImVec4(0.58f, 0.52f, 0.68f, 1.00f);
}

void NrthUI_ApplyTheme()
{
    ApplyThemePreset(0);
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

extern "C" void NrthUI_PushToastNotification(const char *msg)
{
    AddNotification_10002cd0(msg);
}

static void FeatureAction(const char *msg)
{
    s_lastAction = msg ? msg : "";
    NrthUI_SyncFeaturesToState();
    AddNotification_10002cd0(msg);
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

/* ---- Custom Styled Navigation & Pill Buttons ---- */
static bool SidebarTabButton(const char *iconBadge, const char *label, const char *subLabel,
                             const char *hiddenId, bool active, const ImVec2 &size)
{
    ImGui::PushID(hiddenId);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList *dl = ImGui::GetWindowDrawList();

    ImU32 bgCol = active
        ? ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccent.x * 0.28f, g_colAccent.y * 0.28f, g_colAccent.z * 0.28f, 0.95f))
        : ImGui::ColorConvertFloat4ToU32(ImVec4(0.10f, 0.06f, 0.15f, 0.72f));

    bool clicked = ImGui::InvisibleButton("##navbtn", size);
    bool hovered = ImGui::IsItemHovered();
    if (hovered && !active) {
        bgCol = ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccent.x * 0.18f, g_colAccent.y * 0.18f, g_colAccent.z * 0.18f, 0.88f));
    }

    dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), bgCol, 8.0f);

    /* Glowing left accent bar when active */
    if (active) {
        ImU32 barCol = ImGui::ColorConvertFloat4ToU32(g_colAccentHover);
        dl->AddRectFilled(pos, ImVec2(pos.x + 4.5f, pos.y + size.y), barCol, 4.0f);
        dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y),
                    ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccentHover.x, g_colAccentHover.y, g_colAccentHover.z, 0.65f)),
                    8.0f, 0, 1.2f);
    } else if (hovered) {
        dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y),
                    ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.35f)),
                    8.0f, 0, 1.0f);
    }

    /* Icon badge pill */
    ImVec2 badgeMin(pos.x + 11.0f, pos.y + 8.0f);
    ImVec2 badgeMax(pos.x + 39.0f, pos.y + size.y - 8.0f);
    ImU32 badgeBg = active
        ? ImGui::ColorConvertFloat4ToU32(g_colAccent)
        : ImGui::ColorConvertFloat4ToU32(ImVec4(0.16f, 0.10f, 0.24f, 1.0f));
    dl->AddRectFilled(badgeMin, badgeMax, badgeBg, 6.0f);

    ImVec2 icSz = ImGui::CalcTextSize(iconBadge);
    dl->AddText(ImVec2(badgeMin.x + (28.0f - icSz.x) * 0.5f, badgeMin.y + (badgeMax.y - badgeMin.y - icSz.y) * 0.5f),
                IM_COL32(255, 255, 255, 255), iconBadge);

    /* Main label + subtitle */
    dl->AddText(ImVec2(pos.x + 48.0f, pos.y + 6.0f),
                active ? IM_COL32(255, 255, 255, 255) : IM_COL32(230, 224, 242, 235),
                label);
    if (subLabel && subLabel[0]) {
        dl->AddText(ImVec2(pos.x + 48.0f, pos.y + 24.0f),
                    active ? ImGui::ColorConvertFloat4ToU32(g_colAccentHover) : IM_COL32(148, 136, 172, 200),
                    subLabel);
    }

    ImGui::PopID();
    return clicked;
}

static bool SubTabPill(const char *label, const char *hiddenId, bool active, const ImVec2 &size)
{
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, g_colAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, g_colAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, g_colAccentHover);
        ImGui::PushStyleColor(ImGuiCol_Border, g_colAccentHover);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, g_colTabIdle);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(g_colAccent.x * 0.55f, g_colAccent.y * 0.55f, g_colAccent.z * 0.55f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, g_colAccent);
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, 0.25f));
    }
    char buf[160];
    snprintf(buf, sizeof(buf), "%s##%s", label, hiddenId);
    bool clicked = ImGui::Button(buf, size);
    ImGui::PopStyleColor(4);
    return clicked;
}

/* Custom modern pill Toggle Switch */
static bool DrawToggleSwitch(const char *id, bool *v)
{
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList *dl = ImGui::GetWindowDrawList();

    float height = 20.0f;
    float width  = 38.0f;
    float radius = height * 0.5f;

    bool clicked = ImGui::InvisibleButton("##toggle", ImVec2(width, height));
    if (clicked) {
        *v = !*v;
    }
    bool hovered = ImGui::IsItemHovered();

    ImU32 bgCol = *v
        ? ImGui::ColorConvertFloat4ToU32(hovered ? g_colAccentHover : g_colAccent)
        : ImGui::ColorConvertFloat4ToU32(hovered ? ImVec4(0.26f, 0.19f, 0.35f, 1.0f) : ImVec4(0.16f, 0.11f, 0.23f, 1.0f));

    dl->AddRectFilled(p, ImVec2(p.x + width, p.y + height), bgCol, radius);
    dl->AddRect(p, ImVec2(p.x + width, p.y + height),
                ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccentHover.x, g_colAccentHover.y, g_colAccentHover.z, *v ? 0.8f : 0.25f)),
                radius, 0, 1.0f);

    float knobX = *v ? (p.x + width - radius) : (p.x + radius);
    dl->AddCircleFilled(ImVec2(knobX, p.y + radius), radius - 3.0f, IM_COL32(255, 255, 255, 255));

    ImGui::PopID();
    return clicked;
}

static void DrawEditor()
{
    ImGui::BeginChild("##lua_gutter", ImVec2(48, -135), true);
    int lines = 1;
    for (const char *p = s_editorBuf; *p; ++p) if (*p == '\n') ++lines;
    for (int i = 1; i <= lines && i < 2000; ++i) {
        ImGui::TextDisabled("%d", i);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::PushItemWidth(-1);
    ImGui::InputTextMultiline("##lua_editor", s_editorBuf, sizeof(s_editorBuf),
                              ImVec2(-1, -135), ImGuiInputTextFlags_AllowTabInput);
    ImGui::PopItemWidth();

    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *customLabel = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                              0x2D, s_customChunk, &s_customGate);

    ImGui::PushStyleColor(ImGuiCol_Button, g_colAccent);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, g_colAccentHover);
    if (ImGui::Button(TR("Execute Script##exec", "تنفيذ السكربت##exec"), ImVec2(145, 34))) {
        s_console.clear();
        if (RunLuaBuffer(s_editorBuf, strlen(s_editorBuf), customLabel, s_vmIndex)) {
            FeatureAction(TR("Script executed", "تم تنفيذ السكربت بنجاح"));
        } else {
            FeatureAction(TR("Script error (see console)", "خطأ في السكربت (راجع المخرجات)"));
        }
    }
    ImGui::PopStyleColor(2);

    ImGui::SameLine();
    NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
    std::string vmPreview = "Default VM";
    if (s_vmIndex > 0 && bridge && (uint32_t)(s_vmIndex - 1) < bridge->slotCount &&
        (uint32_t)(s_vmIndex - 1) < NRTH_VM_REGISTRY_CAP) {
        const char *nm = (const char *)bridge->registry_1013bf04[s_vmIndex - 1].resourceMeta;
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "%s (0x%08X)", nm[0] ? nm : customLabel,
                 bridge->registry_1013bf04[s_vmIndex - 1].luaStatePtr32);
        vmPreview = lbl;
    }
    ImGui::SetNextItemWidth(210);
    if (ImGui::BeginCombo("##vm_combo", vmPreview.c_str())) {
        if (ImGui::Selectable("Default VM", s_vmIndex == 0)) {
            s_vmIndex = 0;
        }
        if (bridge) {
            for (uint32_t i = 0; i < bridge->slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
                const char *nm = (const char *)bridge->registry_1013bf04[i].resourceMeta;
                char lbl[64];
                snprintf(lbl, sizeof(lbl), "%s (0x%08X)##vm_%u", nm[0] ? nm : customLabel,
                         bridge->registry_1013bf04[i].luaStatePtr32, i);
                if (ImGui::Selectable(lbl, s_vmIndex == (int)(i + 1))) {
                    s_vmIndex = (int)(i + 1);
                }
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Clear##console", "مسح##console"), ImVec2(90, 34))) s_console.clear();
    ImGui::SameLine();
    ImGui::TextDisabled("%s", TR("Output Console:", "مخرجات التنفيذ:"));

    ImGui::BeginChild("##lua_console", ImVec2(-1, -1), true);
    if (s_console.empty()) {
        ImGui::TextDisabled("%s", TR("print(...) output appears here | DARKANARCHY Executor", "مخرجات print(...) تظهر هنا | منفذ DARKANARCHY"));
    } else {
        ImGui::TextUnformatted(s_console.c_str());
    }
    ImGui::EndChild();
}

static void DrawScriptsList()
{
    if (!s_scriptsScanned) ScanLuaScripts();
    ImGui::TextDisabled("%s", TR("Path: .\\lua\\  |  Place .lua scripts to inject", "المسار: .\\lua\\  |  ضع ملفات .lua للحقن المباشر"));
    ImGui::BeginChild("##scripts_list", ImVec2(-1, -50), true);
    if (s_scripts.empty()) {
        ImGui::TextDisabled("%s", TR("No scripts found in .\\lua\\", "لم يتم العثور على سكربتات في مجلد lua"));
    }
    for (int i = 0; i < (int)s_scripts.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_scripts[i].name.c_str(), s_scriptSel == i)) s_scriptSel = i;
        ImGui::SameLine(240);
        if (ImGui::SmallButton(TR("Inject##inj", "حقن##inj")))
            FeatureAction(("Injected: " + s_scripts[i].name).c_str());
        ImGui::SameLine();
        ImGui::Checkbox(TR("Auto-Inject##auto", "حقن تلقائي##auto"), &s_scripts[i].autoInject);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (ImGui::Button(TR("Refresh List##sc_ref", "تحديث القائمة##sc_ref"), ImVec2(120, 32))) {
        ScanLuaScripts();
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Dump##sc_dmp", "سحب المحدد##sc_dmp"), ImVec2(110, 32))) {
        if (s_scriptSel >= 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Dump script saved: %s", s_scripts[s_scriptSel].name.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Dump All##sc_dmpall", "سحب الكل##sc_dmpall"), ImVec2(110, 32))) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Dump all scripts saved (%d)", (int)s_scripts.size());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, g_colAccent);
    if (ImGui::Button(TR("Run Selected##script", "تشغيل المحدد##script"), ImVec2(130, 32)) && s_scriptSel >= 0) {
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
                FeatureAction(TR("Script executed", "تم تشغيل السكربت"));
            else
                FeatureAction(TR("Script error (see console)", "خطأ في تشغيل السكربت"));
        }
    }
    ImGui::PopStyleColor();
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
    ImGui::TextDisabled("%s", TR("Live CResourceManager Controller + Resource Cache", "متحكم موارد السيرفر المباشر (CResourceManager)"));
    static char search[64] = "";
    ImGui::InputTextWithHint("##res_search", TR("Search resource...", "ابحث عن مورد..."), search, sizeof(search));
    static int resSel = 0;
    if (resSel >= (int)s_resources.size()) resSel = 0;
    std::string preview = s_resources.empty() ? TR("Select Resource", "اختر المورد") : s_resources[resSel];
    ImGui::SetNextItemWidth(280);
    if (ImGui::BeginCombo("##res_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_resources.size(); ++i) {
            if (search[0] && s_resources[i].find(search) == std::string::npos) continue;
            if (ImGui::Selectable(s_resources[i].c_str(), resSel == i)) resSel = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::TextColored(g_colAccentHover, "(%d)", (int)s_resources.size());
    ImGui::SameLine();
    if (ImGui::Button(TR("Stop Resource##stop_res", "إيقاف المورد##stop_res"), ImVec2(140, 32))) {
        if (!s_resources.empty() && resSel >= 0 && resSel < (int)s_resources.size()) {
            std::string stoppedName = s_resources[resSel];
            Nrth_StopClientResource_100054a0(stoppedName.c_str());
            s_resources.erase(s_resources.begin() + resSel);
            if (resSel >= (int)s_resources.size() && resSel > 0) --resSel;
            char msg[128];
            snprintf(msg, sizeof(msg), "Resource stopped: %s", stoppedName.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("%s", TR("Blocked Events List:", "قائمة الأحداث المحظورة:"));
    for (auto &e : s_blockedEvents) ImGui::BulletText("%s (blocked)", e.c_str());
}

static void DrawEvents()
{
    static int evSel = 0;
    static const char *kEvents[] = {"onClientRender", "onClientPlayerDamage", "onClientVehicleEnter",
                                    "onClientChatMessage", "onClientElementDataChange", "onClientPreRender"};
    ImGui::SetNextItemWidth(260);
    if (ImGui::BeginCombo("##event_combo", kEvents[evSel])) {
        for (int i = 0; i < 6; ++i) if (ImGui::Selectable(kEvents[i], evSel == i)) evSel = i;
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Block##event", "حظر##event"), ImVec2(90, 30))) {
        s_blockedEvents.push_back(kEvents[evSel]);
        FeatureAction(("Event blocked: " + std::string(kEvents[evSel])).c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Unblock##event", "فك الحظر##event"), ImVec2(95, 30)) && !s_blockedEvents.empty()) {
        FeatureAction(("Event unblocked: " + s_blockedEvents.back()).c_str());
        s_blockedEvents.pop_back();
    }
    ImGui::SameLine();
    ImGui::Checkbox(TR("Block All Events##blkall", "حظر جميع الأحداث##blkall"), &s_blockAllEvents);

    static char trig[96] = "";
    ImGui::InputTextWithHint("##trigger_input", TR("triggerServerEvent name...", "اسم الحدث triggerServerEvent..."), trig, sizeof(trig));
    ImGui::SameLine();
    if (ImGui::Button(TR("Add to Block List##add_blk", "إضافة لقائمة الحظر##add_blk")) && trig[0]) {
        s_blockedEvents.push_back(trig);
        FeatureAction(("Event blocked: " + std::string(trig)).c_str());
        trig[0] = 0;
    }
    ImGui::Separator();
    ImGui::Text("%s", TR("Recent Triggers (click Block to filter):", "الأحداث الملتقطة مؤخراً (اضغط حظر للفلترة):"));
    if (s_recentTriggers.empty()) ImGui::TextDisabled("%s", TR("No triggers captured yet", "لا توجد أحداث ملتقطة بعد"));
    for (int i = 0; i < (int)s_recentTriggers.size(); ++i) {
        ImGui::PushID(i);
        ImGui::BulletText("%s", s_recentTriggers[i].c_str());
        ImGui::SameLine(280);
        if (ImGui::SmallButton(TR("Block##tr", "حظر##tr"))) {
            s_blockedEvents.push_back(s_recentTriggers[i]);
            FeatureAction(("Event blocked: " + s_recentTriggers[i]).c_str());
        }
        ImGui::PopID();
    }
}

static void DrawEventsTable()
{
    ImGui::TextDisabled("%s", TR("Events Table (Live Event Registry View)", "جدول الأحداث المباشر (سجل الأحداث)"));
    if (ImGui::BeginTable("##events_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn(TR("Event", "الحدث"));
        ImGui::TableSetupColumn(TR("Source", "المصدر"));
        ImGui::TableSetupColumn(TR("State", "الحالة"));
        ImGui::TableHeadersRow();
        for (auto &e : s_recentTriggers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextDisabled("%s", TR("tracked", "مراقب"));
        }
        for (auto &e : s_blockedEvents) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextColored(g_colAccentHover, "%s", TR("(blocked)", "(محظور)"));
        }
        ImGui::EndTable();
    }
}

static void DrawPackets()
{
    EnsurePacketsPopulated();
    if (ImGui::Button(TR("Refresh##pkt_ref", "تحديث##pkt_ref"))) {
        s_packetsPopulated = false;
        s_packets.clear();
        EnsurePacketsPopulated();
        FeatureAction("Refresh");
    }
    ImGui::SameLine();
    ImGui::Text("%s: %zu", TR("Packets", "الحزم"), s_packets.size());
    ImGui::SameLine();
    if (ImGui::Button(TR("Clear All##pkt_clr", "مسح الكل##pkt_clr"))) s_packets.clear();
    ImGui::SameLine();
    if (ImGui::Button(TR("Unblock All##pkt_unb", "فك حظر الكل##pkt_unb")))
        for (auto &p : s_packets) p.blocked = false;
    ImGui::SameLine();
    ImGui::InputTextWithHint("##packet_search", TR("Search packet...", "ابحث عن حزمة..."), s_packetSearch, sizeof(s_packetSearch));

    ImGui::BeginChild("packets_left", ImVec2(-290, -1), true);
    if (s_packets.empty()) {
        ImGui::TextDisabled("%s", TR("No packets detected.", "لا توجد حزم."));
    }
    for (int i = 0; i < (int)s_packets.size(); ++i) {
        if (s_packetSearch[0] && s_packets[i].name.find(s_packetSearch) == std::string::npos) {
            continue;
        }
        ImGui::PushID(i);
        if (ImGui::Selectable(s_packets[i].name.c_str(), s_packetSel == i)) s_packetSel = i;
        ImGui::SameLine();
        if (s_packets[i].blocked) {
            ImGui::TextColored(g_colAccentHover, "BLOCKED");
        } else {
            ImGui::TextDisabled("OK");
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("packets_right", ImVec2(0, -1), true);
    if (s_packetSel >= 0 && s_packetSel < (int)s_packets.size()) {
        const PacketRow &p = s_packets[s_packetSel];
        ImGui::TextColored(g_colAccentHover, "%s", p.name.c_str());
        ImGui::Separator();
        ImGui::Text("%s: %s", TR("Time", "الوقت"), p.time.c_str());
        ImGui::Text("ID: %d", p.id);
        ImGui::TextColored(p.blocked ? g_colAccentHover : ImVec4(0.3f, 0.9f, 0.5f, 1.f),
                           "%s", p.blocked ? TR("STATUS: BLOCKED", "الحالة: محظور") : TR("STATUS: ALLOWED", "الحالة: مسموح"));
        ImGui::Spacing();
        if (ImGui::Button(TR("Toggle Block##pkt_blk", "تبديل الحظر##pkt_blk"), ImVec2(-1, 30)))
            s_packets[s_packetSel].blocked = !s_packets[s_packetSel].blocked;
        if (ImGui::Button(TR("Resend Packet##pkt_res", "إعادة إرسال##pkt_res"), ImVec2(-1, 30))) {
            char msg[160];
            snprintf(msg, sizeof(msg), "Resending packet: %s", p.name.c_str());
            FeatureAction(msg);
        }
        if (ImGui::Button(TR("Copy Name##pkt_cpy", "نسخ الاسم##pkt_cpy"), ImVec2(-1, 30))) {
            ImGui::SetClipboardText(p.name.c_str());
            char msg[160];
            snprintf(msg, sizeof(msg), "Packet name copied: %s", p.name.c_str());
            FeatureAction(msg);
        }
    } else {
        ImGui::TextDisabled("%s", TR("Select a packet from the list", "اختر حزمة من القائمة لعرض التفاصيل"));
    }
    ImGui::EndChild();
}

static bool SaveDumperEntryToDisk(const DumperFileEntry &entry)
{
    CreateDirectoryA("C:\\NVX", NULL);
    CreateDirectoryA("C:\\NVX\\dump", NULL);
    CreateDirectoryA("C:\\DARKANARCHY", NULL);
    CreateDirectoryA("C:\\DARKANARCHY\\dump", NULL);
    std::string safeName;
    for (char ch : entry.name) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
            safeName.push_back(ch);
        } else if (ch == '/' || ch == '\\' || ch == ':') {
            safeName.push_back('_');
        }
    }
    if (safeName.empty()) safeName = "script.lua";
    if (safeName.find(".lua") == std::string::npos) safeName += ".lua";
    std::string fullPath = "C:\\NVX\\dump\\" + safeName;
    FILE *fp = fopen(fullPath.c_str(), "wb");
    if (!fp) return false;
    fwrite(entry.code.data(), 1, entry.code.size(), fp);
    fclose(fp);
    return true;
}

static void DrawDumper()
{
    static int dumpSel = -1;
    static char dumpFilter[64] = "";
    ImGui::InputTextWithHint("##dump_filter", TR("Search captured scripts...", "ابحث في السكربتات المسحوبة..."), dumpFilter, sizeof(dumpFilter));
    ImGui::SameLine();
    if (ImGui::Button(TR("Dump Selected##d_sel", "حفظ المحدد##d_sel")) && dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        if (SaveDumperEntryToDisk(s_dumperEntries[dumpSel])) {
            FeatureAction(("Dump script saved: " + s_dumperEntries[dumpSel].name).c_str());
        } else {
            FeatureAction("Failed to save dump file");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Dump All##d_all", "حفظ الكل##d_all"))) {
        int saved = 0;
        for (const auto &e : s_dumperEntries) {
            if (SaveDumperEntryToDisk(e)) ++saved;
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "Dump all scripts saved (%d)", saved);
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Load in Editor##d_ed", "فتح في المحرر##d_ed")) && dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        const std::string &code = s_dumperEntries[dumpSel].code;
        size_t copyLen = code.size() < (sizeof(s_editorBuf) - 1) ? code.size() : (sizeof(s_editorBuf) - 1);
        memcpy(s_editorBuf, code.data(), copyLen);
        s_editorBuf[copyLen] = '\0';
        s_topTab = 0;
        s_scriptsSub = 0;
        FeatureAction(TR("Loaded script into editor", "تم فتح السكربت في المحرر"));
    }

    ImGui::BeginChild("##dumper_left", ImVec2(270, -1), true);
    ImGui::TextColored(g_colAccentHover, "%s (%zu)", TR("Captured Scripts", "السكربتات الملتقطة"), s_dumperEntries.size());
    ImGui::Separator();
    for (int i = 0; i < (int)s_dumperEntries.size(); ++i) {
        if (dumpFilter[0] && s_dumperEntries[i].name.find(dumpFilter) == std::string::npos) continue;
        if (ImGui::Selectable(s_dumperEntries[i].name.c_str(), dumpSel == i)) {
            dumpSel = i;
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("%s", TR("Resolved Engine Offsets:", "عناوين المحرك المكتشفة:"));
    uint32_t count = 0;
    const uintptr_t *offsets = Nrth_GetClientResolvedOffsets(&count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t addr = offsets[i] ? (uint32_t)offsets[i] : (0x10000000u + i * 0x10u);
        ImGui::Text("0x%08X (#%02u %s)", addr, i + 1, offsets[i] ? "ok" : "pend");
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##dumper_right", ImVec2(0, -1), true);
    if (dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        const DumperFileEntry &e = s_dumperEntries[dumpSel];
        ImGui::Text("Chunk: %s (%zu bytes)", e.name.c_str(), e.code.size());
        ImGui::Separator();
        if (e.code.size() > 65536) {
            ImGui::TextDisabled("File big, no view script");
        } else {
            ImGui::TextUnformatted(e.code.c_str());
        }
    } else {
        ImGui::TextDisabled("%s", TR("Select a captured script from the left panel to preview or dump to C:\\NVX\\dump\\",
                                     "اختر سكربت من القائمة الجانبية لمعاينته أو حفظه على القرص"));
    }
    ImGui::EndChild();
}

static void DrawPlayerTab()
{
    ImGui::InputTextWithHint("##player_filter", TR("Search player...", "ابحث عن لاعب..."), s_playerFilterBuf, sizeof(s_playerFilterBuf));
    ImGui::SetNextItemWidth(280);
    std::string preview = s_players.empty() ? TR("Select player...", "اختر لاعباً...") :
        (s_players[s_playerSel].name + (s_players[s_playerSel].isYou ? " (you)" : ""));
    if (ImGui::BeginCombo("##player_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_players.size(); ++i) {
            if (s_playerFilterBuf[0] && s_players[i].name.find(s_playerFilterBuf) == std::string::npos) continue;
            std::string lbl = s_players[i].name + (s_players[i].isYou ? " (you)" : "");
            if (ImGui::Selectable(lbl.c_str(), s_playerSel == i)) s_playerSel = i;
        }
        if (s_players.empty()) ImGui::TextDisabled("%s", TR("No players found", "لا يوجد لاعبون حالياً"));
        ImGui::EndCombo();
    }
    if (ImGui::Button(TR("Teleport to Player##tp_pl", "الانتقال إلى اللاعب##tp_pl"), ImVec2(150, 32))) FeatureAction("Teleport");
    ImGui::SameLine();
    if (ImGui::Button(TR("Bomb Player##bmb_pl", "تفجير اللاعب##bmb_pl"), ImVec2(130, 32))) FeatureAction("Bomb");
    ImGui::SameLine();
    if (ImGui::Button(TR("Add Friend##add_fr", "إضافة صديق##add_fr"), ImVec2(120, 32))) {
        if (!s_players.empty()) s_friends.push_back(s_players[s_playerSel].name);
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Remove Friend##del_fr", "حذف صديق##del_fr"), ImVec2(120, 32)) && !s_friends.empty())
        s_friends.pop_back();
    ImGui::Separator();
    ImGui::TextColored(g_colAccentHover, "%s", TR("Friends List", "قائمة الأصدقاء"));
    if (s_friends.empty()) ImGui::TextDisabled("%s", TR("No friends added", "لم تتم إضافة أصدقاء بعد"));
    for (auto &f : s_friends) ImGui::BulletText("%s", f.c_str());
}

static void TriggerFeatureImmediateAction(Feature &f)
{
    if (strcmp(f.label, "All Weapons") == 0 && f.on) {
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction(TR("All weapons given (1000 ammo)", "تم إعطاء جميع الأسلحة (1000 طلقة)"));
        return;
    }
    if (strcmp(f.label, "Jetpack") == 0) {
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(f.on ? TR("Jetpack enabled", "تم تفعيل الحقيبة النفاثة") : TR("Jetpack disabled", "تم إيقاف الحقيبة النفاثة"));
        return;
    }
    if (strcmp(f.label, "Repair Car") == 0 && f.on) {
        if (Nrth_RepairCurrentVehicle_1002f070()) {
            FeatureAction(TR("Vehicle repaired", "تم إصلاح المركبة بنجاح"));
        } else {
            FeatureAction(TR("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
        }
        return;
    }
    if (strcmp(f.label, "Start Engine") == 0 && f.on) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) {
            FeatureAction(TR("Engine started", "تم تشغيل محرك المركبة"));
        } else {
            FeatureAction(TR("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
        }
        return;
    }
    if (strcmp(f.label, "Unlock Car") == 0 && f.on) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) {
            FeatureAction(TR("Unlocked nearest vehicle", "تم فتح أقرب مركبة"));
        } else {
            FeatureAction(TR("No vehicle found nearby", "لا توجد مركبة قريبة"));
        }
        return;
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "%s %s", f.label, f.on ? "enabled" : "disabled");
    FeatureAction(msg);
}

static void FeatureCardRow(Feature &f, const char *id)
{
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float availW = ImGui::GetContentRegionAvail().x;
    float rowH   = 36.0f;
    ImDrawList *dl = ImGui::GetWindowDrawList();

    ImU32 cardBg = f.on
        ? ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccent.x * 0.20f, g_colAccent.y * 0.20f, g_colAccent.z * 0.20f, 0.88f))
        : ImGui::ColorConvertFloat4ToU32(ImVec4(0.10f, 0.07f, 0.16f, 0.78f));
    dl->AddRectFilled(p, ImVec2(p.x + availW, p.y + rowH), cardBg, 7.0f);
    dl->AddRect(p, ImVec2(p.x + availW, p.y + rowH),
                ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccent.x, g_colAccent.y, g_colAccent.z, f.on ? 0.65f : 0.20f)),
                7.0f, 0, 1.0f);

    ImGui::SetCursorScreenPos(ImVec2(p.x + 10.0f, p.y + 8.0f));
    if (DrawToggleSwitch("##sw", &f.on)) {
        NrthUI_SyncFeaturesToState();
        TriggerFeatureImmediateAction(f);
    }

    ImGui::SameLine(0.0f, 10.0f);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 1.0f);
    const char *dispLabel = (s_lang == 0) ? AR(f.arLabel) : f.label;
    if (f.on) {
        ImGui::TextColored(g_colAccentHover, "%s", dispLabel);
    } else {
        ImGui::TextUnformatted(dispLabel);
    }

    ImGui::SetCursorScreenPos(ImVec2(p.x + availW - 42.0f, p.y + 6.0f));
    if (ImGui::SmallButton(TR("CFG##gear", "ضبط##gear"))) {
        ImGui::OpenPopup("##settings_panel");
    }

    if (ImGui::BeginPopup("##settings_panel")) {
        ImGui::TextColored(g_colAccentHover, "%s", (s_lang == 0) ? AR(f.arSettings) : f.settings);
        ImGui::Separator();
        if (strcmp(f.label, "Give HP") == 0) {
            if (ImGui::SliderFloat(TR("HP Value##sp", "قيمة الصحة##sp"), &s_hpValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Give Armor") == 0) {
            if (ImGui::SliderFloat(TR("Armor Value##sp", "قيمة الدرع##sp"), &s_armorValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "AirBreak") == 0) {
            if (ImGui::SliderFloat(TR("Speed: %.2f", "السرعة: %.2f"), &s_abSpeed, 0.1f, 10.f)) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat(TR("Increment: %.2f", "التسارع: %.2f"), &s_abIncr, 0.05f, 2.f)) NrthUI_SyncFeaturesToState();
            ImGui::Separator();
            ImGui::Text("%s", TR("Controls: W/A/S/D + Space / LCtrl", "التحكم: W/A/S/D + المسافة / LCtrl"));
        } else if (strcmp(f.label, "Click Warp") == 0) {
            if (ImGui::SliderFloat(TR("Max Distance##sp", "أقصى مسافة##sp"), &s_maxDist, 10, 1000)) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat(TR("Crosshair Size##sp", "حجم المؤشر##sp"), &s_crossSize, 2, 40)) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox(TR("Ground Warp##sp", "انتقال للأرض##sp"), &s_groundWarp)) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox(TR("Enter Vehicle##sp", "دخول المركبة##sp"), &s_enterVehicle)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-ScreenShot") == 0) {
            if (ImGui::Checkbox(TR("Hide OBS / Discord", "إخفاء عن OBS و Discord"), &s_hideObsDiscord)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-AFK") == 0) {
            ImGui::Checkbox(TR("Enable Anti-AFK", "تفعيل مانع الخمول"), &s_antiAfk);
        } else {
            ImGui::TextDisabled("%s", TR("Synced with DARKANARCHY engine", "متزامن مع محرك DARKANARCHY"));
        }
        ImGui::Separator();
        if (s_capturingFeature == &f) {
            ImGui::Button(TR("Press any key...", "اضغط أي زر..."));
            for (int vk = 1; vk < 256; ++vk) {
                if (vk == VK_LBUTTON || vk == VK_RBUTTON) continue;
                if (GetAsyncKeyState(vk) & 1) {
                    f.key = (vk == VK_ESCAPE) ? 0 : vk;
                    s_capturingFeature = nullptr;
                    break;
                }
            }
        } else {
            char keyBtn[96];
            if (f.key > 0) snprintf(keyBtn, sizeof(keyBtn), "Key: %d##kbtn", f.key);
            else           snprintf(keyBtn, sizeof(keyBtn), "%s", TR("Bind Hotkey...##kbtn", "تعيين اختصار...##kbtn"));
            if (ImGui::Button(keyBtn)) {
                s_capturingFeature = &f;
            }
        }
        ImGui::SameLine();
        const char *modesEn[] = { "Hold", "Toggle" };
        ImGui::SetNextItemWidth(95);
        ImGui::Combo("##mode", &f.mode, modesEn, 2);
        ImGui::EndPopup();
    }

    ImGui::SetCursorScreenPos(ImVec2(p.x, p.y + rowH + 5.0f));
    ImGui::Dummy(ImVec2(availW, 0.0f));
    ImGui::PopID();
}

static void DrawOtherTab()
{
    ImGui::TextColored(g_colAccentHover, "%s",
                       TR("PLAYER & COMBAT MODULES  |  BY XRAOUF", "خصائص اللاعب والقتال  |  تطوير XRAOUF"));
    ImGui::Separator();
    ImGui::Spacing();

    int totalFeatures = (int)(sizeof(s_cheatFeatures) / sizeof(Feature));
    int half = (totalFeatures + 1) / 2;

    ImGui::Columns(2, "##cheat_cols", false);
    for (int i = 0; i < half; ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureCardRow(s_cheatFeatures[i], id);
    }
    ImGui::NextColumn();
    for (int i = half; i < totalFeatures; ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureCardRow(s_cheatFeatures[i], id);
    }
    ImGui::Columns(1);

    ImGui::Separator();
    ImGui::TextDisabled("%s", TR("Quick Actions:", "إجراءات سريعة:"));
    if (ImGui::Button(TR("Give All Weapons##qa_wep", "إعطاء جميع الأسلحة##qa_wep"), ImVec2(155, 32))) {
        s_cheatFeatures[13].on = true;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction(TR("All weapons given (1000 ammo)", "تم إعطاء جميع الأسلحة"));
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Toggle High Jump##qa_hj", "تفعيل القفزة الخارقة##qa_hj"), ImVec2(155, 32))) {
        s_cheatFeatures[10].on = !s_cheatFeatures[10].on;
        NrthUI_SyncFeaturesToState();
        FeatureAction(s_cheatFeatures[10].on ? "High Jump enabled" : "High Jump disabled");
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Money Exploit (+50K)##qa_mn", "ثغرة الأموال (+50K)##qa_mn"), ImVec2(160, 32))) {
        s_cheatFeatures[11].on = !s_cheatFeatures[11].on;
        if (s_cheatFeatures[11].on) {
            static const char kMoneyLua[] = "givePlayerMoney(50000)";
            NrthUI_ExecuteLuaViaBridge(kMoneyLua, sizeof(kMoneyLua) - 1, 0);
        }
        FeatureAction(s_cheatFeatures[11].on ? "Money Exploit enabled" : "Money Exploit disabled");
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Toggle Jetpack##qa_jp", "الحقيبة النفاثة##qa_jp"), ImVec2(140, 32))) {
        s_cheatFeatures[12].on = !s_cheatFeatures[12].on;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(s_cheatFeatures[12].on ? "Jetpack enabled" : "Jetpack disabled");
    }
}

static void DrawMarkersTab()
{
    ImGui::InputTextWithHint("##marker_name", TR("Location marker name...", "اسم الموقع لحفظه..."), s_markerName, sizeof(s_markerName));
    ImGui::SameLine();
    if (ImGui::Button(TR("Save Position##sv_mk", "حفظ الإحداثيات##sv_mk"), ImVec2(140, 30)) && s_markerName[0]) {
        float mx = 0.0f, my = 0.0f, mz = 0.0f;
        Nrth_GetLocalPlayerPosition(&mx, &my, &mz);
        MarkerRow m = {s_markerName, mx, my, mz};
        s_markers.push_back(m);
        char msg[128];
        snprintf(msg, sizeof(msg), "Marker saved: %s", s_markerName);
        FeatureAction(msg);
        s_markerName[0] = 0;
    }
    ImGui::Separator();
    if (s_markers.empty()) ImGui::TextDisabled("%s", TR("No saved coordinates yet", "لا توجد مواقع محفوظة حالياً"));
    for (int i = 0; i < (int)s_markers.size(); ++i) {
        ImGui::PushID(i);
        MarkerRow &m = s_markers[i];
        char line[128];
        snprintf(line, sizeof(line), "%s (%.1f, %.1f, %.1f)", m.name.c_str(), m.x, m.y, m.z);
        ImGui::BulletText("%s", line);
        ImGui::SameLine(300);
        if (ImGui::SmallButton(TR("Teleport##mk_tp", "انتقال##mk_tp"))) {
            if (Nrth_TeleportLocalPlayer(m.x, m.y, m.z)) {
                FeatureAction(("Teleported to: " + m.name).c_str());
            } else {
                FeatureAction("Teleport");
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton(TR("Delete##mk_del", "حذف##mk_del"))) {
            s_markers.erase(s_markers.begin() + i);
            ImGui::PopID();
            break;
        }
        ImGui::PopID();
    }
}

static void DrawVehicleTab()
{
    ImGui::Columns(2, "##vehcols", false);
    ImGui::SetColumnWidth(0, 330);
    ImGui::TextColored(g_colAccentHover, "%s", TR("Vehicle Modifications", "خصائص وتعديلات المركبة"));
    ImGui::Separator();
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "vf%d", i);
        FeatureCardRow(s_vehicleFeatures[i], id);
    }
    ImGui::NextColumn();

    ImGui::TextColored(g_colAccentHover, "%s", TR("Vehicle Control & Spawner", "التحكم بالمركبات وقائمة السيارات"));
    ImGui::Separator();
    ImGui::SetNextItemWidth(-1);
    std::string prev = std::string(kVehicleNames[s_vehicleSel]) + " (HP: 1000)";
    if (ImGui::BeginCombo("##vehicles_combo", s_vehicleSel >= 0 ? prev.c_str() : "Select vehicle...")) {
        for (int i = 0; i < (int)(sizeof(kVehicleNames) / sizeof(kVehicleNames[0])); ++i) {
            if (ImGui::Selectable(kVehicleNames[i], s_vehicleSel == i)) s_vehicleSel = i;
        }
        ImGui::EndCombo();
    }
    ImGui::Spacing();
    if (ImGui::Button(TR("Teleport to Vehicle##v_tp1", "الانتقال إلى المركبة##v_tp1"), ImVec2(-1, 32)))
        FeatureAction("Teleport to Vehicle");
    if (ImGui::Button(TR("Bring Vehicle to Me##v_tp2", "سحب المركبة إليك##v_tp2"), ImVec2(-1, 32)))
        FeatureAction("Vehicle teleported to you");
    if (ImGui::Button(TR("Repair Current Vehicle##v_rep", "إصلاح المركبة الحالية##v_rep"), ImVec2(-1, 32))) {
        if (Nrth_RepairCurrentVehicle_1002f070()) FeatureAction("Vehicle repaired");
        else FeatureAction("You must be in a vehicle");
    }
    if (ImGui::Button(TR("Start Vehicle Engine##v_eng", "تشغيل محرك المركبة##v_eng"), ImVec2(-1, 32))) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) FeatureAction("Engine started");
        else FeatureAction("You must be in a vehicle");
    }
    if (ImGui::Button(TR("Unlock Nearest Vehicle##v_unl", "فتح قفل أقرب مركبة##v_unl"), ImVec2(-1, 32))) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) FeatureAction("Unlocked nearest vehicle");
        else FeatureAction("No vehicle found nearby");
    }
    if (ImGui::Button(TR("Instant Stop Vehicle##v_stp", "إيقاف المركبة فوراً##v_stp"), ImVec2(-1, 32))) {
        if (Nrth_StopCurrentVehicle()) FeatureAction("Vehicle stopped");
        else FeatureAction("You must be in a vehicle");
    }
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.65f, 0.08f, 0.18f, 1.0f));
    if (ImGui::Button(TR("Destroy / Bomb Vehicle##v_bmb", "تفجير المركبة الحالية##v_bmb"), ImVec2(-1, 32))) {
        if (Nrth_DestroyCurrentVehicle()) FeatureAction("Vehicle destroyed");
        else FeatureAction("You must be in a vehicle");
    }
    ImGui::PopStyleColor();
    ImGui::Columns(1);
}

static void DrawColorSettings()
{
    if (ImGui::TreeNode(TR("Advanced Color Palette Editor##col_tree", "محرر الألوان المتقدم##col_tree"))) {
        static char filter[64] = "";
        ImGui::InputTextWithHint("##filter", TR("Search color...", "ابحث عن عنصر لون..."), filter, sizeof(filter));
        static const struct { const char *name; ImGuiCol col; } kColors[] = {
            {"Text", ImGuiCol_Text}, {"Text Disabled", ImGuiCol_TextDisabled},
            {"Window BG", ImGuiCol_WindowBg}, {"Child BG", ImGuiCol_ChildBg},
            {"Popup BG", ImGuiCol_PopupBg}, {"Border", ImGuiCol_Border},
            {"Frame BG", ImGuiCol_FrameBg}, {"Frame BG Hovered", ImGuiCol_FrameBgHovered},
            {"Frame BG Active", ImGuiCol_FrameBgActive},
            {"Check Mark", ImGuiCol_CheckMark}, {"Slider Grab", ImGuiCol_SliderGrab},
            {"Slider Grab Active", ImGuiCol_SliderGrabActive},
            {"Button", ImGuiCol_Button}, {"Button Hovered", ImGuiCol_ButtonHovered},
            {"Button Active", ImGuiCol_ButtonActive},
            {"Header", ImGuiCol_Header}, {"Header Hovered", ImGuiCol_HeaderHovered},
            {"Header Active", ImGuiCol_HeaderActive},
            {"Tab", ImGuiCol_Tab}, {"Tab Hovered", ImGuiCol_TabHovered},
            {"Tab Active", ImGuiCol_TabActive},
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
                if (ImGui::ColorEdit4(k.name, (float *)&c, ImGuiColorEditFlags_NoInputs))
                    ImGui::GetStyle().Colors[k.col] = c;
            }
            ImGui::EndTable();
        }
        if (ImGui::Button(TR("Reset Colors##rst_col", "استعادة الألوان الافتراضية##rst_col"))) {
            ApplyThemePreset(s_themePreset);
            FeatureAction("Colors reset");
        }
        ImGui::TreePop();
    }
}

/* ---------------------------------------------------------------------------
 * BOT LAB tab — local ped deployment + session analysis + stay mode
 * ------------------------------------------------------------------------- */
static void DrawBotsTab()
{
    const ImVec4 kPink  = ImVec4(0.96f, 0.30f, 0.55f, 1.0f);
    const ImVec4 kGreen = ImVec4(0.30f, 0.85f, 0.45f, 1.0f);

    ImGui::TextColored(kPink, "%s", TR("BOT LAB — LOCAL PEDS", "مختبر البوتات — شخصيات محلية"));
    ImGui::TextDisabled("%s",
        TR("Client-side peds via the game's own Lua (createPed). Visible to you only —"
           " the server and other players never see them (only the server can add real players).",
           "شخصيات من جهة العميل عبر لوا اللعبة (createPed). تراها أنت فقط —"
           " الخادم واللاعبون الآخرون لا يرونها (فقط الخادم يضيف لاعبين حقيقيين)."));
    ImGui::Spacing();

    /* ---- Panel 1: session / entry analysis (real client state) ---------- */
    if (ImGui::CollapsingHeader(TR("Connection Analysis##bot_an", "تحليل الدخول والاتصال##bot_an"),
                                ImGuiTreeNodeFlags_DefaultOpen)) {
        const bool inGame = NrthHook_IsInGame() != 0;
        ImGui::TextColored(inGame ? kGreen : ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "%s",
            inGame ? TR("Game state: IN SERVER", "حالة اللعبة: داخل الخادم")
                   : TR("Game state: in menu", "حالة اللعبة: في القائمة"));
        ImGui::TextDisabled("%s: %u",
            TR("MTA client hooks armed", "خطافات عميل MTA المُسلّحة"),
            (unsigned)Nrth_GetTotalInstalledHooks());
        /* session clock: starts on first in-game detection */
        static ULONGLONG s_firstInGame = 0;
        if (inGame) {
            if (s_firstInGame == 0) s_firstInGame = GetTickCount64();
            const ULONGLONG dt = (GetTickCount64() - s_firstInGame) / 1000ull;
            ImGui::TextDisabled("%s: %02u:%02u",
                TR("Session time", "مدة الجلسة"),
                (unsigned)((dt / 60ull) % 100ull), (unsigned)(dt % 60ull));
        } else {
            s_firstInGame = 0;
            ImGui::TextDisabled("%s", TR("Session time: --:--", "مدة الجلسة: --:--"));
        }
    }
    ImGui::Spacing();

    /* ---- Panel 2: local bot deployment ---------------------------------- */
    if (ImGui::CollapsingHeader(TR("Deploy Local Bots##bot_dp", "نشر البوتات المحلية##bot_dp"),
                                ImGuiTreeNodeFlags_DefaultOpen)) {
        static int s_botCount = 8;
        ImGui::SliderInt(TR("Bot count##bot_n", "عدد البوتات##bot_n"), &s_botCount, 1, 64);
        ImGui::TextDisabled("%s: %u",
            TR("Currently deployed", "المنشورة حاليًا"),
            (unsigned)NrthUI_GetBotLabDeployed());

        if (ImGui::Button(TR("Deploy##bot_go", "نشر##bot_go"), ImVec2(150, 34))) {
            if (!NrthHook_IsInGame()) {
                FeatureAction(TR("Enter the server first (mtasa://...)", "ادخل الخادم أولًا (mtasa://...)"));
            } else {
                static char s_lua[4096];
                NrthUI_BuildBotsDeployLua(s_botCount, s_lua, sizeof(s_lua));
                NrthUI_ExecuteLuaViaBridge(s_lua, strlen(s_lua), 0);
                NrthUI_SetBotLabDeployed((uint32_t)s_botCount);
                FeatureAction(TR("Local bots deployed", "تم نشر البوتات المحلية"));
            }
        }
        ImGui::SameLine();
        if (ImGui::Button(TR("Remove All##bot_rm", "إزالة الكل##bot_rm"), ImVec2(150, 34))) {
            static char s_lua[1024];
            NrthUI_BuildBotsRemoveLua(s_lua, sizeof(s_lua));
            NrthUI_ExecuteLuaViaBridge(s_lua, strlen(s_lua), 0);
            NrthUI_SetBotLabDeployed(0);
            FeatureAction(TR("Local bots removed", "تمت إزالة البوتات المحلية"));
        }
    }
    ImGui::Spacing();

    /* ---- Panel 3: stay mode (keep session alive while away) ------------- */
    if (ImGui::CollapsingHeader(TR("Stay Mode##bot_stay", "وضع البقاء##bot_stay"),
                                ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("%s",
            TR("Keeps YOUR game session connected while you are away (anti-idle + a frozen"
               " local twin in your skin). Do not close the game: when the client exits the"
               " server removes you — nothing can stay connected after that.",
               "يُبقي جلستك متصلة وأنت بعيد (مانع خمول + شبح محلي متجمد بشخصيتك)."
               " لا تُغلق اللعبة: عند إغلاق العميل يحذفك الخادم — لا شيء يمكنه البقاء متصلًا بعدها."));

        const bool stay = NrthUI_IsStayModeOn() != 0;
        if (ImGui::Button(stay ? TR("Stay Mode: ON — disable##bot_sm",
                                    "وضع البقاء: مُفعّل — إيقاف##bot_sm")
                               : TR("Stay Mode: OFF — enable##bot_sm",
                                    "وضع البقاء: متوقف — تفعيل##bot_sm"),
                           ImVec2(240, 34))) {
            /* flip the existing Anti-AFK feature row so the tabs stay in sync */
            const size_t nFeat = sizeof(s_cheatFeatures) / sizeof(s_cheatFeatures[0]);
            for (size_t i = 0; i < nFeat; ++i) {
                if (strcmp(s_cheatFeatures[i].label, "Anti-AFK") == 0) {
                    s_cheatFeatures[i].on = !stay;
                    break;
                }
            }
            NrthUI_SyncFeaturesToState();
            if (!stay) {
                static char s_lua[1024];
                NrthUI_BuildGhostTwinLua(s_lua, sizeof(s_lua));
                if (NrthHook_IsInGame()) {
                    NrthUI_ExecuteLuaViaBridge(s_lua, strlen(s_lua), 0);
                }
                NrthUI_SetStayMode(1);
                FeatureAction(TR("Stay Mode ON (anti-idle + local ghost)",
                                 "وضع البقاء مُفعّل (مانع خمول + شبح محلي)"));
            } else {
                NrthUI_SetStayMode(0);
                FeatureAction(TR("Stay Mode OFF", "تم إيقاف وضع البقاء"));
            }
        }
    }
}

static void DrawConfigTab()
{
    if (!s_configsScanned) ScanConfigs();
    ImGui::Columns(2, "##cfgcols", false);
    ImGui::SetColumnWidth(0, 240);
    ImGui::TextColored(g_colAccentHover, "%s", TR("Saved Profiles (.ovr)", "ملفات الإعدادات (.ovr)"));
    ImGui::BeginChild("##cfgitem", ImVec2(-1, -1), true);
    if (s_configs.empty()) ImGui::TextDisabled("%s", TR("No configs found", "لا توجد ملفات محفوظة"));
    for (int i = 0; i < (int)s_configs.size(); ++i) {
        if (ImGui::Selectable(s_configs[i].name.c_str(), s_cfgSel == i)) s_cfgSel = i;
    }
    ImGui::EndChild();
    ImGui::NextColumn();

    ImGui::BeginChild("##cfg_right", ImVec2(0, -1), true);

    /* Language & Theme Section */
    ImGui::TextColored(g_colAccentHover, "%s", TR("Language & Visual Theme (DARKANARCHY BY XRAOUF)", "اللغة والمظهر الاحترافي (DARKANARCHY BY XRAOUF)"));
    ImGui::Separator();

    if (ImGui::Button(TR("Language: العربية (Arabic)##lang_ar", "اللغة الحالية: العربية (نشط)##lang_ar"), ImVec2(200, 32))) {
        s_lang = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Language: English (Active)##lang_en", "Switch to English##lang_en"), ImVec2(200, 32))) {
        s_lang = 1;
    }

    ImGui::Spacing();
    ImGui::Text("%s:", TR("Color Theme Preset", "ثيم الألوان"));
    static const char *kThemeNamesEn[] = {
        "1. Dark Anarchy (Crimson & Cyber Violet)",
        "2. Blood Moon (Pure Crimson & Onyx)",
        "3. Abyss Violet (Neon Amethyst)",
        "4. XRAOUF Gold (Imperial Gold & Carbon)",
        "5. Cyber Matrix (Neon Emerald)"
    };
    ImGui::SetNextItemWidth(310);
    if (ImGui::Combo("##theme_preset", &s_themePreset, kThemeNamesEn, 5)) {
        ApplyThemePreset(s_themePreset);
    }

    ImGui::Checkbox(TR("Show AI Background Wallpaper##bg_chk", "إظهار خلفية القائمة (AI)##bg_chk"), &s_showBgImage);
    ImGui::SameLine();
    ImGui::Checkbox(TR("Show AI Logo Emblem##lg_chk", "إظهار شعار DARKANARCHY##lg_chk"), &s_showLogoImg);
    ImGui::Checkbox(TR("Animated Cyber Embers##pt_chk", "مؤثرات الجزيئات المتحركة##pt_chk"), &s_showParticles);
    ImGui::SameLine();
    ImGui::Checkbox(TR("Custom Cyber Crosshair##xh_chk", "مؤشر تصويب مخصص##xh_chk"), &s_customCrosshair);
    if (s_showBgImage) {
        ImGui::SliderFloat(TR("Background Opacity##bg_op", "شفافية الخلفية##bg_op"), &s_bgOpacity, 0.05f, 0.85f, "%.2f");
    }

    ImGui::Spacing();
    ImGui::TextColored(g_colAccentHover, "%s", TR("TTF Typography & Font Engine", "إعدادات خطوط TTF (العربية والإنجليزية)"));
    static const char *kFontModes[] = {
        "Hybrid: ChakraPetch (EN) + Tajawal Bold (AR)",
        "Arabic Display: Tajawal Bold Full (AR + EN)"
    };
    ImGui::SetNextItemWidth(310);
    if (ImGui::Combo(TR("Active TTF Pair##fmode", "نوع الخط النشط##fmode"), &s_fontMode, kFontModes, 2)) {
        ImGuiIO &io = ImGui::GetIO();
        if (s_fontMode == 1 && s_pFontArabic) {
            io.FontDefault = s_pFontArabic;
        } else if (s_pFontMain) {
            io.FontDefault = s_pFontMain;
        }
    }
    if (ImGui::SliderFloat(TR("Font Scale##fscale", "حجم الخط##fscale"), &s_uiScale, 0.85f, 1.25f, "%.2fx")) {
        ImGui::GetIO().FontGlobalScale = s_uiScale;
    }

    ImGui::Separator();
    ImGui::TextColored(g_colAccentHover, "%s", TR("Profile Management", "إدارة ملفات الإعدادات"));
    ImGui::InputText(TR("Profile Name##sa", "اسم الملف##sa"), s_cfgName, sizeof(s_cfgName));
    if (ImGui::Button(TR("Save##cfg_sv", "حفظ##cfg_sv"), ImVec2(90, 30))) {
        std::string f = std::string(s_cfgName) + ".ovr";
        NrthConfig_SaveOvr(f.c_str(), NULL);
        char msg[128];
        snprintf(msg, sizeof(msg), "Config saved: %s", f.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Load##cfg_ld", "تحميل##cfg_ld"), ImVec2(90, 30)) && s_cfgSel >= 0) {
        NrthConfig_Load(s_configs[s_cfgSel].name.c_str());
        NrthConfig_Save(NULL);
        char msg[128];
        snprintf(msg, sizeof(msg), "Config loaded: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Delete##cfg_dl", "حذف##cfg_dl"), ImVec2(90, 30)) && s_cfgSel >= 0) {
        DeleteFileA(s_configs[s_cfgSel].name.c_str());
        char msg[128];
        snprintf(msg, sizeof(msg), "Config deleted: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button(TR("Reset Default##cfg_rs", "استعادة الافتراضي##cfg_rs"), ImVec2(125, 30))) {
        g_cfg.menuKey   = NRTH_VK_INSERT;
        g_cfg.noSpoofer = 0;
        ApplyThemePreset(0);
        NrthConfig_Save(NULL);
        FeatureAction("Reset to default style");
    }

    ImGui::Separator();
    ImGui::Checkbox(TR("Watermark Overlay##wm_c", "شريط العلامة المائية##wm_c"), &g_cfg.watermark);
    ImGui::SameLine();
    ImGui::Checkbox(TR("Toast Notifications##nt_c", "الإشعارات المنبثقة##nt_c"), &g_cfg.notifications);
    ImGui::SameLine();
    ImGui::Checkbox(TR("Keybind Overlay##kb_c", "نافذة الاختصارات##kb_c"), &s_showKeybindWindow);
    ImGui::Separator();

    ImGui::Text("%s:", TR("Menu Toggle Key", "زر فتح وإغلاق القائمة"));
    ImGui::SameLine();
    if (s_waitingForKey) {
        ImGui::Button(TR("Press any key...##mk_wait", "اضغط أي زر...##mk_wait"));
        for (int k = 1; k < 256; ++k) {
            if (k == VK_LBUTTON || k == VK_RBUTTON) continue;
            if (GetAsyncKeyState(k) & 1) {
                g_cfg.menuKey = k;
                NrthConfig_Save(NULL);
                s_waitingForKey = false;
                break;
            }
        }
    } else if (ImGui::Button(TR("Change Key##mk_set", "تغيير الزر##mk_set"))) {
        s_waitingForKey = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(VK: %d | Insert = 45)", g_cfg.menuKey);

    ImGui::Separator();
    DrawColorSettings();
    ImGui::Separator();
    ImGui::TextColored(g_colAccentHover, "DARKANARCHY v4.0  |  DEVELOPED BY XRAOUF");
    ImGui::TextDisabled("%s", TR("TTF Fonts: DarkAnarchy-English.ttf + DarkAnarchy-Arabic.ttf | AI D3D9 Textures Active",
                                 "الخطوط المدمجة: TTF عربي + إنجليزي | شعار وخلفية الذكاء الاصطناعي نشطة"));
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
            if (f.mode == 1) {
                if (GetAsyncKeyState(f.key) & 1) {
                    f.on = !f.on;
                    NrthUI_SyncFeaturesToState();
                    TriggerFeatureImmediateAction(f);
                }
            } else {
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

/* Matches DrawWatermark at VA 0x10012bc0 — Redesigned for DARKANARCHY | DEV: XRAOUF */
static void DrawWatermark_10012bc0(void)
{
    if (!g_cfg.watermark) {
        return;
    }
    ImGuiIO &io = ImGui::GetIO();
    float fps = io.Framerate > 0.0f ? io.Framerate : 60.0f;
    char wmBuf[256];
    snprintf(wmBuf, sizeof(wmBuf), "DARKANARCHY  |  DEV: XRAOUF  |  FPS: %.0f  |  %s", fps, s_status.c_str());

    ImVec2 textSz = ImGui::CalcTextSize(wmBuf);
    float winW = textSz.x + (s_pLogoTexture ? 68.0f : 34.0f);
    float posX = (io.DisplaySize.x > winW + 20.0f) ? (io.DisplaySize.x - winW - 16.0f) : 12.0f;
    ImGui::SetNextWindowPos(ImVec2(posX, 14.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.90f);
    if (ImGui::Begin("##Watermark", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove)) {
        if (s_pLogoTexture) {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddImageRounded(
                (ImTextureID)s_pLogoTexture,
                p, ImVec2(p.x + 28.0f, p.y + 18.0f),
                ImVec2(0, 0), ImVec2(1, 1),
                IM_COL32(255, 255, 255, 255), 4.0f);
            ImGui::Dummy(ImVec2(30.0f, 18.0f));
            ImGui::SameLine();
        }
        ImGui::TextColored(g_colAccentHover, "DARKANARCHY");
        ImGui::SameLine();
        ImGui::TextColored(g_colSecondary, "| DEV: XRAOUF |");
        ImGui::SameLine();
        ImGui::Text("FPS: %.0f | %s", fps, (s_lang == 0 && s_status == "No connected server.")
                    ? AR("غير متصل بالسيرفر") : s_status.c_str());
    }
    ImGui::End();
}

/* Custom Cyber Crosshair Overlay when Click Warp or Custom Crosshair is enabled */
static void DrawCustomCrosshairOverlay(void)
{
    if (!s_customCrosshair && !s_cheatFeatures[9].on) {
        return;
    }
    ImGuiIO &io = ImGui::GetIO();
    if (io.DisplaySize.x <= 0.0f || io.DisplaySize.y <= 0.0f) return;

    ImVec2 center(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
    float sz = s_crossSize > 4.0f ? s_crossSize : 12.0f;
    ImDrawList *bgDl = ImGui::GetBackgroundDrawList();
    ImU32 colMain = ImGui::ColorConvertFloat4ToU32(g_colAccentHover);
    ImU32 colSub  = ImGui::ColorConvertFloat4ToU32(g_colSecondary);

    bgDl->AddCircle(center, sz * 0.65f, colSub, 24, 1.5f);
    bgDl->AddLine(ImVec2(center.x - sz, center.y), ImVec2(center.x - 3.0f, center.y), colMain, 2.0f);
    bgDl->AddLine(ImVec2(center.x + 3.0f, center.y), ImVec2(center.x + sz, center.y), colMain, 2.0f);
    bgDl->AddLine(ImVec2(center.x, center.y - sz), ImVec2(center.x, center.y - 3.0f), colMain, 2.0f);
    bgDl->AddLine(ImVec2(center.x, center.y + 3.0f), ImVec2(center.x, center.y + sz), colMain, 2.0f);
    bgDl->AddCircleFilled(center, 2.0f, IM_COL32(255, 255, 255, 255));
}

/* Matches DrawKeybindList at VA 0x100130a0 */
static void DrawKeybindList_100130a0(void)
{
    if (!s_showKeybindWindow) {
        return;
    }
    ImGui::SetNextWindowPos(ImVec2(14.0f, 60.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(250.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.88f);
    if (ImGui::Begin(TR("DARKANARCHY Keybinds##floating", "اختصارات DARKANARCHY##floating"), &s_showKeybindWindow,
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings)) {
        bool any = false;
        auto listFeatureArray = [&](Feature *arr, int count) {
            for (int i = 0; i < count; ++i) {
                if (arr[i].key > 0) {
                    any = true;
                    ImGui::Text("%s [%s]", (s_lang == 0) ? AR(arr[i].arLabel) : arr[i].label,
                                arr[i].mode ? "Toggle" : "Hold");
                    ImGui::SameLine(190.0f);
                    if (arr[i].on) {
                        ImGui::TextColored(g_colAccentHover, "ON");
                    } else {
                        ImGui::TextDisabled("OFF");
                    }
                }
            }
        };
        listFeatureArray(s_cheatFeatures, (int)(sizeof(s_cheatFeatures) / sizeof(Feature)));
        listFeatureArray(s_vehicleFeatures, (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)));
        if (!any) {
            ImGui::TextDisabled("%s", TR("No active binds", "لا توجد اختصارات نشطة"));
        }
    }
    ImGui::End();
}

/* Matches DrawNotifications at VA 0x10016990 */
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
    float baseY = (io.DisplaySize.y > 100.0f ? io.DisplaySize.y : 720.0f) - 74.0f;
    float baseX = (io.DisplaySize.x > 300.0f ? io.DisplaySize.x : 1280.0f) - 305.0f;
    for (int i = 0; i < (int)s_notifications.size(); ++i) {
        char winId[32];
        snprintf(winId, sizeof(winId), "##toast_%d", i);
        ImGui::SetNextWindowPos(ImVec2(baseX, baseY - i * 64.0f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(290.0f, 56.0f), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.94f);
        if (ImGui::Begin(winId, nullptr,
                         ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings |
                         ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoMove)) {
            ImVec2 wp = ImGui::GetWindowPos();
            ImVec2 ws = ImGui::GetWindowSize();
            ImDrawList *dl = ImGui::GetWindowDrawList();

            float ratio = 1.0f - (float)(now - s_notifications[i].createdTick) / (float)kDurationMs;
            if (ratio < 0.0f) ratio = 0.0f;
            dl->AddRectFilled(ImVec2(wp.x, wp.y + ws.y - 3.0f),
                              ImVec2(wp.x + ws.x * ratio, wp.y + ws.y),
                              ImGui::ColorConvertFloat4ToU32(g_colAccentHover), 2.0f);

            ImGui::TextColored(g_colAccentHover, "DARKANARCHY | XRAOUF");
            ImGui::TextUnformatted(s_notifications[i].text.c_str());
        }
        ImGui::End();
    }
}

/* Animated Cyber Embers & Angular Corner HUD Brackets */
static void DrawCyberEmbersAndHud(ImDrawList *dl, const ImVec2 &winPos, const ImVec2 &winSize)
{
    if (s_showParticles) {
        float t = (float)ImGui::GetTime();
        for (int i = 0; i < 24; ++i) {
            float seed = (float)i * 1.37f;
            float px = winPos.x + fmodf((sinf(seed * 3.1f + t * 0.25f) * 0.5f + 0.5f) * winSize.x, winSize.x);
            float py = winPos.y + winSize.y - fmodf((t * (18.0f + (i % 5) * 6.0f) + seed * 95.0f), winSize.y);
            float alpha = 0.18f + 0.22f * sinf(t * 2.4f + seed);
            float rad   = 1.5f + (float)(i % 3) * 0.8f;
            ImVec4 c = (i & 1) ? g_colAccentHover : g_colSecondary;
            dl->AddCircleFilled(ImVec2(px, py), rad,
                                ImGui::ColorConvertFloat4ToU32(ImVec4(c.x, c.y, c.z, alpha)));
        }
    }

    /* Cyber HUD Corner Brackets */
    ImU32 cornerCol = ImGui::ColorConvertFloat4ToU32(g_colAccentHover);
    float cl = 22.0f;
    /* Top-left */
    dl->AddLine(winPos, ImVec2(winPos.x + cl, winPos.y), cornerCol, 2.5f);
    dl->AddLine(winPos, ImVec2(winPos.x, winPos.y + cl), cornerCol, 2.5f);
    /* Top-right */
    dl->AddLine(ImVec2(winPos.x + winSize.x, winPos.y), ImVec2(winPos.x + winSize.x - cl, winPos.y), cornerCol, 2.5f);
    dl->AddLine(ImVec2(winPos.x + winSize.x, winPos.y), ImVec2(winPos.x + winSize.x, winPos.y + cl), cornerCol, 2.5f);
    /* Bottom-left */
    dl->AddLine(ImVec2(winPos.x, winPos.y + winSize.y), ImVec2(winPos.x + cl, winPos.y + winSize.y), cornerCol, 2.5f);
    dl->AddLine(ImVec2(winPos.x, winPos.y + winSize.y), ImVec2(winPos.x, winPos.y + winSize.y - cl), cornerCol, 2.5f);
    /* Bottom-right */
    dl->AddLine(ImVec2(winPos.x + winSize.x, winPos.y + winSize.y), ImVec2(winPos.x + winSize.x - cl, winPos.y + winSize.y), cornerCol, 2.5f);
    dl->AddLine(ImVec2(winPos.x + winSize.x, winPos.y + winSize.y), ImVec2(winPos.x + winSize.x, winPos.y + winSize.y - cl), cornerCol, 2.5f);
}

void NrthUI_Build()
{
    ImGui::SetNextWindowSize(ImVec2(940, 620), ImGuiCond_FirstUseEver);
    if (!s_menuOpen) return;

    if (!ImGui::Begin("DARKANARCHY | DEV: XRAOUF###DarkAnarchyMain", &s_menuOpen,
                      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar)) {
        ImGui::End();
        return;
    }

    ImVec2 winPos  = ImGui::GetWindowPos();
    ImVec2 winSize = ImGui::GetWindowSize();
    ImDrawList *dl = ImGui::GetWindowDrawList();

    /* 1. Render AI Background Wallpaper across the window canvas */
    if (s_showBgImage && s_pBgTexture) {
        ImU32 bgTint = ImGui::ColorConvertFloat4ToU32(ImVec4(1.0f, 1.0f, 1.0f, s_bgOpacity));
        dl->AddImageRounded((ImTextureID)s_pBgTexture,
                            winPos,
                            ImVec2(winPos.x + winSize.x, winPos.y + winSize.y),
                            ImVec2(0, 0), ImVec2(1, 1),
                            bgTint, 12.0f);
    }

    /* Top neon gradient accent line across the window */
    ImU32 colLeft  = ImGui::ColorConvertFloat4ToU32(g_colAccentHover);
    ImU32 colRight = ImGui::ColorConvertFloat4ToU32(g_colSecondary);
    dl->AddRectFilledMultiColor(winPos, ImVec2(winPos.x + winSize.x, winPos.y + 4.0f),
                                colLeft, colRight, colRight, colLeft);
    DrawCyberEmbersAndHud(dl, winPos, winSize);

    /* ---- LEFT SIDEBAR (Logo + Brand + Developer XRAOUF + Vertical Nav + Language Toggle) ---- */
    ImGui::BeginChild("##da_sidebar", ImVec2(226, 0), true);
    {
        /* AI-Generated Logo Banner */
        if (s_showLogoImg && s_pLogoTexture) {
            ImVec2 lp = ImGui::GetCursorScreenPos();
            float lw = ImGui::GetContentRegionAvail().x;
            float lh = lw * (180.0f / 320.0f);
            dl->AddImageRounded((ImTextureID)s_pLogoTexture,
                                lp, ImVec2(lp.x + lw, lp.y + lh),
                                ImVec2(0, 0), ImVec2(1, 1),
                                IM_COL32(255, 255, 255, 255), 8.0f);
            dl->AddRect(lp, ImVec2(lp.x + lw, lp.y + lh),
                        ImGui::ColorConvertFloat4ToU32(ImVec4(g_colAccentHover.x, g_colAccentHover.y, g_colAccentHover.z, 0.7f)),
                        8.0f, 0, 1.5f);
            ImGui::Dummy(ImVec2(lw, lh + 4.0f));
        }

        /* Title & Developer XRAOUF Badge */
        if (s_pFontTitle) ImGui::PushFont(s_pFontTitle);
        ImGui::TextColored(g_colAccentHover, "DARKANARCHY");
        if (s_pFontTitle) ImGui::PopFont();

        ImGui::TextColored(g_colSecondary, "%s", TR("DEVELOPER: XRAOUF", "المطور: XRAOUF"));
        ImGui::Separator();
        ImGui::Spacing();

        float navW = ImGui::GetContentRegionAvail().x;
        struct NavDef {
            const char *badge;
            const char *enTitle;
            const char *arTitle;
            const char *enSub;
            const char *arSub;
        };
        static const NavDef kNavs[6] = {
            { "LUA", "Scripts",  "السكربتات",     "Executor & Hooks",   "منفذ لوا والأحداث"   },
            { "DMP", "Dumper",   "ساحب الملفات",  "Client Extractor",   "استخراج السكربتات"   },
            { "CHT", "Cheat",    "خصائص الغش",   "Player & Combat",    "اللاعب والقتال"      },
            { "VEH", "Vehicle",  "المركبات",      "Mods & Spawner",     "تعديل المركبات"      },
            { "BOT", "Bot Lab",  "مختبر البوتات", "Local Bots & Stay",  "بوتات محلية وبقاء"   },
            { "CFG", "Config",   "الإعدادات",     "Theme & Language",   "المظهر واللغة"       },
        };

        for (int i = 0; i < 6; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_top_%d", i);
            const char *title = (s_lang == 0) ? AR(kNavs[i].arTitle) : kNavs[i].enTitle;
            const char *sub   = (s_lang == 0) ? AR(kNavs[i].arSub)   : kNavs[i].enSub;
            if (SidebarTabButton(kNavs[i].badge, title, sub, hid, s_topTab == i, ImVec2(navW, 46.0f))) {
                s_topTab = i;
            }
            ImGui::Spacing();
        }

        /* Language Switcher & Footer at bottom of Sidebar */
        ImGui::Separator();
        if (ImGui::Button(s_lang == 0 ? AR("اللغة: العربية -> EN##lsw") : "Lang: English -> AR##lsw", ImVec2(navW, 30.0f))) {
            s_lang = (s_lang == 0) ? 1 : 0;
        }
        ImGui::TextDisabled("BY XRAOUF | v4.0");
    }
    ImGui::EndChild();

    ImGui::SameLine();

    /* ---- RIGHT MAIN WORKSPACE ---- */
    ImGui::BeginGroup();
    {
        /* Top Header Bar */
        ImGui::BeginChild("##da_header", ImVec2(0, 50), true);
        {
            if (s_pFontTitle) ImGui::PushFont(s_pFontTitle);
            ImGui::TextColored(g_colAccentHover, "DARKANARCHY");
            if (s_pFontTitle) ImGui::PopFont();
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(g_colSecondary, "%s", TR("BY XRAOUF", "تطوير XRAOUF"));
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.82f, 0.80f, 0.92f, 1.0f), "%s",
                               (s_lang == 0 && s_status == "No connected server.")
                               ? AR("غير متصل بالسيرفر") : s_status.c_str());

            if (!s_lastAction.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("• %s", s_lastAction.c_str());
            }

            /* Right-aligned Language & Close buttons */
            float rightOff = ImGui::GetWindowWidth() - 135.0f;
            if (rightOff > 360.0f) {
                ImGui::SameLine(rightOff);
                if (ImGui::SmallButton(s_lang == 0 ? "EN##top_lang" : AR("عربي##top_lang"))) {
                    s_lang = (s_lang == 0) ? 1 : 0;
                }
                ImGui::SameLine();
                if (ImGui::SmallButton(TR("Hide [INS]##cls", "إخفاء##cls"))) {
                    s_menuOpen = false;
                }
            }
        }
        ImGui::EndChild();

        /* Active Tab Content */
        if (s_topTab == 0) {
            static const char *kSubEn[] = {"Editor", "Scripts", "Resources", "Events", "Events Table", "Packets"};
            static const char *kSubAr[] = {"المحرر", "السكربتات", "الموارد", "الأحداث", "جدول الأحداث", "الحزم"};
            float sw = (ImGui::GetContentRegionAvail().x - 5 * 8.f) / 6.f;
            for (int i = 0; i < 6; ++i) {
                char hid[32];
                snprintf(hid, sizeof(hid), "nvx_ssub_%d", i);
                const char *lbl = (s_lang == 0) ? AR(kSubAr[i]) : kSubEn[i];
                if (SubTabPill(lbl, hid, s_scriptsSub == i, ImVec2(sw, 30))) s_scriptsSub = i;
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
            static const char *kCSubEn[] = {"Player", "Features", "Markers"};
            static const char *kCSubAr[] = {"اللاعبين", "خصائص الغش", "الإحداثيات"};
            float sw = (ImGui::GetContentRegionAvail().x - 2 * 8.f) / 3.f;
            for (int i = 0; i < 3; ++i) {
                char hid[32];
                snprintf(hid, sizeof(hid), "nvx_csub_%d", i);
                const char *lbl = (s_lang == 0) ? AR(kCSubAr[i]) : kCSubEn[i];
                if (SubTabPill(lbl, hid, s_cheatSub == i, ImVec2(sw, 30))) s_cheatSub = i;
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
        } else if (s_topTab == 4) {
            ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
            DrawBotsTab();
            ImGui::EndChild();
        } else {
            ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
            DrawConfigTab();
            ImGui::EndChild();
        }
    }
    ImGui::EndGroup();

    ImGui::End();
}

extern "C" void NrthUI_RenderFrame(bool menuOpen)
{
    PollHotkeys_10012250();
    DrawWatermark_10012bc0();
    DrawKeybindList_100130a0();
    DrawCustomCrosshairOverlay();
    if (menuOpen) {
        s_menuOpen = true;
        NrthUI_Build();
    }
    DrawNotifications_10016990();
}

#else /* Headless / non-Win32 build for verification tests */

extern "C" void NrthUI_ApplyTheme(void) {}
extern "C" void NrthUI_InitFonts(void) {}
extern "C" void NrthUI_InitTextures(void *pD3DDevice9) { (void)pD3DDevice9; }
extern "C" void NrthUI_ReleaseTextures(void) {}
extern "C" void NrthUI_Build(void) {}
extern "C" void NrthUI_RenderFrame(bool menuOpen) { (void)menuOpen; }
extern "C" void NrthUI_PushToastNotification(const char *msg) { (void)msg; }

#endif
