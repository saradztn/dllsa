#pragma once
/**
 * ============================================================================
 * nrth_ui.h — NRTH overlay UI & MTA Packet / Feature Sync interface
 * ============================================================================
 * Evidence:
 *   - Window title "North Cheat" (VA 0x100ea0d8)
 *   - Top tabs "%s##nvx_top_%d": Scripts | Dumper | Cheat | Vehicle | Config
 *   - PACKET_ID_* table (.rdata 0x100e9be4..0x100eaaa4, including
 *     PACKET_ID_CHEAT_CHALLENGEMEMORY at 0x100eb6a8)
 *   - Report channels: PLAYER_SCREENSHOT, PLAYER_TRANSGRESSION,
 *     PLAYER_DIAGNOSTIC, PLAYER_ACINFO
 *   - Sync structs: SPlayerHealthSync, SWeaponAimSync
 *   - Lua VM bridge: 0x1013bf04 (stride 0x1C, L at +0x18), default_L 0x1013c95c,
 *     loadbuffer 0x1013c94c ("@custom"), pcall 0x1013c974, flag 0x1013c939,
 *     script buffer 0x1013beec, VirtualQuery pointer guard.
 * ============================================================================
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct _NrthPacketDef {
    int         id;
    const char *name;
    bool        isReportChannel;
} NrthPacketDef;

#ifdef __cplusplus
extern "C" {
#endif

void NrthUI_ApplyTheme(void);
void NrthUI_Build(void);
void NrthUI_RenderFrame(bool menuOpen);

const NrthPacketDef *NrthUI_GetPacketCatalog(uint32_t *outCount);
void                 NrthUI_SyncFeaturesToState(void);
bool                 NrthUI_ExecuteLuaViaBridge(const char *code, size_t len, int vmMode);

/* ---- Live hook callbacks (0x100047b0, 0x100050a0, 0x100052b0, 0x1001da80) */
void     NrthUI_OnClientScriptLoaded(const char *chunkName, const char *code, size_t len);
bool     NrthUI_ShouldBlockServerEvent(const char *eventName);
void     NrthUI_OnResourceStarted(const char *resName);
bool     NrthUI_OnPacketSent(unsigned char packetId);
uint32_t NrthUI_GetMarkerCount(void);
bool     NrthUI_GetMarkerAt(uint32_t idx, float *outX, float *outY, float *outZ);
void     NrthUI_PushToastNotification(const char *msg);

#ifdef __cplusplus
}
#endif
