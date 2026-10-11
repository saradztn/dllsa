#pragma once
/**
 * ============================================================================
 * nrth_ui.h — DARKANARCHY (by XRAOUF) Overlay UI & MTA Packet / Feature Sync
 * ============================================================================
 * Features:
 *   - Bilingual UI: Arabic (العربية with contextual shaping & RTL BiDi) + English
 *   - Custom TTF Fonts: DarkAnarchy-English.ttf + DarkAnarchy-Arabic.ttf
 *   - AI-Generated Logo & Background D3D9 textures ("DARKANARCHY BY XRAOUF")
 *   - Multi-theme custom glassmorphic cyber-anarchy design
 *   - Full MTA PACKET_ID_* catalogue, SPlayerHealthSync, SWeaponAimSync & Lua VM bridge
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
void NrthUI_InitFonts(void);
void NrthUI_InitTextures(void *pD3DDevice9);
void NrthUI_ReleaseTextures(void);
void NrthUI_Build(void);
void NrthUI_RenderFrame(bool menuOpen);

/* ---- Session Lab core (pure, testable in both suite modes) --------------- */
uint8_t  NrthHook_IsInGame(void);              /* g_pClientGame_10148ee8 != NULL   */
uint32_t NrthUI_IsStayModeOn(void);
void     NrthUI_SetStayMode(uint32_t on);
void     NrthUI_BuildSessionProbeLua(char *buf, size_t cap);

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
