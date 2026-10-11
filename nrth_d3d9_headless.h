#pragma once
/**
 * ============================================================================
 * nrth_d3d9_headless.h — Minimal D3D9 type declarations for the Linux
 * verification harness (NRTH_UI_HEADLESS). Never compiled on Windows, where
 * the real <d3d9.h> is used. Only the declarations the embedded-UI code
 * touches (CreateTextureFromQoi path) exist here; nothing is instantiated
 * headless because NrthUI_InitTextures(NULL) returns early.
 * ============================================================================
 */
#include <stdint.h>

typedef long HRESULT;
#ifndef FAILED
#define FAILED(hr) ((HRESULT)(hr) < 0)
#endif

typedef struct RECT_ { long left, top, right, bottom; } RECT_H;
typedef unsigned int UINT_H;

enum D3DFORMAT_H { D3DFMT_A8R8G8B8 = 21 };
enum D3DPOOL_H    { D3DPOOL_MANAGED = 1 };

struct D3DLOCKED_RECT {
    int   Pitch;
    void *pBits;
};

struct IDirect3DTexture9 {
    virtual unsigned long Release() = 0;
    virtual HRESULT LockRect(UINT_H Level, D3DLOCKED_RECT *pLockedRect,
                             const RECT_H *pRect, unsigned long Flags) = 0;
    virtual HRESULT UnlockRect(UINT_H Level) = 0;
};

struct IDirect3DDevice9 {
    virtual HRESULT CreateTexture(UINT_H Width, UINT_H Height, UINT_H Levels,
                                  unsigned long Usage, int Format, int Pool,
                                  IDirect3DTexture9 **ppTexture, void *pShared) = 0;
};
