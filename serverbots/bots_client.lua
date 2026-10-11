-- ============================================================================
-- DARKANARCHY Server Bots — client side | DEV: XRAOUF
-- Draws "BOT #n" nametags over the server-side bots so everyone can tell
-- they are bots (matches the report-fidelity lab purpose).
-- ============================================================================

local function drawNametags()
    local px, py, pz = getElementPosition(getLocalPlayer())
    for _, ped in ipairs(getElementsByType("ped")) do
        local idx = getElementData(ped, "daBot")
        if idx then
            local x, y, z = getElementPosition(ped)
            if getDistanceBetweenPoints3D(px, py, pz, x, y, z) < 60 then
                local sx, sy = getScreenFromWorldPosition(x, y, z + 1.1, 0)
                if sx and sy then
                    local label = ("BOT #%d"):format(tonumber(idx) or 0)
                    local w = dxGetTextWidth(label, 1, "default-bold") + 10
                    dxDrawRectangle(sx - w / 2, sy - 4, w, 20, tocolor(0, 0, 0, 140))
                    dxDrawText(label, sx, sy, sx, sy + 12, tocolor(255, 60, 80, 255),
                               1, "default-bold", "center", "top")
                end
            end
        end
    end
end
addEventHandler("onClientRender", root, drawNametags)
