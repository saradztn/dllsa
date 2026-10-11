-- ============================================================================
-- DARKANARCHY Server Bots — server side | DEV: XRAOUF
-- For the operator's OWN server only (report-fidelity testing lab).
-- Bots are real server-side peds: the server simulates and syncs them, so
-- EVERY player on the server sees them. Admin/Console permission required.
--
-- Commands:
--   /addbots <1..64>   spawn N bots around you
--   /delbots           remove all bots
-- ============================================================================

local daBots    = {}
local daWander  = nil
local kSkins    = {7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30}

local function clearAll()
    for _, p in ipairs(daBots) do
        if isElement(p) then
            destroyElement(p)
        end
    end
    daBots = {}
    if daWander then
        killTimer(daWander)
        daWander = nil
    end
end

local function spawnAround(player, n)
    local px, py, pz = getElementPosition(player)
    local interior, dimension = getElementInterior(player), getElementDimension(player)
    for i = 1, n do
        local a  = (i / n) * math.pi * 2
        local bx = px + 4.0 * math.cos(a)
        local by = py + 4.0 * math.sin(a)
        local bz = pz + 0.5
        local ped = createPed(kSkins[(i % #kSkins) + 1], bx, by, bz, 0, interior, dimension)
        if ped then
            setElementData(ped, "daBot", i, true) -- broadcast: nametags on all clients
            setElementHealth(ped, 100)
            setPedRotation(ped, math.random(0, 359))
            daBots[#daBots + 1] = ped
        end
    end
    -- server-side wander: positions sync to every player automatically
    if daWander then killTimer(daWander) end
    daWander = setTimer(function()
        for _, p in ipairs(daBots) do
            if isElement(p) then
                local x, y, z = getElementPosition(p)
                setPedRotation(p, math.random(0, 359))
                setElementPosition(p, x + math.random(-2, 2), y + math.random(-2, 2), z)
            end
        end
    end, 1500, 0)
end

local function isAdminOrConsole(player)
    if player == nil then return true end -- server console / runccon
    return hasObjectPermissionTo(player, "function.kickPlayer", false)
end

addCommandHandler("addbots", function(player, _, n)
    if not isAdminOrConsole(player) then
        if player then outputChatBox("DARKANARCHY: admin only.", player, 210, 30, 60) end
        return
    end
    n = math.max(1, math.min(tonumber(n) or 8, 64))
    clearAll()
    if player then
        spawnAround(player, n)
        outputChatBox(("DARKANARCHY: %d bots deployed around %s"):format(n, getPlayerName(player)),
                      root, 210, 30, 60)
    end
end, false, false)

addCommandHandler("delbots", function(player)
    if not isAdminOrConsole(player) then
        if player then outputChatBox("DARKANARCHY: admin only.", player, 210, 30, 60) end
        return
    end
    clearAll()
    outputChatBox("DARKANARCHY: bots removed.", root, 210, 30, 60)
end, false, false)

addEventHandler("onResourceStop", resourceRoot, clearAll)
