-- ============================================================================
-- DARKANARCHY Server Guard — server side | DEV: XRAOUF
-- Blue-team protection layer for the operator's OWN server.
-- Detects and (optionally) blocks the "fake players / join flood / mimicry"
-- attack class at the only place it can be stopped: the server itself.
--
-- Detections:
--   D1 per-IP join rate      (many joins, one IP — LAN botnet pattern)
--   D2 global join burst     (server-wide join storm)
--   D3 duplicate serials     (same serial on 2+ concurrent players)
--   D4 nick churn            (one player renaming rapidly — mimicry probe)
--   D5 fake-bot nick pattern (player nicks pretending to be our BOT peds)
--
-- Actions: admin alert + server log; optional auto-ban (off by default).
-- Commands (admins): /guardstatus, /guardautoban, /guardreset
-- ============================================================================

local kJoinWindowSec   = 60    -- D1 window
local kMaxJoinsPerIP   = 4     -- D1 threshold per window
local kBurstWindowSec  = 10    -- D2 window
local kMaxBurstJoins   = 8     -- D2 threshold server-wide
local kMaxNickRenames  = 4     -- D4 renames per 60s per player
local kBanSeconds      = 600   -- auto-ban duration when enabled

local ipJoins    = {}          -- ip -> { timestamps }
local burst      = {}          -- global join timestamps
local serialRefs = {}          -- serial -> concurrent players count
local nickHist   = {}          -- player element -> { timestamps }
local alarms     = 0
local autoBan    = false

-- ---------------------------------------------------------------- utilities
local function isAdmin(player)
    if not isElement(player) then return false end
    return hasObjectPermissionTo(player, "function.banIP", false)
end

local function alertAdmins(msg)
    alarms = alarms + 1
    outputServerLog("GUARD: " .. msg)
    for _, p in ipairs(getElementsByType("player")) do
        if isAdmin(p) then
            outputChatBox("GUARD: " .. msg, p, 255, 70, 90)
        end
    end
end

local function trimOld(list, now, window)
    local out = {}
    for _, t in ipairs(list) do
        if now - t <= window then out[#out + 1] = t end
    end
    return out
end

local function banIPForFlood(ip, why)
    if not autoBan then return end
    local ban = banIP(ip, root, "DARKANARCHY guard: " .. why, kBanSeconds)
    if ban then
        outputServerLog(("GUARD: auto-banned %s for %ds (%s)"):format(ip, kBanSeconds, why))
    end
end

-- ---------------------------------------------------------------- D1 / D2
addEventHandler("onPlayerConnect", root, function(nick, ip, user, serial, ver)
    local now = getRealTime().timestamp

    -- D1: per-IP join rate
    ipJoins[ip] = trimOld(ipJoins[ip] or {}, now, kJoinWindowSec)
    table.insert(ipJoins[ip], now)
    if #ipJoins[ip] > kMaxJoinsPerIP then
        alertAdmins(("D1 join-flood from %s (%d joins in %ds) nick=%s serial=%s")
            :format(ip, #ipJoins[ip], kJoinWindowSec, tostring(nick), tostring(serial)))
        banIPForFlood(ip, "join flood")
        cancelEvent(true, "DARKANARCHY: connection refused (join flood).")
        return
    end

    -- D2: server-wide join burst
    burst = trimOld(burst, now, kBurstWindowSec)
    table.insert(burst, now)
    if #burst > kMaxBurstJoins then
        alertAdmins(("D2 join burst: %d connections in %ds (latest from %s)")
            :format(#burst, kBurstWindowSec, ip))
        banIPForFlood(ip, "join burst")
        cancelEvent(true, "DARKANARCHY: connection refused (join burst).")
        return
    end
end)

-- ---------------------------------------------------------------- D3 serials
addEventHandler("onPlayerJoin", root, function()
    local serial = getPlayerSerial(source)
    if serial and serial ~= "" then
        serialRefs[serial] = (serialRefs[serial] or 0) + 1
        if serialRefs[serial] > 1 then
            alertAdmins(("D3 duplicate serial ACTIVE x%d: %s (%s)")
                :format(serialRefs[serial], serial, getPlayerName(source)))
        end
    end
end)

addEventHandler("onPlayerQuit", root, function()
    local serial = getPlayerSerial(source)
    if serial and serialRefs[serial] then
        serialRefs[serial] = math.max(0, serialRefs[serial] - 1)
        if serialRefs[serial] == 0 then serialRefs[serial] = nil end
    end
    nickHist[source] = nil
end)

-- ---------------------------------------------------------------- D4 / D5
addEventHandler("onPlayerChangeNick", root, function(oldNick, newNick)
    local now = getRealTime().timestamp
    nickHist[source] = trimOld(nickHist[source] or {}, now, 60)
    table.insert(nickHist[source], now)
    if #nickHist[source] > kMaxNickRenames then
        alertAdmins(("D4 nick churn: %s renamed %d times/60s (now %s)")
            :format(tostring(oldNick), #nickHist[source], tostring(newNick)))
    end
    -- D5: pretending to be a DARKANARCHY bot ped (impersonation of the lab setup)
    if type(newNick) == "string" and newNick:upper():find("BOT%s*#") then
        alertAdmins(("D5 fake-bot nick: %s -> %s (our bots are PEDS with nametags, not players)")
            :format(tostring(oldNick), tostring(newNick)))
    end
end)

-- ---------------------------------------------------------------- commands
addCommandHandler("guardstatus", function(player)
    if player and not isAdmin(player) then return end
    local now = getRealTime().timestamp
    local lastMin = 0
    for _, ts in pairs(ipJoins) do lastMin = lastMin + #trimOld(ts, now, kJoinWindowSec) end
    local players = #getElementsByType("player")
    local dupes = 0
    for _, c in pairs(serialRefs) do if c > 1 then dupes = dupes + 1 end end
    local function say(msg)
        if player then outputChatBox(msg, player, 255, 70, 90)
        else outputServerLog("GUARD: " .. msg) end
    end
    say(("GUARD status: players=%d | joins last %ds=%d | dup-serials=%d | alarms=%d | autoban=%s")
        :format(players, kJoinWindowSec, lastMin, dupes, alarms, tostring(autoBan)))
end, false, false)

addCommandHandler("guardautoban", function(player)
    if player and not isAdmin(player) then return end
    autoBan = not autoBan
    local function say(msg)
        if player then outputChatBox(msg, player, 255, 70, 90)
        else outputServerLog("GUARD: " .. msg) end
    end
    say("GUARD auto-ban is now " .. tostring(autoBan))
end, false, false)

addCommandHandler("guardreset", function(player)
    if player and not isAdmin(player) then return end
    ipJoins, burst, nickHist = {}, {}, {}
    local function say(msg)
        if player then outputChatBox(msg, player, 255, 70, 90)
        else outputServerLog("GUARD: " .. msg) end
    end
    say("GUARD counters reset (serial tracking kept).")
end, false, false)

outputServerLog("DARKANARCHY Server Guard loaded: D1 IP-flood, D2 burst, D3 dup-serials, D4 nick-churn, D5 fake-bot nicks.")
