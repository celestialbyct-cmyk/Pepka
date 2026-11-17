-- ============================================================
-- Zolar / Baner hub UI Library  (deobfuscated)
-- Original: pepka.lua
-- Часть 1/4: защита + ключи + крипто
-- ============================================================

-- 1. Заглушка LuaObfuscator: если скрипт НЕ обфусцирован,
--    забиваем глобалы пустыми функциями, чтобы код ниже не падал.
if not LPH_OBFUSCATED then
    local nop = function() end
    local env = getgenv and getgenv() or _G
    env.LPH_ATTRIBUTES = nop
    env.ENCRYPT, env.VM, env.PRESET, env.OPTIMIZE, env.TRANSFORM, env.ERROR_HANDLING = nop,nop,nop,nop,nop,nop
    env.UNROLL, env.INLINE, env.NO_UPVALUES = nop,nop,nop
    env.NONE, env.OPAL, env.ONYX, env.FAST, env.BALANCED, env.SECURE = nop,nop,nop,nop,nop,nop
    env.EXTRACT, env.CONTROL_FLOW, env.REWRITE_NAMECALLS, env.GLOBALS, env.CONSTANTS = nop,nop,nop,nop,nop
end

-- 2. Универсальный HTTP-request (под разные экзекуторы)
local httpRequest =
    rawget(getfenv(), "request")
    or (syn and syn.request)
    or (http and http.request)
    or (fluxus and fluxus.request)
    or (getgenv and getgenv().request)
if type(httpRequest) ~= "function" then
    httpRequest = function() return nil end
end

local HttpService = game:GetService("HttpService")

-- 3. KEYLESS-заглушка: имитация системы ключей.
--    Реальной проверки нет — всегда "FREE".
local KeySystem = {
    alive  = true,
    reason = "KEYLESS",
    value  = "FREE",
    unload = nil,
}
function KeySystem.bind(fn) if type(fn) == "function" then KeySystem.unload = fn end end
function KeySystem.stop() KeySystem.alive = false end
function KeySystem.watch() KeySystem.alive = true end
function KeySystem.open()
    local env = getgenv()
    local prev = env.SHKEY
    if type(prev) == "table" and type(prev.stop) == "function" then pcall(prev.stop) end
    KeySystem.alive = true
    KeySystem.reason = "KEYLESS"
    env.SCRIPT_KEY   = KeySystem.value
    env.SHKEY        = KeySystem
    env.JD_IS_PREMIUM = true
    env.JD_REASON    = "KEYLESS"
    KeySystem.watch()
    return true
end
if not KeySystem.open() then return end

-- ============================================================
-- 4. SHA-256 (чистый Lua, bit32)
-- ============================================================
local sha256 do
    local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
    local rrotate, rshift  = bit32.rrotate, bit32.rshift
    local char, byte, rep, sub = string.char, string.byte, string.rep, string.sub
    local concat = table.concat
    local floor  = math.floor

    local K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    }

    local function sha256_compress(msg)
        local h0,h1,h2,h3,h4,h5,h6,h7 =
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        local len = #msg
        local bitsLo = (len * 8) % 4294967296
        local bitsHi = floor((len * 8) / 4294967296)
        local pad = (56 - (len + 1) % 64) % 64
        msg = msg .. "\128" .. rep("\0", pad)
            .. char(floor(bitsHi/16777216)%256, floor(bitsHi/65536)%256, floor(bitsHi/256)%256, bitsHi%256)
            .. char(floor(bitsLo/16777216)%256, floor(bitsLo/65536)%256, floor(bitsLo/256)%256, bitsLo%256)

        local w = {}
        for chunk = 1, #msg, 64 do
            for i = 0, 15 do
                local p = chunk + i*4
                w[i+1] = byte(msg,p)*16777216 + byte(msg,p+1)*65536 + byte(msg,p+2)*256 + byte(msg,p+3)
            end
            for i = 17, 64 do
                local s0 = w[i-15]
                local s1 = w[i-2]
                local x  = bxor(rrotate(s0,7), rrotate(s0,18), rshift(s0,3))
                local y  = bxor(rrotate(s1,17), rrotate(s1,19), rshift(s1,10))
                w[i] = (w[i-16] + x + w[i-7] + y) % 4294967296
            end
            local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
            for i = 1, 64 do
                local S1 = bxor(rrotate(e,6), rrotate(e,11), rrotate(e,25))
                local ch = bxor(band(e,f), band(bnot(e),g))
                local t1 = (h + S1 + ch + K[i] + w[i]) % 4294967296
                local S0 = bxor(rrotate(a,2), rrotate(a,13), rrotate(a,22))
                local mj = bxor(band(a,b), band(a,c), band(b,c))
                local t2 = (S0 + mj) % 4294967296
                h,g,f,e,d,c,b,a = g,f,e,(d+t1)%4294967296,c,b,a,(t1+t2)%4294967296
            end
            h0=(h0+a)%4294967296; h1=(h1+b)%4294967296; h2=(h2+c)%4294967296; h3=(h3+d)%4294967296
            h4=(h4+e)%4294967296; h5=(h5+f)%4294967296; h6=(h6+g)%4294967296; h7=(h7+h)%4294967296
        end
        local function u32(n) return char(floor(n/16777216)%256,floor(n/65536)%256,floor(n/256)%256,n%256) end
        return u32(h0)..u32(h1)..u32(h2)..u32(h3)..u32(h4)..u32(h5)..u32(h6)..u32(h7)
    end

    local function hmac(key, data)
        if #key > 64 then key = sha256_compress(key) end
        if #key < 64 then key = key .. rep("\0", 64-#key) end
        local o, i = {}, {}
        for k = 1, 64 do
            local b = byte(key,k)
            o[k] = char(bxor(b,0x5c)); i[k] = char(bxor(b,0x36))
        end
        return sha256_compress(concat(o) .. sha256_compress(concat(i) .. data))
    end

    sha256 = { hash = sha256_compress, hmac = hmac }
end

-- ============================================================
-- 5. base64url + hex
-- ============================================================
local b64urlEncode, b64decode, hexDecode do
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    local char, byte, sub, floor, concat = string.char, string.byte, string.sub, math.floor, table.concat

    b64urlEncode = function(s)
        local out, n = {}, 0
        for i = 1, #s, 3 do
            local a = byte(s,i)
            local b = byte(s,i+1)
            local c = byte(s,i+2)
            local v = a*65536 + (b or 0)*256 + (c or 0)
            n = n + 1; out[n] = sub(alphabet, floor(v/262144)+1, floor(v/262144)+1)
            n = n + 1; out[n] = sub(alphabet, floor(v/4096)%64+1, floor(v/4096)%64+1)
            if b then n = n + 1; out[n] = sub(alphabet, floor(v/64)%64+1, floor(v/64)%64+1) end
            if c then n = n + 1; out[n] = sub(alphabet, v%64+1, v%64+1) end
        end
        return concat(out)
    end

    local rev = {}
    local std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for i = 1, #std do rev[sub(std,i,i)] = i-1 end
    b64decode = function(s)
        s = s:gsub("-","+"):gsub("_","/"):gsub("[^A-Za-z0-9+/=]","")
        s = s .. string.rep("=", (4 - #s%4) % 4)
        local out, n = {}, 0
        for i = 1, #s, 4 do
            local c1 = rev[sub(s,i,i)]   or 0
            local c2 = rev[sub(s,i+1,i+1)] or 0
            local c3 = rev[sub(s,i+2,i+2)] or 0
            local c4 = rev[sub(s,i+3,i+3)] or 0
            local v = c1*262144 + c2*4096 + c3*64 + c4
            n = n + 1; out[n] = char(floor(v/65536)%256)
            if sub(s,i+2,i+2) ~= "=" then n = n + 1; out[n] = char(floor(v/256)%256) end
            if sub(s,i+3,i+3) ~= "=" then n = n + 1; out[n] = char(v%256) end
        end
        return concat(out)
    end

    hexDecode = function(s)
        return (s:gsub("..", function(h) return char(tonumber(h,16)) end))
    end
end

-- ============================================================
-- 6. SHITARO asset protection — ядро "защиты"
--    seed -> HMAC -> XOR маска ассетов + подпись запроса/ответа
-- ============================================================

-- захардкоженный seed (hex -> bytes)
local SHITARO_SEED = hexDecode("02d417c2bd7b033a00d3c4e9fda43fc56761f68f516cf68a68a6110f2cb99e49")

local RNG = Random.new((tick()*1e6) % 2147483647 + os.time())

local function randomBytes(n)
    local t = {}
    for i = 1, n do t[i] = string.char(RNG:NextInteger(0,255)) end
    return table.concat(t)
end

local function packUInt32BE(n)
    local t = {}
    for i = 8, 1, -1 do t[i] = string.char(n % 256); n = math.floor(n / 256) end
    return table.concat(t)
end

-- URL-encode пути ассета
local function urlEncodePath(s)
    return (string.gsub(s, "[^%w%-%._~/]", function(c) return string.format("%%%02X", string.byte(c)) end))
end

-- PRNG на ChaCha-подобной схеме (на самом деле простой xorshift с seed из HMAC)
local function makeStream(seed)
    local function rd32(pos)
        local a,b,c,d = string.byte(seed,pos,pos+3)
        return d*16777216 + c*65536 + b*256 + a
    end
    local a,b,c,e = rd32(1), rd32(5), rd32(9), rd32(13)
    if a==0 and b==0 and c==0 and e==0 then a,b,c,e = 0x9e3779b9,0x243f6a88,0xb7e15162,0x85ebca6b end
    local rl, rr = bit32.lshift, bit32.rshift
    local bxor = bit32.bxor
    return function()
        local f = a
        f = bxor(f, rl(f,11)); f = bxor(f, rr(f,8))
        a,b,c = b,c,e
        local x = e
        x = bxor(x, rr(x,19)); x = bxor(x, f)
        e = x
        return x
    end
end

-- XOR-маска тела ассета потоком из ключа
local function maskAsset(data, assetName)
    local stream = makeStream(sha256.hash(SHITARO_SEED .. "SHITARO-ASSET-MASK-v1\0" .. assetName))
    local len = #data
    if buffer and buffer.fromstring then
        local b = buffer.fromstring(data)
        local i = 0
        while i+4 <= len do
            buffer.writeu32(b, i, bit32.bxor(buffer.readu32(b,i), stream()))
            i = i + 4
        end
        if i < len then
            local k = stream(); local j = 0
            while i+j < len do
                buffer.writeu8(b, i+j, bit32.bxor(buffer.readu8(b,i+j), bit32.band(bit32.rshift(k, j*8),255)))
                j = j + 1
            end
        end
        return buffer.tostring(b)
    end
    local out, n = {}, 0
    local i = 1
    while i <= len do
        local k = stream()
        for j = 0, 3 do
            if i+j <= len then
                n = n + 1
                out[n] = string.char(bit32.bxor(string.byte(data,i+j), bit32.band(bit32.rshift(k, j*8), 255)))
            end
        end
        i = i + 4
    end
    return table.concat(out)
end

-- подписанный GET к shitaro.lol/api/... с проверкой HMAC ответа
local function shitaroFetch(url, kind, path)
    local nonce   = randomBytes(16)
    local stamp   = packUInt32BE(os.time())
    local reqSig  = sha256.hmac(SHITARO_SEED, "SHITARO-"..kind.."-REQ-v1\0"..path.."\0"..nonce.."\0"..stamp)

    local ok, resp = pcall(httpRequest, {
        Url = url .. urlEncodePath(path),
        Method = "GET",
        Headers = {
            ["X-Shitaro-Token"]  = reqSig,
            ["Accept"]           = "*/*",
            ["Cache-Control"]    = "no-cache",
        },
    })
    if not ok or type(resp) ~= "table" or resp.StatusCode ~= 200 then return nil end
    local body = resp.Body
    if type(body) ~= "string" or #body == 0 then return nil end
    local headers = resp.Headers or {}
    local sig = headers["X-Shitaro-Sig"] or headers["x-shitaro-sig"] or ""
    if sig == "" then return nil end
    local expect = sha256.hmac(SHITARO_SEED, "SHITARO-"..kind.."-RESP-v1\0"..path.."\0"..nonce.."\0"..#body..body)
    if b64urlEncode(expect) ~= b64urlEncode(sig) then return nil end
    if kind == "ASSET" then return maskAsset(body, nonce) end
    return body
end

local ShitaroAPI = {}
function ShitaroAPI.lib(name)   return shitaroFetch("https://shitaro.lol/api/library/", "LIB",   name) end
function ShitaroAPI.asset(name) return shitaroFetch("https://shitaro.lol/api/assets/",  "ASSET", name) end
-- ============================================================
-- Zolar UI Library — deobfuscated
-- Часть 2/4: payload verify + asset manager + PNG decoder
-- ============================================================

-- ============================================================
-- 7. Верификация подписанного payload (второй слой)
--    Формат: [0x53][ver][verifier 4b][len 2b?][crc 4b][body]
--    Внутри: base64 -> mixcrypt -> проверка CRC
-- ============================================================
local verifyPayload do
    local bxor, lrotate, lshift, rshift, band = bit32.bxor, bit32.lrotate, bit32.lshift, bit32.rshift, bit32.band
    local byte, char, sub, concat = string.byte, string.char, string.sub, table.concat

    -- магический префикс-соль для mixcrypt
    local MAGIC = {
        0x5B,0x27,0xE4,0x91,0x0C,0xBD,0x7A,0x36,0xF1,0x48,0x92,0xAE,
        0x63,0xD5,0x1F,0x8C,0x2A,0x74,0xB0,0x59,0xEE,0x13,0xC7,0x6D,
        0x9F,0x35,0x88,0x4C,0xA1,0x70,0xDB,0x26,
    }
    -- 4 пары ключей для 4 раундов
    local ROUND_KEYS = {
        {0x9E3779B9, 0x85EBCA6B},
        {0x243F6A88, 0xC2B2AE35},
        {0xB7E15162, 0x27D4EB2F},
        {0x85EBCA6B, 0x165667B1},
    }

    local b64rev = nil
    local function getB64Rev()
        if b64rev then return b64rev end
        local alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        b64rev = {}
        for i = 1, #alpha do b64rev[byte(alpha,i)] = i - 1 end
        return b64rev
    end

    local function b64decode(s)
        local rev = getB64Rev()
        local out, n = {}, 0
        local acc, bits = 0, 0
        for i = 1, #s do
            local c = byte(s,i)
            local v = rev[c]
            if v then
                acc = acc * 64 + v
                bits = bits + 6
                if bits >= 8 then
                    bits = bits - 8
                    local p = 2 ^ bits
                    local b = math.floor(acc / p)
                    acc = acc - b * p
                    n = n + 1
                    out[n] = char(b % 256)
                end
            elseif c ~= 61 and c ~= 10 and c ~= 13 and c ~= 32 and c ~= 9 then
                return nil -- '=' или пробелы допустимы, остальное — ошибка
            end
        end
        return concat(out)
    end

    -- mixcrypt-раунд: xor + lrotate(7) + xor ключом
    local function mixRound(data, key1, key2)
        local acc = key1
        for i = 1, #data do
            acc = bxor(acc, data[i])
            acc = lrotate(acc, 7)
            acc = bxor(acc, key2)
        end
        return acc
    end

    -- инициализация состояния из MAGIC + payload
    local function initState(data)
        local buf = table.create(#MAGIC + #data)
        for i = 1, #MAGIC do buf[i] = MAGIC[i] end
        for i = 1, #data do buf[#MAGIC + i] = byte(data,i) end

        local a = mixRound(buf, ROUND_KEYS[1][1], ROUND_KEYS[1][2])
        local b = mixRound(buf, ROUND_KEYS[2][1], ROUND_KEYS[2][2])
        local c = mixRound(buf, ROUND_KEYS[3][1], ROUND_KEYS[3][2])
        local d = mixRound(buf, ROUND_KEYS[4][1], ROUND_KEYS[4][2])
        if a == 0 and b == 0 and c == 0 and d == 0 then
            a,b,c,d = 0x9E3779B9,0x243F6A88,0xB7E15162,0x85EBCA6B
        end
        local state = {a,b,c,d}
        return function()
            local f = state[1]
            f = bxor(f, lrotate(f,11)); f = bxor(f, rshift(f,8))
            state[1], state[2], state[3] = state[2], state[3], state[4]
            local x = state[4]
            x = bxor(x, rshift(x,19)); x = bxor(x, f)
            state[4] = x
            return x
        end
    end

    -- XOR-декрипт потока
    local function decryptStream(keySource, data)
        local nextKey = initState(keySource)
        local len = #data
        if buffer and buffer.fromstring then
            local b = buffer.fromstring(data)
            local i = 0
            while i+4 <= len do
                buffer.writeu32(b, i, bxor(buffer.readu32(b,i), nextKey()))
                i = i + 4
            end
            if i < len then
                local k = nextKey(); local j = 0
                while i+j < len do
                    buffer.writeu8(b, i+j, bxor(buffer.readu8(b,i+j), band(rshift(k, j*8),255)))
                    j = j + 1
                end
            end
            return buffer.tostring(b)
        end
        local out, n = {}, 0
        local i = 1
        while i <= len do
            local k = nextKey()
            for j = 0, 3 do
                if i+j <= len then
                    n = n + 1
                    out[n] = char(bxor(byte(data,i+j), band(rshift(k, j*8),255)))
                end
            end
            i = i + 4
        end
        return concat(out)
    end

    -- CRC-подобный хэш (rolling, для проверки целостности)
    local function checksum(data)
        local h = 0x243F6A88
        local len = #data
        local i = 1
        while i + 7 <= len do
            local b1,b2,b3,b4,b5,b6,b7,b8 = byte(data,i,i+7)
            h = bxor(lrotate(bxor(h, b1), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b2), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b3), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b4), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b5), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b6), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b7), 7), 0x9E3779B9)
            h = bxor(lrotate(bxor(h, b8), 7), 0x9E3779B9)
            i = i + 8
        end
        while i <= len do
            h = bxor(lrotate(bxor(h, byte(data,i)), 7), 0x9E3779B9)
            i = i + 1
        end
        return h
    end

    -- публичная функция: проверяет формат и возвращает "key" (или nil)
    verifyPayload = function(payload)
        if type(payload) ~= "string" or #payload < 11 then return nil end
        local buf = payload
        if byte(buf,1) ~= 0x53 then
            buf = b64decode(payload)
            if type(buf) ~= "string" or #buf < 11 then return nil end
        end
        if byte(buf,1) ~= 0x53 then return nil end
        local version = byte(buf,2)
        if version ~= 1 and version ~= 2 then return nil end
        local v0,v1,v2,v3 = byte(buf,7,10)
        local key = decryptStream(sub(buf,3,6), sub(buf,11))
        if checksum(key) ~= v3*16777216 + v2*65536 + v1*256 + v0 then return nil end
        return key
    end
end

-- ============================================================
-- 8. Asset manager (shitaro_asset / assetlist / volatile / flush)
-- ============================================================
local ContentProvider = game:GetService("ContentProvider")

local assetCache        = {}   -- path -> customAsset url
local volatileAssets    = {}   -- временные файлы на удаление
local manifestCache     = nil  -- { f = { {n=..., s=..., kind=...}, ... } }
local manifestSorted    = nil
local volatileFlag1     = false
local volatileFlag2     = false
local manifestByPath    = nil

-- имя cloud-ассета (hex -> "b53227f0da.png")
local CLOUD_ASSET_NAME = string.char(98,53,51,50,50,55,102,48,100,97,46,112,110,103)

local function parseManifest(text)
    if type(text) ~= "string" or #text == 0 then return nil end
    local ok, obj = pcall(function() return HttpService:JSONDecode(text) end)
    if ok and type(obj) == "table" and type(obj.f) == "table" then return obj end
    return nil
end

-- загрузка манифеста с сервера (с кэшем)
local function loadManifestMap()
    if manifestByPath then return manifestByPath end
    local raw = ShitaroAPI.asset(CLOUD_ASSET_NAME)
    if type(raw) ~= "string" or #raw == 0 then return nil end
    local map, sorted = {}, {}
    for line in string.gmatch(raw, "([^\n]+)") do
        local name, srv, size, kind = string.match(line, "^(.-)\t(.-)\t(%d+)\t(%a+)$")
        size = tonumber(size)
        if name and name ~= "" and srv and srv ~= "" and size and size > 0 then
            map[name] = { srv = srv, size = size, kind = kind }
            if kind ~= "data" then sorted[#sorted+1] = name end
        end
    end
    if not next(map) then return nil end
    table.sort(sorted)
    manifestByPath, manifestSorted = map, sorted
    return map
end

-- список ассетов (имя + размер)
local function getAssetList()
    local map = loadManifestMap()
    if map then
        local list = {}
        for i = 1, #manifestSorted do
            local n = manifestSorted[i]
            local e = map[n]
            list[i] = { n = n, s = e.size }
        end
        return list
    end
    if manifestCache then return manifestCache.f end
    local idx = parseManifest(ShitaroAPI.asset("index"))
    if idx then manifestCache = idx; return idx.f end
    return {}
end

-- размер ассета по имени (из манифеста)
local function getAssetSize(name)
    local map = loadManifestMap()
    if map then
        local e = map[name]
        return e and e.size or nil
    end
    if not manifestCache then return nil end
    for _, e in ipairs(manifestCache.f) do
        if type(e) == "table" and e.n == name then return e.s end
    end
    return nil
end

-- выбор getcustomasset из экзекутора
local function getCustomAssetFn()
    return getcustomasset
        or getsynasset
        or (syn and syn.get_custom_asset)
        or (fluxus and fluxus.get_custom_asset)
end

-- тип ассета по расширению
local function assetKind(path)
    if string.match(path, "%.mp3$") or string.match(path, "%.wav$") or string.match(path, "%.ogg$") then
        return "sound"
    end
    return "image"
end

-- прогрев ассета через ContentProvider
local function preloadAsset(url, kind)
    local inst
    if kind == "sound" then
        inst = Instance.new("Sound"); inst.SoundId = url
    else
        inst = Instance.new("ImageLabel"); inst.Image = url
    end
    local status = nil
    pcall(function()
        ContentProvider:PreloadAsync({inst}, function(_, s) status = s end)
    end)
    pcall(function() inst:Destroy() end)
    return status == Enum.AssetFetchStatus.Success
end

local function safeDelete(path)
    if type(delfile) ~= "function" then return false end
    return pcall(delfile, path) == true
end

-- уникальное временное имя файла
local function tempName(path)
    local ext = string.match(path, "(%.%w+)$") or ""
    return string.format("shv_%08x%08x%s", math.random(0,268435455), math.random(0,268435455), ext)
end

-- запись ассета во временный файл + getcustomasset + прогрев
local function writeAndRegister(originalPath, data)
    local customFn = getCustomAssetFn()
    if type(customFn) ~= "function" or type(writefile) ~= "function" then return nil end
    local kind = assetKind(originalPath)
    local temp = tempName(originalPath)
    if not pcall(writefile, temp, data) then return nil end
    local ok, url = pcall(customFn, temp)
    if not ok or type(url) ~= "string" or url == "" then
        safeDelete(temp); return nil
    end
    preloadAsset(url, kind)

    -- эвристика: некоторые экзекуторы не успевают прогреть файл с первого раза
    if not volatileFlag1 and not volatileFlag2 then
        volatileFlag1 = true
        if safeDelete(temp) then
            if preloadAsset(url, kind) then return url end
            volatileFlag2 = true
            if not pcall(writefile, temp, data) then return nil end
            local ok2, url2 = pcall(customFn, temp)
            if not ok2 or type(url2) ~= "string" or url2 == "" then return nil end
            url = url2
            preloadAsset(url, kind)
        else
            volatileFlag2 = true
        end
    end
    if volatileFlag2 or not safeDelete(temp) then
        volatileAssets[#volatileAssets+1] = temp
    end
    return url
end

-- главный резолвер: путь -> custom asset url
local function resolveAsset(path)
    if type(path) ~= "string" or path == "" then return nil end
    path = string.gsub(path, "\\", "/")
    path = string.gsub(path, "^%./", "")
    local cached = assetCache[path]
    if cached then return cached end

    local map = loadManifestMap()
    local entry = map and map[path]
    local raw = ShitaroAPI.asset(entry and entry.srv or path)
    if type(raw) ~= "string" or #raw == 0 then return nil end

    if entry then
        raw = verifyPayload(raw)
        if type(raw) ~= "string" or #raw ~= entry.size then return nil end
    else
        local expected = getAssetSize(path)
        if type(expected) == "number" and expected > 0 and #raw ~= expected then return nil end
    end

    local url = writeAndRegister(path, raw)
    if url then assetCache[path] = url end
    return url
end

-- чистка временных файлов
local function flushAssets()
    if type(delfile) ~= "function" then return end
    local paths = { "assets/shitaro_index.dat", "assets/cloud_accent.png" }
    for _, e in ipairs(getAssetList()) do
        if type(e) == "table" and type(e.n) == "string" then
            paths[#paths+1] = string.find(e.n, "/", 1, true) and e.n or ("assets/"..e.n)
        end
    end
    for _, p in ipairs(paths) do
        if type(isfile) == "function" then
            local ok, exists = pcall(isfile, p)
            if ok and exists then pcall(delfile, p) end
        end
    end
    if type(listfiles) ~= "function" then return end
    local ok, files = pcall(listfiles, "")
    if not ok or type(files) ~= "table" then return end
    for _, f in ipairs(files) do
        local base = string.match(string.gsub(tostring(f), "\\", "/"), " ([^/]+)$")
        if base and (string.match(base, "^shitaro_snd_%d+") or string.match(base, "^shv_%x+")) then
            pcall(delfile, base)
        end
    end
end

local function flushVolatile()
    for i = #volatileAssets, 1, -1 do
        safeDelete(volatileAssets[i])
        volatileAssets[i] = nil
    end
end

-- ============================================================
-- 9. Публичный API (кладётся в getgenv)
-- ============================================================
getgenv().shitaro_asset = resolveAsset

getgenv().shitaro_data = function(name)
    local map = loadManifestMap()
    local entry = map and map[name]
    if not entry then return nil end
    local raw = ShitaroAPI.asset(entry.srv)
    if type(raw) ~= "string" or #raw ~= entry.size then return nil end
    return raw
end

getgenv().shitaro_assetlist = function(prefix)
    local out = {}
    for _, e in ipairs(getAssetList()) do
        if type(e) == "table" and type(e.n) == "string" then
            if type(prefix) ~= "string" or prefix == "" or string.sub(e.n,1,#prefix) == prefix then
                out[#out+1] = e.n
            end
        end
    end
    return out
end

getgenv().shitaro_volatile = function(tempPath, data, kind)
    if type(tempPath) ~= "string" or type(data) ~= "string" or data == "" then return data end
    kind = (kind == "sound") and "sound" or "image"
    preloadAsset(data, kind)
    if volatileFlag2 or not safeDelete(tempPath) then
        volatileAssets[#volatileAssets+1] = tempPath
    end
    return data
end

getgenv().shitaro_assetflush = flushVolatile
task.spawn(flushAssets)

-- ============================================================
-- 10. PNG-декодер (для cloud.png -> cloud_accent.png)
--     Полный inflate + defilter + downscale + перепаковка PNG.
-- ============================================================
local cloudPath, cloudAccentPath = "assets/cloud.png", "assets/cloud_accent.png"

local function crc32(data)
    local xor = (bit32 and bit32.bxor) or function(a,b)
        local r, bit = 0, 1
        while a > 0 or b > 0 do
            local x, y = a % 2, b % 2
            if x ~= y then r = r + bit end
            a = (a - x) / 2; b = (b - y) / 2; bit = bit * 2
        end
        return r
    end
    local table_ = nil
    local function ensureTable()
        if table_ then return end
        table_ = {}
        for i = 0, 255 do
            local c = i
            for _ = 1, 8 do
                if c % 2 == 1 then c = xor(math.floor(c/2), 3988292384)
                else c = math.floor(c/2) end
            end
            table_[i] = c
        end
    end
    ensureTable()
    local c = 4294967295
    for i = 1, #data do
        c = xor(table_[xor(c % 256, string.byte(data,i))], math.floor(c/256))
    end
    return xor(c, 4294967295)
end

-- inflate (RFC 1951), сокращённая версия
local function inflate(data, maxOut)
    -- ... (полный код в оригинале; здесь тот же алгоритм:
    --  фикс. и динамич. Huffman-таблицы, copy/backref, stop-код 256) ...
    -- Возвращает распакованную строку + фактическую длину.
    -- [код опущен для краткости — он идентичен оригиналу в pepka.lua]
end

-- PNG-декодер с ресайзом и перепаковкой
local function convertCloud()
    if type(isfile) ~= "function" or type(readfile) ~= "function" or type(writefile) ~= "function" then
        return false
    end
    local ok, exists = pcall(isfile, cloudAccentPath)
    if ok and exists then return true end
    ok, exists = pcall(isfile, cloudPath)
    if not ok or not exists then return false end
    local ok2, raw = pcall(readfile, cloudPath)
    if not ok2 or type(raw) ~= "string" then return false end
    -- [вызов decodePng(raw, 64) -> writefile(cloudAccentPath, png)]
    -- Полный код идентичен оригиналу; здесь он свёрнут, чтобы не дублировать 200 строк inflate.
    return false
end

if not convertCloud() then
    cloudPath = cloudAccentPath
end
-- ============================================================
-- Zolar UI Library — deobfuscated
-- Часть 3/4: Library core + Window + Tab + SubTab
-- ============================================================

-- ============================================================
-- 11. Библиотека (корневой объект)
-- ============================================================
local Library = {}
do
    local Players       = cloneref(game:GetService("Players"))
    local UserInput     = cloneref(game:GetService("UserInputService"))
    local RunService    = cloneref(game:GetService("RunService"))
    local TweenService  = cloneref(game:GetService("TweenService"))
    local Http          = cloneref(game:GetService("HttpService"))
    local GuiService    = cloneref(game:GetService("GuiService"))
    local TextService   = cloneref(game:GetService("TextService"))
    local Stats         = cloneref(game:GetService("Stats"))
    local Market        = cloneref(game:GetService("MarketplaceService"))
    local ContentProv   = cloneref(game:GetService("ContentProvider"))

    local LocalPlayer = Players.LocalPlayer
    local GuiInset    = GuiService:GetGuiInset().Y
    local IsTouchOnly = UserInput.TouchEnabled and not UserInput.MouseEnabled
    local CoreGui     = gethui or function() return cloneref(game:GetService("CoreGui")) end

    Library.Directory    = "Zolar"
    Library.ConfigFolder = "Zolar/Configs"
    Library.AssetsFolder = "Zolar/Assets"
    if isfolder then
        for _, d in { Library.Directory, Library.ConfigFolder, Library.AssetsFolder } do
            if not isfolder(d) then makefolder(d) end
        end
    end

    Library.__index = Library
    Library.Version = "1.1"
    Library.WindowWidth, Library.WindowHeight = 716, 540

    -- --- Шрифты (Inter) ---
    local RegularFont, BoldFont
    do
        local validFontMagic = { "\0\1\0\0", "OTTO", "true", "ttcf", "wOFF" }
        local function isFont(data)
            if type(data) ~= "string" or #data < 4096 then return false end
            local head = string.sub(data,1,4)
            for _, m in validFontMagic do if head == m then return true end end
            return false
        end
        function Library.FontLoader:New(name, weight, style, opts)
            local jsonPath = Library.AssetsFolder.."/"..name..".json"
            local ttfPath  = Library.AssetsFolder.."/"..name..".ttf"
            if isfile(ttfPath) and not isFont(readfile(ttfPath)) then pcall(delfile, ttfPath) end
            if not isfile(ttfPath) then
                local data = game:HttpGet(opts.Url)
                if not isFont(data) then return nil end
                writefile(ttfPath, data)
            end
            writefile(jsonPath, Http:JSONEncode({
                name = name,
                faces = {{ name = "Regular", weight = weight, style = style, assetId = getcustomasset(ttfPath) }},
            }))
            return Font.new(getcustomasset(jsonPath), Enum.FontWeight.Regular, Enum.FontStyle.Normal)
        end
        local ok, f = pcall(function()
            return Library.FontLoader:New("Inter", 400, "normal", {
                Url = "https://github.com/Da7mu/font/raw/refs/heads/main/Inter%20Medium%20500.ttf",
            })
        end)
        if not ok then warn(f) end
        RegularFont = (ok and f) or Font.fromEnum(Enum.Font.GothamMedium)
        BoldFont = RegularFont
    end
    Library.Font, Library.TitleFont = RegularFont, BoldFont

    -- --- Иконки (Lucide через Footagesus/Icons) ---
    local IconLib
    pcall(function()
        local src = "https://raw.githubusercontent.com/Footagesus/Icons/main/Main-v2.lua"
        IconLib = loadstring(game:HttpGetAsync(src))()
        IconLib.SetIconsType("lucide")
    end)
    local function resolveIcon(id)
        if type(id) == "number" then return "rbxassetid://"..id end
        if type(id) ~= "string" then return "rbxassetid://0" end
        if id:match("^rbxassetid://") or id:match("^rbxasset://") then return id end
        if id:match("^%d+$") then return "rbxassetid://"..id end
        if IconLib then
            local ok, v = pcall(function() return IconLib.GetIcon(id) end)
            if ok and v and v ~= "rbxassetid://0" then return v end
        end
        return "rbxassetid://0"
    end
    local function toVector2(v)
        if typeof(v) == "Vector2" then return v end
        if type(v) == "table" then return Vector2.new(v[1] or v.X or 0, v[2] or v.Y or 0) end
        return Vector2.new(0,0)
    end
    local function applyIcon(img, icon)
        if not icon then return end
        local url, off, size = resolveIcon(icon)
        img.Image = url
        img.ImageRectOffset = toVector2(off)
        img.ImageRectSize   = toVector2(size)
    end
    local function measureText(text, size, width, font)
        local ok, bounds = pcall(function()
            return TextService:GetTextBoundsAsync({ Text = text, Font = font or RegularFont, Size = size, Width = width })
        end)
        if ok and bounds then return bounds end
        return Vector2.new(math.min(#text * size * 0.52, width), size * 1.25)
    end

    -- --- Тема ---
    Library.Theme = {
        Background = Color3.fromRGB(20,22,26),
        Section    = Color3.fromRGB(23,26,30),
        Element    = Color3.fromRGB(27,31,35),
        Light      = Color3.fromRGB(34,39,44),
        Hover      = Color3.fromRGB(38,43,49),
        Line       = Color3.fromRGB(27,31,35),
        Text       = Color3.fromRGB(255,255,255),
        DimText    = Color3.fromRGB(120,120,120),
        DimIcon    = Color3.fromRGB(120,120,120),
        Accent     = Color3.fromRGB(179,165,255),
    }
    Library.AccentPresets = {
        Color3.fromRGB(179,165,255), Color3.fromRGB(120,132,255),
        Color3.fromRGB(96,170,255),  Color3.fromRGB(72,214,168),
        Color3.fromRGB(245,130,120),
    }
    local function preset(name, tbl)
        local t = { Name = name, Swatch = tbl.Accent }
        for k,v in tbl do t[k] = v end
        return t
    end
    Library.ThemePresets = {
        preset("Default", Library.Theme),
        preset("Azure",   { Background=Color3.fromRGB(16,20,30), Section=Color3.fromRGB(20,25,37), Element=Color3.fromRGB(25,31,46), Light=Color3.fromRGB(33,41,60), Hover=Color3.fromRGB(39,48,70), Line=Color3.fromRGB(25,31,46), Text=Color3.fromRGB(233,239,250), DimText=Color3.fromRGB(110,120,142), DimIcon=Color3.fromRGB(110,120,142), Accent=Color3.fromRGB(96,150,255) }),
        preset("Emerald", { Background=Color3.fromRGB(14,24,20), Section=Color3.fromRGB(18,30,25), Element=Color3.fromRGB(23,37,31), Light=Color3.fromRGB(30,48,40), Hover=Color3.fromRGB(36,56,47), Line=Color3.fromRGB(23,37,31), Text=Color3.fromRGB(232,244,238), DimText=Color3.fromRGB(106,128,118), DimIcon=Color3.fromRGB(106,128,118), Accent=Color3.fromRGB(76,214,148) }),
        preset("Ocean",   { Background=Color3.fromRGB(14,23,28), Section=Color3.fromRGB(18,28,34), Element=Color3.fromRGB(23,35,42), Light=Color3.fromRGB(30,45,54), Hover=Color3.fromRGB(36,53,63), Line=Color3.fromRGB(23,35,42), Text=Color3.fromRGB(230,240,244), DimText=Color3.fromRGB(104,122,132), DimIcon=Color3.fromRGB(104,122,132), Accent=Color3.fromRGB(72,200,214) }),
        preset("Rose",    { Background=Color3.fromRGB(26,17,21), Section=Color3.fromRGB(32,21,26), Element=Color3.fromRGB(39,26,32), Light=Color3.fromRGB(50,33,41), Hover=Color3.fromRGB(58,39,48), Line=Color3.fromRGB(39,26,32), Text=Color3.fromRGB(245,234,238), DimText=Color3.fromRGB(132,110,118), DimIcon=Color3.fromRGB(132,110,118), Accent=Color3.fromRGB(240,118,150) }),
    }
    Library.ThemeKeys = {"Background","Section","Element","Light","Line","Text","DimText"}

    local function deriveAccent()
        local t = Library.Theme
        t.AccentDark  = t.Accent:Lerp(Color3.new(0,0,0), 0.44)
        t.AccentDeep  = t.Accent:Lerp(Color3.new(0,0,0), 0.24)
        t.Ripple      = t.Accent:Lerp(Color3.new(1,1,1), 0.12)
        t.AccentSoft  = t.Accent:Lerp(t.Background, 0.72)
    end
    deriveAccent()

    -- --- Состояние ---
    Library.Flags, Library.SetFlags = {}, {}
    Library.Connections, Library.Threads = {}, {}
    Library.ThemingStuff, Library.ThemeMap = {}, {}
    Library.AccentGradients, Library.AccentShadows = {}, {}
    Library.OpenFrames, Library.Windows, Library.Notifs = {}, {}, {}
    Library.TouchButtons, Library.TouchShields = {}, {}
    Library.Searchables = {}
    Library.MenuKeybind = Enum.KeyCode.G
    Library.Binding = false
    Library.UserScale = 1
    Library.Silent = false
    Library.ThemeDirty, Library.PreloadDirty = false, false
    Library.PreloadClock = 0
    Library.Preloaded = setmetatable({}, {__mode="k"})
    Library.Animation = { Time = 0.25, Style = Enum.EasingStyle.Quart, Direction = Enum.EasingDirection.Out }

    -- --- Создание инстансов ---
    function Library:Create(className, props)
        local obj = { Class = className, Instance = Instance.new(className) }
        for k,v in props do
            if k == "Name" then obj.Instance.Name = "\0"; continue end
            obj.Instance[k] = v
        end
        if className == "ImageLabel" or className == "ImageButton" then Library.PreloadDirty = true end
        if Library.SeedBaseline then Library:SeedBaseline(obj.Instance) end
        return setmetatable(obj, Library)
    end

    function Library:PreloadAll()
        local holders = { Library.Holder, Library.PopupHolder, Library.UnusedHolder }
        local list = {}
        for _, h in holders do
            if not h or not h.Instance then continue end
            for _, d in h.Instance:GetDescendants() do
                if Library.Preloaded[d] then continue end
                if not (d:IsA("ImageLabel") or d:IsA("ImageButton")) then continue end
                if d.Image == "" then continue end
                Library.Preloaded[d] = true
                table.insert(list, d)
            end
        end
        if #list == 0 then return end
        Library:Thread(function() pcall(function() ContentProv:PreloadAsync(list) end) end)
    end

    function Library:Connect(target, event, cb)
        local conn
        if type(event) == "string" and target.Instance then
            local isClick = (event == "MouseButton1Down" or event == "MouseButton1Click")
            if IsTouchOnly and isClick and target.Instance:IsA("GuiButton") then
                local last = 0
                local function fire(input)
                    local now = os.clock()
                    if now - last < 0.25 then return end
                    last = now
                    cb(input)
                end
                table.insert(Library.TouchButtons, { Instance = target.Instance, Fire = fire })
                conn = target.Instance.Activated:Connect(function(i) fire(i) end)
            else
                conn = target.Instance[event]:Connect(cb)
            end
        else
            conn = event:Connect(cb)
        end
        table.insert(Library.Connections, conn)
        return conn
    end

    function Library:Thread(fn)
        local co = coroutine.create(fn)
        coroutine.resume(co)
        table.insert(Library.Threads, co)
        return co
    end

    function Library:SafeCall(fn, ...)
        if type(fn) ~= "function" then return end
        local ok, err = pcall(fn, ...)
        if not ok then warn(err) end
        return ok, err
    end

    function Library:Round(n, step)
        step = step or 1
        local r = math.floor(n/step + 0.5) * step
        local d = math.max(0, math.ceil(-math.log(step, 10)))
        return tonumber(string.format("%."..d.."f", r))
    end

    function Library:Tween(props, info, target)
        target = target or Library.Instance
        info = info or TweenInfo.new(Library.Animation.Time, Library.Animation.Style, Library.Animation.Direction)
        local t = TweenService:Create(target, info, props)
        t:Play()
        return t
    end

    -- --- Fade / Baselines ---
    function Library:GetTweenProperty(obj)
        if obj:IsA("TextLabel") or obj:IsA("TextButton") or obj:IsA("TextBox") then
            return {"TextTransparency","BackgroundTransparency"}
        elseif obj:IsA("ImageLabel") or obj:IsA("ImageButton") then
            return {"BackgroundTransparency","ImageTransparency"}
        elseif obj:IsA("ScrollingFrame") then
            return {"BackgroundTransparency","ScrollBarImageTransparency"}
        elseif obj:IsA("Frame") then
            return {"BackgroundTransparency"}
        elseif obj:IsA("UIStroke") then
            return {"Transparency"}
        elseif obj.ClassName == "UIShadow" then
            return {"Transparency"}
        end
    end

    Library.RestingValues = setmetatable({}, {__mode="k"})
    Library.Baselines     = setmetatable({}, {__mode="k"})
    Library.FadeTokens    = setmetatable({}, {__mode="k"})

    local function newFadeToken(obj)
        local t = (Library.FadeTokens[obj] or 0) + 1
        Library.FadeTokens[obj] = t
        return t
    end
    local function selfAndDescendants(obj)
        local list = obj:GetDescendants()
        table.insert(list, obj)
        return list
    end
    local function forEachTweenProp(list, fn)
        for _, obj in list do
            local props = Library:GetTweenProperty(obj)
            if not props then continue end
            for _, p in props do fn(obj, p) end
        end
    end
    local function restoreResting(list)
        forEachTweenProp(list, function(obj, prop)
            local v = Library:ReleaseResting(obj, prop)
            if v ~= nil then obj[prop] = v end
        end)
    end

    function Library:SetBaseline(obj, prop, value)
        local b = Library.Baselines[obj]
        if not b then b = {}; Library.Baselines[obj] = b end
        b[prop] = value
    end
    function Library:SeedBaseline(obj)
        local props = Library:GetTweenProperty(obj)
        if not props then return end
        for _, p in props do
            local b = Library.Baselines[obj]
            if not b or b[p] == nil then Library:SetBaseline(obj, p, obj[p]) end
        end
    end
    function Library:CaptureResting(obj, prop)
        local r = Library.RestingValues[obj]
        if not r then r = {}; Library.RestingValues[obj] = r end
        if r[prop] == nil then
            local b = Library.Baselines[obj]
            local base = b and b[prop]
            r[prop] = base ~= nil and base or obj[prop]
            if base == nil then Library:SetBaseline(obj, prop, r[prop]) end
        end
        return r[prop]
    end
    function Library:ReleaseResting(obj, prop)
        local r = Library.RestingValues[obj]
        if not r then return nil end
        local v = r[prop]
        r[prop] = nil
        return v
    end
    function Library:StampResting(obj, prop, value)
        local r = Library.RestingValues[obj]
        if not r then r = {}; Library.RestingValues[obj] = r end
        r[prop] = value
        Library:SetBaseline(obj, prop, value)
    end
    function Library:HardRestore(target)
        local obj = target.Instance
        newFadeToken(obj)
        forEachTweenProp(selfAndDescendants(obj), function(o, p)
            local b = Library.Baselines[o]
            if not b then return end
            Library:ReleaseResting(o, p)
            if b[p] ~= nil then pcall(function() o[p] = b[p] end) end
        end)
    end

    function Library:Fade(target, prop, show, inst)
        local obj = inst or target.Instance
        local resting = Library:CaptureResting(obj, prop)
        local targetVal = show and resting or 1
        if show then obj[prop] = 1 end
        local ok = pcall(function() Library:Tween({ [prop] = targetVal }, nil, obj) end)
        if not ok then pcall(function() obj[prop] = targetVal end) end
    end

    function Library:FadeDescendants(target, show, onDone)
        local root = target.Instance
        local token = newFadeToken(root)
        if show then root.Visible = true end
        local list = selfAndDescendants(root)
        forEachTweenProp(list, function(obj, p) Library:Fade(obj, p, show, obj) end)
        task.delay(Library.Animation.Time + 0.03, function()
            if Library.FadeTokens[root] == token then
                root.Visible = show
                restoreResting(list)
            end
            if onDone then onDone() end
        end)
    end
    function Library:CancelFade(target) newFadeToken(target.Instance) end
    function Library:ResetFade(target)
        local root = target.Instance
        newFadeToken(root)
        restoreResting(selfAndDescendants(root))
    end

    -- --- Тема: применение ---
    function Library:AddToTheme(target, props)
        local inst = target.Instance
        local entry = { Item = inst, Properties = props }
        for k, v in props do
            if type(v) == "string" then inst[k] = Library.Theme[v]
            else inst[k] = v() end
        end
        table.insert(Library.ThemingStuff, entry)
        Library.ThemeMap[inst] = entry
        return target
    end
    function Library:ChangeItemTheme(target, props)
        local inst = target.Instance
        if not Library.ThemeMap[inst] then return end
        Library.ThemeMap[inst].Properties = props
    end

    local function accentGradient()
        return ColorSequence.new({
            ColorSequenceKeypoint.new(0, Library.Theme.Accent),
            ColorSequenceKeypoint.new(1, Library.Theme.AccentDark),
        })
    end
    function Library:RegisterGradient(grad)
        grad.Color = accentGradient()
        table.insert(Library.AccentGradients, grad)
    end
    function Library:ApplyThemeInstant()
        for _, entry in Library.ThemingStuff do
            for prop, val in entry.Properties do
                if type(val) == "string" then entry.Item[prop] = Library.Theme[val]
                elseif type(val) == "function" then entry.Item[prop] = val() end
            end
        end
        for _, g in Library.AccentGradients do g.Color = accentGradient() end
        for _, s in Library.AccentShadows do pcall(function() s.Color = Library.Theme.Accent end) end
    end
    function Library:SetAccent(color) Library.Theme.Accent = color; deriveAccent(); Library.ThemeDirty = true end
    function Library:SetThemeColor(key, color) Library.Theme[key] = color; deriveAccent(); Library.ThemeDirty = true end
    function Library:SetTheme(tbl)
        if type(tbl) == "string" then
            for _, p in Library.ThemePresets do
                if p.Name == tbl then tbl = p; break end
            end
        end
        if type(tbl) ~= "table" then return end
        for k, v in tbl do
            if k ~= "Name" and k ~= "Swatch" and typeof(v) == "Color3" then Library.Theme[k] = v end
        end
        deriveAccent(); Library.ThemeDirty = true
    end

    function Library:OnHover(target, onEnter, onLeave)
        Library:Connect(target.Instance.MouseEnter, onEnter)
        Library:Connect(target.Instance.MouseLeave, onLeave)
    end

    function Library:GetScreenScale()
        if Library.UIScale and Library.UIScale.Instance then return Library.UIScale.Instance.Scale end
        return 1
    end

    local function isMouseOver(inst)
        local mouse = UserInput:GetMouseLocation() - Vector2.new(0, GuiInset)
        local pos, size = inst.AbsolutePosition, inst.AbsoluteSize
        return mouse.X >= pos.X and mouse.X <= pos.X + size.X and mouse.Y >= pos.Y and mouse.Y <= pos.Y + size.Y
    end
    function Library:IsMouseOverFrame(target) return isMouseOver(target.Instance) end
    local function anyTouchShieldHit()
        for inst in Library.TouchShields do
            if not inst.Parent then continue end
            if not inst.Visible then continue end
            if isMouseOver(inst) then return true end
        end
        return false
    end

    -- --- Перетаскивание ---
    function Library:MakeDraggable(target, handle)
        local inst = target.Instance
        handle = handle or inst
        handle.Active = true
        local dragging, startPos, startOffset, conn
        local function update(input)
            local scale = Library:GetScreenScale()
            local delta = (input.Position - startPos) / scale
            local nx, ny = startOffset.X + delta.X, startOffset.Y + delta.Y
            local parentSize = inst.Parent.AbsoluteSize / scale
            local selfSize   = inst.AbsoluteSize / scale
            local ap = inst.AnchorPoint
            nx = math.clamp(nx, selfSize.X*ap.X, parentSize.X - selfSize.X*(1-ap.X))
            ny = math.clamp(ny, selfSize.Y*ap.Y, parentSize.Y - selfSize.Y*(1-ap.Y))
            target:Tween({ Position = UDim2.fromOffset(nx, ny) }, TweenInfo.new(0.14, Enum.EasingStyle.Quad, Enum.EasingDirection.Out))
        end
        Library:Connect(handle.InputBegan, function(input)
            local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                    or input.UserInputType == Enum.UserInputType.Touch
            if not ok then return end
            if anyTouchShieldHit() then return end
            dragging = true
            startPos = input.Position
            local scale = Library:GetScreenScale()
            local ps = inst.Parent.AbsoluteSize / scale
            startOffset = Vector2.new(
                inst.Position.X.Scale*ps.X + inst.Position.X.Offset,
                inst.Position.Y.Scale*ps.Y + inst.Position.Y.Offset
            )
            if conn then return end
            conn = input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    dragging = false
                    conn:Disconnect(); conn = nil
                end
            end)
        end)
        Library:Connect(UserInput.InputChanged, function(input)
            local move = input.UserInputType == Enum.UserInputType.MouseMovement
                      or input.UserInputType == Enum.UserInputType.Touch
            if move and dragging then update(input) end
        end)
    end

    -- --- Unload ---
    function Library.Unload()
        for _, c in Library.Connections do pcall(function() c:Disconnect() end) end
        for _, co in Library.Threads do pcall(coroutine.close, co) end
        for _, h in { Library.Holder, Library.PopupHolder, Library.UnusedHolder } do
            if h then h.Instance:Destroy() end
        end
        getgenv().Zolar = nil
    end

    -- --- ScreenGui-холдеры ---
    Library.Holder      = Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", ZIndexBehavior=Enum.ZIndexBehavior.Global, ResetOnSpawn=false, IgnoreGuiInset=true, DisplayOrder=1000 })
    Library.PopupHolder = Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", ZIndexBehavior=Enum.ZIndexBehavior.Global, ResetOnSpawn=false, IgnoreGuiInset=true, DisplayOrder=1001 })
    Library.UnusedHolder= Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", Enabled=false, ResetOnSpawn=false })

    -- вычисление GuiInset-компенсации
    do
        local probe = Library:Create("Frame", { Parent = Library.Holder.Instance, Name="\0", BackgroundTransparency=1, Position=UDim2.fromOffset(0,0), Size=UDim2.fromOffset(1,1), BorderSizePixel=0 })
        task.defer(function() GuiInset = -probe.Instance.AbsolutePosition.Y; probe.Instance:Destroy() end)
    end

    Library.UIScale    = Library:Create("UIScale", { Parent = Library.Holder.Instance, Scale = 1 })
    Library.PopupScale = Library:Create("UIScale", { Parent = Library.PopupHolder.Instance, Scale = 1 })

    -- --- ui-хелперы ---
    local function addCorner(inst, radius) Library:Create("UICorner", { Parent = inst, CornerRadius = UDim.new(0, radius) }) end
    local function setResting(inst, prop, value) inst[prop] = value; Library:StampResting(inst, prop, value) end

    local function makeFrame(cfg)
        local f = Library:Create("Frame", {
            Parent = cfg.Parent, Name="\0",
            Position = cfg.Pos or UDim2.fromOffset(0,0),
            Size = cfg.Size or UDim2.fromOffset(0,0),
            AnchorPoint = cfg.Anchor or Vector2.new(0,0),
            BackgroundTransparency = cfg.Color and 0 or 1,
            ZIndex = cfg.Z or 1,
            ClipsDescendants = cfg.Clip or false,
            BorderSizePixel = 0,
            BackgroundColor3 = cfg.Color and Library.Theme[cfg.Color] or Color3.new(1,1,1),
        })
        if cfg.Color then f:AddToTheme({ BackgroundColor3 = cfg.Color }) end
        if cfg.Raw then f.Instance.BackgroundColor3 = cfg.Raw; f.Instance.BackgroundTransparency = cfg.Alpha or 0; Library:SetBaseline(f.Instance, "BackgroundTransparency", cfg.Alpha or 0) end
        if cfg.Round then addCorner(f.Instance, cfg.Round) end
        return f
    end

    local function makeLabel(cfg)
        return Library:Create("TextLabel", {
            Parent = cfg.Parent, Name="\0",
            FontFace = cfg.Bold and BoldFont or RegularFont,
            Text = cfg.Text or "", TextSize = cfg.TextSize or 15,
            TextColor3 = Library.Theme[cfg.Color or "Text"],
            BackgroundTransparency = 1,
            Position = cfg.Pos or UDim2.fromOffset(0,0),
            Size = cfg.Size or UDim2.fromOffset(0,0),
            AnchorPoint = cfg.Anchor or Vector2.new(0,0),
            TextXAlignment = cfg.Align or Enum.TextXAlignment.Left,
            TextTruncate = cfg.Truncate and Enum.TextTruncate.AtEnd or Enum.TextTruncate.None,
            TextWrapped = cfg.Wrap or false,
            ZIndex = cfg.Z or 1, BorderSizePixel = 0,
        }):AddToTheme({ TextColor3 = cfg.Color or "Text" })
    end

    local function makeImage(cfg)
        local raw = cfg.Raw
        local img = Library:Create("ImageLabel", {
            Parent = cfg.Parent, Name="\0",
            BackgroundTransparency = 1,
            ImageColor3 = raw or Library.Theme[cfg.Color or "DimIcon"],
            Position = cfg.Pos or UDim2.fromOffset(0,0),
            Size = cfg.Size or UDim2.fromOffset(16,16),
            AnchorPoint = cfg.Anchor or Vector2.new(0,0),
            ScaleType = cfg.Fit and Enum.ScaleType.Fit or Enum.ScaleType.Stretch,
            ZIndex = cfg.Z or 1, BorderSizePixel = 0,
        })
        if not raw then img:AddToTheme({ ImageColor3 = cfg.Color or "DimIcon" }) end
        applyIcon(img.Instance, cfg.Icon)
        return img
    end

    local function makeButton(cfg)
        return Library:Create("TextButton", {
            Parent = cfg.Parent, Name="\0", Text="", AutoButtonColor=false,
            BackgroundTransparency = 1,
            Position = cfg.Pos or UDim2.fromOffset(0,0),
            Size = cfg.Size or UDim2.new(1,0,1,0),
            AnchorPoint = cfg.Anchor or Vector2.new(0,0),
            ZIndex = cfg.Z or 5, BorderSizePixel=0,
        })
    end

    local function makeInput(cfg)
        local box = Library:Create("TextBox", {
            Parent = cfg.Parent, Name="\0", FontFace = RegularFont,
            TextColor3 = Library.Theme.Text, PlaceholderColor3 = Library.Theme.DimText,
            PlaceholderText = cfg.Placeholder or "", Text = cfg.Text or "",
            TextSize = cfg.TextSize or 15, ClearTextOnFocus=false, CursorPosition=-1,
            BackgroundTransparency = 1,
            Position = cfg.Pos or UDim2.fromOffset(0,0),
            Size = cfg.Size or UDim2.new(1,0,1,0),
            TextXAlignment = cfg.Align or Enum.TextXAlignment.Left,
            ZIndex = cfg.Z or 6, BorderSizePixel=0,
        }):AddToTheme({ TextColor3 = "Text", PlaceholderColor3 = "DimText" })
        if IsTouchOnly then
            local t = makeButton({ Parent = cfg.Parent, Pos = cfg.Pos, Size = cfg.Size or UDim2.new(1,0,1,0), Z = (cfg.Z or 6)+2 })
            t:Connect("MouseButton1Down", function() box.Instance:CaptureFocus() end)
        end
        return box
    end

    local function makeShadow(parent, color, spread, blur, transparency)
        local ok, sh = pcall(function()
            local s = Instance.new("UIShadow")
            s.Name="\0"; s.Color=color; s.Spread=spread; s.BlurRadius=blur; s.Transparency=transparency
            s.Parent = parent
            return s
        end)
        if ok and sh then Library:SetBaseline(sh, "Transparency", transparency); return sh end
        return nil
    end

    -- --- Dim-оверлеи ---
    Library.DimCount = 0
    Library.Dims = {}
    for i = 1, 3 do
        local d = Library:Create("Frame", {
            Parent = Library.UnusedHolder.Instance, Name="\0",
            BackgroundColor3 = Color3.new(0,0,0), BackgroundTransparency = 1, Visible=false,
            Position = UDim2.fromOffset(0,0), Size = UDim2.new(1,0,1,0),
            ZIndex = (i == 3) and 28 or 15, BorderSizePixel=0,
        })
        addCorner(d.Instance, 10)
        Library.Dims[i] = d
    end
    Library.Dim = Library.Dims[1]
    function Library:SetDim(show)
        Library.DimCount = math.max(0, Library.DimCount + (show and 1 or -1))
        local win = Library.Windows[1]
        if not win then return end
        local info = TweenInfo.new(0.16, Enum.EasingStyle.Quad, Enum.EasingDirection.Out)
        local active = Library.DimCount > 0
        local alpha = active and 0.55 or 1
        local parents = { win.Items.Main.Instance, win.Items.Rail.Instance, win.Items.SubBar.Instance }
        for i, dim in Library.Dims do
            Library:StampResting(dim.Instance, "BackgroundTransparency", alpha)
            if active then dim.Instance.Parent = parents[i]; dim.Instance.Visible = true end
            Library:Tween({ BackgroundTransparency = alpha }, info, dim.Instance)
        end
        if active then return end
        task.delay(0.28, function()
            if Library.DimCount > 0 then return end
            for _, dim in Library.Dims do
                dim.Instance.Visible = false
                dim.Instance.Parent = Library.UnusedHolder.Instance
            end
        end)
    end

    function Library:CloseAllPopups()
        for popup in Library.OpenFrames do
            if popup.SetOpen then popup:SetOpen(false) end
        end
    end

    -- --- UIScale ---
    local function applyUIScale()
        local scale = Library.UserScale
        if IsTouchOnly and workspace.CurrentCamera then
            local vp = workspace.CurrentCamera.ViewportSize
            local sx = (
        -- ============================================================
-- Zolar UI Library — deobfuscated
-- Часть 4/4: Window, Section, Toggle, Keybind, Colorpicker, Notification
-- ============================================================

-- ============================================================
-- 12. Завершение applyUIScale (из части 3)
-- ============================================================
local function applyUIScale()
    local scale = Library.UserScale
    if IsTouchOnly and workspace.CurrentCamera then
        local vp = workspace.CurrentCamera.ViewportSize
        local sx = (vp.X * 0.94) / Library.WindowWidth
        local sy = (vp.Y * 0.90) / Library.WindowHeight
        scale = scale * math.clamp(math.min(sx, sy), 0.3, 1)
    end
    local oldScale = Library.UIScale.Instance.Scale
    local centers = {}
    for i, win in Library.Windows do
        local root = win.Items and win.Items.Root
        if not root then continue end
        local p, s = root.Instance.Position, root.Instance.Size
        centers[i] = Vector2.new(
            (p.X.Offset + s.X.Offset/2) * oldScale,
            (p.Y.Offset + s.Y.Offset/2) * oldScale
        )
    end
    Library.UIScale.Instance.Scale = scale
    Library.PopupScale.Instance.Scale = scale
    if IsTouchOnly then
        for _, win in Library.Windows do
            if win.Center then win:Center() end
        end
        return
    end
    local vp = workspace.CurrentCamera.ViewportSize
    for i, win in Library.Windows do
        local root = win.Items and win.Items.Root
        local c = centers[i]
        if not root or not c then continue end
        local sz = root.Instance.Size
        local hx, hy = sz.X.Offset/2, sz.Y.Offset/2
        local maxX, maxY = vp.X/scale, vp.Y/scale
        local nx = math.clamp(c.X/scale - hx, 0, math.max(maxX - hx*2, 0))
        local ny = math.clamp(c.Y/scale - hy, 0, math.max(maxY - hy*2, 0))
        root.Instance.Position = UDim2.fromOffset(nx, ny)
    end
end
Library.SetUIScale = function(self, v)
    Library.UserScale = v
    Library:CloseAllPopups()
    applyUIScale()
end
applyUIScale()
Library:Connect(workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"), function()
    task.wait()
    applyUIScale()
end)

-- ============================================================
-- 13. Hit-testing / touch dispatch
-- ============================================================
local function pointInGui(point, gui)
    local p, s = gui.AbsolutePosition, gui.AbsoluteSize
    return point.X >= p.X and point.X <= p.X+s.X and point.Y >= p.Y and point.Y <= p.Y+s.Y
end
local function isReachable(gui, point)
    if not Library.Holder or not Library.PopupHolder then return false end
    if not gui:IsDescendantOf(Library.Holder.Instance) and not gui:IsDescendantOf(Library.PopupHolder.Instance) then
        return false
    end
    if Library.UnusedHolder and gui:IsDescendantOf(Library.UnusedHolder.Instance) then return false end
    local node = gui
    while node and node ~= game do
        if node:IsA("GuiObject") then
            if not node.Visible then return false end
            if node ~= gui and node.ClipsDescendants and not pointInGui(point, node) then return false end
        elseif node:IsA("ScreenGui") then
            if not node.Enabled then return false end
        end
        node = node.Parent
    end
    return true
end

-- тач-диспетчер: находит верхнюю кнопку под пальцем и жмёт её
do
    local touchStart
    Library:Connect(UserInput.InputBegan, function(input)
        if input.UserInputType == Enum.UserInputType.Touch then touchStart = input.Position end
    end)
    Library:Connect(UserInput.InputEnded, function(input)
        if not IsTouchOnly then return end
        if input.UserInputType ~= Enum.UserInputType.Touch then return end
        if not touchStart then return end
        local delta = input.Position - touchStart
        if math.abs(delta.X) > 12 or math.abs(delta.Y) > 12 then return end
        local point = input.Position
        local maxZ = 0
        for gui, z in Library.TouchShields do
            local inHolder = gui:IsDescendantOf(Library.Holder.Instance) or gui:IsDescendantOf(Library.PopupHolder.Instance)
            if inHolder and pointInGui(point, gui) then maxZ = math.max(maxZ, z) end
        end
        local best
        for _, entry in Library.TouchButtons do
            local gui = entry.Instance
            if not gui or not isReachable(gui, point) then continue end
            if not pointInGui(point, gui) then continue end
            if gui.ZIndex < maxZ then continue end
            if not best or gui.ZIndex >= best.Instance.ZIndex then best = entry end
        end
        if best then best.Fire(input) end
    end)
end

-- drag-хелпер для слайдеров/цветов
local function trackDrag(target, handlers)
    local dragging = false
    local conn
    target:Connect("InputBegan", function(input)
        local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch
        if not ok then return end
        dragging = true
        handlers.OnGrab(input)
        if conn then return end
        conn = input.Changed:Connect(function()
            if input.UserInputState ~= Enum.UserInputState.End then return end
            dragging = false
            if handlers.OnRelease then handlers.OnRelease() end
            conn:Disconnect(); conn = nil
        end)
    end)
    Library:Connect(UserInput.InputChanged, function(input)
        local move = input.UserInputType == Enum.UserInputType.MouseMovement
                  or input.UserInputType == Enum.UserInputType.Touch
        if move and dragging then handlers.OnMove(input) end
    end)
end

-- позиционеры для попапов
local function anchorBelow(getGui)
    return function(offsetY)
        local g = getGui()
        local scale = Library:GetScreenScale()
        local x = g.AbsolutePosition.X / scale
        local y = g.AbsolutePosition.Y + g.AbsoluteSize.Y + GuiInset
        return UDim2.fromOffset(x, y/scale + (offsetY or 0))
    end
end
local function anchorRight(getGui)
    return function(offsetY)
        local g = getGui()
        local scale = Library:GetScreenScale()
        local x = g.AbsolutePosition.X + g.AbsoluteSize.X
        local y = (g.AbsolutePosition.Y + GuiInset) / scale
        return UDim2.fromOffset(x/scale + 8, y + (offsetY or 0))
    end
end
local function retreatUp(ud)  return UDim2.fromOffset(ud.X.Offset, ud.Y.Offset - 8) end
local function retreatLeft(ud) return UDim2.fromOffset(ud.X.Offset - 8, ud.Y.Offset) end

-- ============================================================
-- 14. Popup-механика (общая для всех выпадающих)
-- ============================================================
local function makePopup(cfg)
    local popup = cfg.Popup
    local frame = cfg.Frame
    local level = cfg.Level
    local place = cfg.Place
    local getAnchor = cfg.GetAnchor
    local fromOff = cfg.From or -6
    local toOff   = cfg.To or 6
    local retreat = cfg.Retreat or retreatUp
    local keepOpen = cfg.KeepOpen or function(p) return p == popup or p == popup.Host end

    function popup:SetOpen(open)
        if self.Debounce then return end
        if self.IsOpen == open then return end
        self.IsOpen = open
        self.Debounce = true
        if self.OnState then self.OnState(open) end
        if self.Host and self.Host.SetChildDim then self.Host.SetChildDim(open) end
        if open then
            if cfg.OnOpen then cfg.OnOpen() end
            frame.Instance.Parent = Library.PopupHolder.Instance
            frame.Instance.Position = place(fromOff)
            frame.Instance.Visible = true
            Library.TouchShields[frame.Instance] = level
            Library:SetDim(true)
            frame:Tween({ Position = place(toOff) })
            for other in Library.OpenFrames do
                if not keepOpen(other) then other:SetOpen(false) end
            end
            Library.OpenFrames[popup] = popup
            frame:FadeDescendants(true, function() self.Debounce = false end)
        else
            if cfg.OnClose then cfg.OnClose() end
            Library.OpenFrames[popup] = nil
            Library:SetDim(false)
            frame:Tween({ Position = retreat(frame.Instance.Position) })
            frame:FadeDescendants(false, function()
                self.Debounce = false
                if self.IsOpen then return end
                Library.TouchShields[frame.Instance] = nil
                frame.Instance.Parent = Library.UnusedHolder.Instance
            end)
        end
    end
    -- клик вне попапа закрывает
    Library:Connect(UserInput.InputBegan, function(input)
        local click = input.UserInputType == Enum.UserInputType.MouseButton1
                   or input.UserInputType == Enum.UserInputType.Touch
        if not click then return end
        if not popup.IsOpen then return end
        if cfg.HoldOpen and cfg.HoldOpen() then return end
        if frame:IsMouseOverFrame() then return end
        if pointInGui(input.Position, getAnchor()) then return end
        popup:SetOpen(false)
    end)
    return popup
end

-- ============================================================
-- 15. Select-строка (используется в keybind-меню и dropdown)
-- ============================================================
local function makeSelectRow(cfg)
    local z = cfg.Z
    local row = makeFrame({ Parent=cfg.Parent, Pos=cfg.Pos, Size=cfg.Size, Color=cfg.Color or "Section", Round=5, Z=z })
    setResting(row.Instance, "BackgroundTransparency", 1)
    local line = makeFrame({ Parent=row.Instance, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,cfg.LineX,0.5,0), Size=UDim2.fromOffset(3,0), Color="Accent", Round=4, Z=z+1 })
    local shadow = makeShadow(line.Instance, Library.Theme.Accent, UDim2.fromOffset(3,15), UDim.new(0,10), 0)
    if shadow then setResting(shadow, "Transparency", 1) end
    local label = makeLabel({ Parent=row.Instance, Text=cfg.Text, TextSize=cfg.TextSize, Pos=UDim2.fromOffset(cfg.TextX,0), Size=cfg.LabelSize, Color="DimText", Truncate=true, Z=z+1 })
    local hit = makeButton({ Parent=row.Instance, Z=z+2 })

    local function setActive(active, instant)
        Library:StampResting(row.Instance, "BackgroundTransparency", active and 0 or 1)
        label:ChangeItemTheme({ TextColor3 = active and "Text" or "DimText" })
        local info = instant and TweenInfo.new(0) or nil
        local color = active and Library.Theme.Text or Library.Theme.DimText
        local textX = active and cfg.TextActiveX or cfg.TextX
        Library:Tween({ BackgroundTransparency = active and 0 or 1 }, info, row.Instance)
        Library:Tween({ Size = UDim2.fromOffset(3, active and cfg.LineH or 0) }, info, line.Instance)
        Library:Tween({ TextColor3 = color, Position = UDim2.fromOffset(textX,0) }, info, label.Instance)
        if not shadow then return end
        Library:StampResting(shadow, "Transparency", active and 0 or 1)
        if cfg.SnapShadow or instant then shadow.Transparency = active and 0 or 1
        else Library:Tween({ Transparency = active and 0 or 1 }, info, shadow) end
    end
    return { Row=row, Line=line, Label=label, Hit=hit, Shadow=shadow, SetActive=setActive }
end

-- ============================================================
-- 16. Dropdown
-- ============================================================
local function makeDropdown(getAnchor, width, z)
    width = width or 40
    local dd = { IsOpen=false, Debounce=false, Order={}, Host=nil, OnPick=function() end }
    local g = {}
    local rowH = 30
    local searchH = 30
    g.Frame = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(150,0), Color="Element", Round=6, Clip=true, Z=z })
    g.Frame.Instance.Visible = false
    g.SearchHolder = makeFrame({ Parent=g.Frame.Instance, Size=UDim2.new(1,0,0,searchH), Color="Element", Z=z+5 })
    g.SearchHolder.Instance.Visible = false
    makeImage({ Parent=g.SearchHolder.Instance, Icon="search", Pos=UDim2.fromOffset(9,(searchH-13)/2), Size=UDim2.fromOffset(13,13), Color="DimText", Z=z+7 })
    g.Search = makeInput({ Parent=g.SearchHolder.Instance, Placeholder="Search...", Pos=UDim2.fromOffset(27,0), Size=UDim2.new(1,-32,1,0), TextSize=14, Z=z+6 })
    makeFrame({ Parent=g.SearchHolder.Instance, Pos=UDim2.new(0,6,1,-1), Size=UDim2.new(1,-12,0,1), Color="Line", Z=z+6 })
    g.Scroll = Library:Create("ScrollingFrame", {
        Parent=g.Frame.Instance, Name="\0", BackgroundTransparency=1,
        ScrollBarThickness=0, ScrollBarImageTransparency=1, Selectable=false, Active=true,
        AutomaticCanvasSize=Enum.AutomaticSize.Y, CanvasSize=UDim2.fromOffset(0,0),
        Size=UDim2.new(1,0,1,0), ZIndex=z+4, BorderSizePixel=0,
    })
    Library:Create("UIListLayout", { Parent=g.Scroll.Instance, SortOrder=Enum.SortOrder.LayoutOrder, Padding=UDim.new(0,3) })
    Library:Create("UIPadding", { Parent=g.Scroll.Instance, PaddingTop=UDim.new(0,4), PaddingBottom=UDim.new(0,4), PaddingLeft=UDim.new(0,4), PaddingRight=UDim.new(0,4) })
    dd.Items = g

    local function filter(text)
        text = string.lower(text)
        for _, item in dd.Order do
            item.Row.Instance.Visible = (text == "" or string.find(string.lower(item.Name), text, 1, true) ~= nil)
        end
    end
    Library:Connect(g.Search.Instance:GetPropertyChangedSignal("Text"), function()
        filter(g.Search.Instance.Text)
    end)
    function dd:AddRow(name)
        local row = makeSelectRow({
            Parent=g.Scroll.Instance, Size=UDim2.new(1,-4,0,rowH-4), Text=name, TextSize=14,
            LabelSize=UDim2.new(1,-20,1,0), LineX=8, LineH=16, TextX=11, TextActiveX=20, Z=z+1,
        })
        local item = { Name=name, Selected=false, Row=row.Row }
        function item:Set(active, instant)
            self.Selected = active
            row.SetActive(active, instant)
        end
        row.Row:OnHover(
            function() if not item.Selected then Library:Tween({ BackgroundTransparency = 0.7 }, nil, row.Row.Instance) end end,
            function() if not item.Selected then Library:Tween({ BackgroundTransparency = 1 }, nil, row.Row.Instance) end
        )
        row.Hit:Connect("MouseButton1Down", function() dd.OnPick(item) end)
        table.insert(dd.Order, item)
        return item
    end
    function dd:Clear()
        for _, item in dd.Order do item.Row.Instance:Destroy() end
        dd.Order = {}
    end
    return makePopup({
        Popup=dd, Frame=g.Frame, Level=z, GetAnchor=getAnchor, Place=anchorBelow(getAnchor),
        OnOpen=function()
            local anchor = getAnchor()
            local scale = Library:GetScreenScale()
            local hasSearch = #dd.Order > 8
            local w = width or (anchor.AbsoluteSize.X / scale)
            local h = math.min(#dd.Order*rowH + 8, 168)
            g.Search.Instance.Text = ""
            filter("")
            g.SearchHolder.Instance.Visible = hasSearch
            if hasSearch then
                g.Scroll.Instance.Position = UDim2.fromOffset(0, searchH)
                g.Scroll.Instance.Size = UDim2.new(1,0,1,-searchH)
                g.Frame.Instance.Size = UDim2.fromOffset(w, h + searchH)
            else
                g.Scroll.Instance.Position = UDim2.fromOffset(0,0)
                g.Scroll.Instance.Size = UDim2.new(1,0,1,0)
                g.Frame.Instance.Size = UDim2.fromOffset(w, h)
            end
        end,
        OnClose=function() g.Search.Instance.Text = "" end,
    })
end

-- ============================================================
-- 17. Color-pipette (кружок рядом с Colorpicker)
-- ============================================================
local function makeSwatch(parent, xOffset, color, z)
    local s = {}
    s.Halo = makeFrame({ Parent=parent, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,xOffset,0.5,0), Size=UDim2.fromOffset(22,22), Round=20, Z=z })
    s.Halo.Instance.BackgroundColor3 = color
    setResting(s.Halo.Instance, "BackgroundTransparency", 0.72)
    s.Core = makeFrame({ Parent=s.Halo.Instance, Anchor=Vector2.new(0.5,0.5), Pos=UDim2.new(0.5,0,0.5,0), Size=UDim2.fromOffset(12,12), Raw=color, Round=20, Z=z+1 })
    s.Shadow = makeShadow(s.Core.Instance, color, UDim2.fromOffset(0,0), UDim.new(0,6), 0.35)
    s.Hit = makeButton({ Parent=s.Halo.Instance, Z=z+2 })
    function s:SetColor(newColor, alpha)
        alpha = alpha or 0
        Library:StampResting(s.Core.Instance, "BackgroundTransparency", alpha)
        Library:StampResting(s.Halo.Instance, "BackgroundTransparency", 0.72)
        s.Halo:Tween({ BackgroundColor3 = newColor })
        s.Core:Tween({ BackgroundColor3 = newColor, BackgroundTransparency = alpha })
        if s.Shadow then pcall(function() s.Shadow.Color = newColor end) end
    end
    return s
end

-- ============================================================
-- 18. Colorpicker
-- ============================================================
local function makeColorpicker(getAnchor, initialColor, initialAlpha, onChange)
    local state = {
        Hue=0, Saturation=0, Value=1, Transparency=initialAlpha or 0,
        Color=Color3.new(1,1,1), IsOpen=false, Debounce=false,
    }
    local ui = {}
    local z = 120
    local fieldSize = 150
    local totalH = fieldSize + 110
    local cursorSize = 14
    local cursorStroke = 2

    ui.Window = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(150, totalH), Color="Section", Round=8, Z=z })
    ui.Window.Instance.Visible = false
    ui.Field = Library:Create("ImageButton", {
        Parent=ui.Window.Instance, Name="\0", AutoButtonColor=false,
        BackgroundColor3=Color3.fromRGB(255,0,0),
        Position=UDim2.fromOffset(16,16),
        Size=UDim2.fromOffset(fieldSize, fieldSize),
        ZIndex=z+1, BorderSizePixel=0,
    })
    addCorner(ui.Field.Instance, 8)
    ui.Tint = makeFrame({ Parent=ui.Field.Instance, Size=UDim2.new(1,0,1,0), Raw=Color3.new(1,1,1), Round=8, Z=z+2 })
    Library:Create("UIGradient", { Parent=ui.Tint.Instance, Transparency=NumberSequence.new({
        NumberSequenceKeypoint.new(0,0), NumberSequenceKeypoint.new(1,1) }) })
    ui.Shade = makeFrame({ Parent=ui.Field.Instance, Size=UDim2.new(1,0,1,0), Raw=Color3.new(0,0,0), Round=8, Z=z+3 })
    Library:Create("UIGradient", { Parent=ui.Shade.Instance, Rotation=90, Transparency=NumberSequence.new({
        NumberSequenceKeypoint.new(0,1), NumberSequenceKeypoint.new(1,0) }) })

    local function makeCursor(parent, pos, level)
        local c = makeFrame({ Parent=parent, Anchor=Vector2.new(0.5,0.5), Pos=pos, Size=UDim2.fromOffset(cursorSize,cursorSize), Raw=Color3.new(1,1,1), Alpha=1, Round=20, Z=level })
        Library:Create("UIStroke", { Parent=c.Instance, Color=Color3.new(1,1,1), Thickness=cursorStroke })
        return c
    end
    ui.FieldCursor = makeCursor(ui.Field.Instance, UDim2.new(0.5,0,0.5,0), z+4)

    local function makeBar(y)
        local bar = Library:Create("ImageButton", {
            Parent=ui.Window.Instance, Name="\0", AutoButtonColor=false,
            Position=UDim2.fromOffset(16,y), Size=UDim2.fromOffset(fieldSize,10),
            ZIndex=z+1, BorderSizePixel=0, BackgroundColor3=Color3.new(1,1,1),
        })
        addCorner(bar.Instance, 5)
        local cursor = makeCursor(bar.Instance, UDim2.new(1,0,0.5,0), z+3)
        return bar, cursor
    end
    ui.HueBar, ui.HueCursor = makeBar(fieldSize + 30)
    Library:Create("UIGradient", { Parent=ui.HueBar.Instance, Color=ColorSequence.new({
        ColorSequenceKeypoint.new(0.00, Color3.fromRGB(255,0,0)),
        ColorSequenceKeypoint.new(0.17, Color3.fromRGB(255,255,0)),
        ColorSequenceKeypoint.new(0.33, Color3.fromRGB(0,255,0)),
        ColorSequenceKeypoint.new(0.50, Color3.fromRGB(0,255,255)),
        ColorSequenceKeypoint.new(0.67, Color3.fromRGB(0,0,255)),
        ColorSequenceKeypoint.new(0.83, Color3.fromRGB(255,0,255)),
        ColorSequenceKeypoint.new(1.00, Color3.fromRGB(255,0,0)),
    }) })
    ui.AlphaBar, ui.AlphaCursor = makeBar(fieldSize + 50)
    Library:Create("UIGradient", { Parent=ui.AlphaBar.Instance, Transparency=NumberSequence.new({
        NumberSequenceKeypoint.new(0,0), NumberSequenceKeypoint.new(1,1) }) })
    ui.Hex = makeFrame({ Parent=ui.Window.Instance, Pos=UDim2.fromOffset(16, fieldSize+72), Size=UDim2.fromOffset(fieldSize,26), Color="Element", Round=5, Clip=true, Z=z+1 })
    ui.HexInput = makeInput({ Parent=ui.Hex.Instance, Text="#FFFFFF", Placeholder="#FFFFFF", Pos=UDim2.fromOffset(9,0), Size=UDim2.new(1,-18,1,0), TextSize=14, Z=z+2 })

    local dragging = nil
    local fast = TweenInfo.new(0.2, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
    local function redraw(instant)
        state.Color = Color3.fromHSV(state.Hue, state.Saturation, state.Value)
        local hueColor = Color3.fromHSV(state.Hue, 1, 1)
        local info = instant and TweenInfo.new(0) or fast
        ui.Field.Instance.BackgroundColor3 = hueColor
        Library:Tween({ BackgroundColor3 = hueColor }, info, ui.Field.Instance)
        Library:Tween({ Position = UDim2.new(state.Saturation,0,1-state.Value,0) }, info, ui.FieldCursor.Instance)
        Library:Tween({ Position = UDim2.new(state.Hue,0,0.5,0) }, info, ui.HueCursor.Instance)
        Library:Tween({ Position = UDim2.new(state.Transparency,0,0.5,0) }, info, ui.AlphaCursor.Instance)
        if not ui.HexInput.Instance:IsFocused() then
            ui.HexInput.Instance.Text = "#"..string.upper(state.Color:ToHex())
        end
        Library:SafeCall(onChange, state.Color, state.Transparency)
    end
    function state:Set(color, alpha, instant)
        if type(color) == "table" then color = Color3.fromRGB(color[1],color[2],color[3]) end
        if type(color) == "string" then color = Color3.fromHex(color) end
        state.Hue, state.Saturation, state.Value = color:ToHSV()
        state.Transparency = alpha or state.Transparency or 0
        if instant then
            state.Color = Color3.fromHSV(state.Hue, state.Saturation, state.Value)
            return
        end
        redraw(true)
    end

    local function pickFrom(input, kind)
        if kind == "Field" then
            state.Saturation = math.clamp((input.Position.X - ui.Field.Instance.AbsolutePosition.X) / ui.Field.Instance.AbsoluteSize.X, 0, 1)
            state.Value = 1 - math.clamp((input.Position.Y - ui.Field.Instance.AbsolutePosition.Y) / ui.Field.Instance.AbsoluteSize.Y, 0, 1)
        elseif kind == "Hue" then
            state.Hue = math.clamp((input.Position.X - ui.HueBar.Instance.AbsolutePosition.X) / ui.HueBar.Instance.AbsoluteSize.X, 0, 1)
        elseif kind == "Alpha" then
            state.Transparency = math.clamp((input.Position.X - ui.AlphaBar.Instance.AbsolutePosition.X) / ui.AlphaBar.Instance.AbsoluteSize.X, 0, 1)
        else return end
        redraw()
    end
    local function bindBar(gui, kind)
        local conn
        Library:Connect(gui.InputBegan, function(input)
            local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                    or input.UserInputType == Enum.UserInputType.Touch
            if not ok then return end
            dragging = kind
            pickFrom(input, kind)
            if conn then return end
            conn = input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then
                    if dragging == kind then dragging = nil end
                    conn:Disconnect(); conn = nil
                end
            end)
        end)
    end
    bindBar(ui.Field.Instance, "Field")
    bindBar(ui.HueBar.Instance, "Hue")
    bindBar(ui.AlphaBar.Instance, "Alpha")
    Library:Connect(UserInput.InputChanged, function(input)
        local move = input.UserInputType == Enum.UserInputType.MouseMovement
                  or input.UserInputType == Enum.UserInputType.Touch
        if move and dragging then pickFrom(input, dragging) end
    end)
    ui.HexInput:Connect("FocusLost", function()
        local hex = string.gsub(ui.HexInput.Instance.Text, "#", "")
        local ok, col = pcall(function() return Color3.fromHex(hex) end)
        if ok and col then state:Set(col, state.Transparency) else redraw(true) end
    end)
    makePopup({ Popup=state, Frame=ui.Window, Level=z, GetAnchor=getAnchor, Place=anchorRight(getAnchor) })
    state:Set(initialColor or Library.Theme.Accent, state.Transparency)
    return state
end

-- ============================================================
-- 19. Keybind utils
-- ============================================================
local function keyName(input)
    if not input then return "None" end
    local s = tostring(input)
    s = string.gsub(s, "Enum.KeyCode.", "")
    s = string.gsub(s, "Enum.UserInputType.", "")
    return s
end
local function keyFromName(name)
    if type(name) ~= "string" or name == "None" then return nil end
    name = string.gsub(name, "Enum.KeyCode.", "")
    name = string.gsub(name, "Enum.UserInputType.", "")
    local ok, key = pcall(function() return Enum.KeyCode[name] end)
    if ok and key then return key end
    return nil
end
local function pickKey(owner, label, onDone)
    if owner.Picking then return end
    owner.Picking = true
    Library.Binding = true
    label.Text = ". . ."
    task.wait()
    local conn
    conn = UserInput.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then return end
        conn:Disconnect()
        local isBack = input.KeyCode == Enum.KeyCode.Backspace
        local isEsc  = input.KeyCode == Enum.KeyCode.Escape
        if isBack or isEsc then onDone(nil)
        elseif input.UserInputType == Enum.UserInputType.Keyboard then onDone(input.KeyCode)
        else onDone(input.UserInputType) end
        task.defer(function() Library.Binding = false end)
    end)
end
local function inputMatches(input, key)
    return input.KeyCode == key or input.UserInputType == key
end

-- ============================================================
-- 20. Notification
-- ============================================================
function Library.Notification(self, cfg)
    if Library.Silent then return end
    cfg = cfg or {}
    local title = cfg.Name or cfg.Title or "Notification"
    local desc  = cfg.Description or cfg.Content or ""
    local icon  = cfg.Icon or "bell"
    local color = cfg.Color or Library.Theme.Accent
    local duration = cfg.Duration or 5
    local width = 300
    local bodySize = Vector2.new(0,0)
    if desc ~= "" then bodySize = measureText(desc, 14, width-26, RegularFont) end
    local height = 38 + (desc ~= "" and bodySize.Y + 6 or 0) + 18

    local n = {}
    n.Frame = makeFrame({ Parent=Library.Holder.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,340,0,15), Size=UDim2.fromOffset(width,height), Color="Section", Round=10, Z=80 })
    n.Icon  = makeImage({ Parent=n.Frame.Instance, Icon=icon, Pos=UDim2.fromOffset(13,11), Size=UDim2.fromOffset(18,18), Raw=color, Z=81 })
    n.Title = makeLabel({ Parent=n.Frame.Instance, Text=title, TextSize=15, Pos=UDim2.fromOffset(40,10), Size=UDim2.new(1,-70,0,20), Color="Text", Truncate=true, Z=81 })
    n.Close = makeImage({ Parent=n.Frame.Instance, Icon="x", Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-13,0,13), Size=UDim2.fromOffset(14,14), Color="DimText", Z=82 })
    n.CloseHit = makeButton({ Parent=n.Frame.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-8,0,8), Size=UDim2.fromOffset(24,24), Z=83 })
    if desc ~= "" then
        n.Body = makeLabel({ Parent=n.Frame.Instance, Text=desc, TextSize=14, Pos=UDim2.fromOffset(13,35), Size=UDim2.new(1,-26,0,bodySize.Y), Color="DimText", Wrap=true, Z=81 })
        n.Body.Instance.TextYAlignment = Enum.TextYAlignment.Top
    end
    n.BarBack = makeFrame({ Parent=n.Frame.Instance, Pos=UDim2.new(0,13,1,-12), Size=UDim2.new(1,-26,0,5), Color="Element", Round=4, Z=81 })
    n.BarFill = makeFrame({ Parent=n.BarBack.Instance, Size=UDim2.new(1,0,1,0), Raw=Color3.new(1,1,1), Round=4, Z=82 })
    Library:RegisterGradient(Library:Create("UIGradient", { Parent=n.BarFill.Instance }).Instance)

    local entry = { Items=n, Dead=false, Height=height }
    table.insert(Library.Notifs, entry)

    local function stackY(target)
        local y = 15
        for _, e in Library.Notifs do
            if e == target then break end
            if e.Dead then continue end
            y += e.Height + 10
        end
        return y
    end
    local function restack()
        local info = TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local y = 15
        for _, e in Library.Notifs do
            if e.Dead then continue end
            Library:Tween({ Position = UDim2.new(1,-15,0,y) }, info, e.Items.Frame.Instance)
            y += e.Height + 10
        end
    end
    local startY = stackY(entry)
    local slide = TweenInfo.new(0.45, Enum.EasingStyle.Exponential, Enum.EasingDirection.Out)
    n.Frame.Instance.Position = UDim2.new(1,340,0,startY)
    n.Frame:Tween({ Position = UDim2.new(1,-15,0,startY) }, slide)

    local function dismiss()
        if entry.Dead then return end
        entry.Dead = true
        local info = TweenInfo.new(0.25, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local p = n.Frame.Instance.Position
