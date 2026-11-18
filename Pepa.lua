-- ============================================================
-- SHITARO MAP VOTE CHEAT — DEOBFUSCATED
-- Target game: Flee the Facility (SummerLobby / Lobby)
-- Backend:     shitaro.lol/api/
-- Obfuscator:  LPH (Luraph)
-- ============================================================


-- ─────────────────────────────────────────────────────────────
-- LAYER 0 — LPH STUB
-- Если файл запускается без LPH VM, заглушает все атрибуты обфускатора
-- (ENCRYPT, VM, PRESET и т.д.) пустыми функциями чтобы не крашнуть
-- ─────────────────────────────────────────────────────────────
if not LPH_OBFUSCATED then
    local noop = function() end
    local env = getgenv and getgenv() or _G
    -- Все LPH-директивы → пустые функции
    env.LPH_ATTRIBUTES = noop
    env.ENCRYPT, env.VM, env.PRESET, env.OPTIMIZE,
    env.TRANSFORM, env.ERROR_HANDLING = noop,noop,noop,noop,noop,noop
    env.UNROLL, env.INLINE, env.NO_UPVALUES = noop,noop,noop
    env.NONE, env.OPAL, env.ONYX, env.FAST,
    env.BALANCED, env.SECURE = noop,noop,noop,noop,noop,noop
    env.EXTRACT, env.CONTROL_FLOW, env.REWRITE_NAMECALLS,
    env.GLOBALS, env.CONSTANTS = noop,noop,noop,noop,noop
end


-- ─────────────────────────────────────────────────────────────
-- LAYER 1 — HTTP ABSTRACTION
-- Поддерживает: syn.request, http.request, fluxus.request, getgenv().request
-- Если ни одного — возвращает nil-функцию (graceful degradation)
-- ─────────────────────────────────────────────────────────────
local http_request =
    rawget(getfenv(), "request") or
    (syn        and syn.request)        or
    (http       and http.request)       or
    (fluxus     and fluxus.request)     or
    (getgenv    and getgenv().request)

if type(http_request) ~= "function" then
    http_request = function() return nil end
end

local HttpService = game:GetService("HttpService")

-- Таблица публичного API (lib/asset fetcher), заполняется ниже
local shitaro_api = {}


-- ─────────────────────────────────────────────────────────────
-- LAYER 2 — KEY SYSTEM (BYPASSED)
-- Скрипт идёт с hardcoded bypass: reason="KEYLESS", value="FREE"
-- JD_IS_PREMIUM = true выставляется всегда, проверки ключа нет
-- ─────────────────────────────────────────────────────────────
local key_state = {
    alive  = true,
    reason = "KEYLESS",
    value  = "FREE",
    unload = nil,
}

function key_state.bind(fn)
    if type(fn) == "function" then key_state.unload = fn end
end

function key_state.stop()  key_state.alive = false end
function key_state.watch() key_state.alive = true  end

function key_state.open()
    local env = getgenv()
    -- Останавливаем предыдущий инстанс если был
    local prev = env.SHKEY
    if type(prev) == "table" and type(prev.stop) == "function" then
        pcall(prev.stop)
    end
    -- Выставляем глобали — всегда KEYLESS / FREE / premium
    key_state.alive  = true
    key_state.reason = "KEYLESS"
    env.SCRIPT_KEY   = key_state.value  -- "FREE"
    env.SHKEY        = key_state
    env.JD_IS_PREMIUM = true
    env.JD_REASON    = "KEYLESS"
    key_state.watch()
    return true
end

if not key_state.open() then return end


-- ─────────────────────────────────────────────────────────────
-- LAYER 3 — CRYPTO LAYER
-- SHA-256, HMAC-SHA256, Base64url encode/decode, XOR stream cipher
-- Используется для подписи запросов к shitaro.lol и шифрования ассетов
-- ─────────────────────────────────────────────────────────────
do
    -- Локальные алиасы
    local band, bxor, bnot   = bit32.band, bit32.bxor, bit32.bnot
    local rrotate, rshift     = bit32.rrotate, bit32.rshift
    local char, byte, rep, sub = string.char, string.byte, string.rep, string.sub
    local concat               = table.concat
    local floor                = math.floor

    -- SHA-256 round constants
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

    -- SHA-256(msg) → 32-байтный бинарный дайджест
    local function sha256(msg)
        local h0,h1,h2,h3 = 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
        local h4,h5,h6,h7 = 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

        local len    = #msg
        local lo     = (len * 8) % 4294967296
        local hi     = floor((len * 8) / 4294967296)
        local padlen = (56 - (len + 1) % 64) % 64

        -- Padding: 0x80, нули, big-endian длина 64 бита
        msg = msg .. "\128" .. rep("\0", padlen) ..
              char(
                  floor(hi/16777216)%256, floor(hi/65536)%256,
                  floor(hi/256)%256,      hi%256,
                  floor(lo/16777216)%256, floor(lo/65536)%256,
                  floor(lo/256)%256,      lo%256
              )

        local W = table.create and table.create(64, 0) or {}

        for chunk = 1, #msg, 64 do
            -- Загружаем 16 слов
            for i = 0, 15 do
                local p = chunk + i*4
                W[i+1] = byte(msg,p)*16777216 + byte(msg,p+1)*65536
                       + byte(msg,p+2)*256     + byte(msg,p+3)
            end
            -- Расширяем до 64 слов
            for i = 17, 64 do
                local s0 = bxor(rrotate(W[i-15],7), rrotate(W[i-15],18), rshift(W[i-15],3))
                local s1 = bxor(rrotate(W[i-2],17), rrotate(W[i-2],19),  rshift(W[i-2],10))
                W[i] = (W[i-16] + s0 + W[i-7] + s1) % 4294967296
            end

            -- Компрессия
            local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
            for i = 1, 64 do
                local S1    = bxor(rrotate(e,6),  rrotate(e,11), rrotate(e,25))
                local ch    = bxor(band(e,f),     band(bnot(e),g))
                local temp1 = (h + S1 + ch + K[i] + W[i]) % 4294967296
                local S0    = bxor(rrotate(a,2),  rrotate(a,13), rrotate(a,22))
                local maj   = bxor(band(a,b),     band(a,c),     band(b,c))
                local temp2 = (S0 + maj) % 4294967296
                h=g; g=f; f=e; e=(d+temp1)%4294967296
                d=c; c=b; b=a; a=(temp1+temp2)%4294967296
            end
            h0=(h0+a)%4294967296; h1=(h1+b)%4294967296
            h2=(h2+c)%4294967296; h3=(h3+d)%4294967296
            h4=(h4+e)%4294967296; h5=(h5+f)%4294967296
            h6=(h6+g)%4294967296; h7=(h7+h)%4294967296
        end

        local function u32be(n)
            return char(floor(n/16777216)%256, floor(n/65536)%256,
                        floor(n/256)%256,      n%256)
        end
        return u32be(h0)..u32be(h1)..u32be(h2)..u32be(h3)
             ..u32be(h4)..u32be(h5)..u32be(h6)..u32be(h7)
    end

    -- HMAC-SHA256(key, msg) → 32-байтный бинарный MAC
    local function hmac_sha256(key, msg)
        if #key > 64 then key = sha256(key) end
        if #key < 64 then key = key .. rep("\0", 64 - #key) end
        local o_pad, i_pad = {}, {}
        for i = 1, 64 do
            local b = byte(key, i)
            o_pad[i] = char(bxor(b, 0x5c))
            i_pad[i] = char(bxor(b, 0x36))
        end
        return sha256(concat(o_pad) .. sha256(concat(i_pad) .. msg))
    end

    -- Base64url encode (алфавит A-Za-z0-9-_)
    local B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    local function base64url_encode(data)
        local out, n = {}, 0
        local i = 1
        while i <= #data do
            local b1 = byte(data, i)
            local b2 = byte(data, i+1)
            local b3 = byte(data, i+2)
            local v  = b1*65536 + (b2 or 0)*256 + (b3 or 0)
            n=n+1; out[n] = sub(B64URL, floor(v/262144)+1,    floor(v/262144)+1)
            n=n+1; out[n] = sub(B64URL, floor(v/4096)%64+1,   floor(v/4096)%64+1)
            if b2 then n=n+1; out[n] = sub(B64URL, floor(v/64)%64+1, floor(v/64)%64+1) end
            if b3 then n=n+1; out[n] = sub(B64URL, v%64+1,           v%64+1) end
            i = i + 3
        end
        return concat(out)
    end

    -- Стандартный Base64 decode (для входящих заголовков от сервера)
    local B64_DEC = {}
    for i = 1, 64 do
        local ch = sub("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", i, i)
        B64_DEC[ch] = i - 1
    end
    local function base64_decode(s)
        s = s:gsub("-","+"):gsub("_","/"):gsub("[^A-Za-z0-9+/=]","")
        s = s .. rep("=", (4 - #s%4)%4)
        local out, n = {}, 0
        for i = 1, #s, 4 do
            local a = B64_DEC[sub(s,i,i)]   or 0
            local b = B64_DEC[sub(s,i+1,i+1)] or 0
            local c = B64_DEC[sub(s,i+2,i+2)] or 0
            local d = B64_DEC[sub(s,i+3,i+3)] or 0
            local v = a*262144 + b*4096 + c*64 + d
            n=n+1; out[n] = char(floor(v/65536)%256)
            if sub(s,i+2,i+2) ~= "=" then n=n+1; out[n] = char(floor(v/256)%256) end
            if sub(s,i+3,i+3) ~= "=" then n=n+1; out[n] = char(v%256) end
        end
        return concat(out)
    end

    -- Hex decode утилита
    local function hex_decode(s)
        return s:gsub("..", function(h) return char(tonumber(h, 16)) end)
    end

    -- Мастер-ключ (hardcoded, 32 байта)
    -- hex: 02d417c2bd7b033a00d3c4e9fda43fc56761f68f516cf68a68a6110f2cb99e49
    local MASTER_KEY = hex_decode("02d417c2bd7b033a00d3c4e9fda43fc56761f68f516cf68a68a6110f2cb99e49")

    -- RNG seeded tick()+os.time()
    local rng = Random.new((tick()*1e6) % 2147483647 + os.time())

    -- Генерация случайных байт
    local function random_bytes(n)
        local t = {}
        for i = 1, n do t[i] = char(rng:NextInteger(0, 255)) end
        return concat(t)
    end

    -- uint64 big-endian из числа (для timestamp в подписи)
    local function u64be(n)
        local t = {}
        for i = 8, 1, -1 do t[i] = char(n % 256); n = floor(n/256) end
        return concat(t)
    end

    -- URL percent-encode
    local function url_encode(s)
        return s:gsub("[^%w%-%._~/]", function(c)
            return string.format("%%%02X", byte(c))
        end)
    end

    -- ─────────────────────────────────────────────────────────
    -- XOR STREAM CIPHER — "SHITARO ASSET MASK v1"
    -- Ключ = HMAC(MASTER_KEY, "SHITARO-ASSET-MASK-v1\0" .. nonce)
    -- PRNG на базе xorshift-подобного mix, 32-битный вывод каждые 4 байта
    -- ─────────────────────────────────────────────────────────
    local lshift, rshift2, band2 = bit32.lshift, bit32.rshift, bit32.band

    local function make_prng(seed_bytes)
        -- Инициализация: 4 слова из первых 16 байт seed_bytes
        local function word(i)
            local a,b,c,d = byte(seed_bytes, i, i+3)
            return (d or 0)*16777216 + (c or 0)*65536 + (b or 0)*256 + (a or 0)
        end
        local s0,s1,s2,s3 = word(1), word(5), word(9), word(13)
        if s0==0 and s1==0 and s2==0 and s3==0 then
            s0,s1,s2,s3 = 0x9e3779b9,0x243f6a88,0xb7e15162,0x85ebca6b
        end
        return function()
            local t = s0
            t = bxor(t, lshift(t,11))
            t = bxor(t, rshift2(t,8))
            s0,s1,s2 = s1,s2,s3
            local r = s3
            r = bxor(r, rshift2(r,19))
            r = bxor(r, t)
            s3 = r
            return r
        end
    end

    local function xor_decrypt_asset(ciphertext, nonce)
        local prng_seed = hmac_sha256(MASTER_KEY, "SHITARO-ASSET-MASK-v1\0" .. nonce)
        local gen  = make_prng(prng_seed)
        local len  = #ciphertext

        if buffer and buffer.fromstring then
            -- Fast path: buffer API
            local buf = buffer.fromstring(ciphertext)
            local off = 0
            while off + 4 <= len do
                buffer.writeu32(buf, off, bxor(buffer.readu32(buf, off), gen()))
                off = off + 4
            end
            if off < len then
                local kw = gen()
                local j  = 0
                while off + j < len do
                    buffer.writeu8(buf, off+j, bxor(buffer.readu8(buf, off+j),
                        band2(rshift2(kw, j*8), 255)))
                    j = j + 1
                end
            end
            return buffer.tostring(buf)
        else
            -- Slow path: table
            local out, n = {}, 0
            local i = 1
            while i <= len do
                local kw = gen()
                for j = 0, 3 do
                    if i+j <= len then
                        n=n+1
                        out[n] = char(bxor(byte(ciphertext, i+j),
                                      band2(rshift2(kw, j*8), 255)))
                    end
                end
                i = i + 4
            end
            return concat(out)
        end
    end

    -- ─────────────────────────────────────────────────────────
    -- SIGNED HTTP CLIENT — shitaro.lol/api/
    --
    -- Каждый запрос:
    --   nonce   = 16 случайных байт
    --   ts      = u64be(os.time())
    --   token   = base64url( HMAC(MASTER_KEY, "SHITARO-{type}-REQ-v1\0{path}\0{nonce}\0{ts}") )
    --
    -- Ответ верифицируется:
    --   sig     = base64_decode(X-Shitaro-Sig header)
    --   expect  = HMAC(MASTER_KEY, "SHITARO-{type}-RESP-v1\0{path}\0{nonce}\0{u64be(#body)}{body}")
    --   sig == expect  → ок, иначе отброс
    --
    -- Для type="ASSET" тело дополнительно XOR-расшифровывается с nonce
    -- ─────────────────────────────────────────────────────────
    local function signed_get(base_url, req_type, path)
        local nonce = random_bytes(16)
        local ts    = u64be(os.time())

        local token = base64url_encode(
            hmac_sha256(MASTER_KEY,
                "SHITARO-" .. req_type .. "-REQ-v1\0" .. path .. "\0" .. nonce .. "\0" .. ts)
        )

        local ok, resp = pcall(http_request, {
            Url     = base_url .. url_encode(path),
            Method  = "GET",
            Headers = {
                ["X-Shitaro-Token"] = token,
                ["Accept"]          = "*/*",
                ["Cache-Control"]   = "no-cache",
            },
        })

        if not ok or type(resp) ~= "table" or resp.StatusCode ~= 200 then
            return nil
        end

        local body = resp.Body
        if type(body) ~= "string" or #body == 0 then return nil end

        -- Верификация подписи ответа
        local headers = resp.Headers or {}
        local sig_b64 = headers["X-Shitaro-Sig"] or headers["x-shitaro-sig"] or ""
        if sig_b64 == "" then return nil end

        local expected_mac = hmac_sha256(MASTER_KEY,
            "SHITARO-" .. req_type .. "-RESP-v1\0" .. path .. "\0"
            .. nonce .. "\0" .. u64be(#body) .. body)

        if base64_decode(sig_b64) ~= expected_mac then return nil end

        -- Ассеты дополнительно шифрованы XOR с nonce
        if req_type == "ASSET" then
            return xor_decrypt_asset(body, nonce)
        end
        return body
    end

    -- Публичный API
    function shitaro_api.lib(name)
        return signed_get("https://shitaro.lol/api/library/", "LIB", name)
    end
    function shitaro_api.asset(name)
        return signed_get("https://shitaro.lol/api/assets/", "ASSET", name)
    end
end


-- ─────────────────────────────────────────────────────────────
-- LAYER 4 — LPH VM PAYLOAD (~434 KB)
-- Этот блок — зашифрованный байткод LPH VM.
-- Деобфусцировать статически невозможно без LPH runtime.
-- При исполнении загружает основную логику чита:
--   • ESP / GUI компоненты
--   • Менеджер подписки (шина событий через `q()`)
--   • Загрузчик ассетов через shitaro_api
-- ─────────────────────────────────────────────────────────────
-- [LPH VM BYTECODE — 434 219 bytes, omitted]
-- Внутри после исполнения становятся доступны:
--   q(fn)  — регистратор модулей (аналог require/task.spawn)
--   t      — объект главного GUI меню (AddSub/AddSection/...)
--   a(name)→string — загрузчик lib-файлов через shitaro_api


-- ─────────────────────────────────────────────────────────────
-- LAYER 5 — MAP VOTE MODULE
-- Регистрируется через q() после расшифровки VM
-- Игра: Flee the Facility (workspace.SummerLobby / Lobby)
-- ─────────────────────────────────────────────────────────────
q(function()
    local Players    = game:GetService("Players")
    local RunService = game:GetService("RunService")
    local LocalPlayer = Players.LocalPlayer

    -- ─── Загрузка списка карт с сервера ────────────────────────
    -- shitaro_api.lib("maps.bin") → "MapName\t<asset_id>\n..."
    local MAP_LIB_KEY = string.char(109,97,112,115,46,98,105,110) -- "maps.bin"

    local function parse_map_list(raw)
        -- raw: строка через `a()` → lib fetch
        local data = a(raw)  -- a() = shitaro_api.lib wrapper из VM
        if type(data) ~= "string" or #data == 0 then return nil end
        local maps = {}
        for line in string.gmatch(data, "([^\n]+)") do
            local name, id = string.match(line, "^(.-)\t(%d+)$")
            local id_n = tonumber(id)
            if name and name ~= "" and id_n and id_n > 0 then
                maps[#maps+1] = { name, id_n }
            end
        end
        return #maps > 0 and maps or nil
    end

    -- ─── Состояние ─────────────────────────────────────────────
    local known_maps     = {}  -- name → true (дедупликация)
    local map_list       = {}  -- []{name, label, image} для GUI списка
    local priority_set   = {}  -- name → true (выбранные приоритетные карты)

    local vote_pads      = {}  -- массив pad-объектов текущей карты голосования
    local pad_conns      = {}  -- соединения сигналов для pad-объектов

    local votepad_root   = nil -- workspace.VotePads контейнер
    local lobby_conn     = nil -- соединение на появление VotePads
    local workspace_conn = nil -- соединение на появление Lobby

    local heartbeat_conn = nil -- Heartbeat — удержание позиции на паде
    local tally_conn     = nil -- сигнал изменения счётчика голосов (для dupe)
    local respawn_conn   = nil -- CharacterAdded — прыжок на пад после смерти

    -- ─── Флаги / настройки ─────────────────────────────────────
    local auto_vote_on   = false  -- toggle: auto vote
    local dupe_mode_on   = false  -- toggle: dupe (умирать для накрутки)
    local script_active  = true   -- false при выгрузке

    local dupe_cap       = 3      -- макс. смертей на одном паде
    local dupe_count     = 0      -- текущий счётчик смертей

    local map_gui_widget = nil    -- виджет ImageList из GUI
    local target_pos     = nil    -- Vector3 целевого пада
    local target_votes   = 0      -- голоса на момент постановки на пад
    local session_id     = 0      -- инкремент для отмены устаревших корутин
    local vote_active    = false  -- идёт ли сессия голосования
    local refresh_queued = false  -- debounce на обновление UI
    local origin_cframe  = nil    -- CFrame до телепорта (для возврата)

    -- ─── Утилиты ───────────────────────────────────────────────

    -- Сортировка map_list по алфавиту
    local function sort_maps()
        table.sort(map_list, function(a, b)
            return string.lower(a.name) < string.lower(b.name)
        end)
    end

    -- Добавить карту в список (дедуп по имени)
    local function register_map(name, image)
        if type(name) ~= "string" or name == "" or name == "MAP NAME" then return false end
        if type(image) ~= "string" or image == "" then return false end
        if known_maps[name] then return false end
        known_maps[name] = image
        map_list[#map_list+1] = { name=name, label=name, image=image }
        return true
    end

    -- Синхронизировать priority_set из GUI виджета
    local function sync_priority()
        if not map_gui_widget then return end
        local val = map_gui_widget:GetValue()
        table.clear(priority_set)
        if type(val) == "table" then
            for _, v in ipairs(val) do
                if type(v) == "string" and v ~= "" then priority_set[v] = true end
            end
        elseif type(val) == "string" and val ~= "" then
            priority_set[val] = true
        end
    end

    -- Загрузить список карт с shitaro.lol и заполнить GUI
    local function fetch_maps()
        local result = nil
        for attempt = 1, 3 do
            result = parse_map_list(MAP_LIB_KEY)
            if result then break end
            task.wait(0.75)
        end
        if not result then return end

        local changed = false
        for _, entry in ipairs(result) do
            if register_map(entry[1], "rbxassetid://" .. entry[2]) then
                changed = true
            end
        end
        if not changed then return end

        sort_maps()
        if map_gui_widget then
            pcall(function() map_gui_widget:SetData(map_list) end)
        end
        sync_priority()
    end

    -- Получить счётчик голосов пада из GUI
    local function get_votes(pad_obj)
        return tonumber(string.match(pad_obj.tally.Text, "%d+")) or 0
    end

    -- Проверить: пад активен и имеет имя карты
    local function pad_is_valid(pad_obj)
        local t = pad_obj.title.Text
        return pad_obj.info.Enabled and t ~= "" and t ~= "MAP NAME"
    end

    -- Есть ли хоть один активный пад
    local function any_pad_active()
        for i = 1, #vote_pads do
            if vote_pads[i].info.Enabled then return true end
        end
        return false
    end

    -- ─── Управление сессией голосования ────────────────────────

    local function disconnect_vote_signals()
        for _, c in ipairs({heartbeat_conn, tally_conn, respawn_conn}) do
            if c then pcall(function() c:Disconnect() end) end
        end
        heartbeat_conn, tally_conn, respawn_conn = nil, nil, nil
    end

    local function stop_vote_session()
        disconnect_vote_signals()
        vote_active  = false
        target_pos   = nil
        dupe_count   = 0
        origin_cframe = nil
    end

    -- Raycast: найти поверхность под падом (Y + 3.2)
    local function get_pad_position(pad)
        local params = RaycastParams.new()
        params.FilterType = Enum.RaycastFilterType.Exclude
        params.FilterDescendantsInstances = {LocalPlayer.Character, votepad_root}
        local hit = workspace:Raycast(
            pad.Position + Vector3.new(0,8,0),
            Vector3.new(0,-40,0),
            params
        )
        local y = hit and (hit.Position.Y + 3.2) or pad.Position.Y
        return Vector3.new(pad.Position.X, y, pad.Position.Z)
    end

    -- Телепорт HumanoidRootPart
    local function teleport_to(pos)
        local char = LocalPlayer.Character
        local hrp  = char and char:FindFirstChild("HumanoidRootPart")
        if not hrp then return false end
        hrp.CFrame = CFrame.new(pos)
        return true
    end

    -- Убить персонажа (для dupe-накрутки)
    local function kill_character()
        local char = LocalPlayer.Character
        local hum  = char and char:FindFirstChildWhichIsA("Humanoid")
        if hum then
            hum:ChangeState(Enum.HumanoidStateType.Dead)
            pcall(function() hum.Health = 0 end)
        elseif char then
            pcall(function() char:BreakJoints() end)
        end
    end

    -- Получить список падов с приоритетных карт
    local function get_priority_pads()
        local result = {}
        for i = 1, #vote_pads do
            local p = vote_pads[i]
            if pad_is_valid(p) and priority_set[p.title.Text] then
                result[#result+1] = p
            end
        end
        return result
    end

    -- ─── Основная логика голосования ───────────────────────────
    local function start_vote_tick(tick_id)
        local candidates = get_priority_pads()
        if #candidates == 0 then stop_vote_session(); return end

        -- Выбрать случайный пад из приоритетных
        local chosen  = candidates[math.random(1, #candidates)]
        target_pos    = get_pad_position(chosen.pad)
        dupe_count    = 0
        target_votes  = get_votes(chosen)

        -- Запомнить позицию до телепорта
        local char = LocalPlayer.Character
        local hrp  = char and char:FindFirstChild("HumanoidRootPart")
        if not hrp then stop_vote_session(); return end
        origin_cframe = hrp.CFrame

        -- Телепорт на пад
        if not teleport_to(target_pos) then stop_vote_session(); return end

        if not dupe_mode_on then
            -- Без dupe: просто встать на пад и через 0.15с вернуться
            task.delay(0.15, function()
                if session_id ~= tick_id then return end
                local c2  = LocalPlayer.Character
                local h2  = c2 and c2:FindFirstChild("HumanoidRootPart")
                if h2 then
                    local hum = c2:FindFirstChildWhichIsA("Humanoid")
                    if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
                    h2.CFrame = origin_cframe
                    task.delay(0.05, function()
                        local c3 = LocalPlayer.Character
                        local h3 = c3 and c3:FindFirstChildWhichIsA("Humanoid")
                        if h3 then pcall(function() h3:ChangeState(Enum.HumanoidStateType.Running) end) end
                    end)
                end
                stop_vote_session()
            end)
            return
        end

        -- Dupe режим:

        -- Heartbeat: удерживать персонажа на паде (антидрейф)
        heartbeat_conn = RunService.Heartbeat:Connect(function()
            if not script_active or session_id ~= tick_id or not target_pos then return end
            local c = LocalPlayer.Character
            local h = c and c:FindFirstChild("HumanoidRootPart")
            if not h then return end
            local delta = Vector3.new(h.Position.X - target_pos.X, 0, h.Position.Z - target_pos.Z)
            if delta.Magnitude > 2.5 then
                h.CFrame = CFrame.new(target_pos)
            end
        end)

        -- Слушаем счётчик голосов: когда счётчик вырос — смерть = ещё один голос
        tally_conn = chosen.tally:GetPropertyChangedSignal("Text"):Connect(function()
            if session_id ~= tick_id or not dupe_mode_on or not chosen.info.Enabled then return end
            local cur = get_votes(chosen)
            if cur <= target_votes then target_votes = cur; return end
            target_votes = cur

            if dupe_count >= dupe_cap then
                -- Лимит достигнут — возврат на origin
                disconnect_vote_signals()
                task.defer(function()
                    if session_id ~= tick_id then return end
                    local c = LocalPlayer.Character
                    local h = c and c:FindFirstChild("HumanoidRootPart")
                    if h and origin_cframe then
                        local hum = c:FindFirstChildWhichIsA("Humanoid")
                        if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
                        h.CFrame = origin_cframe
                        task.delay(0.05, function()
                            local c2 = LocalPlayer.Character
                            local h2 = c2 and c2:FindFirstChildWhichIsA("Humanoid")
                            if h2 then pcall(function() h2:ChangeState(Enum.HumanoidStateType.Running) end) end
                        end)
                    end
                    stop_vote_session()
                end)
                return
            end

            dupe_count = dupe_count + 1
            kill_character()
        end)

        -- После respawn — снова встать на пад (если лимит не исчерпан)
        respawn_conn = LocalPlayer.CharacterAdded:Connect(function(char)
            if session_id ~= tick_id or not dupe_mode_on then return end
            local hrp = char:WaitForChild("HumanoidRootPart", 6)
            if not hrp or session_id ~= tick_id
               or not chosen.info.Enabled or not target_pos then return end

            if dupe_count >= dupe_cap then
                -- Лимит — вернуться на origin
                if origin_cframe then
                    local hum = char:FindFirstChildWhichIsA("Humanoid")
                    if hum then pcall(function() hum:ChangeState(Enum.HumanoidStateType.Physics) end) end
                    hrp.CFrame = origin_cframe
                    task.delay(0.05, function()
                        local c2  = LocalPlayer.Character
                        local h2  = c2 and c2:FindFirstChildWhichIsA("Humanoid")
                        if h2 then pcall(function() h2:ChangeState(Enum.HumanoidStateType.Running) end) end
                    end)
                end
                return
            end

            hrp.CFrame = CFrame.new(target_pos)
        end)
    end

    -- ─── Триггер обновления состояния ──────────────────────────

    -- Запустить/сбросить сессию при изменении состояния падов
    local function evaluate_state()
        refresh_queued = false
        if not script_active then return end

        -- Автоматически регистрировать новые карты из падов
        local changed = false
        for i = 1, #vote_pads do
            local p = vote_pads[i]
            if p.info.Enabled and register_map(p.title.Text, p.icon.Image) then
                changed = true
            end
        end
        if changed then
            sort_maps()
            if map_gui_widget then
                pcall(function() map_gui_widget:SetData(map_list) end)
            end
            sync_priority()
        end

        -- Если падов нет — стоп
        if not any_pad_active() then
            if vote_active then stop_vote_session() end
            return
        end

        -- Если auto vote выключен или уже идёт сессия — выход
        if not auto_vote_on or vote_active then return end

        -- Запуск новой сессии
        vote_active = true
        session_id  = session_id + 1
        start_vote_tick(session_id)
    end

    local function schedule_evaluate()
        if refresh_queued or not script_active then return end
        refresh_queued = true
        task.delay(0.25, evaluate_state)
    end

    -- ─── Парсинг структуры VotePad ─────────────────────────────
    -- Каждый VotePad содержит:
    --   Pad          BasePart — точка телепорта
    --   MapInfoGui   BillboardGui — видимость (Enabled)
    --   VoteInfoGui  BillboardGui → Container → MapName (TextLabel), Votes (TextLabel)
    --   MapIcon      ImageLabel — иконка карты
    local function parse_votepad(instance)
        local pad    = instance:FindFirstChild("Pad")
        local info   = instance:FindFirstChild("MapInfoGui")
        local vote_g = instance:FindFirstChild("VoteInfoGui")
        local icon   = info  and info:FindFirstChild("MapIcon")
        local cont   = vote_g and vote_g:FindFirstChild("Container")
        local title  = cont  and cont:FindFirstChild("MapName")
        local tally  = cont  and cont:FindFirstChild("Votes")
        if not (pad and info and icon and title and tally) then return nil end
        return { pad=pad, info=info, icon=icon, title=title, tally=tally }
    end

    -- ─── Слежка за VotePads контейнером ────────────────────────
    local function watch_votepad_container(container)
        for _, c in ipairs(pad_conns) do pcall(function() c:Disconnect() end) end
        table.clear(pad_conns)
        table.clear(vote_pads)

        votepad_root = container
        if not container then return end

        for _, child in ipairs(container:GetChildren()) do
            local p = parse_votepad(child)
            if p then
                vote_pads[#vote_pads+1] = p
                pad_conns[#pad_conns+1] = p.info:GetPropertyChangedSignal("Enabled"):Connect(schedule_evaluate)
                pad_conns[#pad_conns+1] = p.title:GetPropertyChangedSignal("Text"):Connect(schedule_evaluate)
                pad_conns[#pad_conns+1] = p.icon:GetPropertyChangedSignal("Image"):Connect(schedule_evaluate)
            end
        end

        schedule_evaluate()
    end

    -- ─── Слежка за Lobby ───────────────────────────────────────
    local function watch_lobby(lobby)
        if lobby_conn then pcall(function() lobby_conn:Disconnect() end); lobby_conn = nil end
        if not lobby then watch_votepad_container(nil); return end

        lobby_conn = lobby.ChildAdded:Connect(function(child)
            if child.Name == "VotePads" then
                task.defer(function() watch_votepad_container(child) end)
            end
        end)
        watch_votepad_container(lobby:FindFirstChild("VotePads"))
    end

    -- ─── GUI ───────────────────────────────────────────────────
    -- t = главный GUI объект (из LPH VM)
    -- Добавляем подменю "maps" если поддерживается, иначе в корень
    local maps_tab = (type(t.AddSub) == "function")
        and t:AddSub({ Name="maps", Icon="map", Tip="map vote" })
        or  t

    local voting_section = maps_tab:AddSection({ Name="voting", Position="full" })

    -- Toggle: auto vote
    local auto_toggle = voting_section:AddToggle({
        Name     = "auto vote",
        Default  = false,
        Flag     = "map_vote_auto",
        Option   = true,
        Callback = function(enabled)
            auto_vote_on = enabled
            if enabled then
                schedule_evaluate()
            else
                stop_vote_session()
            end
        end,
    })

    -- Sub-toggle: dupe
    auto_toggle.Option:AddToggle({
        Name     = "dupe",
        Default  = false,
        Flag     = "map_vote_dupe",
        Callback = function(enabled)
            dupe_mode_on = enabled
            if not enabled then
                -- Отключить respawn/tally сигналы
                for _, c in ipairs({tally_conn, respawn_conn}) do
                    if c then pcall(function() c:Disconnect() end) end
                end
                tally_conn, respawn_conn = nil, nil
            end
        end,
    })

    -- Sub-slider: dupe cap (1–10)
    auto_toggle.Option:AddSlider({
        Name     = "count",
        Default  = 3,
        Min      = 1,
        Max      = 11,
        Flag     = "map_vote_dupe_cap",
        Callback = function(v)
            dupe_cap = math.clamp(math.floor(tonumber(v) or 3), 1, 10)
        end,
    })

    -- ImageList: выбор приоритетных карт
    map_gui_widget = maps_tab:AddImageList({
        Name     = "maps",
        Icon     = "map",
        Position = "full",
        Multi    = true,
        Thumb    = "Asset",
        Height   = 300,
        Cell     = 78,
        Tools    = false,
        Blank    = "map",
        Empty    = "no maps seen yet",
        Values   = map_list,
        Default  = {},
        Flag     = "map_vote_priority",
        Callback = function(val)
            table.clear(priority_set)
            if type(val) == "table" then
                for _, v in ipairs(val) do
                    if type(v) == "string" and v ~= "" then priority_set[v] = true end
                end
            elseif type(val) == "string" and val ~= "" then
                priority_set[val] = true
            end
        end,
    })

    -- ─── Запуск ────────────────────────────────────────────────
    -- Следим за текущим Lobby
    watch_lobby(workspace:FindFirstChild("SummerLobby"))

    -- Следим за появлением нового Lobby
    workspace_conn = workspace.ChildAdded:Connect(function(child)
        if child.Name == "Lobby" then
            task.defer(function() watch_lobby(child) end)
        end
    end)

    -- Загрузить список карт с сервера
    task.spawn(fetch_maps)

    -- ─── Выгрузка ──────────────────────────────────────────────
    getgenv().MAPVOTE_UNLOAD = function()
        script_active  = false
        auto_vote_on   = false
        dupe_mode_on   = false
        stop_vote_session()

        for _, c in ipairs(pad_conns) do
            pcall(function() c:Disconnect() end)
        end
        table.clear(pad_conns)
        table.clear(vote_pads)

        for _, c in ipairs({lobby_conn, workspace_conn}) do
            if c then pcall(function() c:Disconnect() end) end
        end
        lobby_conn, workspace_conn, votepad_root = nil, nil, nil
    end
end)
