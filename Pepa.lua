Сделай local HttpService = game:GetService("HttpService")
local ContentProvider = game:GetService("ContentProvider")

local httpRequest =
    rawget(getfenv(), "request")
    or (syn and syn.request)
    or (http and http.request)
    or (fluxus and fluxus.request)
    or (getgenv and getgenv().request)
if type(httpRequest) ~= "function" then
    httpRequest = function() return nil end
end

local sha256 = {}
do
    local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
    local rrotate, rshift = bit32.rrotate, bit32.rshift
    local char, byte, rep, sub = string.char, string.byte, string.rep, string.sub
    local concat = table.concat
    local floor = math.floor

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

    local function compress(msg)
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
                local x = bxor(rrotate(s0,7), rrotate(s0,18), rshift(s0,3))
                local y = bxor(rrotate(s1,17), rrotate(s1,19), rshift(s1,10))
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
        local function u32(n)
            return char(floor(n/16777216)%256, floor(n/65536)%256, floor(n/256)%256, n%256)
        end
        return u32(h0)..u32(h1)..u32(h2)..u32(h3)..u32(h4)..u32(h5)..u32(h6)..u32(h7)
    end

    function sha256.hash(data)
        return compress(data)
    end
    function sha256.hmac(key, data)
        if #key > 64 then key = compress(key) end
        if #key < 64 then key = key .. rep("\0", 64-#key) end
        local o, i = {}, {}
        for k = 1, 64 do
            local b = byte(key,k)
            o[k] = char(bxor(b,0x5c)); i[k] = char(bxor(b,0x36))
        end
        return compress(concat(o) .. compress(concat(i) .. data))
    end
end

local function b64urlEncode(s)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    local char, byte, sub, floor, concat = string.char, string.byte, string.sub, math.floor, table.concat
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

local function b64decode(s)
    local rev = {}
    local std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for i = 1, #std do rev[string.sub(std,i,i)] = i-1 end
    s = s:gsub("-","+"):gsub("_","/"):gsub("[^A-Za-z0-9+/=]","")
    s = s .. string.rep("=", (4 - #s%4) % 4)
    local out, n = {}, 0
    for i = 1, #s, 4 do
        local c1 = rev[string.sub(s,i,i)] or 0
        local c2 = rev[string.sub(s,i+1,i+1)] or 0
        local c3 = rev[string.sub(s,i+2,i+2)] or 0
        local c4 = rev[string.sub(s,i+3,i+3)] or 0
        local v = c1*262144 + c2*4096 + c3*64 + c4
        n = n + 1; out[n] = string.char(math.floor(v/65536)%256)
        if string.sub(s,i+2,i+2) ~= "=" then n = n + 1; out[n] = string.char(math.floor(v/256)%256) end
        if string.sub(s,i+3,i+3) ~= "=" then n = n + 1; out[n] = string.char(v%256) end
    end
    return table.concat(out)
end

local function hexDecode(s)
    return (s:gsub("..", function(h) return string.char(tonumber(h,16)) end))
end

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

local function urlEncodePath(s)
    return (string.gsub(s, "[^%w%-%._~/]", function(c) return string.format("%%%02X", string.byte(c)) end))
end

local function makeStream(seed)
    local function rd32(pos)
        local a,b,c,d = string.byte(seed,pos,pos+3)
        return d*16777216 + c*65536 + b*256 + a
    end
    local a,b,c,e = rd32(1), rd32(5), rd32(9), rd32(13)
    if a==0 and b==0 and c==0 and e==0 then
        a,b,c,e = 0x9e3779b9,0x243f6a88,0xb7e15162,0x85ebca6b
    end
    local rl, rr, bxor = bit32.lshift, bit32.rshift, bit32.bxor
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

local function shitaroFetch(url, kind, path)
    local nonce = randomBytes(16)
    local stamp = packUInt32BE(os.time())
    local reqSig = sha256.hmac(SHITARO_SEED, "SHITARO-"..kind.."-REQ-v1\0"..path.."\0"..nonce.."\0"..stamp)
    local ok, resp = pcall(httpRequest, {
        Url = url .. urlEncodePath(path),
        Method = "GET",
        Headers = {
            ["X-Shitaro-Token"] = reqSig,
            ["Accept"] = "*/*",
            ["Cache-Control"] = "no-cache",
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
function ShitaroAPI.lib(name)
    return shitaroFetch("https://shitaro.lol/api/library/", "LIB", name)
end
function ShitaroAPI.asset(name)
    return shitaroFetch("https://shitaro.lol/api/assets/", "ASSET", name)
end
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
    Library.Baselines = setmetatable({}, {__mode="k"})
    Library.FadeTokens = setmetatable({}, {__mode="k"})

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
            local selfSize = inst.AbsoluteSize / scale
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

    function Library.Unload()
        for _, c in Library.Connections do pcall(function() c:Disconnect() end) end
        for _, co in Library.Threads do pcall(coroutine.close, co) end
        for _, h in { Library.Holder, Library.PopupHolder, Library.UnusedHolder } do
            if h then h.Instance:Destroy() end
        end
        getgenv().Zolar = nil
    end

    Library.Holder = Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", ZIndexBehavior=Enum.ZIndexBehavior.Global, ResetOnSpawn=false, IgnoreGuiInset=true, DisplayOrder=1000 })
    Library.PopupHolder = Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", ZIndexBehavior=Enum.ZIndexBehavior.Global, ResetOnSpawn=false, IgnoreGuiInset=true, DisplayOrder=1001 })
    Library.UnusedHolder = Library:Create("ScreenGui", { Parent = CoreGui(), Name="\0", Enabled=false, ResetOnSpawn=false })

    do
        local probe = Library:Create("Frame", { Parent = Library.Holder.Instance, Name="\0", BackgroundTransparency=1, Position=UDim2.fromOffset(0,0), Size=UDim2.fromOffset(1,1), BorderSizePixel=0 })
        task.defer(function() GuiInset = -probe.Instance.AbsolutePosition.Y; probe.Instance:Destroy() end)
    end

    Library.UIScale = Library:Create("UIScale", { Parent = Library.Holder.Instance, Scale = 1 })
    Library.PopupScale = Library:Create("UIScale", { Parent = Library.PopupHolder.Instance, Scale = 1 })

    local function addCorner(inst, radius)
        Library:Create("UICorner", { Parent = inst, CornerRadius = UDim.new(0, radius) })
    end
    local function setResting(inst, prop, value)
        inst[prop] = value
        Library:StampResting(inst, prop, value)
    end

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
        if cfg.Raw then
            f.Instance.BackgroundColor3 = cfg.Raw
            f.Instance.BackgroundTransparency = cfg.Alpha or 0
            Library:SetBaseline(f.Instance, "BackgroundTransparency", cfg.Alpha or 0)
        end
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
end
local applyUIScale = function()
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

function Library.SetUIScale(self, v)
    Library.UserScale = v
    Library:CloseAllPopups()
    applyUIScale()
end
applyUIScale()
Library:Connect(workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"), function()
    task.wait()
    applyUIScale()
end)

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
local function retreatUp(ud) return UDim2.fromOffset(ud.X.Offset, ud.Y.Offset - 8) end
local function retreatLeft(ud) return UDim2.fromOffset(ud.X.Offset - 8, ud.Y.Offset) end

local function makePopup(cfg)
    local popup = cfg.Popup
    local frame = cfg.Frame
    local level = cfg.Level
    local place = cfg.Place
    local getAnchor = cfg.GetAnchor
    local fromOff = cfg.From or -6
    local toOff = cfg.To or 6
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
            function() if not item.Selected then Library:Tween({ BackgroundTransparency = 1 }, nil, row.Row.Instance) end end
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
        local isEsc = input.KeyCode == Enum.KeyCode.Escape
        if isBack or isEsc then onDone(nil)
        elseif input.UserInputType == Enum.UserInputType.Keyboard then onDone(input.KeyCode)
        else onDone(input.UserInputType) end
        task.defer(function() Library.Binding = false end)
    end)
end
local function inputMatches(input, key)
    return input.KeyCode == key or input.UserInputType == key
end

function Library.Notification(self, cfg)
    if Library.Silent then return end
    cfg = cfg or {}
    local title = cfg.Name or cfg.Title or "Notification"
    local desc = cfg.Description or cfg.Content or ""
    local icon = cfg.Icon or "bell"
    local color = cfg.Color or Library.Theme.Accent
    local duration = cfg.Duration or 5
    local width = 300
    local bodySize = Vector2.new(0,0)
    if desc ~= "" then bodySize = measureText(desc, 14, width-26, RegularFont) end
    local height = 38 + (desc ~= "" and bodySize.Y + 6 or 0) + 18

    local n = {}
    n.Frame = makeFrame({ Parent=Library.Holder.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,340,0,15), Size=UDim2.fromOffset(width,height), Color="Section", Round=10, Z=80 })
    n.Icon = makeImage({ Parent=n.Frame.Instance, Icon=icon, Pos=UDim2.fromOffset(13,11), Size=UDim2.fromOffset(18,18), Raw=color, Z=81 })
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
        Library:Tween({ Position = UDim2.new(1,-15,0,p.Y.Offset-14) }, info, n.Frame.Instance)
        n.Frame:FadeDescendants(false)
        task.delay(0.3, function()
            local idx = table.find(Library.Notifs, entry)
            if idx then table.remove(Library.Notifs, idx) end
            n.Frame.Instance:Destroy()
            restack()
        end)
    end
    n.CloseHit:Connect("MouseButton1Down", dismiss)
    Library:Tween({ Size = UDim2.new(0,0,1,0) }, TweenInfo.new(duration, Enum.EasingStyle.Linear, Enum.EasingDirection.Out), n.BarFill.Instance)
    task.delay(duration, dismiss)
end

function Library.Window(self, cfg)
    cfg = cfg or {}
    local W, H = Library.WindowWidth, Library.WindowHeight
    local topH = 51
    local railX, railW = 10, 60
    local railH = 340
    local subW = 260
    local subH = 50
    local railTop = topH + railX
    local railY = math.floor((H - railH) / 2)
    local subX = railTop + math.floor((W - subW) / 2)
    local subY = H - math.floor(subH / 2)
    local totalW = railTop + W
    local totalH = subY + subH
    local colW = math.floor((W - 46) / 2)
    local col2X = colW + 16
    local subCenterX = railTop + math.floor(W / 2)
    local maxSubW = W - 120

    local win = {
        Name = cfg.Name or "ZOLAR",
        Icon = cfg.Icon or "layers",
        IsOpen = true, Tabs = {}, Current = nil,
        ContentW = W - 30, ContentH = H - 96,
        ColW = colW, Col2X = col2X, Items = {},
    }
    if cfg.Accent then Library:SetAccent(cfg.Accent) end
    local ui = {}
    local vp = workspace.CurrentCamera.ViewportSize
    local scale = Library:GetScreenScale()
    ui.Root = makeFrame({ Parent=Library.Holder.Instance,
        Pos=UDim2.fromOffset(vp.X/(2*scale) - totalW/2, vp.Y/(2*scale) - totalH/2),
        Size=UDim2.fromOffset(totalW, totalH), Z=1 })
    ui.Main = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(railTop,0), Size=UDim2.fromOffset(W,H), Color="Background", Round=10, Clip=true, Z=1 })
    ui.Rail = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(0,railY), Size=UDim2.fromOffset(railW,railH), Color="Section", Round=10, Z=1 })
    ui.SubBar = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(subX,subY), Size=UDim2.fromOffset(subW,subH), Color="Section", Round=10, Clip=true, Z=20 })
    ui.TopBar = makeFrame({ Parent=ui.Main.Instance, Size=UDim2.fromOffset(W,topH), Color="Section", Round=10, Z=2 })
    makeFrame({ Parent=ui.TopBar.Instance, Pos=UDim2.fromOffset(0,topH-12), Size=UDim2.fromOffset(W,12), Color="Section", Z=2 })
    ui.TopLine = makeFrame({ Parent=ui.Main.Instance, Pos=UDim2.fromOffset(0,50), Size=UDim2.fromOffset(W,1), Color="Element", Z=3 })
    ui.HubIcon = makeImage({ Parent=ui.TopBar.Instance, Icon=win.Icon, Pos=UDim2.fromOffset(10,10), Size=UDim2.fromOffset(30,30), Raw=Color3.new(1,1,1), Fit=true, Z=3 })
    ui.Search = makeFrame({ Parent=ui.TopBar.Instance, Pos=UDim2.fromOffset(50,11), Size=UDim2.fromOffset(280,30), Color="Element", Round=5, Z=3 })
    makeImage({ Parent=ui.Search.Instance, Icon="search", Pos=UDim2.fromOffset(7,7), Size=UDim2.fromOffset(16,16), Color="DimText", Z=4 })
    ui.SearchBox = makeInput({ Parent=ui.Search.Instance, Placeholder="search", Pos=UDim2.fromOffset(30,-1), Size=UDim2.new(1,-38,1,0), TextSize=15, Z=4 })
    ui.Username = makeLabel({ Parent=ui.TopBar.Instance, Text=LocalPlayer.DisplayName, TextSize=15, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-56,0,8), Size=UDim2.fromOffset(240,18), Color="Text", Align=Enum.TextXAlignment.Right, Truncate=true, Z=3 })
    ui.Version = makeFrame({ Parent=ui.TopBar.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-56,0,29), Size=UDim2.fromOffset(36,14), Color="Background", Round=3, Z=3 })
    Library:Create("UIStroke", { Parent=ui.Version.Instance, Color=Library.Theme.Element, Thickness=1 }):AddToTheme({ Color="Element" })
    makeLabel({ Parent=ui.Version.Instance, Text="v"..Library.Version, TextSize=12, Size=UDim2.new(1,0,1,0), Color="DimText", Align=Enum.TextXAlignment.Center, Z=4 })

    local function makeAvatar(parent, cfgA)
        local a = Library:Create("ImageLabel", {
            Parent=parent, Name="\0",
            AnchorPoint=cfgA.Anchor or Vector2.new(0,0), Position=cfgA.Pos,
            Size=UDim2.fromOffset(cfgA.Size,cfgA.Size),
            BackgroundColor3=Library.Theme.Element, ZIndex=cfgA.Z, BorderSizePixel=0,
            Image="rbxthumb://type=AvatarHeadShot&id="..LocalPlayer.UserId.."&w="..cfgA.Res.."&h="..cfgA.Res,
        }):AddToTheme({ BackgroundColor3="Element" })
        addCorner(a.Instance, cfgA.Round)
        return a
    end
    ui.Avatar = makeAvatar(ui.TopBar.Instance, { Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-10,0.5,0), Size=30, Res=60, Round=20, Z=3 })
    ui.ProfileHit = makeButton({ Parent=ui.TopBar.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-4,0,8), Size=UDim2.fromOffset(42,36), Z=5 })

    local profilePopup = { IsOpen=false, Debounce=false }
    local profileW = 240
    local profile = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(profileW,272), Color="Section", Round=10, Z=45 })
    profile.Instance.Visible = false
    makeAvatar(profile.Instance, { Pos=UDim2.fromOffset(14,14), Size=42, Res=100, Round=21, Z=46 })
    makeLabel({ Parent=profile.Instance, Text=LocalPlayer.DisplayName, TextSize=15, Pos=UDim2.fromOffset(68,16), Size=UDim2.fromOffset(profileW-82,20), Color="Text", Truncate=true, Z=46 })
    makeLabel({ Parent=profile.Instance, Text="@"..LocalPlayer.Name, TextSize=13, Pos=UDim2.fromOffset(68,37), Size=UDim2.fromOffset(profileW-82,16), Color="DimText", Truncate=true, Z=46 })
    local function divider(y) makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,y), Size=UDim2.fromOffset(profileW-28,1), Color="Element", Z=46 }) end
    local function infoRow(y, label, value)
        makeLabel({ Parent=profile.Instance, Text=label, TextSize=14, Pos=UDim2.fromOffset(14,y), Size=UDim2.fromOffset(100,18), Color="DimText", Z=46 })
        makeLabel({ Parent=profile.Instance, Text=value, TextSize=14, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-14,0,y), Size=UDim2.fromOffset(120,18), Color="Text", Align=Enum.TextXAlignment.Right, Truncate=true, Z=46 })
    end
    divider(68)
    infoRow(79, "User ID", tostring(LocalPlayer.UserId))
    infoRow(105, "Account age", tostring(LocalPlayer.AccountAge).." days")
    local idHit = makeButton({ Parent=profile.Instance, Pos=UDim2.fromOffset(10,76), Size=UDim2.fromOffset(profileW-20,24), Z=47 })
    idHit:Connect("MouseButton1Down", function()
        if setclipboard then pcall(setclipboard, tostring(LocalPlayer.UserId)) end
        Library:Notification({ Name="User ID copied", Description="Your user id is now in the clipboard.", Icon="copy", Duration=3 })
    end)
    local refreshProfile
    divider(134)
    makeLabel({ Parent=profile.Instance, Text="Interface scale", TextSize=14, Pos=UDim2.fromOffset(14,146), Size=UDim2.fromOffset(140,18), Color="DimText", Z=46 })
    local scaleLabel = makeLabel({ Parent=profile.Instance, Text="100%", TextSize=14, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-14,0,146), Size=UDim2.fromOffset(60,18), Color="Text", Align=Enum.TextXAlignment.Right, Z=46 })
    local scaleTrack = makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,172), Size=UDim2.fromOffset(profileW-28,8), Color="Light", Round=20, Z=46 })
    local scaleFill = makeFrame({ Parent=scaleTrack.Instance, Size=UDim2.new(0.5,0,1,0), Raw=Color3.new(1,1,1), Round=20, Z=47 })
    Library:RegisterGradient(Library:Create("UIGradient", { Parent=scaleFill.Instance }).Instance)
    local scaleKnob = makeFrame({ Parent=scaleTrack.Instance, Anchor=Vector2.new(0.5,0.5), Pos=UDim2.new(0.5,0,0.5,0), Size=UDim2.fromOffset(12,12), Raw=Color3.fromRGB(197,197,197), Round=20, Z=48 })
    local scaleHit = makeButton({ Parent=profile.Instance, Pos=UDim2.fromOffset(8,166), Size=UDim2.fromOffset(profileW-16,22), Z=49 })
    local draggingScale, pendingScale = false, 100
    local function updateScale(input)
        local track = scaleTrack.Instance
        local ratio = math.clamp((input.Position.X - track.AbsolutePosition.X) / track.AbsoluteSize.X, 0, 1)
        pendingScale = Library:Round(50 + ratio*100, 5)
        local r = (pendingScale-50)/100
        scaleLabel.Instance.Text = tostring(pendingScale).."%"
        scaleFill.Instance.Size = UDim2.new(r,0,1,0)
        scaleKnob.Instance.Position = UDim2.new(r,0,0.5,0)
    end
    scaleHit:Connect("InputBegan", function(input)
        local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch
        if not ok then return end
        draggingScale = true
        updateScale(input)
    end)
    Library:Connect(UserInput.InputEnded, function(input)
        local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch
        if ok and draggingScale then
            draggingScale = false
            Library.UserScale = pendingScale / 100
            applyUIScale()
            if refreshProfile then refreshProfile() end
        end
    end)
    Library:Connect(UserInput.InputChanged, function(input)
        local move = input.UserInputType == Enum.UserInputType.MouseMovement
                  or input.UserInputType == Enum.UserInputType.Touch
        if move and draggingScale then updateScale(input) end
    end)
    makeLabel({ Parent=profile.Instance, Text="Menu toggle", TextSize=14, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,14,0,205), Size=UDim2.fromOffset(110,20), Color="DimText", Z=46 })
    local cmdIcon = makeImage({ Parent=profile.Instance, Icon="command", Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-14,0,205), Size=UDim2.fromOffset(16,16), Color="DimText", Z=46 })
    local cmdHit = makeButton({ Parent=profile.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-8,0,205), Size=UDim2.fromOffset(26,26), Z=48 })
    cmdHit:OnHover(
        function() cmdIcon:Tween({ ImageColor3 = Library.Theme.Text }) end,
        function() cmdIcon:Tween({ ImageColor3 = Library.Theme.DimText }) end
    )
    local keybindPopup = { IsOpen=false, Debounce=false, Picking=false, Host=profilePopup }
    local keybindW = 170
    local keybindFrame = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(keybindW,72), Color="Section", Round=8, Z=46 })
    keybindFrame.Instance.Visible = false
    makeLabel({ Parent=keybindFrame.Instance, Text="Menu keybind", TextSize=12, Pos=UDim2.fromOffset(11,8), Size=UDim2.fromOffset(keybindW-22,14), Color="DimText", Truncate=true, Z=47 })
    local kbBox = makeFrame({ Parent=keybindFrame.Instance, Pos=UDim2.fromOffset(9,32), Size=UDim2.fromOffset(keybindW-18,30), Color="Light", Round=5, Clip=true, Z=47 })
    local kbLabel = makeLabel({ Parent=kbBox.Instance, Text=keyName(Library.MenuKeybind), TextSize=13, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Truncate=true, Z=48 })
    local kbHit = makeButton({ Parent=kbBox.Instance, Z=49 })
    local function anchorCmdKeybind(offsetY)
        local g = cmdIcon.Instance
        local scale = Library:GetScreenScale()
        local x = (g.AbsolutePosition.X + g.AbsoluteSize.X) / scale + 8 + (offsetY or 0)
        local y = (g.AbsolutePosition.Y + GuiInset) / scale - 4
        return UDim2.fromOffset(x, y)
    end
    makePopup({ Popup=keybindPopup, Frame=keybindFrame, Level=46, GetAnchor=function() return cmdHit.Instance end,
        Place=anchorCmdKeybind, From=-6, To=2, Retreat=retreatLeft })
    cmdHit:Connect("MouseButton1Down", function() keybindPopup:SetOpen(not keybindPopup.IsOpen) end)
    kbHit:Connect("MouseButton1Click", function()
        if keybindPopup.Picking then return end
        keybindPopup.Picking = true
        Library.Binding = true
        kbLabel.Instance.Text = ". . ."
        task.wait()
        local conn
        conn = UserInput.InputBegan:Connect(function(input)
            if input.UserInputType ~= Enum.UserInputType.Keyboard then return end
            conn:Disconnect()
            if input.KeyCode ~= Enum.KeyCode.Escape then Library.MenuKeybind = input.KeyCode end
            kbLabel.Instance.Text = keyName(Library.MenuKeybind)
            keybindPopup.Picking = false
            task.defer(function() Library.Binding = false end)
        end)
    end)

    local unloadBtn = makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,236), Size=UDim2.fromOffset(profileW-28,28), Color="Light", Round=6, Clip=true, Z=46 })
    makeLabel({ Parent=unloadBtn.Instance, Text="Unload", TextSize=14, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Z=47 })
    local unloadHit = makeButton({ Parent=unloadBtn.Instance, Z=48 })
    unloadBtn:OnHover(
        function() unloadBtn:Tween({ BackgroundColor3 = Library.Theme.Hover }) end,
        function() unloadBtn:Tween({ BackgroundColor3 = Library.Theme.Light }) end
    )
    unloadHit:Connect("MouseButton1Down", function()
        profilePopup:SetOpen(false)
        task.delay(Library.Animation.Time + 0.12, function() Library:Unload() end)
    end)

    local function anchorProfile(offsetY)
        local g = ui.Avatar.Instance
        local scale = Library:GetScreenScale()
        local x = (g.AbsolutePosition.X + g.AbsoluteSize.X) / scale - profileW
        local y = (g.AbsolutePosition.Y + g.AbsoluteSize.Y + GuiInset) / scale + (offsetY or 0)
        return UDim2.fromOffset(x, y)
    end
    refreshProfile = function()
        if profilePopup.IsOpen then profile.Instance.Position = anchorProfile(10) end
    end
    makePopup({ Popup=profilePopup, Frame=profile, Level=45, GetAnchor=function() return ui.ProfileHit.Instance end,
        Place=anchorProfile, From=-2, To=10, HoldOpen=function() return keybindPopup.IsOpen end })
    win.Profile = profilePopup
    ui.ProfileHit:Connect("MouseButton1Down", function() profilePopup:SetOpen(not profilePopup.IsOpen) end)

    ui.Content = makeFrame({ Parent=ui.Main.Instance, Pos=UDim2.fromOffset(15,65), Size=UDim2.fromOffset(W-30,H-96), Clip=true, Z=2 })
    win.Items = ui
    ui.Root:MakeDraggable(ui.Main.Instance)
    ui.Root:MakeDraggable(ui.Rail.Instance)
    table.insert(Library.Windows, win)

    function win:Center()
        local s = Library:GetScreenScale()
        local v = workspace.CurrentCamera.ViewportSize
        ui.Root.Instance.Position = UDim2.fromOffset(v.X/(2*s) - totalW/2, v.Y/(2*s) - totalH/2)
    end
    function win:LayoutRail()
        local n = #win.Tabs
        local h = n > 0 and (50*n + 10) or railH
        local y = math.floor((H - h) / 2)
        ui.Rail.Instance.Size = UDim2.fromOffset(railW, h)
        ui.Rail.Instance.Position = UDim2.fromOffset(0, y)
    end
    function win:FitSubBar(instant)
        local tab = win.Current
        if not tab or not tab.SubLayout then return end
        if #tab.Subs == 0 then return end
        local s = Library:GetScreenScale()
        local contentW = tab.SubLayout.AbsoluteContentSize.X / s + 16
        if contentW <= 16 then return end
        local overflow = contentW > maxSubW
        local w = math.min(contentW, maxSubW)
        local x = subCenterX - math.floor(w/2)
        local info = instant and TweenInfo.new(0) or TweenInfo.new(0.24, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        Library:Tween({ Position = UDim2.fromOffset(x, subY), Size = UDim2.fromOffset(w, subH) }, info, ui.SubBar.Instance)
        local scroll = tab.Items.SubRow.Instance
        scroll.ScrollingEnabled = overflow
        scroll.ScrollBarThickness = overflow and 3 or 0
    end
    function win:LayoutSubBar(instant) win:FitSubBar(instant) end
    function win:SetOpen(open)
        self.IsOpen = open
        if not open then Library:CloseAllPopups() end
        local sub = self.Current and self.Current.Current
        if sub and sub.SnapVisible then sub:SnapVisible() end
        if open and self.PlayIntro then self:PlayIntro()
        else ui.Root:FadeDescendants(open) end
    end

    Library:Connect(UserInput.InputBegan, function(input, processed)
        if processed or Library.Binding then return end
        if input.KeyCode == Library.MenuKeybind then win:SetOpen(not win.IsOpen) end
    end)

    local function doSearch(query)
        query = string.lower(query)
        for _, item in Library.Searchables do
            if item.Window ~= win then continue end
            local match = query == ""
                       or string.find(string.lower(item.Name), query, 1, true) ~= nil
            if not match and item.Section then
                match = string.find(string.lower(item.Section.Name), query, 1, true) ~= nil
            end
            item.Visible = match
            if item.Section then item.Section.Dirty = true end
        end
        for _, tab in win.Tabs do
            for _, sub in tab.Subs do
                for _, section in sub.Sections do
                    if section.Dirty then
                        section.Dirty = false
                        section:Reflow()
                    end
                end
            end
        end
        local sub = win.Current and win.Current.Current
        if sub and #sub.Sections > 0 then
            local sig = tostring(sub)
            for _, section in sub.Sections do
                for _, row in section.Rows do
                    sig ..= (row.Visible ~= false) and "1" or "0"
                end
            end
            if sig ~= win.SearchSig then
                win.SearchSig = sig
                sub:Show()
            end
        end
    end
    local searchDebounce = 0
    Library:Connect(ui.SearchBox.Instance:GetPropertyChangedSignal("Text"), function()
        searchDebounce += 1
        local ticket = searchDebounce
        task.delay(0.1, function()
            if ticket ~= searchDebounce then return end
            doSearch(ui.SearchBox.Instance.Text)
        end)
    end)

    function win:PlayIntro()
        local resting = ui.Root.Instance.Position
        ui.Root.Instance.Position = UDim2.fromOffset(resting.X.Offset, resting.Y.Offset + 24)
        ui.Root:FadeDescendants(true)
        Library:Tween({ Position = resting }, TweenInfo.new(0.5, Enum.EasingStyle.Quint, Enum.EasingDirection.Out), ui.Root.Instance)
    end
    task.defer(function() win:PlayIntro() end)
    return setmetatable(win, Library)
end

function Library.Tab(self, cfg)
    cfg = cfg or {}
    local win = self
    local tab = {
        Name = cfg.Name or "Tab", Icon = cfg.Icon or "circle",
        Window = win, Subs = {}, Current = nil, Active = false, Items = {},
    }
    local ui = {}
    local y = 10 + #win.Tabs * 50
    ui.Row = makeFrame({ Parent=win.Items.Rail.Instance, Pos=UDim2.fromOffset(10,y), Size=UDim2.fromOffset(40,40), Color="Element", Round=8, Clip=true, Z=3 })
    setResting(ui.Row.Instance, "BackgroundTransparency", 1)
    ui.Bar = makeFrame({ Parent=win.Items.Rail.Instance, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,0,0,y+20), Size=UDim2.fromOffset(3,0), Color="Accent", Round=4, Z=4 })
    ui.BarShadow = makeShadow(ui.Bar.Instance, Library.Theme.Accent, UDim2.fromOffset(3,15), UDim.new(0,10), 0)
    if ui.BarShadow then setResting(ui.BarShadow, "Transparency", 1) end
    ui.Icon = makeImage({ Parent=ui.Row.Instance, Icon=tab.Icon, Pos=UDim2.fromOffset(10,10), Size=UDim2.fromOffset(20,20), Color="DimIcon", Z=4 })
    ui.Hit = makeButton({ Parent=ui.Row.Instance, Z=6 })
    ui.SubRow = Library:Create("ScrollingFrame", {
        Parent=win.Items.SubBar.Instance, Name="\0", BackgroundTransparency=1,
        ScrollBarThickness=0, ScrollBarImageColor3=Library.Theme.Accent,
        ScrollingDirection=Enum.ScrollingDirection.X, ScrollingEnabled=false, Selectable=false, Active=true,
        AutomaticCanvasSize=Enum.AutomaticSize.X, CanvasSize=UDim2.fromOffset(0,0),
        Size=UDim2.new(1,0,1,0), ZIndex=21, BorderSizePixel=0,
    }):AddToTheme({ ScrollBarImageColor3="Accent" })
    ui.SubRow.Instance.Visible = false
    ui.SubLayout = Library:Create("UIListLayout", {
        Parent=ui.SubRow.Instance, FillDirection=Enum.FillDirection.Horizontal,
        HorizontalAlignment=Enum.HorizontalAlignment.Left, VerticalAlignment=Enum.VerticalAlignment.Center,
        SortOrder=Enum.SortOrder.LayoutOrder, Padding=UDim.new(0,6),
    })
    Library:Create("UIPadding", { Parent=ui.SubRow.Instance, PaddingLeft=UDim.new(0,8), PaddingRight=UDim.new(0,8) })
    win.Items.Root:MakeDraggable(ui.SubRow.Instance)
    tab.SubLayout = ui.SubLayout.Instance
    Library:Connect(tab.SubLayout:GetPropertyChangedSignal("AbsoluteContentSize"), function()
        if win.Current == tab then win:FitSubBar(true) end
    end)
    tab.Items = ui

    function tab:SetVisual(active)
        self.Active = active
        Library:StampResting(ui.Row.Instance, "BackgroundTransparency", active and 0 or 1)
        if ui.BarShadow then
            Library:StampResting(ui.BarShadow, "Transparency", active and 0 or 1)
            ui.BarShadow.Transparency = active and 0 or 1
        end
        ui.Icon:ChangeItemTheme({ ImageColor3 = active and "Accent" or "DimIcon" })
        ui.Icon:Tween({ ImageColor3 = active and Library.Theme.Accent or Library.Theme.DimIcon })
        ui.Row:Tween({ BackgroundTransparency = active and 0 or 1 })
        ui.Bar:Tween({ Size = UDim2.fromOffset(3, active and 16 or 0) })
    end
    ui.Row:OnHover(
        function() if not tab.Active then ui.Icon:Tween({ ImageColor3 = Library.Theme.Text }) end end,
        function() if not tab.Active then ui.Icon:Tween({ ImageColor3 = Library.Theme.DimIcon }) end end
    )
    local function syncCurrent()
        local sub = tab.Current or tab.Subs[1]
        if not sub then return end
        tab.Current = sub
        for _, s in tab.Subs do s:SetVisual(s == sub) end
        sub:Show()
    end
    function tab:Select()
        if win.Current == tab then return end
        Library:CloseAllPopups()
        if win.Current then
            win.Current:SetVisual(false)
            win.Current.Items.SubRow.Instance.Visible = false
            if win.Current.Current then win.Current.Current:Hide() end
        end
        win.Current = tab
        tab:SetVisual(true)
        ui.SubRow.Instance.Visible = true
        syncCurrent()
        win:LayoutSubBar()
    end
    ui.Hit:Connect("MouseButton1Down", function() tab:Select() end)
    table.insert(win.Tabs, tab)
    win:LayoutRail()
    if #win.Tabs == 1 then
        win.Current = tab
        tab:SetVisual(true)
        ui.SubRow.Instance.Visible = true
        task.defer(function() syncCurrent(); win:LayoutSubBar() end)
    end
    return setmetatable(tab, Library)
end

function Library.SubTab(self, cfg)
    cfg = cfg or {}
    local parentTab = self
    local win = parentTab.Window
    local sub = {
        Name = cfg.Name or "SubTab", Icon = cfg.Icon or "circle",
        Tab = parentTab, Window = win, Sections = {}, Columns = {}, Active = false,
        ShowToken = 0, Items = {},
    }
    local ui = {}
    local contentW, contentH = win.ContentW, win.ContentH
    local colW, col2X = win.ColW, win.Col2X
    local labelW = math.ceil(measureText(sub.Name, 15, 300, RegularFont).X)
    local collapsedW = 40
    local expandedW = 37 + labelW + 12
    sub.CollapsedW, sub.ExpandedW = collapsedW, expandedW

    ui.Pill = makeFrame({ Parent=parentTab.Items.SubRow.Instance, Size=UDim2.fromOffset(collapsedW,30), Color="Element", Round=5, Clip=true, Z=22 })
    setResting(ui.Pill.Instance, "BackgroundTransparency", 1)
    ui.Pill.Instance.LayoutOrder = #parentTab.Subs
    ui.Icon = makeImage({ Parent=ui.Pill.Instance, Icon=sub.Icon, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,11,0.5,0), Size=UDim2.fromOffset(18,18), Color="DimIcon", Z=23 })
    ui.Label = makeLabel({ Parent=ui.Pill.Instance, Text=sub.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,37,0.5,0), Size=UDim2.fromOffset(labelW+8,20), Color="Text", Z=23 })
    setResting(ui.Label.Instance, "TextTransparency", 1)
    local function fitPill()
        local w = math.ceil(ui.Label.Instance.TextBounds.X)
        if w <= 0 then return end
        expandedW = 37 + w + 12
        sub.ExpandedW = expandedW
        ui.Label.Instance.Size = UDim2.fromOffset(w+8,20)
        if parentTab.Current == sub then
            ui.Pill.Instance.Size = UDim2.fromOffset(expandedW,30)
            win:FitSubBar(true)
        end
    end
    Library:Connect(ui.Label.Instance:GetPropertyChangedSignal("TextBounds"), fitPill)
    task.defer(fitPill)
    ui.Hit = makeButton({ Parent=ui.Pill.Instance, Z=25 })
    ui.Page = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(contentW,contentH), Z=3 })
    ui.Page.Instance.Visible = false

    local function makeColumn(x)
        local scroll = Library:Create("ScrollingFrame", {
            Parent=ui.Page.Instance, Name="\0", BackgroundTransparency=1,
            ScrollBarThickness=0, ScrollBarImageTransparency=1, Selectable=false, Active=true,
            Position=UDim2.fromOffset(x,0), Size=UDim2.fromOffset(colW,contentH),
            CanvasSize=UDim2.fromOffset(0,0), ZIndex=3, BorderSizePixel=0,
        })
        local col = { Scroll=scroll, Width=colW, Sections={} }
        function col:Reflow()
            local y = 0
            for _, sec in self.Sections do
                sec.Y = y
                sec.Items.Holder.Instance.Position = UDim2.fromOffset(0,y)
                y += sec.Height + 16
            end
            scroll.Instance.CanvasSize = UDim2.fromOffset(0, math.max(y-16,0))
        end
        return col
    end
    sub.Columns[1] = makeColumn(0)
    sub.Columns[2] = makeColumn(col2X)
    sub.Items = ui

    function sub:SetVisual(active, instant)
        Library:StampResting(ui.Pill.Instance, "BackgroundTransparency", active and 0 or 1)
        Library:StampResting(ui.Label.Instance, "TextTransparency", active and 0 or 1)
        local info = instant and TweenInfo.new(0) or TweenInfo.new(0.28, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local w = active and expandedW or collapsedW
        Library:Tween({ Size = UDim2.fromOffset(w,30) }, info, ui.Pill.Instance)
        Library:Tween({ TextTransparency = active and 0 or 1 }, info, ui.Label.Instance)
        ui.Icon:ChangeItemTheme({ ImageColor3 = active and "Accent" or "DimIcon" })
        ui.Icon:Tween({ ImageColor3 = active and Library.Theme.Accent or Library.Theme.DimIcon }, info)
        ui.Pill:Tween({ BackgroundTransparency = active and 0 or 1 }, info)
    end
    ui.Pill:OnHover(
        function() if parentTab.Current ~= sub then ui.Icon:Tween({ ImageColor3 = Library.Theme.Text }) end end,
        function() if parentTab.Current ~= sub then ui.Icon:Tween({ ImageColor3 = Library.Theme.DimIcon }) end end
    )

    local rowSlide = TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
    local rowX = 18
    local staggerSection = 0.07
    local staggerRow = 0.045

    local function eachSectionRow(fn)
        for _, col in sub.Columns do
            for _, sec in col.Sections do
                for _, row in sec.Rows do fn(row, sec) end
            end
        end
    end
    local function cancelAllMoves()
        eachSectionRow(function(row)
            if row.Move then pcall(function() row.Move:Cancel() end) end
            row.Move = nil
        end)
    end
    local function resetSections()
        for _, col in sub.Columns do
            for _, sec in col.Sections do
                sec.Items.Holder.Instance.Position = UDim2.fromOffset(0, sec.Y)
                sec.Items.Frame.Instance.Position = UDim2.fromOffset(0,26)
                for _, row in sec.Rows do
                    row.Frame:CancelFade()
                    row.Frame.Instance.Visible = row.Visible ~= false
                end
            end
        end
    end
    local function snapPage()
        ui.Page.Instance.Position = UDim2.fromOffset(0,0)
        ui.Page:HardRestore()
        resetSections()
        eachSectionRow(function(row) row.Frame.Instance.Position = UDim2.fromOffset(0, row.Y) end)
    end

    function sub:Show()
        self.ShowToken += 1
        local token = self.ShowToken
        self.Active = true
        cancelAllMoves()
        ui.Page:CancelFade()
        ui.Page:HardRestore()
        for _, tab in win.Tabs do
            for _, other in tab.Subs do
                if other ~= sub and other.Items and other.Items.Page then
                    local page = other.Items.Page.Instance
                    if page.Parent ~= Library.UnusedHolder.Instance then
                        other.Active = false
                        other.ShowToken += 1
                        page.Visible = false
                        page.Parent = Library.UnusedHolder.Instance
                    end
                end
            end
        end
        ui.Page.Instance.Parent = win.Items.Content.Instance
        ui.Page.Instance.Position = UDim2.fromOffset(0,0)
        ui.Page.Instance.Visible = true
        Library:SafeCall(self.PageIntro)
        if #self.Sections == 0 then return end
        resetSections()
        local secIndex = 0
        for _, col in self.Columns do
            for _, sec in col.Sections do
                secIndex += 1
                local idx = secIndex
                for _, row in sec.Rows do
                    row.Frame:CancelFade()
                    row.Frame.Instance.Visible = false
                end
                task.delay((idx-1)*staggerSection, function()
                    if self.ShowToken ~= token or not self.Active then return end
                    sec.Frame:FadeDescendants(true)
                    for i, row in sec.Rows do
                        if row.Visible == false then continue end
                        task.delay(i*staggerRow, function()
                            local resting = UDim2.fromOffset(0, row.Y)
                            row.Frame.Instance.Visible = true
                            if self.ShowToken ~= token or not self.Active then
                                row.Frame.Instance.Position = resting
                                return
                            end
                            row.Frame.Instance.Position = UDim2.fromOffset(rowX, row.Y)
                            row.Move = Library:Tween({ Position = resting }, rowSlide, row.Frame.Instance)
                            row.Frame:FadeDescendants(true)
                        end)
                    end
                end)
            end
        end
    end
    function sub:Hide(onDone)
        self.Active = false
        self.ShowToken += 1
        Library:SafeCall(self.PageOutro)
        cancelAllMoves()
        ui.Page:CancelFade()
        ui.Page:ResetFade()
        snapPage()
        ui.Page.Instance.Visible = false
        ui.Page.Instance.Parent = Library.UnusedHolder.Instance
        if onDone then Library:SafeCall(onDone) end
    end
    function sub:SnapVisible()
        self.ShowToken += 1
        self.Active = true
        cancelAllMoves()
        ui.Page:CancelFade()
        snapPage()
        ui.Page.Instance.Visible = true
    end
    ui.Hit:Connect("MouseButton1Down", function()
        if parentTab.Current == sub then return end
        Library:CloseAllPopups()
        if parentTab.Current then
            parentTab.Current:SetVisual(false)
            parentTab.Current:Hide()
        end
        parentTab.Current = sub
        sub:SetVisual(true)
        sub:Show()
        win:LayoutSubBar()
    end)
    table.insert(parentTab.Subs, sub)
    if #parentTab.Subs == 1 then
        parentTab.Current = sub
        sub:SetVisual(true, true)
    end
    if win.Current == parentTab then win:LayoutSubBar() end
    return setmetatable(sub, Library)
end

function Library.Section(self, cfg)
    cfg = cfg or {}
    local sub = self
    local side = cfg.Side or 1
    if side == "Right" then side = 2 end
    if side == "Left" then side = 1 end
    local col = sub.Columns[side] or sub.Columns[1]
    local section = {
        Name = cfg.Name or "Section", SubTab = sub, Column = col,
        Width = col.Width, Y = 0, Height = 0, Rows = {}, Dirty = false, Items = {},
    }
    local ui = {}
    ui.Holder = makeFrame({ Parent=col.Scroll.Instance, Size=UDim2.fromOffset(col.Width,40), Z=3 })
    local labelW = math.ceil(measureText(section.Name, 15, 240, RegularFont).X)
    local headerW = labelW + 26
    ui.Header = makeFrame({ Parent=ui.Holder.Instance, Pos=UDim2.fromOffset(0,1), Size=UDim2.fromOffset(headerW,25), Color="Section", Round=10, Z=3 })
    ui.HeaderFill = makeFrame({ Parent=ui.Header.Instance, Pos=UDim2.fromOffset(0,15), Size=UDim2.fromOffset(headerW,10), Color="Section", Z=3 })
    ui.Label = makeLabel({ Parent=ui.Header.Instance, Text=section.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,13,0.5,1), Size=UDim2.fromOffset(labelW+6,20), Color="Text", Z=4 })
    local function fitHeader()
        local w = math.ceil(ui.Label.Instance.TextBounds.X)
        if w <= 0 then return end
        labelW = w; headerW = w + 26
        ui.Label.Instance.Size = UDim2.fromOffset(w+6,20)
        ui.Header.Instance.Size = UDim2.fromOffset(headerW,25)
        ui.HeaderFill.Instance.Size = UDim2.fromOffset(headerW,10)
    end
    Library:Connect(ui.Label.Instance:GetPropertyChangedSignal("TextBounds"), fitHeader)
    task.defer(fitHeader)
    ui.Frame = makeFrame({ Parent=ui.Holder.Instance, Pos=UDim2.fromOffset(0,26), Size=UDim2.fromOffset(col.Width,14), Color="Section", Round=10, Z=3 })
    ui.BodyFill = makeFrame({ Parent=ui.Frame.Instance, Pos=UDim2.fromOffset(0,0), Size=UDim2.fromOffset(10,10), Color="Section", Z=3 })
    section.Items = ui

    function section:Reflow()
        local pad = 8
        local y = pad
        local visibleCount = 0
        for _, row in self.Rows do
            local vis = row.Visible ~= false
            row.Frame.Instance.Visible = vis
            if not vis then continue end
            row.Y = y
            row.Frame.Instance.Position = UDim2.fromOffset(0, y)
            y += row.Height
            visibleCount += 1
        end
        local bodyH = visibleCount > 0 and (y + 8) or 0
        ui.Frame.Instance.Size = UDim2.fromOffset(section.Width, bodyH)
        ui.Holder.Instance.Visible = visibleCount > 0
        section.Height = visibleCount > 0 and (26 + bodyH) or 0
        ui.Holder.Instance.Size = UDim2.fromOffset(section.Width, math.max(section.Height,1))
        col:Reflow()
    end
    function section:AddRow(height, name)
        local frame = makeFrame({ Parent=ui.Frame.Instance, Size=UDim2.fromOffset(section.Width, height), Z=4 })
        local row = {
            Frame = frame, Height = height, Y = 0, Visible = true,
            Name = name or section.Name, Section = section, Window = sub.Window,
        }
        table.insert(section.Rows, row)
        table.insert(Library.Searchables, row)
        section:Reflow()
        return frame, row
    end
    table.insert(sub.Sections, section)
    table.insert(col.Sections, section)
    section:Reflow()
    return setmetatable(section, Library)
end

function Library.Toggle(self, cfg)
    cfg = cfg or {}
    local section = self
    local toggle = {
        Name = cfg.Name or "Toggle", Default = cfg.Default or false, Flag = cfg.Flag,
        Callback = cfg.Callback or function() end, Value = false, Visual = nil, Token = 0, Items = {},
    }
    local row = section:AddRow(32, toggle.Name)
    local ui = { Row = row }
    ui.Label = makeLabel({ Parent=row.Instance, Text=toggle.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,15,0.5,0), Size=UDim2.fromOffset(section.Width-80,20), Color="DimText", Truncate=true, Z=5 })
    ui.Box = makeFrame({ Parent=row.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-15,0.5,0), Size=UDim2.fromOffset(35,21), Color="Element", Round=10, Clip=true, Z=5 })
    ui.Circle = makeFrame({ Parent=ui.Box.Instance, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,4,0.5,0), Size=UDim2.fromOffset(13,13), Color="DimText", Round=20, Z=6 })
    makeShadow(ui.Circle.Instance, Library.Theme.Accent, UDim2.fromOffset(3,3), UDim.new(0,5), 0.7)
    ui.Hit = makeButton({ Parent=row.Instance, Size=UDim2.new(1,0,1,0), Z=8 })
    toggle.Items = ui

    local pad = 4
    local stretchW = 35 - pad*2
    local offPos = UDim2.new(0,pad,0.5,0)
    local onPos = UDim2.new(1,-pad,0.5,0)
    local knobSize = UDim2.fromOffset(13,13)

    function toggle.SetVisual(active, instant)
        active = active and true or false
        if toggle.Visual == active then return end
        toggle.Visual = active
        toggle.Token += 1
        local token = toggle.Token
        if toggle.GrowTween then pcall(function() toggle.GrowTween:Cancel() end) end
        if toggle.SnapTween then pcall(function() toggle.SnapTween:Cancel() end) end
        toggle.GrowTween, toggle.SnapTween = nil, nil
        local boxColor = active and "Light" or "Element"
        local knobColor = active and "Accent" or "DimText"
        local textColor = active and "Text" or "DimText"
        local anchor = active and Vector2.new(0,0.5) or Vector2.new(1,0.5)
        local pos = active and onPos or offPos
        local finalAnchor = active and Vector2.new(1,0.5) or Vector2.new(0,0.5)
        local finalPos = active and offPos or onPos
        ui.Box:ChangeItemTheme({ BackgroundColor3 = boxColor })
        ui.Label:ChangeItemTheme({ TextColor3 = textColor })
        ui.Circle:ChangeItemTheme({ BackgroundColor3 = knobColor })
        local accentColor = Library.Theme[knobColor]
        if instant then
            ui.Box.Instance.BackgroundColor3 = Library.Theme[boxColor]
            ui.Label.Instance.TextColor3 = Library.Theme[textColor]
            ui.Circle.Instance.BackgroundColor3 = accentColor
            ui.Circle.Instance.Size = knobSize
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            return
        end
        local growInfo = TweenInfo.new(0.14, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local snapInfo = TweenInfo.new(0.16, Enum.EasingStyle.Back, Enum.EasingDirection.Out)
        local colorInfo = TweenInfo.new(0.2, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        Library:Tween({ BackgroundColor3 = Library.Theme[boxColor] }, colorInfo, ui.Box.Instance)
        Library:Tween({ TextColor3 = Library.Theme[textColor] }, colorInfo, ui.Label.Instance)
        Library:Tween({ BackgroundColor3 = accentColor }, colorInfo, ui.Circle.Instance)
        ui.Circle.Instance.AnchorPoint = anchor
        ui.Circle.Instance.Position = pos
        toggle.GrowTween = Library:Tween({ Size = UDim2.fromOffset(stretchW,13) }, growInfo, ui.Circle.Instance)
        task.delay(0.08, function()
            if toggle.Token ~= token then return end
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            toggle.SnapTween = Library:Tween({ Size = knobSize }, snapInfo, ui.Circle.Instance)
        end)
        task.delay(0.3, function()
            if toggle.Token ~= token then return end
            if ui.Circle.Instance.Size == knobSize then return end
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            ui.Circle.Instance.Size = knobSize
        end)
    end
    function toggle:Set(value)
        self.Value = value and true or false
        if self.Flag then Library.Flags[self.Flag] = self.Value end
        self.SetVisual(self.Value, false)
        Library:SafeCall(self.Callback, self.Value)
    end
    function toggle:Get() return self.Value end
    ui.Hit:Connect("MouseButton1Down", function() toggle:Set(not toggle.Value) end)

    toggle.SlotX = -58
    local function reserveSlot(w)
        local slot = toggle.SlotX
        toggle.SlotX -= w + 8
        ui.Label.Instance.Size = UDim2.fromOffset(section.Width + toggle.SlotX - 15, 20)
        return slot
    end

    local function makeSideIcon(slotX, icon)
        local img = makeImage({ Parent=row.Instance, Icon=icon, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,slotX,0.5,0), Size=UDim2.fromOffset(16,16), Color="DimText", Z=6 })
        local hit = makeButton({ Parent=row.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,slotX+2,0.5,0), Size=UDim2.fromOffset(22,22), Z=9 })
        hit:OnHover(
            function() img:Tween({ ImageColor3 = Library.Theme.Text }) end,
            function() img:Tween({ ImageColor3 = Library.Theme.DimText }) end
        )
        return img, hit
    end
    local function anchorRightOf(gui)
        return function(extra)
            local s = Library:GetScreenScale()
            local x = (gui.AbsolutePosition.X + gui.AbsoluteSize.X) / s + 8 + (extra or 0)
            local y = (gui.AbsolutePosition.Y + GuiInset) / s - 4
            return UDim2.fromOffset(x, y)
        end
    end

    function toggle:Colorpicker(opts)
        opts = opts or {}
        local state = { Color = opts.Default or Library.Theme.Accent, Transparency = opts.Transparency or 0 }
        local slot = reserveSlot(22)
        local swatch = makeSwatch(row.Instance, slot, state.Color, 6)
        local picker = makeColorpicker(function() return swatch.Halo.Instance end, opts.Name or toggle.Name, state.Color, state.Transparency,
            function(color, alpha)
                state.Color, state.Transparency = color, alpha
                swatch:SetColor(color, alpha)
                if opts.Flag then Library.Flags[opts.Flag] = { __color = color:ToHex(), __alpha = alpha } end
                Library:SafeCall(opts.Callback, color, alpha)
            end)
        swatch.Hit:Connect("MouseButton1Down", function() picker:SetOpen(not picker.IsOpen) end)
        if opts.Flag then
            Library.SetFlags[opts.Flag] = function(c, a) picker:Set(c, a) end
        end
        function state:Set(c, a) picker:Set(c, a) end
        state.Picker = picker
        return state
    end

    function toggle:Keybind(opts)
        opts = opts or {}
        local kb = { Key = opts.Default, Mode = opts.Mode or "Toggle", Flag = opts.Flag, Picking = false, IsOpen = false, Debounce = false }
        local slot = reserveSlot(20)
        local img, hit = makeSideIcon(slot, "command")
        local popupW = 160
        local popup = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(popupW,128), Color="Section", Round=8, Z=40 })
        popup.Instance.Visible = false
        makeLabel({ Parent=popup.Instance, Text="Keybind", TextSize=12, Pos=UDim2.fromOffset(11,7), Size=UDim2.fromOffset(popupW-22,14), Color="DimText", Z=41 })
        local keyBox = makeFrame({ Parent=popup.Instance, Pos=UDim2.fromOffset(8,26), Size=UDim2.fromOffset(popupW-16,26), Color="Light", Round=5, Z=41 })
        local keyLabel = makeLabel({ Parent=keyBox.Instance, Text="None", TextSize=13, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Truncate=true, Z=42 })
        local keyHit = makeButton({ Parent=keyBox.Instance, Z=43 })
        local modeRows = {}
        local function addMode(y, name)
            local r = makeSelectRow({ Parent=popup.Instance, Pos=UDim2.fromOffset(8,y), Size=UDim2.fromOffset(popupW-16,28), Color="Element", Text=name, TextSize=13, LabelSize=UDim2.new(1,-18,1,0), LineX=6, LineH=14, TextX=10, TextActiveX=17, SnapShadow=true, Z=41 })
            r.Hit:Connect("MouseButton1Down", function() kb:SetMode(name) end)
            table.insert(modeRows, { Name=name, SetActive=r.SetActive })
        end
        addMode(60, "Toggle")
        addMode(92, "Hold")
        local function syncFlag()
            if not kb.Flag then return end
            Library.Flags[kb.Flag] = { Key = kb.Key and tostring(kb.Key) or "None", Mode = kb.Mode }
        end
        function kb:SetMode(mode, instant)
            self.Mode = mode
            for _, r in modeRows do r.SetActive(r.Name == mode, instant) end
            syncFlag()
        end
        function kb:Set(key)
            self.Key = key
            keyLabel.Instance.Text = keyName(key)
            self.Picking = false
            syncFlag()
        end
        makePopup({ Popup=kb, Frame=popup, Level=40, GetAnchor=function() return hit.Instance end, Place=anchorRightOf(hit.Instance), From=-6, To=2, Retreat=retreatLeft })
        hit:Connect("MouseButton1Down", function() kb:SetOpen(not kb.IsOpen) end)
        keyHit:Connect("MouseButton1Click", function()
            pickKey(kb, keyLabel.Instance, function(key) kb:Set(key) end)
        end)
        Library:Connect(UserInput.InputBegan, function(input, processed)
            if processed or kb.Picking or not kb.Key then return end
            if not inputMatches(input, kb.Key) then return end
            if kb.Mode == "Hold" then toggle:Set(true) else toggle:Set(not toggle.Value) end
        end)
        Library:Connect(UserInput.InputEnded, function(input)
            if kb.Mode ~= "Hold" or not kb.Key then return end
            if not inputMatches(input, kb.Key) then return end
            toggle:Set(false)
        end)
        if kb.Flag then
            Library.SetFlags[kb.Flag] = function(v)
                if type(v) == "table" then
                    if v.Mode then kb:SetMode(v.Mode, true) end
                    v = v.Key
                end
                kb:Set(keyFromName(v))
            end
        end
        kb:SetMode(kb.Mode, true)
        kb:Set(kb.Key)
        return kb
    end

    function toggle:Extra(opts)
        opts = opts or {}
        if toggle.ExtraPanel then return toggle.ExtraPanel end
        local panel = { IsOpen=false, Debounce=false, NextY=30, Width=opts.Width or 220 }
        local slot = reserveSlot(20)
        local img, hit = makeSideIcon(slot, "settings-2")
        local popup = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(panel.Width,38), Color="Section", Round=8, Z=2 })
        popup.Instance.Visible = false
        makeLabel({ Parent=popup.Instance, Text=toggle.Name, TextSize=12, Pos=UDim2.fromOffset(12,8), Size=UDim2.fromOffset(panel.Width-24,14), Color="DimText", Truncate=true, Z=3 })
        local dimOverlay = makeFrame({ Parent=popup.Instance, Size=UDim2.new(1,0,1,0), Raw=Color3.new(0,0,0), Alpha=1, Round=8, Z=30 })
        dimOverlay.Instance.Visible = false
        Library:StampResting(dimOverlay.Instance, "BackgroundTransparency", 1)
        local dimming = false
        function panel.SetChildDim(show)
            if dimming == show then return end
            dimming = show
            local info = TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out)
            local alpha = show and 0.5 or 1
            Library:StampResting(dimOverlay.Instance, "BackgroundTransparency", alpha)
            if show then dimOverlay.Instance.Visible = true end
            Library:Tween({ BackgroundTransparency = alpha }, info, dimOverlay.Instance)
            if show then return end
            task.delay(0.24, function() if not dimming then dimOverlay.Instance.Visible = false end end)
        end
        function panel:AddRow(h, name)
            local frame = makeFrame({ Parent=popup.Instance, Pos=UDim2.fromOffset(0,panel.NextY), Size=UDim2.fromOffset(panel.Width,h), Z=3 })
            local row = { Frame=frame, Height=h, Y=panel.NextY, Visible=true, Name=name or toggle.Name }
            panel.NextY += h
            popup.Instance.Size = UDim2.fromOffset(panel.Width, panel.NextY+8)
            return frame, row
        end
        makePopup({ Popup=panel, Frame=popup, Level=2, GetAnchor=function() return hit.Instance end, Place=anchorRightOf(hit.Instance) })
        hit:Connect("MouseButton1Down", function() panel:SetOpen(not panel.IsOpen) end)
        toggle.ExtraPanel = panel
        return panel
    end

    toggle:Set(toggle.Default or false)
    if toggle.Flag then Library.Flags[toggle.Flag] = toggle.Value end
    return toggle
end

getgenv().Zolar = Library
return Library
local applyUIScale = function()
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

function Library.SetUIScale(self, v)
    Library.UserScale = v
    Library:CloseAllPopups()
    applyUIScale()
end
applyUIScale()
Library:Connect(workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"), function()
    task.wait()
    applyUIScale()
end)

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
local function retreatUp(ud) return UDim2.fromOffset(ud.X.Offset, ud.Y.Offset - 8) end
local function retreatLeft(ud) return UDim2.fromOffset(ud.X.Offset - 8, ud.Y.Offset) end

local function makePopup(cfg)
    local popup = cfg.Popup
    local frame = cfg.Frame
    local level = cfg.Level
    local place = cfg.Place
    local getAnchor = cfg.GetAnchor
    local fromOff = cfg.From or -6
    local toOff = cfg.To or 6
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
            function() if not item.Selected then Library:Tween({ BackgroundTransparency = 1 }, nil, row.Row.Instance) end end
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
        local isEsc = input.KeyCode == Enum.KeyCode.Escape
        if isBack or isEsc then onDone(nil)
        elseif input.UserInputType == Enum.UserInputType.Keyboard then onDone(input.KeyCode)
        else onDone(input.UserInputType) end
        task.defer(function() Library.Binding = false end)
    end)
end
local function inputMatches(input, key)
    return input.KeyCode == key or input.UserInputType == key
end

function Library.Notification(self, cfg)
    if Library.Silent then return end
    cfg = cfg or {}
    local title = cfg.Name or cfg.Title or "Notification"
    local desc = cfg.Description or cfg.Content or ""
    local icon = cfg.Icon or "bell"
    local color = cfg.Color or Library.Theme.Accent
    local duration = cfg.Duration or 5
    local width = 300
    local bodySize = Vector2.new(0,0)
    if desc ~= "" then bodySize = measureText(desc, 14, width-26, RegularFont) end
    local height = 38 + (desc ~= "" and bodySize.Y + 6 or 0) + 18

    local n = {}
    n.Frame = makeFrame({ Parent=Library.Holder.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,340,0,15), Size=UDim2.fromOffset(width,height), Color="Section", Round=10, Z=80 })
    n.Icon = makeImage({ Parent=n.Frame.Instance, Icon=icon, Pos=UDim2.fromOffset(13,11), Size=UDim2.fromOffset(18,18), Raw=color, Z=81 })
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
        Library:Tween({ Position = UDim2.new(1,-15,0,p.Y.Offset-14) }, info, n.Frame.Instance)
        n.Frame:FadeDescendants(false)
        task.delay(0.3, function()
            local idx = table.find(Library.Notifs, entry)
            if idx then table.remove(Library.Notifs, idx) end
            n.Frame.Instance:Destroy()
            restack()
        end)
    end
    n.CloseHit:Connect("MouseButton1Down", dismiss)
    Library:Tween({ Size = UDim2.new(0,0,1,0) }, TweenInfo.new(duration, Enum.EasingStyle.Linear, Enum.EasingDirection.Out), n.BarFill.Instance)
    task.delay(duration, dismiss)
end

function Library.Window(self, cfg)
    cfg = cfg or {}
    local W, H = Library.WindowWidth, Library.WindowHeight
    local topH = 51
    local railX, railW = 10, 60
    local railH = 340
    local subW = 260
    local subH = 50
    local railTop = topH + railX
    local railY = math.floor((H - railH) / 2)
    local subX = railTop + math.floor((W - subW) / 2)
    local subY = H - math.floor(subH / 2)
    local totalW = railTop + W
    local totalH = subY + subH
    local colW = math.floor((W - 46) / 2)
    local col2X = colW + 16
    local subCenterX = railTop + math.floor(W / 2)
    local maxSubW = W - 120

    local win = {
        Name = cfg.Name or "ZOLAR",
        Icon = cfg.Icon or "layers",
        IsOpen = true, Tabs = {}, Current = nil,
        ContentW = W - 30, ContentH = H - 96,
        ColW = colW, Col2X = col2X, Items = {},
    }
    if cfg.Accent then Library:SetAccent(cfg.Accent) end
    local ui = {}
    local vp = workspace.CurrentCamera.ViewportSize
    local scale = Library:GetScreenScale()
    ui.Root = makeFrame({ Parent=Library.Holder.Instance,
        Pos=UDim2.fromOffset(vp.X/(2*scale) - totalW/2, vp.Y/(2*scale) - totalH/2),
        Size=UDim2.fromOffset(totalW, totalH), Z=1 })
    ui.Main = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(railTop,0), Size=UDim2.fromOffset(W,H), Color="Background", Round=10, Clip=true, Z=1 })
    ui.Rail = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(0,railY), Size=UDim2.fromOffset(railW,railH), Color="Section", Round=10, Z=1 })
    ui.SubBar = makeFrame({ Parent=ui.Root.Instance, Pos=UDim2.fromOffset(subX,subY), Size=UDim2.fromOffset(subW,subH), Color="Section", Round=10, Clip=true, Z=20 })
    ui.TopBar = makeFrame({ Parent=ui.Main.Instance, Size=UDim2.fromOffset(W,topH), Color="Section", Round=10, Z=2 })
    makeFrame({ Parent=ui.TopBar.Instance, Pos=UDim2.fromOffset(0,topH-12), Size=UDim2.fromOffset(W,12), Color="Section", Z=2 })
    ui.TopLine = makeFrame({ Parent=ui.Main.Instance, Pos=UDim2.fromOffset(0,50), Size=UDim2.fromOffset(W,1), Color="Element", Z=3 })
    ui.HubIcon = makeImage({ Parent=ui.TopBar.Instance, Icon=win.Icon, Pos=UDim2.fromOffset(10,10), Size=UDim2.fromOffset(30,30), Raw=Color3.new(1,1,1), Fit=true, Z=3 })
    ui.Search = makeFrame({ Parent=ui.TopBar.Instance, Pos=UDim2.fromOffset(50,11), Size=UDim2.fromOffset(280,30), Color="Element", Round=5, Z=3 })
    makeImage({ Parent=ui.Search.Instance, Icon="search", Pos=UDim2.fromOffset(7,7), Size=UDim2.fromOffset(16,16), Color="DimText", Z=4 })
    ui.SearchBox = makeInput({ Parent=ui.Search.Instance, Placeholder="search", Pos=UDim2.fromOffset(30,-1), Size=UDim2.new(1,-38,1,0), TextSize=15, Z=4 })
    ui.Username = makeLabel({ Parent=ui.TopBar.Instance, Text=LocalPlayer.DisplayName, TextSize=15, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-56,0,8), Size=UDim2.fromOffset(240,18), Color="Text", Align=Enum.TextXAlignment.Right, Truncate=true, Z=3 })
    ui.Version = makeFrame({ Parent=ui.TopBar.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-56,0,29), Size=UDim2.fromOffset(36,14), Color="Background", Round=3, Z=3 })
    Library:Create("UIStroke", { Parent=ui.Version.Instance, Color=Library.Theme.Element, Thickness=1 }):AddToTheme({ Color="Element" })
    makeLabel({ Parent=ui.Version.Instance, Text="v"..Library.Version, TextSize=12, Size=UDim2.new(1,0,1,0), Color="DimText", Align=Enum.TextXAlignment.Center, Z=4 })

    local function makeAvatar(parent, cfgA)
        local a = Library:Create("ImageLabel", {
            Parent=parent, Name="\0",
            AnchorPoint=cfgA.Anchor or Vector2.new(0,0), Position=cfgA.Pos,
            Size=UDim2.fromOffset(cfgA.Size,cfgA.Size),
            BackgroundColor3=Library.Theme.Element, ZIndex=cfgA.Z, BorderSizePixel=0,
            Image="rbxthumb://type=AvatarHeadShot&id="..LocalPlayer.UserId.."&w="..cfgA.Res.."&h="..cfgA.Res,
        }):AddToTheme({ BackgroundColor3="Element" })
        addCorner(a.Instance, cfgA.Round)
        return a
    end
    ui.Avatar = makeAvatar(ui.TopBar.Instance, { Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-10,0.5,0), Size=30, Res=60, Round=20, Z=3 })
    ui.ProfileHit = makeButton({ Parent=ui.TopBar.Instance, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-4,0,8), Size=UDim2.fromOffset(42,36), Z=5 })

    local profilePopup = { IsOpen=false, Debounce=false }
    local profileW = 240
    local profile = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(profileW,272), Color="Section", Round=10, Z=45 })
    profile.Instance.Visible = false
    makeAvatar(profile.Instance, { Pos=UDim2.fromOffset(14,14), Size=42, Res=100, Round=21, Z=46 })
    makeLabel({ Parent=profile.Instance, Text=LocalPlayer.DisplayName, TextSize=15, Pos=UDim2.fromOffset(68,16), Size=UDim2.fromOffset(profileW-82,20), Color="Text", Truncate=true, Z=46 })
    makeLabel({ Parent=profile.Instance, Text="@"..LocalPlayer.Name, TextSize=13, Pos=UDim2.fromOffset(68,37), Size=UDim2.fromOffset(profileW-82,16), Color="DimText", Truncate=true, Z=46 })
    local function divider(y) makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,y), Size=UDim2.fromOffset(profileW-28,1), Color="Element", Z=46 }) end
    local function infoRow(y, label, value)
        makeLabel({ Parent=profile.Instance, Text=label, TextSize=14, Pos=UDim2.fromOffset(14,y), Size=UDim2.fromOffset(100,18), Color="DimText", Z=46 })
        makeLabel({ Parent=profile.Instance, Text=value, TextSize=14, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-14,0,y), Size=UDim2.fromOffset(120,18), Color="Text", Align=Enum.TextXAlignment.Right, Truncate=true, Z=46 })
    end
    divider(68)
    infoRow(79, "User ID", tostring(LocalPlayer.UserId))
    infoRow(105, "Account age", tostring(LocalPlayer.AccountAge).." days")
    local idHit = makeButton({ Parent=profile.Instance, Pos=UDim2.fromOffset(10,76), Size=UDim2.fromOffset(profileW-20,24), Z=47 })
    idHit:Connect("MouseButton1Down", function()
        if setclipboard then pcall(setclipboard, tostring(LocalPlayer.UserId)) end
        Library:Notification({ Name="User ID copied", Description="Your user id is now in the clipboard.", Icon="copy", Duration=3 })
    end)
    local refreshProfile
    divider(134)
    makeLabel({ Parent=profile.Instance, Text="Interface scale", TextSize=14, Pos=UDim2.fromOffset(14,146), Size=UDim2.fromOffset(140,18), Color="DimText", Z=46 })
    local scaleLabel = makeLabel({ Parent=profile.Instance, Text="100%", TextSize=14, Anchor=Vector2.new(1,0), Pos=UDim2.new(1,-14,0,146), Size=UDim2.fromOffset(60,18), Color="Text", Align=Enum.TextXAlignment.Right, Z=46 })
    local scaleTrack = makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,172), Size=UDim2.fromOffset(profileW-28,8), Color="Light", Round=20, Z=46 })
    local scaleFill = makeFrame({ Parent=scaleTrack.Instance, Size=UDim2.new(0.5,0,1,0), Raw=Color3.new(1,1,1), Round=20, Z=47 })
    Library:RegisterGradient(Library:Create("UIGradient", { Parent=scaleFill.Instance }).Instance)
    local scaleKnob = makeFrame({ Parent=scaleTrack.Instance, Anchor=Vector2.new(0.5,0.5), Pos=UDim2.new(0.5,0,0.5,0), Size=UDim2.fromOffset(12,12), Raw=Color3.fromRGB(197,197,197), Round=20, Z=48 })
    local scaleHit = makeButton({ Parent=profile.Instance, Pos=UDim2.fromOffset(8,166), Size=UDim2.fromOffset(profileW-16,22), Z=49 })
    local draggingScale, pendingScale = false, 100
    local function updateScale(input)
        local track = scaleTrack.Instance
        local ratio = math.clamp((input.Position.X - track.AbsolutePosition.X) / track.AbsoluteSize.X, 0, 1)
        pendingScale = Library:Round(50 + ratio*100, 5)
        local r = (pendingScale-50)/100
        scaleLabel.Instance.Text = tostring(pendingScale).."%"
        scaleFill.Instance.Size = UDim2.new(r,0,1,0)
        scaleKnob.Instance.Position = UDim2.new(r,0,0.5,0)
    end
    scaleHit:Connect("InputBegan", function(input)
        local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch
        if not ok then return end
        draggingScale = true
        updateScale(input)
    end)
    Library:Connect(UserInput.InputEnded, function(input)
        local ok = input.UserInputType == Enum.UserInputType.MouseButton1
                or input.UserInputType == Enum.UserInputType.Touch
        if ok and draggingScale then
            draggingScale = false
            Library.UserScale = pendingScale / 100
            applyUIScale()
            if refreshProfile then refreshProfile() end
        end
    end)
    Library:Connect(UserInput.InputChanged, function(input)
        local move = input.UserInputType == Enum.UserInputType.MouseMovement
                  or input.UserInputType == Enum.UserInputType.Touch
        if move and draggingScale then updateScale(input) end
    end)
    makeLabel({ Parent=profile.Instance, Text="Menu toggle", TextSize=14, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,14,0,205), Size=UDim2.fromOffset(110,20), Color="DimText", Z=46 })
    local cmdIcon = makeImage({ Parent=profile.Instance, Icon="command", Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-14,0,205), Size=UDim2.fromOffset(16,16), Color="DimText", Z=46 })
    local cmdHit = makeButton({ Parent=profile.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-8,0,205), Size=UDim2.fromOffset(26,26), Z=48 })
    cmdHit:OnHover(
        function() cmdIcon:Tween({ ImageColor3 = Library.Theme.Text }) end,
        function() cmdIcon:Tween({ ImageColor3 = Library.Theme.DimText }) end
    )
    local keybindPopup = { IsOpen=false, Debounce=false, Picking=false, Host=profilePopup }
    local keybindW = 170
    local keybindFrame = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(keybindW,72), Color="Section", Round=8, Z=46 })
    keybindFrame.Instance.Visible = false
    makeLabel({ Parent=keybindFrame.Instance, Text="Menu keybind", TextSize=12, Pos=UDim2.fromOffset(11,8), Size=UDim2.fromOffset(keybindW-22,14), Color="DimText", Truncate=true, Z=47 })
    local kbBox = makeFrame({ Parent=keybindFrame.Instance, Pos=UDim2.fromOffset(9,32), Size=UDim2.fromOffset(keybindW-18,30), Color="Light", Round=5, Clip=true, Z=47 })
    local kbLabel = makeLabel({ Parent=kbBox.Instance, Text=keyName(Library.MenuKeybind), TextSize=13, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Truncate=true, Z=48 })
    local kbHit = makeButton({ Parent=kbBox.Instance, Z=49 })
    local function anchorCmdKeybind(offsetY)
        local g = cmdIcon.Instance
        local scale = Library:GetScreenScale()
        local x = (g.AbsolutePosition.X + g.AbsoluteSize.X) / scale + 8 + (offsetY or 0)
        local y = (g.AbsolutePosition.Y + GuiInset) / scale - 4
        return UDim2.fromOffset(x, y)
    end
    makePopup({ Popup=keybindPopup, Frame=keybindFrame, Level=46, GetAnchor=function() return cmdHit.Instance end,
        Place=anchorCmdKeybind, From=-6, To=2, Retreat=retreatLeft })
    cmdHit:Connect("MouseButton1Down", function() keybindPopup:SetOpen(not keybindPopup.IsOpen) end)
    kbHit:Connect("MouseButton1Click", function()
        if keybindPopup.Picking then return end
        keybindPopup.Picking = true
        Library.Binding = true
        kbLabel.Instance.Text = ". . ."
        task.wait()
        local conn
        conn = UserInput.InputBegan:Connect(function(input)
            if input.UserInputType ~= Enum.UserInputType.Keyboard then return end
            conn:Disconnect()
            if input.KeyCode ~= Enum.KeyCode.Escape then Library.MenuKeybind = input.KeyCode end
            kbLabel.Instance.Text = keyName(Library.MenuKeybind)
            keybindPopup.Picking = false
            task.defer(function() Library.Binding = false end)
        end)
    end)

    local unloadBtn = makeFrame({ Parent=profile.Instance, Pos=UDim2.fromOffset(14,236), Size=UDim2.fromOffset(profileW-28,28), Color="Light", Round=6, Clip=true, Z=46 })
    makeLabel({ Parent=unloadBtn.Instance, Text="Unload", TextSize=14, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Z=47 })
    local unloadHit = makeButton({ Parent=unloadBtn.Instance, Z=48 })
    unloadBtn:OnHover(
        function() unloadBtn:Tween({ BackgroundColor3 = Library.Theme.Hover }) end,
        function() unloadBtn:Tween({ BackgroundColor3 = Library.Theme.Light }) end
    )
    unloadHit:Connect("MouseButton1Down", function()
        profilePopup:SetOpen(false)
        task.delay(Library.Animation.Time + 0.12, function() Library:Unload() end)
    end)

    local function anchorProfile(offsetY)
        local g = ui.Avatar.Instance
        local scale = Library:GetScreenScale()
        local x = (g.AbsolutePosition.X + g.AbsoluteSize.X) / scale - profileW
        local y = (g.AbsolutePosition.Y + g.AbsoluteSize.Y + GuiInset) / scale + (offsetY or 0)
        return UDim2.fromOffset(x, y)
    end
    refreshProfile = function()
        if profilePopup.IsOpen then profile.Instance.Position = anchorProfile(10) end
    end
    makePopup({ Popup=profilePopup, Frame=profile, Level=45, GetAnchor=function() return ui.ProfileHit.Instance end,
        Place=anchorProfile, From=-2, To=10, HoldOpen=function() return keybindPopup.IsOpen end })
    win.Profile = profilePopup
    ui.ProfileHit:Connect("MouseButton1Down", function() profilePopup:SetOpen(not profilePopup.IsOpen) end)

    ui.Content = makeFrame({ Parent=ui.Main.Instance, Pos=UDim2.fromOffset(15,65), Size=UDim2.fromOffset(W-30,H-96), Clip=true, Z=2 })
    win.Items = ui
    ui.Root:MakeDraggable(ui.Main.Instance)
    ui.Root:MakeDraggable(ui.Rail.Instance)
    table.insert(Library.Windows, win)

    function win:Center()
        local s = Library:GetScreenScale()
        local v = workspace.CurrentCamera.ViewportSize
        ui.Root.Instance.Position = UDim2.fromOffset(v.X/(2*s) - totalW/2, v.Y/(2*s) - totalH/2)
    end
    function win:LayoutRail()
        local n = #win.Tabs
        local h = n > 0 and (50*n + 10) or railH
        local y = math.floor((H - h) / 2)
        ui.Rail.Instance.Size = UDim2.fromOffset(railW, h)
        ui.Rail.Instance.Position = UDim2.fromOffset(0, y)
    end
    function win:FitSubBar(instant)
        local tab = win.Current
        if not tab or not tab.SubLayout then return end
        if #tab.Subs == 0 then return end
        local s = Library:GetScreenScale()
        local contentW = tab.SubLayout.AbsoluteContentSize.X / s + 16
        if contentW <= 16 then return end
        local overflow = contentW > maxSubW
        local w = math.min(contentW, maxSubW)
        local x = subCenterX - math.floor(w/2)
        local info = instant and TweenInfo.new(0) or TweenInfo.new(0.24, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        Library:Tween({ Position = UDim2.fromOffset(x, subY), Size = UDim2.fromOffset(w, subH) }, info, ui.SubBar.Instance)
        local scroll = tab.Items.SubRow.Instance
        scroll.ScrollingEnabled = overflow
        scroll.ScrollBarThickness = overflow and 3 or 0
    end
    function win:LayoutSubBar(instant) win:FitSubBar(instant) end
    function win:SetOpen(open)
        self.IsOpen = open
        if not open then Library:CloseAllPopups() end
        local sub = self.Current and self.Current.Current
        if sub and sub.SnapVisible then sub:SnapVisible() end
        if open and self.PlayIntro then self:PlayIntro()
        else ui.Root:FadeDescendants(open) end
    end

    Library:Connect(UserInput.InputBegan, function(input, processed)
        if processed or Library.Binding then return end
        if input.KeyCode == Library.MenuKeybind then win:SetOpen(not win.IsOpen) end
    end)

    local function doSearch(query)
        query = string.lower(query)
        for _, item in Library.Searchables do
            if item.Window ~= win then continue end
            local match = query == ""
                       or string.find(string.lower(item.Name), query, 1, true) ~= nil
            if not match and item.Section then
                match = string.find(string.lower(item.Section.Name), query, 1, true) ~= nil
            end
            item.Visible = match
            if item.Section then item.Section.Dirty = true end
        end
        for _, tab in win.Tabs do
            for _, sub in tab.Subs do
                for _, section in sub.Sections do
                    if section.Dirty then
                        section.Dirty = false
                        section:Reflow()
                    end
                end
            end
        end
        local sub = win.Current and win.Current.Current
        if sub and #sub.Sections > 0 then
            local sig = tostring(sub)
            for _, section in sub.Sections do
                for _, row in section.Rows do
                    sig ..= (row.Visible ~= false) and "1" or "0"
                end
            end
            if sig ~= win.SearchSig then
                win.SearchSig = sig
                sub:Show()
            end
        end
    end
    local searchDebounce = 0
    Library:Connect(ui.SearchBox.Instance:GetPropertyChangedSignal("Text"), function()
        searchDebounce += 1
        local ticket = searchDebounce
        task.delay(0.1, function()
            if ticket ~= searchDebounce then return end
            doSearch(ui.SearchBox.Instance.Text)
        end)
    end)

    function win:PlayIntro()
        local resting = ui.Root.Instance.Position
        ui.Root.Instance.Position = UDim2.fromOffset(resting.X.Offset, resting.Y.Offset + 24)
        ui.Root:FadeDescendants(true)
        Library:Tween({ Position = resting }, TweenInfo.new(0.5, Enum.EasingStyle.Quint, Enum.EasingDirection.Out), ui.Root.Instance)
    end
    task.defer(function() win:PlayIntro() end)
    return setmetatable(win, Library)
end

function Library.Tab(self, cfg)
    cfg = cfg or {}
    local win = self
    local tab = {
        Name = cfg.Name or "Tab", Icon = cfg.Icon or "circle",
        Window = win, Subs = {}, Current = nil, Active = false, Items = {},
    }
    local ui = {}
    local y = 10 + #win.Tabs * 50
    ui.Row = makeFrame({ Parent=win.Items.Rail.Instance, Pos=UDim2.fromOffset(10,y), Size=UDim2.fromOffset(40,40), Color="Element", Round=8, Clip=true, Z=3 })
    setResting(ui.Row.Instance, "BackgroundTransparency", 1)
    ui.Bar = makeFrame({ Parent=win.Items.Rail.Instance, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,0,0,y+20), Size=UDim2.fromOffset(3,0), Color="Accent", Round=4, Z=4 })
    ui.BarShadow = makeShadow(ui.Bar.Instance, Library.Theme.Accent, UDim2.fromOffset(3,15), UDim.new(0,10), 0)
    if ui.BarShadow then setResting(ui.BarShadow, "Transparency", 1) end
    ui.Icon = makeImage({ Parent=ui.Row.Instance, Icon=tab.Icon, Pos=UDim2.fromOffset(10,10), Size=UDim2.fromOffset(20,20), Color="DimIcon", Z=4 })
    ui.Hit = makeButton({ Parent=ui.Row.Instance, Z=6 })
    ui.SubRow = Library:Create("ScrollingFrame", {
        Parent=win.Items.SubBar.Instance, Name="\0", BackgroundTransparency=1,
        ScrollBarThickness=0, ScrollBarImageColor3=Library.Theme.Accent,
        ScrollingDirection=Enum.ScrollingDirection.X, ScrollingEnabled=false, Selectable=false, Active=true,
        AutomaticCanvasSize=Enum.AutomaticSize.X, CanvasSize=UDim2.fromOffset(0,0),
        Size=UDim2.new(1,0,1,0), ZIndex=21, BorderSizePixel=0,
    }):AddToTheme({ ScrollBarImageColor3="Accent" })
    ui.SubRow.Instance.Visible = false
    ui.SubLayout = Library:Create("UIListLayout", {
        Parent=ui.SubRow.Instance, FillDirection=Enum.FillDirection.Horizontal,
        HorizontalAlignment=Enum.HorizontalAlignment.Left, VerticalAlignment=Enum.VerticalAlignment.Center,
        SortOrder=Enum.SortOrder.LayoutOrder, Padding=UDim.new(0,6),
    })
    Library:Create("UIPadding", { Parent=ui.SubRow.Instance, PaddingLeft=UDim.new(0,8), PaddingRight=UDim.new(0,8) })
    win.Items.Root:MakeDraggable(ui.SubRow.Instance)
    tab.SubLayout = ui.SubLayout.Instance
    Library:Connect(tab.SubLayout:GetPropertyChangedSignal("AbsoluteContentSize"), function()
        if win.Current == tab then win:FitSubBar(true) end
    end)
    tab.Items = ui

    function tab:SetVisual(active)
        self.Active = active
        Library:StampResting(ui.Row.Instance, "BackgroundTransparency", active and 0 or 1)
        if ui.BarShadow then
            Library:StampResting(ui.BarShadow, "Transparency", active and 0 or 1)
            ui.BarShadow.Transparency = active and 0 or 1
        end
        ui.Icon:ChangeItemTheme({ ImageColor3 = active and "Accent" or "DimIcon" })
        ui.Icon:Tween({ ImageColor3 = active and Library.Theme.Accent or Library.Theme.DimIcon })
        ui.Row:Tween({ BackgroundTransparency = active and 0 or 1 })
        ui.Bar:Tween({ Size = UDim2.fromOffset(3, active and 16 or 0) })
    end
    ui.Row:OnHover(
        function() if not tab.Active then ui.Icon:Tween({ ImageColor3 = Library.Theme.Text }) end end,
        function() if not tab.Active then ui.Icon:Tween({ ImageColor3 = Library.Theme.DimIcon }) end end
    )
    local function syncCurrent()
        local sub = tab.Current or tab.Subs[1]
        if not sub then return end
        tab.Current = sub
        for _, s in tab.Subs do s:SetVisual(s == sub) end
        sub:Show()
    end
    function tab:Select()
        if win.Current == tab then return end
        Library:CloseAllPopups()
        if win.Current then
            win.Current:SetVisual(false)
            win.Current.Items.SubRow.Instance.Visible = false
            if win.Current.Current then win.Current.Current:Hide() end
        end
        win.Current = tab
        tab:SetVisual(true)
        ui.SubRow.Instance.Visible = true
        syncCurrent()
        win:LayoutSubBar()
    end
    ui.Hit:Connect("MouseButton1Down", function() tab:Select() end)
    table.insert(win.Tabs, tab)
    win:LayoutRail()
    if #win.Tabs == 1 then
        win.Current = tab
        tab:SetVisual(true)
        ui.SubRow.Instance.Visible = true
        task.defer(function() syncCurrent(); win:LayoutSubBar() end)
    end
    return setmetatable(tab, Library)
end

function Library.SubTab(self, cfg)
    cfg = cfg or {}
    local parentTab = self
    local win = parentTab.Window
    local sub = {
        Name = cfg.Name or "SubTab", Icon = cfg.Icon or "circle",
        Tab = parentTab, Window = win, Sections = {}, Columns = {}, Active = false,
        ShowToken = 0, Items = {},
    }
    local ui = {}
    local contentW, contentH = win.ContentW, win.ContentH
    local colW, col2X = win.ColW, win.Col2X
    local labelW = math.ceil(measureText(sub.Name, 15, 300, RegularFont).X)
    local collapsedW = 40
    local expandedW = 37 + labelW + 12
    sub.CollapsedW, sub.ExpandedW = collapsedW, expandedW

    ui.Pill = makeFrame({ Parent=parentTab.Items.SubRow.Instance, Size=UDim2.fromOffset(collapsedW,30), Color="Element", Round=5, Clip=true, Z=22 })
    setResting(ui.Pill.Instance, "BackgroundTransparency", 1)
    ui.Pill.Instance.LayoutOrder = #parentTab.Subs
    ui.Icon = makeImage({ Parent=ui.Pill.Instance, Icon=sub.Icon, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,11,0.5,0), Size=UDim2.fromOffset(18,18), Color="DimIcon", Z=23 })
    ui.Label = makeLabel({ Parent=ui.Pill.Instance, Text=sub.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,37,0.5,0), Size=UDim2.fromOffset(labelW+8,20), Color="Text", Z=23 })
    setResting(ui.Label.Instance, "TextTransparency", 1)
    local function fitPill()
        local w = math.ceil(ui.Label.Instance.TextBounds.X)
        if w <= 0 then return end
        expandedW = 37 + w + 12
        sub.ExpandedW = expandedW
        ui.Label.Instance.Size = UDim2.fromOffset(w+8,20)
        if parentTab.Current == sub then
            ui.Pill.Instance.Size = UDim2.fromOffset(expandedW,30)
            win:FitSubBar(true)
        end
    end
    Library:Connect(ui.Label.Instance:GetPropertyChangedSignal("TextBounds"), fitPill)
    task.defer(fitPill)
    ui.Hit = makeButton({ Parent=ui.Pill.Instance, Z=25 })
    ui.Page = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(contentW,contentH), Z=3 })
    ui.Page.Instance.Visible = false

    local function makeColumn(x)
        local scroll = Library:Create("ScrollingFrame", {
            Parent=ui.Page.Instance, Name="\0", BackgroundTransparency=1,
            ScrollBarThickness=0, ScrollBarImageTransparency=1, Selectable=false, Active=true,
            Position=UDim2.fromOffset(x,0), Size=UDim2.fromOffset(colW,contentH),
            CanvasSize=UDim2.fromOffset(0,0), ZIndex=3, BorderSizePixel=0,
        })
        local col = { Scroll=scroll, Width=colW, Sections={} }
        function col:Reflow()
            local y = 0
            for _, sec in self.Sections do
                sec.Y = y
                sec.Items.Holder.Instance.Position = UDim2.fromOffset(0,y)
                y += sec.Height + 16
            end
            scroll.Instance.CanvasSize = UDim2.fromOffset(0, math.max(y-16,0))
        end
        return col
    end
    sub.Columns[1] = makeColumn(0)
    sub.Columns[2] = makeColumn(col2X)
    sub.Items = ui

    function sub:SetVisual(active, instant)
        Library:StampResting(ui.Pill.Instance, "BackgroundTransparency", active and 0 or 1)
        Library:StampResting(ui.Label.Instance, "TextTransparency", active and 0 or 1)
        local info = instant and TweenInfo.new(0) or TweenInfo.new(0.28, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local w = active and expandedW or collapsedW
        Library:Tween({ Size = UDim2.fromOffset(w,30) }, info, ui.Pill.Instance)
        Library:Tween({ TextTransparency = active and 0 or 1 }, info, ui.Label.Instance)
        ui.Icon:ChangeItemTheme({ ImageColor3 = active and "Accent" or "DimIcon" })
        ui.Icon:Tween({ ImageColor3 = active and Library.Theme.Accent or Library.Theme.DimIcon }, info)
        ui.Pill:Tween({ BackgroundTransparency = active and 0 or 1 }, info)
    end
    ui.Pill:OnHover(
        function() if parentTab.Current ~= sub then ui.Icon:Tween({ ImageColor3 = Library.Theme.Text }) end end,
        function() if parentTab.Current ~= sub then ui.Icon:Tween({ ImageColor3 = Library.Theme.DimIcon }) end end
    )

    local rowSlide = TweenInfo.new(0.3, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
    local rowX = 18
    local staggerSection = 0.07
    local staggerRow = 0.045

    local function eachSectionRow(fn)
        for _, col in sub.Columns do
            for _, sec in col.Sections do
                for _, row in sec.Rows do fn(row, sec) end
            end
        end
    end
    local function cancelAllMoves()
        eachSectionRow(function(row)
            if row.Move then pcall(function() row.Move:Cancel() end) end
            row.Move = nil
        end)
    end
    local function resetSections()
        for _, col in sub.Columns do
            for _, sec in col.Sections do
                sec.Items.Holder.Instance.Position = UDim2.fromOffset(0, sec.Y)
                sec.Items.Frame.Instance.Position = UDim2.fromOffset(0,26)
                for _, row in sec.Rows do
                    row.Frame:CancelFade()
                    row.Frame.Instance.Visible = row.Visible ~= false
                end
            end
        end
    end
    local function snapPage()
        ui.Page.Instance.Position = UDim2.fromOffset(0,0)
        ui.Page:HardRestore()
        resetSections()
        eachSectionRow(function(row) row.Frame.Instance.Position = UDim2.fromOffset(0, row.Y) end)
    end

    function sub:Show()
        self.ShowToken += 1
        local token = self.ShowToken
        self.Active = true
        cancelAllMoves()
        ui.Page:CancelFade()
        ui.Page:HardRestore()
        for _, tab in win.Tabs do
            for _, other in tab.Subs do
                if other ~= sub and other.Items and other.Items.Page then
                    local page = other.Items.Page.Instance
                    if page.Parent ~= Library.UnusedHolder.Instance then
                        other.Active = false
                        other.ShowToken += 1
                        page.Visible = false
                        page.Parent = Library.UnusedHolder.Instance
                    end
                end
            end
        end
        ui.Page.Instance.Parent = win.Items.Content.Instance
        ui.Page.Instance.Position = UDim2.fromOffset(0,0)
        ui.Page.Instance.Visible = true
        Library:SafeCall(self.PageIntro)
        if #self.Sections == 0 then return end
        resetSections()
        local secIndex = 0
        for _, col in self.Columns do
            for _, sec in col.Sections do
                secIndex += 1
                local idx = secIndex
                for _, row in sec.Rows do
                    row.Frame:CancelFade()
                    row.Frame.Instance.Visible = false
                end
                task.delay((idx-1)*staggerSection, function()
                    if self.ShowToken ~= token or not self.Active then return end
                    sec.Frame:FadeDescendants(true)
                    for i, row in sec.Rows do
                        if row.Visible == false then continue end
                        task.delay(i*staggerRow, function()
                            local resting = UDim2.fromOffset(0, row.Y)
                            row.Frame.Instance.Visible = true
                            if self.ShowToken ~= token or not self.Active then
                                row.Frame.Instance.Position = resting
                                return
                            end
                            row.Frame.Instance.Position = UDim2.fromOffset(rowX, row.Y)
                            row.Move = Library:Tween({ Position = resting }, rowSlide, row.Frame.Instance)
                            row.Frame:FadeDescendants(true)
                        end)
                    end
                end)
            end
        end
    end
    function sub:Hide(onDone)
        self.Active = false
        self.ShowToken += 1
        Library:SafeCall(self.PageOutro)
        cancelAllMoves()
        ui.Page:CancelFade()
        ui.Page:ResetFade()
        snapPage()
        ui.Page.Instance.Visible = false
        ui.Page.Instance.Parent = Library.UnusedHolder.Instance
        if onDone then Library:SafeCall(onDone) end
    end
    function sub:SnapVisible()
        self.ShowToken += 1
        self.Active = true
        cancelAllMoves()
        ui.Page:CancelFade()
        snapPage()
        ui.Page.Instance.Visible = true
    end
    ui.Hit:Connect("MouseButton1Down", function()
        if parentTab.Current == sub then return end
        Library:CloseAllPopups()
        if parentTab.Current then
            parentTab.Current:SetVisual(false)
            parentTab.Current:Hide()
        end
        parentTab.Current = sub
        sub:SetVisual(true)
        sub:Show()
        win:LayoutSubBar()
    end)
    table.insert(parentTab.Subs, sub)
    if #parentTab.Subs == 1 then
        parentTab.Current = sub
        sub:SetVisual(true, true)
    end
    if win.Current == parentTab then win:LayoutSubBar() end
    return setmetatable(sub, Library)
end

function Library.Section(self, cfg)
    cfg = cfg or {}
    local sub = self
    local side = cfg.Side or 1
    if side == "Right" then side = 2 end
    if side == "Left" then side = 1 end
    local col = sub.Columns[side] or sub.Columns[1]
    local section = {
        Name = cfg.Name or "Section", SubTab = sub, Column = col,
        Width = col.Width, Y = 0, Height = 0, Rows = {}, Dirty = false, Items = {},
    }
    local ui = {}
    ui.Holder = makeFrame({ Parent=col.Scroll.Instance, Size=UDim2.fromOffset(col.Width,40), Z=3 })
    local labelW = math.ceil(measureText(section.Name, 15, 240, RegularFont).X)
    local headerW = labelW + 26
    ui.Header = makeFrame({ Parent=ui.Holder.Instance, Pos=UDim2.fromOffset(0,1), Size=UDim2.fromOffset(headerW,25), Color="Section", Round=10, Z=3 })
    ui.HeaderFill = makeFrame({ Parent=ui.Header.Instance, Pos=UDim2.fromOffset(0,15), Size=UDim2.fromOffset(headerW,10), Color="Section", Z=3 })
    ui.Label = makeLabel({ Parent=ui.Header.Instance, Text=section.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,13,0.5,1), Size=UDim2.fromOffset(labelW+6,20), Color="Text", Z=4 })
    local function fitHeader()
        local w = math.ceil(ui.Label.Instance.TextBounds.X)
        if w <= 0 then return end
        labelW = w; headerW = w + 26
        ui.Label.Instance.Size = UDim2.fromOffset(w+6,20)
        ui.Header.Instance.Size = UDim2.fromOffset(headerW,25)
        ui.HeaderFill.Instance.Size = UDim2.fromOffset(headerW,10)
    end
    Library:Connect(ui.Label.Instance:GetPropertyChangedSignal("TextBounds"), fitHeader)
    task.defer(fitHeader)
    ui.Frame = makeFrame({ Parent=ui.Holder.Instance, Pos=UDim2.fromOffset(0,26), Size=UDim2.fromOffset(col.Width,14), Color="Section", Round=10, Z=3 })
    ui.BodyFill = makeFrame({ Parent=ui.Frame.Instance, Pos=UDim2.fromOffset(0,0), Size=UDim2.fromOffset(10,10), Color="Section", Z=3 })
    section.Items = ui

    function section:Reflow()
        local pad = 8
        local y = pad
        local visibleCount = 0
        for _, row in self.Rows do
            local vis = row.Visible ~= false
            row.Frame.Instance.Visible = vis
            if not vis then continue end
            row.Y = y
            row.Frame.Instance.Position = UDim2.fromOffset(0, y)
            y += row.Height
            visibleCount += 1
        end
        local bodyH = visibleCount > 0 and (y + 8) or 0
        ui.Frame.Instance.Size = UDim2.fromOffset(section.Width, bodyH)
        ui.Holder.Instance.Visible = visibleCount > 0
        section.Height = visibleCount > 0 and (26 + bodyH) or 0
        ui.Holder.Instance.Size = UDim2.fromOffset(section.Width, math.max(section.Height,1))
        col:Reflow()
    end
    function section:AddRow(height, name)
        local frame = makeFrame({ Parent=ui.Frame.Instance, Size=UDim2.fromOffset(section.Width, height), Z=4 })
        local row = {
            Frame = frame, Height = height, Y = 0, Visible = true,
            Name = name or section.Name, Section = section, Window = sub.Window,
        }
        table.insert(section.Rows, row)
        table.insert(Library.Searchables, row)
        section:Reflow()
        return frame, row
    end
    table.insert(sub.Sections, section)
    table.insert(col.Sections, section)
    section:Reflow()
    return setmetatable(section, Library)
end

function Library.Toggle(self, cfg)
    cfg = cfg or {}
    local section = self
    local toggle = {
        Name = cfg.Name or "Toggle", Default = cfg.Default or false, Flag = cfg.Flag,
        Callback = cfg.Callback or function() end, Value = false, Visual = nil, Token = 0, Items = {},
    }
    local row = section:AddRow(32, toggle.Name)
    local ui = { Row = row }
    ui.Label = makeLabel({ Parent=row.Instance, Text=toggle.Name, TextSize=15, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,15,0.5,0), Size=UDim2.fromOffset(section.Width-80,20), Color="DimText", Truncate=true, Z=5 })
    ui.Box = makeFrame({ Parent=row.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,-15,0.5,0), Size=UDim2.fromOffset(35,21), Color="Element", Round=10, Clip=true, Z=5 })
    ui.Circle = makeFrame({ Parent=ui.Box.Instance, Anchor=Vector2.new(0,0.5), Pos=UDim2.new(0,4,0.5,0), Size=UDim2.fromOffset(13,13), Color="DimText", Round=20, Z=6 })
    makeShadow(ui.Circle.Instance, Library.Theme.Accent, UDim2.fromOffset(3,3), UDim.new(0,5), 0.7)
    ui.Hit = makeButton({ Parent=row.Instance, Size=UDim2.new(1,0,1,0), Z=8 })
    toggle.Items = ui

    local pad = 4
    local stretchW = 35 - pad*2
    local offPos = UDim2.new(0,pad,0.5,0)
    local onPos = UDim2.new(1,-pad,0.5,0)
    local knobSize = UDim2.fromOffset(13,13)

    function toggle.SetVisual(active, instant)
        active = active and true or false
        if toggle.Visual == active then return end
        toggle.Visual = active
        toggle.Token += 1
        local token = toggle.Token
        if toggle.GrowTween then pcall(function() toggle.GrowTween:Cancel() end) end
        if toggle.SnapTween then pcall(function() toggle.SnapTween:Cancel() end) end
        toggle.GrowTween, toggle.SnapTween = nil, nil
        local boxColor = active and "Light" or "Element"
        local knobColor = active and "Accent" or "DimText"
        local textColor = active and "Text" or "DimText"
        local anchor = active and Vector2.new(0,0.5) or Vector2.new(1,0.5)
        local pos = active and onPos or offPos
        local finalAnchor = active and Vector2.new(1,0.5) or Vector2.new(0,0.5)
        local finalPos = active and offPos or onPos
        ui.Box:ChangeItemTheme({ BackgroundColor3 = boxColor })
        ui.Label:ChangeItemTheme({ TextColor3 = textColor })
        ui.Circle:ChangeItemTheme({ BackgroundColor3 = knobColor })
        local accentColor = Library.Theme[knobColor]
        if instant then
            ui.Box.Instance.BackgroundColor3 = Library.Theme[boxColor]
            ui.Label.Instance.TextColor3 = Library.Theme[textColor]
            ui.Circle.Instance.BackgroundColor3 = accentColor
            ui.Circle.Instance.Size = knobSize
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            return
        end
        local growInfo = TweenInfo.new(0.14, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        local snapInfo = TweenInfo.new(0.16, Enum.EasingStyle.Back, Enum.EasingDirection.Out)
        local colorInfo = TweenInfo.new(0.2, Enum.EasingStyle.Quart, Enum.EasingDirection.Out)
        Library:Tween({ BackgroundColor3 = Library.Theme[boxColor] }, colorInfo, ui.Box.Instance)
        Library:Tween({ TextColor3 = Library.Theme[textColor] }, colorInfo, ui.Label.Instance)
        Library:Tween({ BackgroundColor3 = accentColor }, colorInfo, ui.Circle.Instance)
        ui.Circle.Instance.AnchorPoint = anchor
        ui.Circle.Instance.Position = pos
        toggle.GrowTween = Library:Tween({ Size = UDim2.fromOffset(stretchW,13) }, growInfo, ui.Circle.Instance)
        task.delay(0.08, function()
            if toggle.Token ~= token then return end
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            toggle.SnapTween = Library:Tween({ Size = knobSize }, snapInfo, ui.Circle.Instance)
        end)
        task.delay(0.3, function()
            if toggle.Token ~= token then return end
            if ui.Circle.Instance.Size == knobSize then return end
            ui.Circle.Instance.AnchorPoint = finalAnchor
            ui.Circle.Instance.Position = finalPos
            ui.Circle.Instance.Size = knobSize
        end)
    end
    function toggle:Set(value)
        self.Value = value and true or false
        if self.Flag then Library.Flags[self.Flag] = self.Value end
        self.SetVisual(self.Value, false)
        Library:SafeCall(self.Callback, self.Value)
    end
    function toggle:Get() return self.Value end
    ui.Hit:Connect("MouseButton1Down", function() toggle:Set(not toggle.Value) end)

    toggle.SlotX = -58
    local function reserveSlot(w)
        local slot = toggle.SlotX
        toggle.SlotX -= w + 8
        ui.Label.Instance.Size = UDim2.fromOffset(section.Width + toggle.SlotX - 15, 20)
        return slot
    end

    local function makeSideIcon(slotX, icon)
        local img = makeImage({ Parent=row.Instance, Icon=icon, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,slotX,0.5,0), Size=UDim2.fromOffset(16,16), Color="DimText", Z=6 })
        local hit = makeButton({ Parent=row.Instance, Anchor=Vector2.new(1,0.5), Pos=UDim2.new(1,slotX+2,0.5,0), Size=UDim2.fromOffset(22,22), Z=9 })
        hit:OnHover(
            function() img:Tween({ ImageColor3 = Library.Theme.Text }) end,
            function() img:Tween({ ImageColor3 = Library.Theme.DimText }) end
        )
        return img, hit
    end
    local function anchorRightOf(gui)
        return function(extra)
            local s = Library:GetScreenScale()
            local x = (gui.AbsolutePosition.X + gui.AbsoluteSize.X) / s + 8 + (extra or 0)
            local y = (gui.AbsolutePosition.Y + GuiInset) / s - 4
            return UDim2.fromOffset(x, y)
        end
    end

    function toggle:Colorpicker(opts)
        opts = opts or {}
        local state = { Color = opts.Default or Library.Theme.Accent, Transparency = opts.Transparency or 0 }
        local slot = reserveSlot(22)
        local swatch = makeSwatch(row.Instance, slot, state.Color, 6)
        local picker = makeColorpicker(function() return swatch.Halo.Instance end, opts.Name or toggle.Name, state.Color, state.Transparency,
            function(color, alpha)
                state.Color, state.Transparency = color, alpha
                swatch:SetColor(color, alpha)
                if opts.Flag then Library.Flags[opts.Flag] = { __color = color:ToHex(), __alpha = alpha } end
                Library:SafeCall(opts.Callback, color, alpha)
            end)
        swatch.Hit:Connect("MouseButton1Down", function() picker:SetOpen(not picker.IsOpen) end)
        if opts.Flag then
            Library.SetFlags[opts.Flag] = function(c, a) picker:Set(c, a) end
        end
        function state:Set(c, a) picker:Set(c, a) end
        state.Picker = picker
        return state
    end

    function toggle:Keybind(opts)
        opts = opts or {}
        local kb = { Key = opts.Default, Mode = opts.Mode or "Toggle", Flag = opts.Flag, Picking = false, IsOpen = false, Debounce = false }
        local slot = reserveSlot(20)
        local img, hit = makeSideIcon(slot, "command")
        local popupW = 160
        local popup = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(popupW,128), Color="Section", Round=8, Z=40 })
        popup.Instance.Visible = false
        makeLabel({ Parent=popup.Instance, Text="Keybind", TextSize=12, Pos=UDim2.fromOffset(11,7), Size=UDim2.fromOffset(popupW-22,14), Color="DimText", Z=41 })
        local keyBox = makeFrame({ Parent=popup.Instance, Pos=UDim2.fromOffset(8,26), Size=UDim2.fromOffset(popupW-16,26), Color="Light", Round=5, Z=41 })
        local keyLabel = makeLabel({ Parent=keyBox.Instance, Text="None", TextSize=13, Size=UDim2.new(1,0,1,0), Color="Text", Align=Enum.TextXAlignment.Center, Truncate=true, Z=42 })
        local keyHit = makeButton({ Parent=keyBox.Instance, Z=43 })
        local modeRows = {}
        local function addMode(y, name)
            local r = makeSelectRow({ Parent=popup.Instance, Pos=UDim2.fromOffset(8,y), Size=UDim2.fromOffset(popupW-16,28), Color="Element", Text=name, TextSize=13, LabelSize=UDim2.new(1,-18,1,0), LineX=6, LineH=14, TextX=10, TextActiveX=17, SnapShadow=true, Z=41 })
            r.Hit:Connect("MouseButton1Down", function() kb:SetMode(name) end)
            table.insert(modeRows, { Name=name, SetActive=r.SetActive })
        end
        addMode(60, "Toggle")
        addMode(92, "Hold")
        local function syncFlag()
            if not kb.Flag then return end
            Library.Flags[kb.Flag] = { Key = kb.Key and tostring(kb.Key) or "None", Mode = kb.Mode }
        end
        function kb:SetMode(mode, instant)
            self.Mode = mode
            for _, r in modeRows do r.SetActive(r.Name == mode, instant) end
            syncFlag()
        end
        function kb:Set(key)
            self.Key = key
            keyLabel.Instance.Text = keyName(key)
            self.Picking = false
            syncFlag()
        end
        makePopup({ Popup=kb, Frame=popup, Level=40, GetAnchor=function() return hit.Instance end, Place=anchorRightOf(hit.Instance), From=-6, To=2, Retreat=retreatLeft })
        hit:Connect("MouseButton1Down", function() kb:SetOpen(not kb.IsOpen) end)
        keyHit:Connect("MouseButton1Click", function()
            pickKey(kb, keyLabel.Instance, function(key) kb:Set(key) end)
        end)
        Library:Connect(UserInput.InputBegan, function(input, processed)
            if processed or kb.Picking or not kb.Key then return end
            if not inputMatches(input, kb.Key) then return end
            if kb.Mode == "Hold" then toggle:Set(true) else toggle:Set(not toggle.Value) end
        end)
        Library:Connect(UserInput.InputEnded, function(input)
            if kb.Mode ~= "Hold" or not kb.Key then return end
            if not inputMatches(input, kb.Key) then return end
            toggle:Set(false)
        end)
        if kb.Flag then
            Library.SetFlags[kb.Flag] = function(v)
                if type(v) == "table" then
                    if v.Mode then kb:SetMode(v.Mode, true) end
                    v = v.Key
                end
                kb:Set(keyFromName(v))
            end
        end
        kb:SetMode(kb.Mode, true)
        kb:Set(kb.Key)
        return kb
    end

    function toggle:Extra(opts)
        opts = opts or {}
        if toggle.ExtraPanel then return toggle.ExtraPanel end
        local panel = { IsOpen=false, Debounce=false, NextY=30, Width=opts.Width or 220 }
        local slot = reserveSlot(20)
        local img, hit = makeSideIcon(slot, "settings-2")
        local popup = makeFrame({ Parent=Library.UnusedHolder.Instance, Size=UDim2.fromOffset(panel.Width,38), Color="Section", Round=8, Z=2 })
        popup.Instance.Visible = false
        makeLabel({ Parent=popup.Instance, Text=toggle.Name, TextSize=12, Pos=UDim2.fromOffset(12,8), Size=UDim2.fromOffset(panel.Width-24,14), Color="DimText", Truncate=true, Z=3 })
        local dimOverlay = makeFrame({ Parent=popup.Instance, Size=UDim2.new(1,0,1,0), Raw=Color3.new(0,0,0), Alpha=1, Round=8, Z=30 })
        dimOverlay.Instance.Visible = false
        Library:StampResting(dimOverlay.Instance, "BackgroundTransparency", 1)
        local dimming = false
        function panel.SetChildDim(show)
            if dimming == show then return end
            dimming = show
            local info = TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out)
            local alpha = show and 0.5 or 1
            Library:StampResting(dimOverlay.Instance, "BackgroundTransparency", alpha)
            if show then dimOverlay.Instance.Visible = true end
            Library:Tween({ BackgroundTransparency = alpha }, info, dimOverlay.Instance)
            if show then return end
            task.delay(0.24, function() if not dimming then dimOverlay.Instance.Visible = false end end)
        end
        function panel:AddRow(h, name)
            local frame = makeFrame({ Parent=popup.Instance, Pos=UDim2.fromOffset(0,panel.NextY), Size=UDim2.fromOffset(panel.Width,h), Z=3 })
            local row = { Frame=frame, Height=h, Y=panel.NextY, Visible=true, Name=name or toggle.Name }
            panel.NextY += h
            popup.Instance.Size = UDim2.fromOffset(panel.Width, panel.NextY+8)
            return frame, row
        end
        makePopup({ Popup=panel, Frame=popup, Level=2, GetAnchor=function() return hit.Instance end, Place=anchorRightOf(hit.Instance) })
        hit:Connect("MouseButton1Down", function() panel:SetOpen(not panel.IsOpen) end)
        toggle.ExtraPanel = panel
        return panel
    end

    toggle:Set(toggle.Default or false)
    if toggle.Flag then Library.Flags[toggle.Flag] = toggle.Value end
    return toggle
end

getgenv().Zolar = Library
return Library
