"""
Telegram 频道视频小网页：登录 / 搜索 / 加频道 / 流式播放
架构：浏览器 -> 本服务 -> Telegram (MTProto, Telethon)
视频不先落盘：/stream 按浏览器的 Range 请求，从 Telegram 按需取片段转发。
只给自己用：不要把 8000 端口公开给全网，见 README 的安全一节。
"""
import asyncio
import ipaddress
import os
import re
import secrets
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.functions.messages import ImportChatInviteRequest
from telethon.tl.types import Channel, Chat, DocumentAttributeFilename, DocumentAttributeVideo, PeerChannel, InputMessagesFilterVideo

API_ID = int(os.environ.get("TG_API_ID", "0") or 0)
API_HASH = os.environ.get("TG_API_HASH", "")
SESSION_PATH = os.environ.get("TG_SESSION", "data/tg.session")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
WEB_PATH = os.environ.get("WEB_PATH", "").strip().strip("/")
WEB_SESSION_DAYS = 30
_web_sessions: dict = {}  # token -> expiry timestamp，cookie 本身不再是密码的哈希，泄露也推不出密码
_web_attempts: dict = {}  # ip -> [失败时间戳]，10 分钟内 5 次失败就限流 10 分钟
_client_lock = asyncio.Lock()
_entity_lock = asyncio.Lock()

app = FastAPI(title="app", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def _security_headers(request, call_next):
    if WEB_PATH:
        raw = request.scope.get("path", "")
        prefix = "/" + WEB_PATH
        if raw == prefix or raw.startswith(prefix + "/"):
            rest = raw[len(prefix):] or "/"
            request.scope["path"] = rest
            request.scope["raw_path"] = rest.encode()
        else:
            return Response(status_code=404, content="Not Found")
    resp = await call_next(request)
    # 不加 CSP default-src：页面用了内联 script，严格 CSP 会直接打断；只加不会打断的防 framing / 嗅探头
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp


def _chmod_session():
    for path in (SESSION_PATH, SESSION_PATH + "-journal"):
        try:
            if path and __import__("os").path.exists(path):
                __import__("os").chmod(path, 0o600)
        except Exception:
            pass


def _client_ip(request):
    # nginx 是用 $remote_addr 覆盖写 X-Real-IP 的，伪造不了；X-Forwarded-For 是追加的，第一个值就是攻击者填的，绝不能当 IP 用。
    # 上一版只认 127.0.0.1/::1 是错的：程序跑在 Docker 里，nginx 连进来时容器里看到的来源是 Docker 网关 IP（如 172.18.0.1），不是回环，
    # 结果所有人都共用网关 IP 一个限流名额，别人输错 5 次就能把所有人锁在门外。
    # 修法：连接来源不是公网 IP 时才认 X-Real-IP——回环、私网（含 Docker 网关）、链路本地都算非公网，远程公网直连则不认任何头。
    # 这么认是安全的，因为应用端口只绑了宿主回环，远程攻击者到不了容器端口，只能走 nginx，而 nginx 会覆盖写 X-Real-IP。
    host = request.client.host if request.client else None
    real = request.headers.get("x-real-ip", "").strip()
    # 只认明确的代理来源，不用 is_global/is_private：Python 里文档段 203.0.113.x、198.51.100.x 的 is_global 也是 False，is_private 也是 True，
    # 靠这两个判断会把文档 IP 也当成可信代理。白名单只列回环、私网（含 Docker 网关 172.17/172.18）、链路本地、IPv6 本地。
    _trusted = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("::1/128"),
                ipaddress.ip_network("fe80::/10"), ipaddress.ip_network("fd00::/8")]
    if real and host:
        try:
            ipaddress.ip_address(real)
            host_ip = ipaddress.ip_address(host)
            if any(host_ip in net for net in _trusted):
                return real
        except ValueError:
            pass
    return host or "unknown"
_client: TelegramClient | None = None
_login_state: dict = {}  # 单用户：{"phone": ..., "phone_code_hash": ...}


def check_web_auth(request: Request):
    if not WEB_PASSWORD:
        raise HTTPException(status_code=401, detail="need_web_auth")
    token = request.cookies.get("web_token")
    exp = _web_sessions.get(token) if token else None
    if exp is None or exp < time.time():
        if token:
            _web_sessions.pop(token, None)
        raise HTTPException(status_code=401, detail="need_web_auth")


async def get_client() -> TelegramClient:
    global _client
    if not API_ID or not API_HASH:
        raise HTTPException(status_code=500, detail="服务器未配置凭证")
    async with _client_lock:
        if _client is None:
            _client = TelegramClient(SESSION_PATH, API_ID, API_HASH)
        if not _client.is_connected():
            await _client.connect()
        _chmod_session()
        return _client


@app.on_event("shutdown")
async def _shutdown_client():
    global _client
    if _client is not None and _client.is_connected():
        try:
            await _client.disconnect()
        except Exception:
            pass


def _tg_error(e):
    # 把 Telethon 抛出的错误翻译成用户能看懂的 400/429，不再直接 500
    name = type(e).__name__
    msg = str(e)
    up = msg.upper()
    if "FLOOD" in name.upper() or "FLOOD" in up:
        import re as _re
        m = _re.search(r"(\d+)", msg)
        sec = m.group(1) if m else "?"
        return 429, f"请求太频繁，请 {sec} 秒后再试"
    if "PHONE_CODE_INVALID" in up or "CODE_INVALID" in up:
        return 400, "验证码不对，请重新输入"
    if "PHONE_CODE_EXPIRED" in up or "CODE_EXPIRED" in up:
        return 400, "验证码已过期，请重新获取"
    if "PASSWORD_HASH_INVALID" in up or "PASSWORD_INVALID" in up:
        return 400, "两步验证密码不对"
    if "PHONE_NUMBER_INVALID" in up or "PHONE_INVALID" in up:
        return 400, "手机号格式不对，请带区号，如 +86138xxxxxxx"
    if "INVITE_HASH_EXPIRED" in up or "INVITE_EXPIRED" in up:
        return 400, "邀请链接已过期"
    if "INVITE_HASH_INVALID" in up or "INVITE_INVALID" in up:
        return 400, "邀请链接无效"
    if "USER_ALREADY_PARTICIPANT" in up or "ALREADY_PARTICIPANT" in up:
        return 400, "已经在群组里了"
    return 400, f"请求失败：{msg[:200]}" if msg else "请求失败"


async def require_login() -> TelegramClient:
    client = await get_client()
    if not await client.is_user_authorized():
        raise HTTPException(status_code=401, detail="未登录账号，请先登录")
    return client


# ---------- 网页密码 ----------
class WebLoginIn(BaseModel):
    password: str


@app.post("/api/web-login")
async def web_login(request: Request, body: WebLoginIn):
    if not WEB_PASSWORD:
        raise HTTPException(status_code=401, detail="网页密码未设置，请在服务器上用 tg reset-password 设置一个")
    ip = _client_ip(request)
    now = time.time()
    # 失败记录加上限：先清掉过期/空的，超过 1000 个 IP 就删掉最旧的一半，防止伪造 IP 撑大字典耗内存
    for k in list(_web_attempts.keys()):
        v = [ts for ts in _web_attempts[k] if now - ts < 600]
        if v:
            _web_attempts[k] = v
        else:
            _web_attempts.pop(k, None)
    if len(_web_attempts) > 1000:
        for k in sorted(_web_attempts.keys(), key=lambda x: min(_web_attempts[x]) if _web_attempts[x] else 0)[:500]:
            _web_attempts.pop(k, None)
    if len(_web_sessions) > 100:
        for k in list(_web_sessions.keys()):
            if _web_sessions[k] < now:
                _web_sessions.pop(k, None)
    attempts = _web_attempts.get(ip, [])
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="尝试太多次，请 10 分钟后再试")
    if not secrets.compare_digest(body.password or "", WEB_PASSWORD):
        attempts.append(now)
        _web_attempts[ip] = attempts
        raise HTTPException(status_code=401, detail="网页密码不对")
    _web_attempts.pop(ip, None)
    token = secrets.token_urlsafe(32)
    _web_sessions[token] = now + WEB_SESSION_DAYS * 24 * 3600
    resp = JSONResponse({"ok": True})
    secure = request.headers.get("x-forwarded-proto", "") == "https" or request.url.scheme == "https"
    resp.set_cookie("web_token", token, httponly=True, samesite="lax", path="/", secure=secure, max_age=WEB_SESSION_DAYS * 24 * 3600)
    return resp


# ---------- Telegram 登录 ----------
class PhoneIn(BaseModel):
    phone: str


class CodeIn(BaseModel):
    code: str


class PasswordIn(BaseModel):
    password: str


@app.get("/api/status")
async def status(request: Request):
    check_web_auth(request)
    if not API_ID or not API_HASH:
        return {"configured": False, "logged_in": False}
    try:
        client = await get_client()
        logged_in = await client.is_user_authorized()
        me = None
        if logged_in:
            u = await client.get_me()
            me = {"id": u.id, "name": (u.first_name or "") + (" " + u.last_name if u.last_name else ""),
                  "username": u.username}
        return {"configured": True, "logged_in": logged_in, "me": me}
    except Exception as e:
        return {"configured": True, "logged_in": False, "error": str(e)}


@app.post("/api/login")
async def login_phone(request: Request, body: PhoneIn):
    check_web_auth(request)
    client = await get_client()
    try:
        sent = await client.send_code_request(body.phone.strip())
    except Exception as e:
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    _login_state["phone"] = body.phone.strip()
    _login_state["phone_code_hash"] = sent.phone_code_hash
    return {"ok": True, "need_code": True}


@app.post("/api/code")
async def login_code(request: Request, body: CodeIn):
    check_web_auth(request)
    client = await get_client()
    phone = _login_state.get("phone")
    if not phone:
        raise HTTPException(status_code=400, detail="请先填手机号获取验证码")
    try:
        await client.sign_in(phone, body.code.strip(),
                             phone_code_hash=_login_state.get("phone_code_hash"))
    except SessionPasswordNeededError:
        return {"ok": False, "need_password": True}
    except Exception as e:
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    return {"ok": True, "logged_in": True}


@app.post("/api/password")
async def login_password(request: Request, body: PasswordIn):
    check_web_auth(request)
    client = await get_client()
    try:
        await client.sign_in(password=body.password)
    except Exception as e:
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    return {"ok": True, "logged_in": True}


@app.post("/api/web-logout")
async def web_logout(request: Request):
    check_web_auth(request)
    token = request.cookies.get("web_token")
    if token:
        _web_sessions.pop(token, None)
    resp = JSONResponse({"ok": True})
    resp.set_cookie("web_token", "", max_age=0, path="/", httponly=True, samesite="lax")
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    check_web_auth(request)
    client = await get_client()
    await client.log_out()
    return {"ok": True}


# ---------- 搜索 / 加频道 / 我的频道 ----------
# 搜到的实体缓存：Telethon 解析未加入的频道/群组需要 access_hash，只靠数字 id 解析会失败。
# 搜完立刻把实体存下来，后面点加入/聊天/视频时直接用缓存的实体，不再只靠数字 id。
_entity_cache: dict = {}
_entity_cache_by_username: dict = {}
_recently_joined: list = []

# 对话列表缓存：iter_dialogs(limit=1000) 原来在搜索、加入、我的频道、实体解析 5 处各拉一遍，
# 加入一次可能拉 2～3 遍，又慢又容易 FloodWait。缓存 5 分钟，5 分钟内所有地方共用同一份；
# 网页上加入/邀请加入成功时立刻失效，下一次拉取就是最新的。经 Telegram App 加入的，
# 最多晚 5 分钟才出现在列表里，这是缓存的代价。
_dialogs_cache: dict = {"time": 0.0, "dialogs": []}
_dialogs_lock = asyncio.Lock()
_DIALOGS_TTL = 300


async def _get_dialogs(client):
    async with _dialogs_lock:
        if _dialogs_cache["dialogs"] and time.time() - _dialogs_cache["time"] < _DIALOGS_TTL:
            return _dialogs_cache["dialogs"]
        dialogs = []
        async for dialog in client.iter_dialogs(limit=1000):
            dialogs.append(dialog)
            _cache_entity(dialog.entity)
        _dialogs_cache["dialogs"] = dialogs
        _dialogs_cache["time"] = time.time()
        return dialogs


def _invalidate_dialogs():
    _dialogs_cache["dialogs"] = []
    _dialogs_cache["time"] = 0.0


def _mark_recently_joined(entity):
    if entity is None:
        return
    eid = getattr(entity, "id", None)
    if eid is None:
        return
    _recently_joined[:] = [e for e in _recently_joined if getattr(e, "id", None) != eid]
    _recently_joined.insert(0, entity)
    del _recently_joined[50:]


def _cache_entity(entity):
    if entity is None:
        return
    eid = getattr(entity, "id", None)
    if eid is not None:
        _entity_cache[eid] = entity
    uname = getattr(entity, "username", None)
    if uname:
        _entity_cache_by_username[uname.lower()] = entity
def _chat_info(entity):
    return {"id": getattr(entity, "id", None),
            "title": getattr(entity, "title", None) or getattr(entity, "first_name", ""),
            "username": getattr(entity, "username", None),
            "type": "channel" if isinstance(entity, Channel) else "chat"}


@app.get("/api/search")
async def search(request: Request, q: str):
    check_web_auth(request)
    client = await require_login()
    q = q.strip()
    if not q:
        return {"results": []}
    results, seen = [], set()

    def add(entity):
        if entity is None or getattr(entity, "id", None) in seen:
            return
        seen.add(entity.id)
        _cache_entity(entity)
        results.append(_chat_info(entity))

    # 1) 直接解析：t.me/jisou、https://t.me/jisou、jisou、@jisou 一律当成 @jisou
    invite = "/+" in q or "joinchat" in q
    norm = None if invite else _normalize_username(q)
    target = norm if norm else q
    search_q = norm[1:] if norm else q  # 全局搜索要用干净的用户名，不能带 t.me/ 前缀
    if not invite:
        try:
            add(await client.get_entity(target))
        except Exception:
            pass
    # 2) Telegram 全局搜索（公开频道/群组/用户）
    try:
        res = await client(SearchRequest(q=search_q, limit=50))
        for c in res.chats:
            add(c)
    except Exception:
        pass
    # 3) 已加入的对话里按名字过滤（中文名、已加的私密频道主要靠这个）
    try:
        for dialog in await _get_dialogs(client):
            title = dialog.title or ""
            if q.lower() in title.lower() or (search_q and search_q.lower() in title.lower()):
                add(dialog.entity)
    except Exception:
        pass
    return {"results": results[:100]}



@app.get("/api/resolve")
async def resolve_entity(request: Request, username: str):
    check_web_auth(request)
    client = await require_login()
    q = username.strip()
    if "/+" in q or "joinchat" in q:
        raise HTTPException(status_code=400, detail="这是邀请链接，请用加入按钮加入，不要直接打开")
    norm = _normalize_username(q) or q
    if norm.startswith("@") and norm[1:].lower() in _entity_cache_by_username:
        return _chat_info(_entity_cache_by_username[norm[1:].lower()])
    try:
        entity = await client.get_entity(norm)
        _cache_entity(entity)
        return _chat_info(entity)
    except Exception:
        raise HTTPException(status_code=404, detail="找不到这个频道/群组，可能是私密的或用户名不对")


class JoinIn(BaseModel):
    channel: str  # @用户名 / t.me/... / t.me/+邀请码 / 数字 id


@app.post("/api/join")
async def join(request: Request, body: JoinIn):
    check_web_auth(request)
    client = await require_login()
    s = body.channel.strip()
    # 私密邀请链接
    m = re.search(r"t\.me/(?:\+|joinchat/)([A-Za-z0-9_-]+)", s)
    if m:
        try:
            res = await client(ImportChatInviteRequest(m.group(1)))
        except Exception as e:
            code, detail = _tg_error(e)
            raise HTTPException(status_code=code, detail=detail)
        entity = res.chats[0] if res.chats else None
        _mark_recently_joined(entity)
        _invalidate_dialogs()
        return {"ok": True, "joined": _chat_info(entity) if entity else None}
    # 数字 id：先在已加入对话里找，找不到再当 PeerChannel 解析（失败给 400 明示，不抛 500）
    entity = None
    if re.fullmatch(r"-?\d+", s):
        # Bot API 格式 -1001234567：Telethon 的频道 id 是去掉 -100 前缀的 1234567，不是 abs() 的 1001234567
        cands = []
        if s.startswith("-100"):
            cands.append(int(s[4:]))
        cands.append(abs(int(s)))
        for cid in cands:
            if cid in _entity_cache:
                entity = _entity_cache[cid]
                break
            for dialog in await _get_dialogs(client):
                if dialog.entity.id == cid:
                    entity = dialog.entity
                    _cache_entity(entity)
                    break
            if entity is not None:
                break
        if entity is None:
            for cid in cands:
                try:
                    entity = await client.get_entity(PeerChannel(cid))
                    break
                except Exception:
                    continue
            if entity is None:
                raise HTTPException(status_code=400, detail="找不到这个频道，请重新搜索一次再点加入")
    else:
        # jisou / t.me/jisou / @jisou 一律归一化成 @jisou 再解析
        arg = _normalize_username(s) or s
        if arg.startswith("@") and arg[1:].lower() in _entity_cache_by_username:
            entity = _entity_cache_by_username[arg[1:].lower()]
        else:
            try:
                entity = await client.get_entity(arg)
                _cache_entity(entity)
            except Exception:
                raise HTTPException(status_code=400, detail="找不到这个频道，请确认用户名/链接正确")
    # 已经在对话里就是已经加入/已经在群组里了，直接当成功（之前这里对 Chat 类型直接报错，
    # 导致已在群组里的结果点加入也失败，用户就看到“频道不能加入”）
    for dialog in await _get_dialogs(client):
        if dialog.entity.id == entity.id:
            _mark_recently_joined(entity)
            return {"ok": True, "joined": _chat_info(entity)}
    if not isinstance(entity, Channel):
        raise HTTPException(status_code=400, detail="这不是频道，这是群组/用户，无法用加入频道的方式加入；群组请用邀请链接，点聊天可以直接进入")
    try:
        await client(JoinChannelRequest(entity))
        _mark_recently_joined(entity)
        _invalidate_dialogs()
    except Exception as e:
        msg = str(e)
        if "ALREADY" in msg.upper() or "PARTICIPANT" in msg.upper():
            pass  # 已经加入了，当成功处理
        elif "PRIVATE" in msg.upper():
            raise HTTPException(status_code=400, detail="这个频道是私密的，需要邀请链接才能加入")
        else:
            raise HTTPException(status_code=400, detail=f"加入失败：{msg[:200]}")
    return {"ok": True, "joined": _chat_info(entity)}


@app.get("/api/channels")
async def my_channels(request: Request):
    check_web_auth(request)
    client = await require_login()
    out = []
    seen = set()
    for dialog in await _get_dialogs(client):
        e = dialog.entity
        _cache_entity(e)
        if isinstance(e, (Channel, Chat)) and e.id not in seen:
            seen.add(e.id)
            out.append(_chat_info(e))
    front = []
    for ent in _recently_joined:
        if ent.id not in seen:
            seen.add(ent.id)
            front.append(_chat_info(ent))
    return {"channels": front + out}


# ---------- 归一化：t.me/jisou / jisou / @jisou 都当成 @jisou ----------
def _normalize_username(s):
    if not s:
        return None
    s = s.strip()
    if "/+" in s or "joinchat" in s:
        return None  # 邀请码不是用户名，走邀请流程
    m = re.search(r"t\.me/(?:@)?([A-Za-z0-9_]+)", s)
    if m:
        if m.group(1) in ("c", "s"):
            return None  # t.me/c/123/45 是私密频道消息链接，t.me/s/xxx 是公开预览，都不是用户名
        return "@" + m.group(1)
    if s.startswith("@"):
        return s
    if re.fullmatch(r"[A-Za-z0-9_]+", s):
        return "@" + s
    return None


# ---------- 视频列表 ----------
async def _channel_entity(client, channel_id: int, username=None):
    # Bot API 格式的负 id 先归一化成 Telethon 的正 id
    if isinstance(channel_id, int) and channel_id < 0 and str(channel_id).startswith("-100"):
        channel_id = int(str(channel_id)[4:])
    # 先查缓存：缩略图/视频/流式播放每次都先遍历 1000 个对话会慢还容易 FloodWait
    if channel_id in _entity_cache:
        return _entity_cache[channel_id]
    uname = _normalize_username(username) if username else None
    if uname and uname[1:].lower() in _entity_cache_by_username:
        return _entity_cache_by_username[uname[1:].lower()]
    async with _entity_lock:
        # 锁里再查一次：30 张缩略图并发时，第一个遍历完缓存后，后面的直接命中，不再重复遍历
        if channel_id in _entity_cache:
            return _entity_cache[channel_id]
        if uname and uname[1:].lower() in _entity_cache_by_username:
            return _entity_cache_by_username[uname[1:].lower()]
        for dialog in await _get_dialogs(client):
            if dialog.entity.id == channel_id:
                return dialog.entity
    if uname:
        try:
            entity = await client.get_entity(uname)
            _cache_entity(entity)
            return entity
        except Exception:
            pass
    try:
        return await client.get_entity(PeerChannel(channel_id))
    except Exception:
        raise HTTPException(status_code=404, detail="找不到这个频道，请重新搜索一次再点进入")


# 消息对象缓存：缩略图一张、视频拖进度一次 Range，原来每次都 get_messages 重新取消息，
# 一页 30 张就是 30 次。列表加载时把消息对象存下来，缩略图/播放直接用，不再重复取。
# 只存消息元数据（媒体引用），不存视频字节，所以占内存很小；30 分钟过期，过期后回落到 get_messages。
_msg_cache: dict = {}
_MSG_TTL = 1800
_MSG_MAX = 2000


def _cache_msg(channel_id, msg):
    if msg is None:
        return
    key = (channel_id, msg.id)
    if len(_msg_cache) >= _MSG_MAX:
        oldest = sorted(_msg_cache.items(), key=lambda kv: kv[1][1])[:500]
        for k, _ in oldest:
            _msg_cache.pop(k, None)
    _msg_cache[key] = (msg, time.time())


def _cached_msg(channel_id, msg_id):
    item = _msg_cache.get((channel_id, msg_id))
    if item is None:
        return None
    msg, ts = item
    if time.time() - ts > _MSG_TTL:
        _msg_cache.pop((channel_id, msg_id), None)
        return None
    return msg


async def _get_message(client, channel_id, msg_id, username=None):
    msg = _cached_msg(channel_id, msg_id)
    if msg is not None:
        return msg
    entity = await _channel_entity(client, channel_id, username)
    msg = await client.get_messages(entity, ids=msg_id)
    if msg is not None:
        _cache_msg(channel_id, msg)
    return msg


# 按字节限的 LRU 图片缓存：原来原图按 100 张、缩略图按 300 张算，满了就一次全清，
# 原图 1～2MB 一张最坏吃一两百 MB，清完又全部重新下。改成按总字节淘汰最久没用的，
# 缩略图 20MB、原图 50MB；单张超上限的不缓存，避免一张大图把整个缓存挤空。
class _BytesLRU:
    def __init__(self, max_bytes):
        self.max_bytes = max_bytes
        self._data = {}
        self._order = []
        self._total = 0

    def get(self, key):
        if key not in self._data:
            return None
        self._order.remove(key)
        self._order.append(key)
        return self._data[key]

    def put(self, key, data):
        size = len(data)
        if size > self.max_bytes:
            return
        if key in self._data:
            self._total -= len(self._data[key])
            self._order.remove(key)
        self._data[key] = data
        self._order.append(key)
        self._total += size
        while self._total > self.max_bytes and self._order:
            old = self._order.pop(0)
            self._total -= len(self._data.pop(old))


def _video_info(msg):
    doc = msg.video or msg.document
    if doc is None:
        return None
    duration = None
    filename = None
    for a in doc.attributes or []:
        if isinstance(a, DocumentAttributeVideo):
            duration = a.duration
        if isinstance(a, DocumentAttributeFilename):
            filename = a.file_name
    # 标题优先级：说明文字 > 文件名 > 空（前端再用日期兜底，不再显示“无标题”）
    # 很多频道视频本身就没有说明文字，之前只取说明文字，所以看起来“没有名字”
    caption = (msg.text or "").strip()
    title = caption[:120] if caption else (filename[:120] if filename else None)
    return {"msg_id": msg.id,
            "title": title,
            "caption": caption[:120],
            "filename": filename,
            "date": msg.date.isoformat() if msg.date else None,
            "size": doc.size,
            "mime": doc.mime_type or "video/mp4",
            "duration": duration,
            "has_thumb": bool(getattr(doc, "thumbs", None))}


@app.get("/api/videos")
async def videos(request: Request, channel_id: int, limit: int = 30, offset_id: int = 0, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    limit = max(1, min(limit, 100))
    entity = await _channel_entity(client, channel_id, username)
    # offset_id 是上一页最后一个视频的 msg_id，Telethon 只返回比它更旧的消息（不含它本身）
    # 多取 1 条用来判断还有没有下一页
    out = []
    # 原来是 (limit+1)*3：已经用了只取视频的过滤器，服务端返回的就全是视频，没必要多取 3 倍。
    async for msg in client.iter_messages(entity, limit=limit + 1, offset_id=offset_id,
                                          filter=InputMessagesFilterVideo):
        _cache_msg(channel_id, msg)
        info = _video_info(msg)
        if info:
            out.append(info)
        if len(out) > limit:
            break
    has_more = len(out) > limit
    if has_more:
        out = out[:limit]
    return {"videos": out, "has_more": has_more,
            "next_offset_id": out[-1]["msg_id"] if has_more and out else None}



# ---------- 视频缩略图：取视频自带的最大缩略图，不下载正片 ----------
_thumb_cache = _BytesLRU(20 * 1024 * 1024)

def _sniff_image_type(data: bytes) -> str:
    if data.startswith(b"\xff\xd8"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG"):
        return "image/png"
    if data.startswith(b"RIFF") and b"WEBP" in data[:12]:
        return "image/webp"
    return "image/jpeg"


@app.get("/thumb/{channel_id}/{msg_id}")
async def thumb(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    key = (channel_id, msg_id)
    data = _thumb_cache.get(key)
    if data is None:
        msg = await _get_message(client, channel_id, msg_id, username)
        if msg is None:
            raise HTTPException(status_code=404, detail="找不到这条视频")
        # thumb=-1 取最大的那张缩略图；没有缩略图返回 None
        data = await client.download_media(msg, file=bytes, thumb=-1)
        if data is None:
            raise HTTPException(status_code=404, detail="这条视频没有缩略图")
        _thumb_cache.put(key, data)
    return Response(content=data, media_type=_sniff_image_type(data),
                    headers={"Cache-Control": "private, max-age=86400"})


# ---------- 聊天模式：全部消息（不只是视频）+ 发文字 ----------

def _inline_buttons(msg):
    # Telethon 1.45: msg.buttons 是 MessageButton 列表的列表，text / data / url / inline_query 都现成
    try:
        btns = getattr(msg, "buttons", None)
        if btns:
            rows = []
            for row in btns:
                r = []
                for b in row:
                    text = getattr(b, "text", "") or ""
                    data = getattr(b, "data", None)
                    url = getattr(b, "url", None)
                    query = getattr(b, "inline_query", None)
                    if data is not None:
                        typ = "callback"
                    elif url:
                        typ = "url"
                    elif query is not None:
                        typ = "switch"
                    else:
                        typ = "other"
                    r.append({"text": text, "type": typ, "url": url, "query": query})
                rows.append(r)
            return rows
    except Exception:
        pass
    # 旧版 reply_markup 兜底
    try:
        markup = getattr(msg, "reply_markup", None)
        rows = getattr(markup, "rows", None) if markup else None
        if rows:
            out = []
            for row in rows:
                r = []
                for b in getattr(row, "buttons", []):
                    text = getattr(b, "text", "") or ""
                    typ = "other"; url = None; query = None
                    bt = getattr(b, "type", None)
                    if bt is not None:
                        cls = type(bt).__name__
                        if "Callback" in cls:
                            typ = "callback"
                        elif "Url" in cls:
                            typ = "url"; url = getattr(bt, "url", None)
                        elif "SwitchInline" in cls:
                            typ = "switch"; query = getattr(bt, "query", None)
                    else:
                        if getattr(b, "data", None) is not None:
                            typ = "callback"
                        elif getattr(b, "url", None):
                            typ = "url"; url = b.url
                    r.append({"text": text, "type": typ, "url": url, "query": query})
                out.append(r)
            return out
    except Exception:
        pass
    return []


def _message_info(msg):
    doc = msg.video or msg.document
    duration = None
    filename = None
    if doc is not None:
        for a in doc.attributes or []:
            if isinstance(a, DocumentAttributeVideo):
                duration = a.duration
            if isinstance(a, DocumentAttributeFilename):
                filename = a.file_name
    if msg.photo:
        kind = "photo"
    elif msg.video or (doc is not None and (doc.mime_type or "").startswith("video/")):
        kind = "video"
    elif doc is not None:
        kind = "document"
    else:
        kind = "text"
    return {"msg_id": msg.id,
            "kind": kind,
            "text": (msg.text or "")[:2000],
            "date": msg.date.isoformat() if msg.date else None,
            "size": doc.size if doc is not None else None,
            "mime": doc.mime_type if doc is not None else None,
            "duration": duration,
            "filename": filename,
            "has_thumb": bool(doc is not None and getattr(doc, "thumbs", None)),
            "buttons": _inline_buttons(msg)}


@app.get("/api/messages")
async def messages(request: Request, channel_id: int, limit: int = 30, offset_id: int = 0, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    limit = max(1, min(limit, 100))
    entity = await _channel_entity(client, channel_id, username)
    out = []
    async for msg in client.iter_messages(entity, limit=limit + 1, offset_id=offset_id):
        _cache_msg(channel_id, msg)
        info = _message_info(msg)
        if info:
            out.append(info)
        if len(out) > limit:
            break
    has_more = len(out) > limit
    if has_more:
        out = out[:limit]
    # 返回最新在前，前端聊天页翻转成从旧到新显示
    return {"messages": out, "has_more": has_more,
            "next_offset_id": out[-1]["msg_id"] if has_more and out else None}


@app.get("/api/search-messages")
async def search_messages(request: Request, channel_id: int, q: str, limit: int = 30, offset_id: int = 0, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    limit = max(1, min(limit, 100))
    q = (q or "").strip()
    if not q:
        return {"messages": [], "has_more": False, "next_offset_id": None}
    entity = await _channel_entity(client, channel_id, username)
    out = []
    async for msg in client.iter_messages(entity, search=q, limit=limit + 1, offset_id=offset_id):
        _cache_msg(channel_id, msg)
        info = _message_info(msg)
        if info:
            out.append(info)
        if len(out) > limit:
            break
    has_more = len(out) > limit
    if has_more:
        out = out[:limit]
    return {"messages": out, "has_more": has_more,
            "next_offset_id": out[-1]["msg_id"] if has_more and out else None}


class CallbackIn(BaseModel):
    channel_id: int
    msg_id: int
    row: int
    col: int
    username: str | None = None


@app.post("/api/callback")
async def callback(request: Request, body: CallbackIn):
    check_web_auth(request)
    client = await require_login()
    entity = await _channel_entity(client, body.channel_id, body.username)
    msg = await client.get_messages(entity, ids=body.msg_id)
    if msg is None:
        raise HTTPException(status_code=404, detail="找不到这条消息")
    try:
        result = await msg.click(i=body.row, j=body.col)
    except Exception as e:
        if "Timeout" in type(e).__name__ or "timeout" in str(e).lower():
            return {"ok": True, "timeout": True}
        raise HTTPException(status_code=400, detail=f"点击失败：{str(e)[:200]}")
    if isinstance(result, str):
        return {"ok": True, "url": result}
    if result is None:
        return {"ok": True}
    return {"ok": True, "alert": getattr(result, "message", None), "url": getattr(result, "url", None)}


class SendIn(BaseModel):
    channel_id: int
    text: str
    username: str | None = None


@app.post("/api/send")
async def send_message(request: Request, body: SendIn):
    check_web_auth(request)
    client = await require_login()
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="消息不能为空")
    entity = await _channel_entity(client, body.channel_id, body.username)
    try:
        sent = await client.send_message(entity, text)
    except Exception as e:
        name = type(e).__name__
        msg = str(e)
        if "WriteForbidden" in name or "WRITE_FORBIDDEN" in msg or "CHAT_WRITE_FORBIDDEN" in msg:
            raise HTTPException(status_code=403, detail="这个频道不允许发言，广播频道只有管理员能发消息")
        if "AdminRequired" in name or "ADMIN" in msg:
            raise HTTPException(status_code=403, detail="这个频道不允许发言，需要管理员权限")
        raise HTTPException(status_code=400, detail=f"发送失败：{msg[:200]}")
    return {"ok": True, "message": _message_info(sent)}


_photo_cache = _BytesLRU(50 * 1024 * 1024)


@app.get("/photo/{channel_id}/{msg_id}")
async def photo(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    key = (channel_id, msg_id)
    data = _photo_cache.get(key)
    if data is None:
        msg = await _get_message(client, channel_id, msg_id, username)
        if msg is None or not msg.photo:
            raise HTTPException(status_code=404, detail="这条消息没有图片")
        data = await client.download_media(msg, file=bytes)
        if data is None:
            raise HTTPException(status_code=404, detail="图片下载失败")
        _photo_cache.put(key, data)
    return Response(content=data, media_type=_sniff_image_type(data),
                    headers={"Cache-Control": "private, max-age=86400"})


# ---------- 流式播放：按 Range 从 Telegram 取片段，不落盘 ----------
def _parse_range(range_header: str | None, total: int):
    # 返回 (start, end)，非法返回 None，调用方回 416；不要在这里抛 int() 的 ValueError 变成 500
    if not range_header or not range_header.startswith("bytes="):
        return 0, total - 1
    spec = range_header[6:].split(",")[0].strip()
    try:
        if spec.startswith("-"):
            n = int(spec[1:])
            if n <= 0:
                return None
            return max(0, total - n), total - 1
        parts = spec.split("-")
        if len(parts) != 2:
            return None
        start = int(parts[0]) if parts[0] else 0
        end = int(parts[1]) if parts[1] else total - 1
    except ValueError:
        return None
    if start < 0 or end < start or start >= total:
        return None
    return start, min(total - 1, end)


# 起播头缓存：每次点播放浏览器都会先要开头几百 KB 读视频信息（Safari 还会先发 bytes=0-1 探测）。
# 内存里缓存最近视频的前 512KB（总共最多 50MB，复用图片的 _BytesLRU），探测和元数据请求不用再走 Telegram。
# 只在本来就要下载 >=512KB 的请求里顺带攒满 512KB 才存，小探测（2 字节）不会为了攒缓存多下 Telegram 的流量，
# 也不会用 2 字节的头把之前攒好的 512KB 覆盖掉。
_HEAD_SIZE = 512 * 1024
_RANGE_CAP = 4 * 1024 * 1024
_head_cache = _BytesLRU(50 * 1024 * 1024)


@app.get("/stream/{channel_id}/{msg_id}")
async def stream(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    msg = await _get_message(client, channel_id, msg_id, username)
    if msg is None:
        raise HTTPException(status_code=404, detail="找不到这条视频")
    media = msg.media
    doc = msg.video or msg.document
    if media is None or doc is None:
        raise HTTPException(status_code=404, detail="这条消息没有视频")
    total = doc.size
    mime = doc.mime_type or "video/mp4"
    range_header = request.headers.get("range")
    parsed = _parse_range(range_header, total)
    if parsed is None:
        return Response(status_code=416, headers={"Content-Range": f"bytes */{total}"})
    start, end = parsed
    # 开放式 Range（bytes=X-，不是后缀 bytes=-N、不是闭合 bytes=X-Y、不是无 Range）才封顶 4MB：
    # 拖进度、关播放器时旧请求不用等发现断开才停，最多白费 4MB；浏览器拿到 206 + 真实 Content-Range 后
    # 需要更多数据时会自己接着要下一段，播放不受影响。无 Range 的整文件请求不封顶，否则直接下载会被截断。
    if range_header and re.fullmatch(r"bytes=\d+-", range_header.strip()):
        end = min(end, start + _RANGE_CAP - 1)
    length = end - start + 1

    headers = {"Accept-Ranges": "bytes", "Content-Length": str(length),
               "Cache-Control": "private, no-store"}
    if range_header:
        headers["Content-Range"] = f"bytes {start}-{end}/{total}"

    head = _head_cache.get((channel_id, msg_id))
    if head is not None and start < len(head):
        # 请求的整段都在已缓存的头里（Safari 探测、元数据小段）：直接回缓存，不走 Telegram
        if length <= len(head) - start:
            data = head[start:start + length]
            if range_header:
                return Response(content=data, status_code=206, media_type=mime, headers=headers)
            return Response(content=data, media_type=mime, headers=headers)
        # 头只覆盖前半段：先回缓存的头，再从 Telegram 接着拉剩余部分
        cached_part = head[start:]
        remainder_start = len(head)
        remainder_length = length - len(cached_part)

        async def gen_cached():
            yield cached_part
            remaining = remainder_length
            async for chunk in client.iter_download(media, offset=remainder_start, file_size=total):
                if remaining <= 0:
                    break
                chunk = chunk[:remaining]
                remaining -= len(chunk)
                yield chunk

        return StreamingResponse(gen_cached(), status_code=206 if range_header else 200,
                                 media_type=mime, headers=headers)

    async def gen():
        # Telethon 的 limit 是分块数，不是字节数，传 limit=length 会一直下到文件末尾，
        # 发出的数据比 Content-Length 多，uvicorn 会断开；Safari 发 bytes=0-1 探测时尤其明显。
        # 这里不传 limit，按字节截断，剩 0 就停。
        remaining = length
        head_buf = bytearray()
        head_stored = False
        async for chunk in client.iter_download(media, offset=start, file_size=total):
            if remaining <= 0:
                break
            chunk = chunk[:remaining]
            remaining -= len(chunk)
            yield chunk
            if start == 0 and not head_stored and len(head_buf) < _HEAD_SIZE:
                head_buf.extend(chunk[:_HEAD_SIZE - len(head_buf)])
                if len(head_buf) >= _HEAD_SIZE or (remaining == 0 and len(head_buf) == total):
                    _head_cache.put((channel_id, msg_id), bytes(head_buf))
                    head_stored = True

    if range_header:
        return StreamingResponse(gen(), status_code=206, media_type=mime, headers=headers)
    return StreamingResponse(gen(), media_type=mime, headers=headers)


@app.get("/")
async def index():
    return FileResponse("index.html")
