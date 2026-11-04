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
from collections import OrderedDict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from telethon import TelegramClient
from telethon.errors import FileReferenceExpiredError, FloodWaitError, SessionPasswordNeededError
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.functions.messages import ImportChatInviteRequest
from telethon.tl.types import Channel, Chat, User, DocumentAttributeFilename, DocumentAttributeVideo, PeerChannel, InputMessagesFilterVideo

API_ID = int(os.environ.get("TG_API_ID", "0") or 0)
API_HASH = os.environ.get("TG_API_HASH", "")
SESSION_PATH = os.environ.get("TG_SESSION", "data/tg.session")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
WEB_PATH = os.environ.get("WEB_PATH", "").strip().strip("/")
WEB_SESSION_DAYS = 30


def _clamp_parallel(v):
    try:
        n = int(v)
    except Exception:
        return 2
    return max(1, min(4, n))


# 并行下载数：全局设置，默认 2，tg set-parallel 最多改到 4（再多容易 FloodWait）。
# 读启动时的环境变量，改完要重启容器才生效，和 WEB_PASSWORD / WEB_PATH 一样。
PARALLEL = _clamp_parallel(os.environ.get("TG_PARALLEL", "2"))
# 全局并发下载任务封顶也是 4：一个视频用满 4 个时，别的视频要等当前窗口放出名额，
# 避免多个视频同时播时总并发超标。缩略图/图片是小文件单次下载，不占这个名额，否则 30 张图会把视频饿死。
_download_sem = asyncio.Semaphore(4)
_web_sessions: dict = {}  # token -> expiry timestamp，cookie 本身不再是密码的哈希，泄露也推不出密码
_web_attempts: dict = {}  # ip -> [失败时间戳]，10 分钟内 5 次失败就限流 10 分钟
# Telegram 登录限流，和网页密码限流分开记：发验证码、验证码、二次密码各算一次，
# 成功发码不算“清零”（否则反复发码就能绕开验证码爆破计数），只有整套登录成功才清。
_tg_attempts: dict = {}  # ip -> [失败时间戳]


def _tg_failures(ip):
    now = time.time()
    v = [ts for ts in _tg_attempts.get(ip, []) if now - ts < 600]
    _tg_attempts[ip] = v
    if len(_tg_attempts) > 1000:
        for k in sorted(_tg_attempts.keys(), key=lambda x: min(_tg_attempts[x]) if _tg_attempts[x] else 0)[:500]:
            _tg_attempts.pop(k, None)
        v = _tg_attempts.get(ip, [])
    return v


def _tg_rate_limited(ip):
    return len(_tg_failures(ip)) >= 5


def _tg_record_failure(ip):
    _tg_attempts.setdefault(ip, []).append(time.time())


def _tg_clear(ip):
    _tg_attempts.pop(ip, None)
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
# 手机号和验证码哈希只在内存里留着，第一步到第二步之间要用，验证完就删，
# 从来不写磁盘、不写日志、不进 session 文件。二次验证密码连这里都不进，
# 只在验证那一下传给 sign_in，用完就清。
_login_state: dict = {}  # 单用户：{"phone": ..., "phone_code_hash": ...}，或 {"need_password": True}


def _clear_login_state():
    _login_state.clear()


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
        # 先清过期的；还超就按过期时间从早到晚踢掉最旧的，只留 100 个。
        # 以前只清过期，100 个都有效时字典就一直涨，重启前不会收敛。
        for k in list(_web_sessions.keys()):
            if _web_sessions[k] < now:
                _web_sessions.pop(k, None)
        if len(_web_sessions) > 100:
            for k in sorted(_web_sessions.keys(), key=lambda x: _web_sessions[x])[:len(_web_sessions) - 100]:
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
    ip = _client_ip(request)
    if _tg_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Telegram 登录尝试太多次，请 10 分钟后再试")
    client = await get_client()
    phone = body.phone.strip()
    body.phone = ""
    try:
        sent = await client.send_code_request(phone)
    except Exception as e:
        _tg_record_failure(ip)
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    _login_state.clear()
    _login_state["phone"] = phone
    _login_state["phone_code_hash"] = sent.phone_code_hash
    return {"ok": True, "need_code": True}


@app.post("/api/code")
async def login_code(request: Request, body: CodeIn):
    check_web_auth(request)
    ip = _client_ip(request)
    if _tg_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Telegram 登录尝试太多次，请 10 分钟后再试")
    client = await get_client()
    phone = _login_state.get("phone")
    if not phone:
        raise HTTPException(status_code=400, detail="请先填手机号获取验证码")
    code = body.code.strip()
    body.code = ""
    try:
        await client.sign_in(phone, code,
                             phone_code_hash=_login_state.get("phone_code_hash"))
    except SessionPasswordNeededError:
        # 验证码已通过，手机号和哈希不再需要，二次验证那步不用它们，直接删，
        # 但要留一个 need_password 标记：/api/password 只认这个标记，不认直接调用。
        _login_state.clear()
        _login_state["need_password"] = True
        return {"ok": False, "need_password": True}
    except Exception as e:
        # 验证码不对时不删，留着让用户直接重填验证码重试，不用重新发；
        # 成功、需要二次验证、退出、重启、下一次填新手机号时都会清掉
        _tg_record_failure(ip)
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    # 验证码已通过，手机号和哈希用完就删
    _clear_login_state()
    _tg_clear(ip)
    return {"ok": True, "logged_in": True}


@app.post("/api/password")
async def login_password(request: Request, body: PasswordIn):
    check_web_auth(request)
    ip = _client_ip(request)
    if _tg_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Telegram 登录尝试太多次，请 10 分钟后再试")
    # 以前这里不校验状态：没走过验证码那一步也能直接调它试二次密码。
    # 现在只认 /api/code 走到二次验证时留下的标记，密码错了标记还在，
    # 可以直接重输密码重试，不用重新收验证码；成功后标记清掉。
    if not _login_state.get("need_password"):
        raise HTTPException(status_code=400, detail="请先填手机号和验证码，走到二次验证这一步再输密码")
    client = await get_client()
    pw = body.password
    body.password = ""
    try:
        await client.sign_in(password=pw)
    except Exception as e:
        _tg_record_failure(ip)
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    finally:
        pw = ""
    _clear_login_state()
    _tg_clear(ip)
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
    _clear_login_state()
    client = await get_client()
    await client.log_out()
    _clear_login_state()
    return {"ok": True}


# ---------- 搜索 / 加频道 / 我的频道 ----------
# 搜到的实体缓存：Telethon 解析未加入的频道/群组需要 access_hash，只靠数字 id 解析会失败。
# 搜完立刻把实体存下来，后面点加入/聊天/视频时直接用缓存的实体，不再只靠数字 id。
_entity_cache: dict = {}
_entity_cache_by_username: dict = {}
_recently_joined: list = []
# 实体缓存以前永不过期、只按数字 id 存：搜到后改名、退群、换号都还是旧实体，
# _recently_joined 更是重启前一直留着。改成 30 分钟过期、最多 2000 条，
# 最近加入的也只保留 1 小时，过期后下次走 get_entity / 对话列表重新取。
_ENTITY_TTL = 1800
_ENTITY_MAX = 2000
_RECENTLY_JOINED_TTL = 3600
_entity_cache_time: dict = {}
_entity_cache_by_username_time: dict = {}
_recently_joined_time: dict = {}


def _cached_entity(eid):
    ent = _entity_cache.get(eid)
    if ent is None:
        return None
    if time.time() - _entity_cache_time.get(eid, 0) > _ENTITY_TTL:
        _entity_cache.pop(eid, None)
        _entity_cache_time.pop(eid, None)
        return None
    return ent


def _cached_entity_by_username(uname_lower):
    ent = _entity_cache_by_username.get(uname_lower)
    if ent is None:
        return None
    if time.time() - _entity_cache_by_username_time.get(uname_lower, 0) > _ENTITY_TTL:
        _entity_cache_by_username.pop(uname_lower, None)
        _entity_cache_by_username_time.pop(uname_lower, None)
        return None
    return ent

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
    _recently_joined_time[eid] = time.time()
    del _recently_joined[50:]


def _cache_entity(entity):
    if entity is None:
        return
    eid = getattr(entity, "id", None)
    if eid is not None:
        if len(_entity_cache) >= _ENTITY_MAX and eid not in _entity_cache:
            oldest = sorted(_entity_cache_time.items(), key=lambda kv: kv[1])[:500]
            for k, _ in oldest:
                _entity_cache.pop(k, None)
                _entity_cache_time.pop(k, None)
        _entity_cache[eid] = entity
        _entity_cache_time[eid] = time.time()
    uname = getattr(entity, "username", None)
    if uname:
        _entity_cache_by_username[uname.lower()] = entity
        _entity_cache_by_username_time[uname.lower()] = time.time()
def _chat_info(entity):
    # 机器人是 User 类型，不是 Channel/Chat：原来 type 一律算 chat，搜索里也分不出来。
    # 超级群组在 Telethon 里也是 Channel，但对用户来说它是群组：删的时候文案写“群组”
    # 才对，写“频道”会让人以为退的是频道，动作虽然一样，提示不能错。
    if isinstance(entity, Channel) and getattr(entity, "megagroup", False):
        typ = "chat"
    elif isinstance(entity, Channel):
        typ = "channel"
    elif isinstance(entity, User) and getattr(entity, "bot", False):
        typ = "bot"
    elif isinstance(entity, User):
        # 私聊：原来一律算 chat，搜索结果里会显示成群组，删除提示也会写错。
        # 现在单独算 private，删除时文案写“私聊”才对。
        typ = "private"
    else:
        typ = "chat"
    return {"id": getattr(entity, "id", None),
            "title": getattr(entity, "title", None) or getattr(entity, "first_name", ""),
            "username": getattr(entity, "username", None),
            "type": typ}


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
    if norm.startswith("@"):
        _cached = _cached_entity_by_username(norm[1:].lower())
        if _cached is not None:
            return _chat_info(_cached)
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
            entity = _cached_entity(cid)
            if entity is not None:
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
        if arg.startswith("@"):
            entity = _cached_entity_by_username(arg[1:].lower())
            if entity is None:
                try:
                    entity = await client.get_entity(arg)
                    _cache_entity(entity)
                except Exception:
                    raise HTTPException(status_code=400, detail="找不到这个频道，请确认用户名/链接正确")
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


class LeaveIn(BaseModel):
    channel_id: int
    username: str | None = None


@app.post("/api/leave")
async def leave_channel(request: Request, body: LeaveIn):
    # 删除频道/群组/机器人：全部频道列表里三种都会出现，所以这里不分类型，
    # 一律用 Telethon 的 delete_dialog：频道和群组就是退出，机器人就是删对话。
    # 私密频道/群组退出后没有邀请链接就回不来了，前端长按弹出的确认框里会先说明这一点。
    # 频道创建者等删不掉的情况会直接报 Telegram 的错，不会假装成功。
    check_web_auth(request)
    client = await require_login()
    entity = await _channel_entity(client, body.channel_id, body.username)
    # 私聊也要能删：上一版这里拦了私聊 User，现在按用户要求放开。
    # Telethon 的 delete_dialog 对 User 就是清对话记录（只清自己这边，revoke 默认关），
    # 不会动对方那边的记录，频道/群组/机器人还是原来的退出/清对话。
    info = _chat_info(entity)
    try:
        await client.delete_dialog(entity)
    except Exception as e:
        code, detail = _tg_error(e)
        raise HTTPException(status_code=code, detail=detail)
    _invalidate_dialogs()
    _recently_joined[:] = [e for e in _recently_joined if getattr(e, "id", None) != entity.id]
    _recently_joined_time.pop(entity.id, None)
    _entity_cache.pop(entity.id, None)
    _entity_cache_time.pop(entity.id, None)
    for uname in list(_entity_cache_by_username.keys()):
        ent = _entity_cache_by_username[uname]
        if getattr(ent, "id", None) == entity.id:
            _entity_cache_by_username.pop(uname, None)
            _entity_cache_by_username_time.pop(uname, None)
    return {"ok": True, "deleted": info}


@app.get("/api/channels")
async def my_channels(request: Request):
    check_web_auth(request)
    client = await require_login()
    out = []
    seen = set()
    for dialog in await _get_dialogs(client):
        e = dialog.entity
        _cache_entity(e)
        # 原来只算 Channel/Chat，机器人是 User，被过滤掉了：刚加入时靠内存里的 _recently_joined
        # 临时顶在前面才看得到，服务一重启（重新 build、改密码、改路径都会重启容器）临时列表就清空，
        # 机器人就从所有频道里消失了，但其实你从没离开过，消息当然还在。改成机器人也算上，
        # 普通私聊 User 还是不算（只给自己用，不想把私聊都摊在列表里）。
        is_bot = isinstance(e, User) and getattr(e, "bot", False)
        if (isinstance(e, (Channel, Chat)) or is_bot) and e.id not in seen:
            seen.add(e.id)
            out.append(_chat_info(e))
    # 最近加入的只保留 1 小时：以前是重启前一直留着，在 Telegram App 里退了群，
    # 这里还一直顶在前面，点进去才报错。现在超时的直接从列表里清掉。
    now = time.time()
    _recently_joined[:] = [e for e in _recently_joined
                           if now - _recently_joined_time.get(getattr(e, "id", None), now) <= _RECENTLY_JOINED_TTL]
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
    # 这里走带过期时间的 helper，不直接查字典，否则 30 分钟 TTL 等于没设。
    _cached = _cached_entity(channel_id)
    if _cached is not None:
        return _cached
    uname = _normalize_username(username) if username else None
    if uname:
        _cached = _cached_entity_by_username(uname[1:].lower())
        if _cached is not None:
            return _cached
    async with _entity_lock:
        # 锁里再查一次：30 张缩略图并发时，第一个遍历完缓存后，后面的直接命中，不再重复遍历
        _cached = _cached_entity(channel_id)
        if _cached is not None:
            return _cached
        if uname:
            _cached = _cached_entity_by_username(uname[1:].lower())
            if _cached is not None:
                return _cached
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
    # OrderedDict 版：get/put 的“移到最新”都是 O(1)，不再用列表 remove（O(n) 线性扫描）。
    # 淘汰从最旧一端 pop，同样 O(1)，总字节数单独记，不用每次求和。
    def __init__(self, max_bytes):
        self.max_bytes = max_bytes
        self._data = OrderedDict()
        self._total = 0

    def get(self, key):
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key, data):
        size = len(data)
        if size > self.max_bytes:
            return
        if key in self._data:
            self._total -= len(self._data[key])
            del self._data[key]
        self._data[key] = data
        self._total += size
        while self._total > self.max_bytes and self._data:
            _old_key, old_data = self._data.popitem(last=False)
            self._total -= len(old_data)


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
    replies_obj = getattr(msg, "replies", None)
    replies_count = 0
    has_comments = False
    if replies_obj is not None:
        try:
            replies_count = int(getattr(replies_obj, "replies", 0) or 0)
            has_comments = bool(getattr(replies_obj, "channel_id", None))
        except Exception:
            pass
    return {"msg_id": msg.id,
            "title": title,
            "caption": caption[:120],
            "filename": filename,
            "date": msg.date.isoformat() if msg.date else None,
            "size": doc.size,
            "mime": doc.mime_type or "video/mp4",
            "duration": duration,
            "has_thumb": bool(getattr(doc, "thumbs", None)),
            "replies": replies_count,
            "has_comments": has_comments}


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
    # 照片尺寸：前端用 width/height 属性先把位置占好，图片后加载时高度不变，
    # 否则先只显示日期，图片一到就把下面内容顶下去，加载更早消息时就会跳。
    # 没尺寸的照片（极少）就返回空，前端按老样子显示，仍可能轻微跳一下。
    pw = ph = None
    if msg.photo:
        try:
            sizes = [s for s in (msg.photo.sizes or [])
                     if getattr(s, "w", None) and getattr(s, "h", None)]
            if sizes:
                best = max(sizes, key=lambda s: s.w * s.h)
                pw, ph = best.w, best.h
        except Exception:
            pw = ph = None
    # 发送人：App 样式的气泡、头像、名字用。sender 可能是 User 或 Channel，
    # 没有就是 None（比如已删号），频道帖子还可能只有 post_author 签名。
    sender = getattr(msg, "sender", None)
    sender_name = None
    sender_username = None
    sender_is_user = False
    if sender is not None:
        try:
            first = getattr(sender, "first_name", "") or ""
            last = getattr(sender, "last_name", "") or ""
            sender_name = (first + (" " + last if last else "")).strip()
            if not sender_name:
                sender_name = getattr(sender, "title", "") or getattr(sender, "username", "") or None
            sender_username = getattr(sender, "username", None)
            # User 才有 first_name/last_name，Channel 只有 title，靠这个区分
            sender_is_user = bool(first or last or getattr(sender, "username", None)) and getattr(sender, "title", None) is None
            # 更稳妥：User 类型没有 title 属性以外的频道特征，上面已够用；
            # 如果 sender 是频道，名字就是频道名，前端按频道帖子处理（不显示头像名字）
            if getattr(sender, "title", None):
                sender_is_user = False
        except Exception:
            sender_name = None
            sender_username = None
            sender_is_user = False
    elif getattr(msg, "post_author", None):
        sender_name = msg.post_author
    # 评论：频道帖子的评论不在频道本身，在关联的讨论组里。
    # msg.replies 就是 Telegram 给的评论信息：replies 是条数，channel_id 是讨论组 id，
    # 没有就是 0 / 没有评论区，前端只在有评论区时才显示“查看评论”按钮。
    replies_obj = getattr(msg, "replies", None)
    replies_count = 0
    has_comments = False
    if replies_obj is not None:
        try:
            replies_count = int(getattr(replies_obj, "replies", 0) or 0)
            has_comments = bool(getattr(replies_obj, "channel_id", None))
        except Exception:
            replies_count = 0
            has_comments = False
    return {"msg_id": msg.id,
            "replies": replies_count,
            "has_comments": has_comments,
            "kind": kind,
            "text": (msg.text or "")[:2000],
            "date": msg.date.isoformat() if msg.date else None,
            "size": doc.size if doc is not None else None,
            "mime": doc.mime_type if doc is not None else None,
            "duration": duration,
            "filename": filename,
            "has_thumb": bool(doc is not None and getattr(doc, "thumbs", None)),
            "pw": pw,
            "ph": ph,
            "sender_id": getattr(msg, "sender_id", None),
            "sender_name": sender_name,
            "sender_username": sender_username,
            "sender_is_user": sender_is_user,
            "out": bool(getattr(msg, "out", False)),
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


async def _discussion_info(client, channel_id, msg_id, username=None):
    # 找帖子的讨论组：先取原帖，再用 Telethon 的 GetDiscussionMessage 拿到讨论组 peer
    # 和原帖在讨论组里的那条镜像消息 id，评论就是回复那条镜像消息的消息。
    # _get_comment_data 是 Telethon 内部方法（1.45 里有），没有公开的取评论接口，
    # 所以直接用它，失败就当没有评论区处理，不让整个页面报错。
    msg = await _get_message(client, channel_id, msg_id, username)
    if msg is None:
        return None
    entity = await _channel_entity(client, channel_id, username)
    try:
        peer, disc_msg_id = await client._get_comment_data(entity, msg)
    except Exception:
        return None
    disc_channel_id = getattr(peer, "channel_id", None)
    return (peer, disc_msg_id, disc_channel_id, msg)


@app.get("/api/comments")
async def comments(request: Request, channel_id: int, msg_id: int, limit: int = 30, offset_id: int = 0, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    limit = max(1, min(limit, 100))
    disc = await _discussion_info(client, channel_id, msg_id, username)
    if disc is None:
        raise HTTPException(status_code=404, detail="这个帖子没有评论区")
    peer, disc_msg_id, disc_channel_id, _orig = disc
    out = []
    async for msg in client.iter_messages(peer, reply_to=disc_msg_id, limit=limit + 1, offset_id=offset_id):
        if disc_channel_id:
            _cache_msg(disc_channel_id, msg)
        info = _message_info(msg)
        if info:
            out.append(info)
        if len(out) > limit:
            break
    has_more = len(out) > limit
    if has_more:
        out = out[:limit]
    return {"messages": out, "has_more": has_more,
            "next_offset_id": out[-1]["msg_id"] if has_more and out else None,
            "discussion_channel_id": disc_channel_id,
            "discussion_msg_id": disc_msg_id}


class CommentIn(BaseModel):
    channel_id: int
    msg_id: int
    text: str
    username: str | None = None


@app.post("/api/comment")
async def post_comment(request: Request, body: CommentIn):
    check_web_auth(request)
    client = await require_login()
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="评论不能为空")
    disc = await _discussion_info(client, body.channel_id, body.msg_id, body.username)
    if disc is None:
        raise HTTPException(status_code=404, detail="这个帖子没有评论区")
    peer, disc_msg_id, disc_channel_id, _orig = disc
    try:
        sent = await client.send_message(peer, text, reply_to=disc_msg_id)
    except Exception as e:
        name = type(e).__name__
        msg = str(e)
        if "WriteForbidden" in name or "WRITE_FORBIDDEN" in msg or "CHAT_WRITE_FORBIDDEN" in msg:
            raise HTTPException(status_code=403, detail="这个讨论组不允许发言")
        if "AdminRequired" in name or "ADMIN" in msg:
            raise HTTPException(status_code=403, detail="这个讨论组不允许发言，需要权限")
        raise HTTPException(status_code=400, detail=f"评论发送失败：{msg[:200]}")
    if disc_channel_id:
        _cache_msg(disc_channel_id, sent)
    return {"ok": True, "message": _message_info(sent), "discussion_channel_id": disc_channel_id}


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
_avatar_cache = _BytesLRU(20 * 1024 * 1024)


@app.get("/avatar/{channel_id}/{msg_id}")
async def avatar(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    # 按消息找发送人头像：先从消息缓存里拿原消息，再按发送人 id 查头像缓存，
    # 没缓存才走一次 Telegram 下载，之后都走缓存，内存有 20MB 上限，不会无限涨。
    # 没有头像（或发送人未知）就 404，前端会显示首字母占位，不会破图。
    check_web_auth(request)
    client = await require_login()
    msg = await _get_message(client, channel_id, msg_id, username)
    if msg is None:
        raise HTTPException(status_code=404, detail="找不到这条消息")
    sender = getattr(msg, "sender", None)
    sender_id = getattr(msg, "sender_id", None)
    if sender is None or sender_id is None:
        raise HTTPException(status_code=404, detail="这条消息没有发送人头像")
    data = _avatar_cache.get(sender_id)
    if data is None:
        try:
            data = await client.download_profile_photo(sender, file=bytes)
        except Exception:
            data = None
        if not data:
            raise HTTPException(status_code=404, detail="发送人没有头像")
        _avatar_cache.put(sender_id, data)
    return Response(content=data, media_type=_sniff_image_type(data),
                    headers={"Cache-Control": "private, max-age=86400"})


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
_RANGE_CAP = 16 * 1024 * 1024
_CHUNK = 512 * 1024  # Telethon 的 request_size 默认就是 512KB，对齐这个尺寸下才不浪费
_head_cache = _BytesLRU(50 * 1024 * 1024)


async def _download_one_chunk(client, media, total, chunk_start, chunk_len):
    # 只取一个 512KB 对齐块：调用方保证 chunk_start 是 512KB 倍数（首块除外，首块在调用方对齐后自己裁掉前面的 skip），
    # 这样 Telethon 不用走 Generic 的“每块多下 512KB 再裁”路线，实测单连接几百 KB/s 时这点很关键。
    # 全局信号量在这里拿：4 个任务占满时，后来的窗口要等，不会无限制并发去撞 FloodWait。
    # 取完第一块必须 close 迭代器：不同 DC 时它会借一个 exported sender，不还回去会越借越多。
    # 不要只取迭代器的第一个 yield 就返回：正常是 512KB 一块，但万一 Telethon
    # 切成更小的片，只取第一片就会少字节，Content-Length 对不上，流就悄悄短一截。
    # 攒满 chunk_len 才返回，不够就说明文件被改小了，调用方按空块报错处理。
    async with _download_sem:
        it = client.iter_download(media, offset=chunk_start, file_size=total)
        buf = bytearray()
        try:
            async for chunk in it:
                buf.extend(chunk)
                if len(buf) >= chunk_len:
                    break
            return bytes(buf[:chunk_len])
        finally:
            close = getattr(it, "close", None)
            if close is not None:
                try:
                    res = close()
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    pass


async def _refresh_media(client, channel_id, msg_id, username=None):
    # FileReference 过期时用：跳过消息缓存，删掉旧缓存再重新 get_messages 取一次，
    # 新消息里的媒体引用是新的，旧引用再下就会一直过期。取不到就返回 None，调用方再报错。
    if channel_id is None or msg_id is None:
        return None
    _msg_cache.pop((channel_id, msg_id), None)
    try:
        msg = await _get_message(client, channel_id, msg_id, username)
    except Exception:
        return None
    return msg.media if msg is not None else None


async def _parallel_gen(client, media, total, start, end, channel_id=None, msg_id=None, username=None):
    # 滑动窗口并行下，不再是“分组”：窗口 = 并行数 × 512KB（默认 2 → 1MB，改到 4 → 2MB），
    # 始终保持并行数个块在下载，最前面一块一交给浏览器就立刻补发下一块，不用等整组都回来。
    # 以前是分组：并行 2 时 A 快 B 慢，A 交出后要等 B 回来才开始下 C，C 的下载和 B 的等待是串行的；
    # 现在 A 一交出 C 就开始和 B 并行下，B 交出后 D 也立刻开始，组与组之间那个完整往返的空档没了。
    # 内存不变：同一时刻在途的还是并行数个块（已下完但还没按顺序交出的块本来就在窗口里），
    # 并发数也不变：新块只在旧块交出时补发，不是一口气全发出去，全局信号量还是 4 封顶。
    # 起点不对齐时：先从对齐起点下首块、自己裁掉前面的 skip，只浪费首块前面不到 512KB，
    # 后面所有块都是对齐的，不会像直接把不对齐起点交给 Telethon 那样每块都多下 512KB。
    # 播放中途报错有重试（只针对已经开始发的流，开始前取消息失败还是直接报 HTTP 错）：
    # FloodWait 且 seconds <= 30：原地 sleep 这么久后重试这一块，超过 30 秒或重试 3 次还不行就报错断流；
    # 以前是 5 秒，Telegram 动不动就给十几秒，5 秒一到就断流，播放器还以为流正常结束了。
    # nginx 的 proxy_read_timeout 是 3600 秒，等 30 秒不会被代理先掐掉，卡一下总比直接断好。
    # FileReferenceExpired：跳过消息缓存重取一次消息，用新媒体引用重试这一块，最多重取 2 次。
    # 空块不再悄悄 break：Content-Length 已经发出去了，空块直接结束等于告诉浏览器“流正常播完了”，
    # 实际是少了一截；现在改成抛错断开连接，播放器会按缺失段重新发 Range 请求续上。
    # 浏览器断开/拖进度时，生成器被取消，在途任务一并取消，不会继续白下 Telegram 的流量。
    aligned_start = (start // _CHUNK) * _CHUNK
    skip = start - aligned_start
    specs = []
    p = aligned_start
    while p <= end:
        # 首块的下载长度：从对齐起点到请求终点（不超过一整块），调用方再裁掉前面的 skip；
        # 其余块就是本块在请求范围内的长度（最后一块可能不足 512KB）。
        # 注意不能用 total-p：小范围（比如 Safari 0-1 探测）终点就在首块内，用 total 会多回一整块，超 Content-Length。
        if p == aligned_start:
            dl_len = min(_CHUNK, end - aligned_start + 1)
        else:
            dl_len = min(_CHUNK, end - p + 1)
        specs.append((p, dl_len))
        p += _CHUNK
    if not specs:
        return
    cur_media = media
    in_flight = {}
    next_to_issue = 0
    next_to_yield = 0
    head_buf = bytearray()

    def _issue(idx):
        s, l = specs[idx]
        in_flight[idx] = asyncio.create_task(_download_one_chunk(client, cur_media, total, s, l))

    try:
        while next_to_issue < min(PARALLEL, len(specs)):
            _issue(next_to_issue)
            next_to_issue += 1
        while next_to_yield < len(specs):
            idx = next_to_yield
            flood_retries = 0
            ref_retries = 0
            while True:
                try:
                    data = await in_flight[idx]
                    break
                except asyncio.CancelledError:
                    raise
                except FloodWaitError as e:
                    secs = getattr(e, "seconds", None)
                    if secs is not None and secs <= 30 and flood_retries < 3:
                        flood_retries += 1
                        try:
                            await asyncio.sleep(secs)
                        except asyncio.CancelledError:
                            raise
                        _issue(idx)
                        continue
                    raise
                except FileReferenceExpiredError:
                    if ref_retries < 2:
                        ref_retries += 1
                        new_media = await _refresh_media(client, channel_id, msg_id, username)
                        if new_media is not None:
                            cur_media = new_media
                            _issue(idx)
                            continue
                    raise
            # 这一块交出去了，窗口空出一个名额，立刻补发下一块（如果还有的话）
            del in_flight[idx]
            next_to_yield += 1
            if next_to_issue < len(specs):
                _issue(next_to_issue)
                next_to_issue += 1
            if not data:
                raise RuntimeError("Telegram 返回空数据块，流中断")
            if idx == 0 and skip:
                data = data[skip:]
                if not data:
                    raise RuntimeError("Telegram 返回空数据块，流中断")
            if start == 0 and idx == 0 and channel_id is not None:
                # 起点是 0 时首块就是头缓存：只有攒满 512KB（或文件本身不足 512KB）才存，
                # 小探测不会把 2 字节的头存进去覆盖旧的
                head_buf.extend(data[:_HEAD_SIZE - len(head_buf)])
                if len(head_buf) >= _HEAD_SIZE or len(head_buf) == total:
                    _head_cache.put((channel_id, msg_id), bytes(head_buf))
            yield data
    except asyncio.CancelledError:
        for t in in_flight.values():
            t.cancel()
        if in_flight:
            await asyncio.gather(*in_flight.values(), return_exceptions=True)
        raise
    except Exception:
        for t in in_flight.values():
            t.cancel()
        if in_flight:
            await asyncio.gather(*in_flight.values(), return_exceptions=True)
        raise
    return


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
    # 开放式 Range（bytes=X-，不是后缀 bytes=-N、不是闭合 bytes=X-Y、不是无 Range）才封顶 16MB：
    # 拖进度、关播放器时旧请求不用等发现断开才停，最多白费 16MB；浏览器拿到 206 + 真实 Content-Range 后
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
        # 头只覆盖前半段：先回缓存的头，再从 Telegram 并行拉剩余部分（剩余起点 512KB 对齐，正好走并行快路）
        cached_part = head[start:]
        remainder_start = len(head)

        async def gen_cached():
            yield cached_part
            async for chunk in _parallel_gen(client, media, total, remainder_start, end,
                                             channel_id=channel_id, msg_id=msg_id, username=username):
                yield chunk

        return StreamingResponse(gen_cached(), status_code=206 if range_header else 200,
                                 media_type=mime, headers=headers)

    # 正常路径也走并行：单连接只有几百 KB/s，并行 2 默认就能翻倍左右，改到 4 最多翻 4 倍（受 Telegram 单连接限速和服务器带宽制约）。
    # 注意 Content-Length 还是按 length 算，并行生成器保证回的字节数正好是 length，不多不少。
    gen = _parallel_gen(client, media, total, start, end, channel_id=channel_id, msg_id=msg_id, username=username)
    if range_header:
        return StreamingResponse(gen, status_code=206, media_type=mime, headers=headers)
    return StreamingResponse(gen, media_type=mime, headers=headers)


@app.get("/")
async def index():
    return FileResponse("index.html")
