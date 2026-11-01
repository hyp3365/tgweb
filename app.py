"""
Telegram 频道视频小网页：登录 / 搜索 / 加频道 / 流式播放
架构：浏览器 -> 本服务 -> Telegram (MTProto, Telethon)
视频不先落盘：/stream 按浏览器的 Range 请求，从 Telegram 按需取片段转发。
只给自己用：不要把 8000 端口公开给全网，见 README 的安全一节。
"""
import hashlib
import os
import re

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
WEB_TOKEN = hashlib.sha256(WEB_PASSWORD.encode()).hexdigest() if WEB_PASSWORD else ""

app = FastAPI(title="app", docs_url=None, redoc_url=None, openapi_url=None)
_client: TelegramClient | None = None
_login_state: dict = {}  # 单用户：{"phone": ..., "phone_code_hash": ...}


def check_web_auth(request: Request):
    if WEB_PASSWORD and request.cookies.get("web_token") != WEB_TOKEN:
        raise HTTPException(status_code=401, detail="need_web_auth")


async def get_client() -> TelegramClient:
    global _client
    if not API_ID or not API_HASH:
        raise HTTPException(status_code=500, detail="服务器未配置凭证")
    if _client is None:
        _client = TelegramClient(SESSION_PATH, API_ID, API_HASH)
    if not _client.is_connected():
        await _client.connect()
    return _client


async def require_login() -> TelegramClient:
    client = await get_client()
    if not await client.is_user_authorized():
        raise HTTPException(status_code=401, detail="未登录账号，请先登录")
    return client


# ---------- 网页密码 ----------
class WebLoginIn(BaseModel):
    password: str


@app.post("/api/web-login")
async def web_login(body: WebLoginIn):
    if not WEB_PASSWORD or body.password != WEB_PASSWORD:
        raise HTTPException(status_code=401, detail="网页密码不对")
    resp = JSONResponse({"ok": True})
    resp.set_cookie("web_token", WEB_TOKEN, httponly=True, samesite="lax", path="/")
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
    sent = await client.send_code_request(body.phone.strip())
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
    return {"ok": True, "logged_in": True}


@app.post("/api/password")
async def login_password(request: Request, body: PasswordIn):
    check_web_auth(request)
    client = await get_client()
    await client.sign_in(password=body.password)
    return {"ok": True, "logged_in": True}


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
        async for dialog in client.iter_dialogs(limit=1000):
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
        res = await client(ImportChatInviteRequest(m.group(1)))
        entity = res.chats[0] if res.chats else None
        _mark_recently_joined(entity)
        return {"ok": True, "joined": _chat_info(entity) if entity else None}
    # 数字 id：先在已加入对话里找，找不到再当 PeerChannel 解析（失败给 400 明示，不抛 500）
    entity = None
    if re.fullmatch(r"-?\d+", s):
        cid = abs(int(s))
        if cid in _entity_cache:
            entity = _entity_cache[cid]
        else:
            async for dialog in client.iter_dialogs(limit=1000):
                if dialog.entity.id == cid:
                    entity = dialog.entity
                    break
        if entity is None:
            try:
                entity = await client.get_entity(PeerChannel(cid))
            except Exception:
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
    async for dialog in client.iter_dialogs(limit=1000):
        if dialog.entity.id == entity.id:
            _mark_recently_joined(entity)
            return {"ok": True, "joined": _chat_info(entity)}
    if not isinstance(entity, Channel):
        raise HTTPException(status_code=400, detail="这不是频道，这是群组/用户，无法用加入频道的方式加入；群组请用邀请链接，点聊天可以直接进入")
    try:
        await client(JoinChannelRequest(entity))
        _mark_recently_joined(entity)
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
    async for dialog in client.iter_dialogs(limit=1000):
        e = dialog.entity
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
        return "@" + m.group(1)
    if s.startswith("@"):
        return s
    if re.fullmatch(r"[A-Za-z0-9_]+", s):
        return "@" + s
    return None


# ---------- 视频列表 ----------
async def _channel_entity(client, channel_id: int, username=None):
    async for dialog in client.iter_dialogs(limit=1000):
        if dialog.entity.id == channel_id:
            return dialog.entity
    # 关键修复：没加入的频道不能只靠 PeerChannel(id) 解析，Telethon 需要 access_hash，
    # 没见过的频道会报 Could not find the input entity（就是日志里的 500）。
    # 顺序：搜索缓存 > 用户名解析 > PeerChannel，失败给 404 明示，不再抛 500。
    uname = _normalize_username(username) if username else None
    if uname and uname[1:].lower() in _entity_cache_by_username:
        return _entity_cache_by_username[uname[1:].lower()]
    if channel_id in _entity_cache:
        return _entity_cache[channel_id]
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
    async for msg in client.iter_messages(entity, limit=(limit + 1) * 3, offset_id=offset_id,
                                          filter=InputMessagesFilterVideo):
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
_thumb_cache: dict = {}

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
        entity = await _channel_entity(client, channel_id, username)
        msg = await client.get_messages(entity, ids=msg_id)
        if msg is None:
            raise HTTPException(status_code=404, detail="找不到这条视频")
        # thumb=-1 取最大的那张缩略图；没有缩略图返回 None
        data = await client.download_media(msg, file=bytes, thumb=-1)
        if data is None:
            raise HTTPException(status_code=404, detail="这条视频没有缩略图")
        if len(_thumb_cache) > 300:
            _thumb_cache.clear()
        _thumb_cache[key] = data
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
    async for msg in client.iter_messages(entity, limit=(limit + 1) * 2, offset_id=offset_id):
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
    async for msg in client.iter_messages(entity, search=q, limit=(limit + 1) * 2, offset_id=offset_id):
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


_photo_cache: dict = {}


@app.get("/photo/{channel_id}/{msg_id}")
async def photo(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    key = (channel_id, msg_id)
    data = _photo_cache.get(key)
    if data is None:
        entity = await _channel_entity(client, channel_id, username)
        msg = await client.get_messages(entity, ids=msg_id)
        if msg is None or not msg.photo:
            raise HTTPException(status_code=404, detail="这条消息没有图片")
        data = await client.download_media(msg, file=bytes)
        if data is None:
            raise HTTPException(status_code=404, detail="图片下载失败")
        if len(_photo_cache) > 100:
            _photo_cache.clear()
        _photo_cache[key] = data
    return Response(content=data, media_type=_sniff_image_type(data),
                    headers={"Cache-Control": "private, max-age=86400"})


# ---------- 流式播放：按 Range 从 Telegram 取片段，不落盘 ----------
def _parse_range(range_header: str | None, total: int):
    if not range_header or not range_header.startswith("bytes="):
        return 0, total - 1
    spec = range_header[6:].split(",")[0].strip()
    if spec.startswith("-"):
        start = max(0, total - int(spec[1:]))
        return start, total - 1
    parts = spec.split("-")
    start = int(parts[0]) if parts[0] else 0
    end = int(parts[1]) if len(parts) > 1 and parts[1] else total - 1
    return max(0, start), min(total - 1, end)


@app.get("/stream/{channel_id}/{msg_id}")
async def stream(request: Request, channel_id: int, msg_id: int, username: str | None = None):
    check_web_auth(request)
    client = await require_login()
    entity = await _channel_entity(client, channel_id, username)
    msg = await client.get_messages(entity, ids=msg_id)
    if msg is None:
        raise HTTPException(status_code=404, detail="找不到这条视频")
    media = msg.media
    doc = msg.video or msg.document
    if media is None or doc is None:
        raise HTTPException(status_code=404, detail="这条消息没有视频")
    total = doc.size
    mime = doc.mime_type or "video/mp4"
    start, end = _parse_range(request.headers.get("range"), total)
    length = end - start + 1

    async def gen():
        # offset/limit 已在上面实测签名里确认：iter_download(file, offset=, limit=)
        async for chunk in client.iter_download(media, offset=start, limit=length, file_size=total):
            yield chunk

    headers = {"Accept-Ranges": "bytes", "Content-Length": str(length),
               "Cache-Control": "private, no-store"}
    if request.headers.get("range"):
        headers["Content-Range"] = f"bytes {start}-{end}/{total}"
        return StreamingResponse(gen(), status_code=206, media_type=mime, headers=headers)
    return StreamingResponse(gen(), media_type=mime, headers=headers)


@app.get("/")
async def index():
    return FileResponse("index.html")
