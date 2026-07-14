"""
Fantastic - MongoDB (Motor) tabanlı backend
=============================================
Bu dosya, orijinal chat.py'nin (FastAPI + SQLAlchemy + SQLite) MongoDB Atlas +
Motor (async driver) kullanacak şekilde yeniden yazılmış halidir.

Neden bu değişiklik?
- Colab oturumları geçicidir (kapanınca disk sıfırlanır) -> SQLite dosyası kaybolur.
- MongoDB Atlas ücretsiz cluster (M0) Colab dışında, kalıcı bir yerde durur.
- GitHub Pages (frontend) ile Colab+ngrok (backend) farklı origin'ler olacağı
  için CORS eklendi.

Gerekli ortam değişkenleri:
- FANTASTIC_MONGO_URI   : MongoDB Atlas bağlantı adresi (mongodb+srv://...)
- FANTASTIC_DB_NAME     : veritabanı adı (varsayılan: "fantastic")
- FANTASTIC_SECRET      : JWT imzalama anahtarı
- FANTASTIC_CORS_ORIGINS: virgülle ayrılmış izinli origin listesi (varsayılan: "*")
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from bson.errors import InvalidId
import bcrypt
import jwt
import datetime
import json
import os

# ==========================================
# 1. VERİTABANI BAĞLANTISI (MongoDB Atlas)
# ==========================================
MONGO_URI = os.environ.get("FANTASTIC_MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("FANTASTIC_DB_NAME", "fantastic")

client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

users_col = db["users"]
posts_col = db["posts"]
likes_col = db["likes"]
comments_col = db["comments"]
friendships_col = db["friendships"]
messages_col = db["messages"]
notifications_col = db["notifications"]


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def oid(id_str: str):
    """Bir string'i güvenli şekilde ObjectId'ye çevirir; geçersizse None döner."""
    try:
        return ObjectId(id_str)
    except (InvalidId, TypeError):
        return None


# Üretimde ortam değişkeninden okunur; yoksa geliştirme anahtarı kullanılır.
SECRET_KEY = os.environ.get("FANTASTIC_SECRET", "super_gizli_anahtar")
security = HTTPBearer()


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode()[:72], hashed_password.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


# GERÇEK KİMLİK DOĞRULAMA: user_id artık istemciden değil, token'dan gelir.
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Oturum geçersiz veya süresi dolmuş.")
    uid = oid(payload.get("uid", ""))
    if uid is None:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı.")
    user = await users_col.find_one({"_id": uid})
    if not user:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı.")
    return user


# ==========================================
# PYDANTIC ŞEMALARI
# ==========================================
class UserCreate(BaseModel):
    username: str
    password: str


class PostCreate(BaseModel):
    content: str
    image_url: str = ""


class ProfileUpdate(BaseModel):
    avatar_url: str
    bio: str


class LikeToggle(BaseModel):
    post_id: str


class CommentCreate(BaseModel):
    post_id: str
    content: str


class FriendAction(BaseModel):
    target_id: str


# ==========================================
# 2. WEBSOCKET YÖNETİCİSİ (değişmedi)
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        await self.broadcast_status()

    async def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        await self.broadcast_status()

    async def send_personal_message(self, message: str, receiver_id: str):
        websocket = self.active_connections.get(receiver_id)
        if websocket:
            try:
                await websocket.send_text(message)
            except Exception:
                pass

    async def broadcast(self, message: str):
        for connection in list(self.active_connections.values()):
            try:
                await connection.send_text(message)
            except Exception:
                pass

    async def broadcast_status(self):
        online_users = list(self.active_connections.keys())
        payload = json.dumps({"type": "status_update", "online_users": online_users})
        await self.broadcast(payload)


manager = ConnectionManager()
app = FastAPI(title="Fantastic")

# GitHub Pages (frontend) farklı origin'den istek atacağı için CORS açık.
# Prod'da FANTASTIC_CORS_ORIGINS ile belirli origin'lere kısıtlamak daha güvenli olur.
_cors_origins = os.environ.get("FANTASTIC_CORS_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _cors_origins == "*" else _cors_origins.split(","),
    allow_credentials=False,  # Bearer token header ile çalışıyoruz, cookie'ye gerek yok.
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def create_indexes():
    await users_col.create_index("username", unique=True)
    await posts_col.create_index([("username", 1)])
    await likes_col.create_index([("post_id", 1), ("user_id", 1)], unique=True)
    await comments_col.create_index([("post_id", 1)])
    await friendships_col.create_index([("sender_id", 1), ("receiver_id", 1)])
    await messages_col.create_index([("sender_id", 1), ("receiver_id", 1)])
    await messages_col.create_index([("receiver_id", 1), ("is_read", 1)])
    await notifications_col.create_index([("user_id", 1)])


# --- Bildirim yardımcıları ---
async def create_notification(user_id: str, actor: dict, ntype: str, post_id: str = ""):
    if user_id == str(actor["_id"]):
        return None  # kendi eylemin için bildirim yok
    doc = {
        "user_id": user_id,
        "actor_id": str(actor["_id"]),
        "actor_name": actor["username"],
        "type": ntype,
        "post_id": post_id,
        "is_read": False,
        "created_at": now_iso(),
    }
    await notifications_col.insert_one(doc)
    return doc


async def push_notification(user_id: str):
    await manager.send_personal_message(json.dumps({"type": "notification"}), user_id)


def serialize_user(u: dict):
    return {"id": str(u["_id"]), "username": u["username"], "avatar_url": u.get("avatar_url", "")}


# ==========================================
# 3. API UÇ NOKTALARI
# ==========================================

@app.get("/")
async def root():
    # Frontend artık GitHub Pages üzerinden servis ediliyor; burası sadece sağlık kontrolü.
    return {"status": "ok", "service": "Fantastic API"}


@app.post("/register")
async def register(user: UserCreate):
    uname = user.username.strip()
    if len(uname) < 3 or len(uname) > 20:
        raise HTTPException(status_code=400, detail="Kullanıcı adı 3-20 karakter olmalı.")
    if len(user.password) < 4:
        raise HTTPException(status_code=400, detail="Şifre en az 4 karakter olmalı.")
    existing = await users_col.find_one({"username": uname})
    if existing:
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten alınmış.")
    doc = {
        "username": uname,
        "password_hash": get_password_hash(user.password),
        "avatar_url": "",
        "bio": "",
        "created_at": now_iso(),
    }
    await users_col.insert_one(doc)
    return {"message": "Kayıt başarılı! Şimdi giriş yapabilirsiniz."}


@app.post("/login")
async def login(user: UserCreate):
    db_user = await users_col.find_one({"username": user.username.strip()})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Hatalı kullanıcı adı veya şifre.")
    uid = str(db_user["_id"])
    token = create_access_token(data={"sub": db_user["username"], "uid": uid})
    return {
        "access_token": token,
        "username": db_user["username"],
        "user_id": uid,
        "avatar_url": db_user.get("avatar_url", ""),
    }


@app.get("/me")
async def me(current: dict = Depends(get_current_user)):
    return {**serialize_user(current), "bio": current.get("bio", "")}


# --- AKIŞ ---
@app.get("/posts")
async def get_posts(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=50),
    user_id: str = "",
    current: dict = Depends(get_current_user),
):
    query: dict = {}
    if user_id:  # bir kullanıcının profil gönderileri
        target = await users_col.find_one({"_id": oid(user_id)})
        if not target:
            return {"posts": [], "has_more": False}
        query["username"] = target["username"]

    total = await posts_col.count_documents(query)
    cursor = posts_col.find(query).sort("_id", -1).skip((page - 1) * limit).limit(limit)
    posts = await cursor.to_list(length=limit)

    usernames = {p["username"] for p in posts}
    authors: dict[str, dict] = {}
    if usernames:
        async for u in users_col.find({"username": {"$in": list(usernames)}}):
            authors[u["username"]] = u

    result = []
    for p in posts:
        pid = str(p["_id"])
        author = authors.get(p["username"])
        likes_count = await likes_col.count_documents({"post_id": pid})
        liked_by_me = await likes_col.find_one({"post_id": pid, "user_id": str(current["_id"])}) is not None
        comments = await comments_col.find({"post_id": pid}).sort("_id", 1).to_list(length=1000)
        result.append({
            "id": pid,
            "username": p["username"],
            "user_id": str(author["_id"]) if author else "",
            "avatar_url": author.get("avatar_url", "") if author else "",
            "content": p["content"],
            "image_url": p.get("image_url", ""),
            "created_at": p.get("created_at", ""),
            "likes_count": likes_count,
            "liked_by_me": liked_by_me,
            "is_mine": p["username"] == current["username"],
            "comments": [
                {"username": c["username"], "user_id": c["user_id"], "content": c["content"], "created_at": c.get("created_at", "")}
                for c in comments
            ],
        })
    return {"posts": result, "has_more": page * limit < total}


@app.post("/posts")
async def create_post(post: PostCreate, current: dict = Depends(get_current_user)):
    content = post.content.strip()
    if not content and not post.image_url.strip():
        raise HTTPException(status_code=400, detail="Gönderi boş olamaz.")
    if len(content) > 1000:
        raise HTTPException(status_code=400, detail="Gönderi en fazla 1000 karakter olabilir.")
    await posts_col.insert_one({
        "username": current["username"],
        "content": content,
        "image_url": post.image_url.strip(),
        "created_at": now_iso(),
    })
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.delete("/posts/{post_id}")
async def delete_post(post_id: str, current: dict = Depends(get_current_user)):
    pid = oid(post_id)
    post = await posts_col.find_one({"_id": pid}) if pid else None
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    if post["username"] != current["username"]:
        raise HTTPException(status_code=403, detail="Sadece kendi gönderini silebilirsin.")
    await likes_col.delete_many({"post_id": post_id})
    await comments_col.delete_many({"post_id": post_id})
    await posts_col.delete_one({"_id": pid})
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.post("/posts/like")
async def toggle_like(data: LikeToggle, current: dict = Depends(get_current_user)):
    pid = oid(data.post_id)
    post = await posts_col.find_one({"_id": pid}) if pid else None
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    uid = str(current["_id"])
    existing = await likes_col.find_one({"post_id": data.post_id, "user_id": uid})
    if existing:
        await likes_col.delete_one({"_id": existing["_id"]})
    else:
        await likes_col.insert_one({"post_id": data.post_id, "user_id": uid})
        owner = await users_col.find_one({"username": post["username"]})
        if owner:
            await create_notification(str(owner["_id"]), current, "like", data.post_id)
            await push_notification(str(owner["_id"]))
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.post("/posts/comment")
async def add_comment(data: CommentCreate, current: dict = Depends(get_current_user)):
    content = data.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Yorum boş olamaz.")
    pid = oid(data.post_id)
    post = await posts_col.find_one({"_id": pid}) if pid else None
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    await comments_col.insert_one({
        "post_id": data.post_id,
        "user_id": str(current["_id"]),
        "username": current["username"],
        "content": content,
        "created_at": now_iso(),
    })
    owner = await users_col.find_one({"username": post["username"]})
    if owner:
        await create_notification(str(owner["_id"]), current, "comment", data.post_id)
        await push_notification(str(owner["_id"]))
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


# --- PROFİL ---
@app.get("/profile/{user_id}")
async def get_profile(user_id: str, current: dict = Depends(get_current_user)):
    uid_obj = oid(user_id)
    user = await users_col.find_one({"_id": uid_obj}) if uid_obj else None
    if not user:
        raise HTTPException(status_code=404, detail="Profil bulunamadı.")
    uid = str(user["_id"])
    post_count = await posts_col.count_documents({"username": user["username"]})
    friend_count = await friendships_col.count_documents({
        "$or": [{"sender_id": uid}, {"receiver_id": uid}],
        "status": "accepted",
    })
    return {
        **serialize_user(user),
        "bio": user.get("bio", ""),
        "created_at": user.get("created_at", ""),
        "post_count": post_count,
        "friend_count": friend_count,
    }


@app.post("/profile/update")
async def update_profile(data: ProfileUpdate, current: dict = Depends(get_current_user)):
    await users_col.update_one(
        {"_id": current["_id"]},
        {"$set": {"avatar_url": data.avatar_url.strip(), "bio": data.bio.strip()[:300]}},
    )
    return {"status": "success"}


# --- ARKADAŞLIK ---
@app.get("/friends")
async def get_friends(current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    friendships = await friendships_col.find({
        "$or": [{"sender_id": uid}, {"receiver_id": uid}],
        "status": "accepted",
    }).to_list(length=1000)
    friend_ids = [oid(f["receiver_id"] if f["sender_id"] == uid else f["sender_id"]) for f in friendships]
    friend_ids = [fid for fid in friend_ids if fid is not None]
    if not friend_ids:
        return []
    friends = await users_col.find({"_id": {"$in": friend_ids}}).to_list(length=1000)
    return [serialize_user(u) for u in friends]


@app.get("/friends/requests")
async def get_friend_requests(current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    pending = await friendships_col.find({"receiver_id": uid, "status": "pending"}).to_list(length=1000)
    sender_ids = [oid(f["sender_id"]) for f in pending]
    sender_ids = [sid for sid in sender_ids if sid is not None]
    if not sender_ids:
        return []
    senders = await users_col.find({"_id": {"$in": sender_ids}}).to_list(length=1000)
    return [serialize_user(u) for u in senders]


@app.get("/users/discover")
async def discover_users(q: str = "", current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    if q.strip():
        query = {
            "$and": [
                {"_id": {"$ne": current["_id"]}},
                {"username": {"$ne": ""}},
                {"username": {"$regex": q.strip(), "$options": "i"}},
            ]
        }
    else:
        query = {"_id": {"$ne": current["_id"]}, "username": {"$ne": ""}}
    all_users = await users_col.find(query).limit(30).to_list(length=30)

    relations = await friendships_col.find({
        "$or": [{"sender_id": uid}, {"receiver_id": uid}]
    }).to_list(length=1000)
    rel_map = {}
    for r in relations:
        other = r["receiver_id"] if r["sender_id"] == uid else r["sender_id"]
        if r["status"] == "accepted":
            rel_map[other] = "accepted"
        else:
            rel_map[other] = "sent_pending" if r["sender_id"] == uid else "received_pending"

    return [{**serialize_user(u), "status": rel_map.get(str(u["_id"]), "none")} for u in all_users]


@app.post("/friends/request")
async def send_friend_request(data: FriendAction, current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    if uid == data.target_id:
        raise HTTPException(status_code=400, detail="Kendine istek gönderemezsin.")
    existing = await friendships_col.find_one({
        "$or": [
            {"sender_id": uid, "receiver_id": data.target_id},
            {"sender_id": data.target_id, "receiver_id": uid},
        ]
    })
    if existing:
        return {"status": "error", "message": "İlişki zaten mevcut."}
    await friendships_col.insert_one({"sender_id": uid, "receiver_id": data.target_id, "status": "pending"})
    await create_notification(data.target_id, current, "friend_request")
    await push_notification(data.target_id)
    return {"status": "success"}


@app.post("/friends/accept")
async def accept_friend_request(data: FriendAction, current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    req = await friendships_col.find_one({
        "sender_id": data.target_id, "receiver_id": uid, "status": "pending",
    })
    if not req:
        raise HTTPException(status_code=400, detail="İstek bulunamadı.")
    await friendships_col.update_one({"_id": req["_id"]}, {"$set": {"status": "accepted"}})
    await create_notification(data.target_id, current, "friend_accept")
    await push_notification(data.target_id)
    return {"status": "success"}


@app.post("/friends/reject")
async def reject_friend_request(data: FriendAction, current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    req = await friendships_col.find_one({
        "sender_id": data.target_id, "receiver_id": uid, "status": "pending",
    })
    if not req:
        raise HTTPException(status_code=400, detail="İstek bulunamadı.")
    await friendships_col.delete_one({"_id": req["_id"]})
    return {"status": "success"}


@app.post("/friends/remove")
async def remove_friend(data: FriendAction, current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    rel = await friendships_col.find_one({
        "$or": [
            {"sender_id": uid, "receiver_id": data.target_id},
            {"sender_id": data.target_id, "receiver_id": uid},
        ],
        "status": "accepted",
    })
    if not rel:
        raise HTTPException(status_code=400, detail="Arkadaşlık bulunamadı.")
    await friendships_col.delete_one({"_id": rel["_id"]})
    return {"status": "success"}


# --- BİLDİRİMLER ---
@app.get("/notifications")
async def get_notifications(current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    notes = await notifications_col.find({"user_id": uid}).sort("_id", -1).limit(30).to_list(length=30)
    unread = await notifications_col.count_documents({"user_id": uid, "is_read": False})
    return {
        "unread": unread,
        "notifications": [
            {
                "id": str(n["_id"]),
                "actor_id": n["actor_id"],
                "actor_name": n["actor_name"],
                "type": n["type"],
                "post_id": n.get("post_id", ""),
                "is_read": bool(n.get("is_read", False)),
                "created_at": n.get("created_at", ""),
            }
            for n in notes
        ],
    }


@app.post("/notifications/read")
async def mark_notifications_read(current: dict = Depends(get_current_user)):
    await notifications_col.update_many(
        {"user_id": str(current["_id"]), "is_read": False},
        {"$set": {"is_read": True}},
    )
    return {"status": "success"}


# --- MESAJLAR ---
@app.get("/messages/unread")
async def unread_counts(current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    rows = await messages_col.find({"receiver_id": uid, "is_read": False}).to_list(length=10000)
    counts: dict[str, int] = {}
    for m in rows:
        counts[m["sender_id"]] = counts.get(m["sender_id"], 0) + 1
    return counts


@app.get("/messages/{other_id}")
async def get_messages(other_id: str, current: dict = Depends(get_current_user)):
    uid = str(current["_id"])
    is_friend = await friendships_col.find_one({
        "$or": [
            {"sender_id": uid, "receiver_id": other_id, "status": "accepted"},
            {"sender_id": other_id, "receiver_id": uid, "status": "accepted"},
        ]
    })
    if not is_friend:
        return []

    # Karşıdan gelenleri okundu işaretle
    await messages_col.update_many(
        {"sender_id": other_id, "receiver_id": uid, "is_read": False},
        {"$set": {"is_read": True}},
    )

    messages = await messages_col.find({
        "$or": [
            {"sender_id": uid, "receiver_id": other_id},
            {"sender_id": other_id, "receiver_id": uid},
        ]
    }).sort("_id", 1).to_list(length=10000)
    return [
        {"sender_id": m["sender_id"], "receiver_id": m["receiver_id"], "content": m["content"], "created_at": m.get("created_at", "")}
        for m in messages
    ]


# --- WEBSOCKET (token ile doğrulanır) ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query("")):
    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4401)
        return
    client_id = str(payload.get("uid"))

    await manager.connect(client_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get("type")

                if msg_type == "message":
                    target_id = str(msg.get("receiver_id", ""))
                    msg_content = (msg.get("content") or "").strip()
                    if not target_id or not msg_content:
                        continue

                    is_friend = await friendships_col.find_one({
                        "$or": [
                            {"sender_id": client_id, "receiver_id": target_id, "status": "accepted"},
                            {"sender_id": target_id, "receiver_id": client_id, "status": "accepted"},
                        ]
                    })

                    if is_friend:
                        created_at = now_iso()
                        await messages_col.insert_one({
                            "sender_id": client_id,
                            "receiver_id": target_id,
                            "content": msg_content,
                            "is_read": False,
                            "created_at": created_at,
                        })
                        await manager.send_personal_message(json.dumps({
                            "type": "message",
                            "sender_id": client_id,
                            "message": msg_content,
                            "created_at": created_at,
                        }), target_id)

                elif msg_type == "typing":
                    target_id = str(msg.get("receiver_id", ""))
                    await manager.send_personal_message(json.dumps({
                        "type": "typing",
                        "sender_id": client_id,
                        "is_typing": bool(msg.get("is_typing", False)),
                    }), target_id)

            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        await manager.disconnect(client_id)
