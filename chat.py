from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, or_, and_, text, inspect
from sqlalchemy.orm import sessionmaker, Session, declarative_base
import bcrypt
import jwt
import datetime
import json
import os

# ==========================================
# 1. VERİTABANI VE MODEL AYARLARI
# ==========================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./fantastic.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    avatar_url = Column(String, default="")
    bio = Column(String, default="")
    created_at = Column(String, default=now_iso)


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    content = Column(String)
    image_url = Column(String, default="")
    created_at = Column(String, default=now_iso)


class Like(Base):
    __tablename__ = "likes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    post_id = Column(Integer, index=True)


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, index=True)
    user_id = Column(String)
    username = Column(String)
    content = Column(String)
    created_at = Column(String, default=now_iso)


class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(String, index=True)
    receiver_id = Column(String, index=True)
    status = Column(String, default="pending")


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(String, index=True)
    receiver_id = Column(String, index=True)
    content = Column(String)
    is_read = Column(Boolean, default=False)
    created_at = Column(String, default=now_iso)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)       # bildirimi alan kişi
    actor_id = Column(String)                  # eylemi yapan kişi
    actor_name = Column(String)
    type = Column(String)                      # like | comment | friend_request | friend_accept
    post_id = Column(Integer, default=0)
    is_read = Column(Boolean, default=False)
    created_at = Column(String, default=now_iso)


Base.metadata.create_all(bind=engine)


# --- Mevcut fantastic.db için otomatik göç (yeni sütunları ekler) ---
def migrate():
    insp = inspect(engine)
    plan = {
        "users":    [("created_at", "TEXT DEFAULT ''")],
        "posts":    [("image_url", "TEXT DEFAULT ''"), ("created_at", "TEXT DEFAULT ''")],
        "comments": [("created_at", "TEXT DEFAULT ''")],
        "messages": [("is_read", "INTEGER DEFAULT 0"), ("created_at", "TEXT DEFAULT ''")],
    }
    with engine.begin() as conn:
        for table, cols in plan.items():
            existing = [c["name"] for c in insp.get_columns(table)]
            for name, ddl in cols:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        # Eski kayıtlara varsayılan zaman damgası ver
        stamp = now_iso()
        for table in ("users", "posts", "comments", "messages"):
            conn.execute(
                text(f"UPDATE {table} SET created_at = :s WHERE created_at IS NULL OR created_at = ''"),
                {"s": stamp},
            )


migrate()

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# GERÇEK KİMLİK DOĞRULAMA: user_id artık istemciden değil, token'dan gelir.
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Oturum geçersiz veya süresi dolmuş.")
    user = db.query(User).filter(User.id == int(payload.get("uid", 0))).first()
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
    post_id: int


class CommentCreate(BaseModel):
    post_id: int
    content: str


class FriendAction(BaseModel):
    target_id: str


# ==========================================
# 2. WEBSOCKET YÖNETİCİSİ
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


# --- Bildirim yardımcıları ---
def create_notification(db: Session, user_id: str, actor: User, ntype: str, post_id: int = 0):
    if user_id == str(actor.id):
        return None  # kendi eylemin için bildirim yok
    n = Notification(
        user_id=user_id,
        actor_id=str(actor.id),
        actor_name=actor.username,
        type=ntype,
        post_id=post_id,
    )
    db.add(n)
    db.commit()
    return n


async def push_notification(user_id: str):
    await manager.send_personal_message(json.dumps({"type": "notification"}), user_id)


def serialize_user(u: User):
    return {"id": str(u.id), "username": u.username, "avatar_url": u.avatar_url or ""}


# ==========================================
# 3. API UÇ NOKTALARI
# ==========================================

@app.get("/")
async def get():
    return FileResponse("index.html")


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    uname = user.username.strip()
    if len(uname) < 3 or len(uname) > 20:
        raise HTTPException(status_code=400, detail="Kullanıcı adı 3-20 karakter olmalı.")
    if len(user.password) < 4:
        raise HTTPException(status_code=400, detail="Şifre en az 4 karakter olmalı.")
    db_user = db.query(User).filter(User.username == uname).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten alınmış.")
    new_user = User(username=uname, password_hash=get_password_hash(user.password))
    db.add(new_user)
    db.commit()
    return {"message": "Kayıt başarılı! Şimdi giriş yapabilirsiniz."}


@app.post("/login")
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username.strip()).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Hatalı kullanıcı adı veya şifre.")
    token = create_access_token(data={"sub": db_user.username, "uid": db_user.id})
    return {
        "access_token": token,
        "username": db_user.username,
        "user_id": str(db_user.id),
        "avatar_url": db_user.avatar_url or "",
    }


@app.get("/me")
def me(current: User = Depends(get_current_user)):
    return {**serialize_user(current), "bio": current.bio or ""}


# --- AKIŞ ---
@app.get("/posts")
def get_posts(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=50),
    user_id: str = "",
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Post)
    if user_id:  # bir kullanıcının profil gönderileri
        target = db.query(User).filter(User.id == int(user_id)).first()
        if not target:
            return {"posts": [], "has_more": False}
        q = q.filter(Post.username == target.username)
    total = q.count()
    posts = q.order_by(Post.id.desc()).offset((page - 1) * limit).limit(limit).all()

    usernames = {p.username for p in posts}
    authors = {u.username: u for u in db.query(User).filter(User.username.in_(usernames)).all()} if usernames else {}

    result = []
    for p in posts:
        author = authors.get(p.username)
        likes_count = db.query(Like).filter(Like.post_id == p.id).count()
        liked_by_me = db.query(Like).filter(Like.post_id == p.id, Like.user_id == str(current.id)).first() is not None
        comments = db.query(Comment).filter(Comment.post_id == p.id).order_by(Comment.id.asc()).all()
        result.append({
            "id": p.id,
            "username": p.username,
            "user_id": str(author.id) if author else "",
            "avatar_url": author.avatar_url if author else "",
            "content": p.content,
            "image_url": p.image_url or "",
            "created_at": p.created_at or "",
            "likes_count": likes_count,
            "liked_by_me": liked_by_me,
            "is_mine": p.username == current.username,
            "comments": [
                {"username": c.username, "user_id": c.user_id, "content": c.content, "created_at": c.created_at or ""}
                for c in comments
            ],
        })
    return {"posts": result, "has_more": page * limit < total}


@app.post("/posts")
async def create_post(post: PostCreate, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    content = post.content.strip()
    if not content and not post.image_url.strip():
        raise HTTPException(status_code=400, detail="Gönderi boş olamaz.")
    if len(content) > 1000:
        raise HTTPException(status_code=400, detail="Gönderi en fazla 1000 karakter olabilir.")
    new_post = Post(username=current.username, content=content, image_url=post.image_url.strip())
    db.add(new_post)
    db.commit()
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.delete("/posts/{post_id}")
async def delete_post(post_id: int, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    if post.username != current.username:
        raise HTTPException(status_code=403, detail="Sadece kendi gönderini silebilirsin.")
    db.query(Like).filter(Like.post_id == post_id).delete()
    db.query(Comment).filter(Comment.post_id == post_id).delete()
    db.delete(post)
    db.commit()
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.post("/posts/like")
async def toggle_like(data: LikeToggle, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == data.post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    uid = str(current.id)
    existing = db.query(Like).filter(Like.post_id == data.post_id, Like.user_id == uid).first()
    if existing:
        db.delete(existing)
        db.commit()
    else:
        db.add(Like(post_id=data.post_id, user_id=uid))
        db.commit()
        owner = db.query(User).filter(User.username == post.username).first()
        if owner:
            create_notification(db, str(owner.id), current, "like", post.id)
            await push_notification(str(owner.id))
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


@app.post("/posts/comment")
async def add_comment(data: CommentCreate, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    content = data.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Yorum boş olamaz.")
    post = db.query(Post).filter(Post.id == data.post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    db.add(Comment(post_id=data.post_id, user_id=str(current.id), username=current.username, content=content))
    db.commit()
    owner = db.query(User).filter(User.username == post.username).first()
    if owner:
        create_notification(db, str(owner.id), current, "comment", post.id)
        await push_notification(str(owner.id))
    await manager.broadcast(json.dumps({"type": "feed_update"}))
    return {"status": "success"}


# --- PROFİL ---
@app.get("/profile/{user_id}")
def get_profile(user_id: str, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="Profil bulunamadı.")
    uid = str(user.id)
    post_count = db.query(Post).filter(Post.username == user.username).count()
    friend_count = db.query(Friendship).filter(
        or_(Friendship.sender_id == uid, Friendship.receiver_id == uid),
        Friendship.status == "accepted",
    ).count()
    return {
        **serialize_user(user),
        "bio": user.bio or "",
        "created_at": user.created_at or "",
        "post_count": post_count,
        "friend_count": friend_count,
    }


@app.post("/profile/update")
def update_profile(data: ProfileUpdate, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current.id).first()
    user.avatar_url = data.avatar_url.strip()
    user.bio = data.bio.strip()[:300]
    db.commit()
    return {"status": "success"}


# --- ARKADAŞLIK ---
@app.get("/friends")
def get_friends(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    friendships = db.query(Friendship).filter(
        or_(Friendship.sender_id == uid, Friendship.receiver_id == uid),
        Friendship.status == "accepted",
    ).all()
    friend_ids = [int(f.receiver_id if f.sender_id == uid else f.sender_id) for f in friendships]
    if not friend_ids:
        return []
    friends = db.query(User).filter(User.id.in_(friend_ids)).all()
    return [serialize_user(u) for u in friends]


@app.get("/friends/requests")
def get_friend_requests(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    pending = db.query(Friendship).filter(Friendship.receiver_id == uid, Friendship.status == "pending").all()
    sender_ids = [int(f.sender_id) for f in pending]
    if not sender_ids:
        return []
    senders = db.query(User).filter(User.id.in_(sender_ids)).all()
    return [serialize_user(u) for u in senders]


@app.get("/users/discover")
def discover_users(q: str = "", current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    query = db.query(User).filter(User.id != current.id, User.username != "")
    if q.strip():
        query = query.filter(User.username.ilike(f"%{q.strip()}%"))
    all_users = query.limit(30).all()

    relations = db.query(Friendship).filter(
        or_(Friendship.sender_id == uid, Friendship.receiver_id == uid)
    ).all()
    rel_map = {}
    for r in relations:
        other = r.receiver_id if r.sender_id == uid else r.sender_id
        if r.status == "accepted":
            rel_map[other] = "accepted"
        else:
            rel_map[other] = "sent_pending" if r.sender_id == uid else "received_pending"

    return [{**serialize_user(u), "status": rel_map.get(str(u.id), "none")} for u in all_users]


@app.post("/friends/request")
async def send_friend_request(data: FriendAction, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    if uid == data.target_id:
        raise HTTPException(status_code=400, detail="Kendine istek gönderemezsin.")
    existing = db.query(Friendship).filter(
        or_(
            and_(Friendship.sender_id == uid, Friendship.receiver_id == data.target_id),
            and_(Friendship.sender_id == data.target_id, Friendship.receiver_id == uid),
        )
    ).first()
    if existing:
        return {"status": "error", "message": "İlişki zaten mevcut."}
    db.add(Friendship(sender_id=uid, receiver_id=data.target_id, status="pending"))
    db.commit()
    create_notification(db, data.target_id, current, "friend_request")
    await push_notification(data.target_id)
    return {"status": "success"}


@app.post("/friends/accept")
async def accept_friend_request(data: FriendAction, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    req = db.query(Friendship).filter(
        Friendship.sender_id == data.target_id,
        Friendship.receiver_id == uid,
        Friendship.status == "pending",
    ).first()
    if not req:
        raise HTTPException(status_code=400, detail="İstek bulunamadı.")
    req.status = "accepted"
    db.commit()
    create_notification(db, data.target_id, current, "friend_accept")
    await push_notification(data.target_id)
    return {"status": "success"}


@app.post("/friends/reject")
def reject_friend_request(data: FriendAction, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    req = db.query(Friendship).filter(
        Friendship.sender_id == data.target_id,
        Friendship.receiver_id == uid,
        Friendship.status == "pending",
    ).first()
    if not req:
        raise HTTPException(status_code=400, detail="İstek bulunamadı.")
    db.delete(req)
    db.commit()
    return {"status": "success"}


@app.post("/friends/remove")
def remove_friend(data: FriendAction, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    rel = db.query(Friendship).filter(
        or_(
            and_(Friendship.sender_id == uid, Friendship.receiver_id == data.target_id),
            and_(Friendship.sender_id == data.target_id, Friendship.receiver_id == uid),
        ),
        Friendship.status == "accepted",
    ).first()
    if not rel:
        raise HTTPException(status_code=400, detail="Arkadaşlık bulunamadı.")
    db.delete(rel)
    db.commit()
    return {"status": "success"}


# --- BİLDİRİMLER ---
@app.get("/notifications")
def get_notifications(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    notes = db.query(Notification).filter(Notification.user_id == uid).order_by(Notification.id.desc()).limit(30).all()
    unread = db.query(Notification).filter(Notification.user_id == uid, Notification.is_read == False).count()  # noqa: E712
    return {
        "unread": unread,
        "notifications": [
            {
                "id": n.id,
                "actor_id": n.actor_id,
                "actor_name": n.actor_name,
                "type": n.type,
                "post_id": n.post_id,
                "is_read": bool(n.is_read),
                "created_at": n.created_at or "",
            }
            for n in notes
        ],
    }


@app.post("/notifications/read")
def mark_notifications_read(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Notification).filter(Notification.user_id == str(current.id), Notification.is_read == False).update(  # noqa: E712
        {"is_read": True}
    )
    db.commit()
    return {"status": "success"}


# --- MESAJLAR ---
@app.get("/messages/unread")
def unread_counts(current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    rows = db.query(Message).filter(Message.receiver_id == uid, Message.is_read == False).all()  # noqa: E712
    counts: dict[str, int] = {}
    for m in rows:
        counts[m.sender_id] = counts.get(m.sender_id, 0) + 1
    return counts


@app.get("/messages/{other_id}")
def get_messages(other_id: str, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    uid = str(current.id)
    is_friend = db.query(Friendship).filter(
        or_(
            and_(Friendship.sender_id == uid, Friendship.receiver_id == other_id, Friendship.status == "accepted"),
            and_(Friendship.sender_id == other_id, Friendship.receiver_id == uid, Friendship.status == "accepted"),
        )
    ).first()
    if not is_friend:
        return []

    # Karşıdan gelenleri okundu işaretle
    db.query(Message).filter(
        Message.sender_id == other_id, Message.receiver_id == uid, Message.is_read == False  # noqa: E712
    ).update({"is_read": True})
    db.commit()

    messages = db.query(Message).filter(
        or_(
            and_(Message.sender_id == uid, Message.receiver_id == other_id),
            and_(Message.sender_id == other_id, Message.receiver_id == uid),
        )
    ).order_by(Message.id.asc()).all()
    return [
        {"sender_id": m.sender_id, "receiver_id": m.receiver_id, "content": m.content, "created_at": m.created_at or ""}
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

                    db = SessionLocal()
                    try:
                        is_friend = db.query(Friendship).filter(
                            or_(
                                and_(Friendship.sender_id == client_id, Friendship.receiver_id == target_id,
                                     Friendship.status == "accepted"),
                                and_(Friendship.sender_id == target_id, Friendship.receiver_id == client_id,
                                     Friendship.status == "accepted"),
                            )
                        ).first()

                        if is_friend:
                            new_msg = Message(sender_id=client_id, receiver_id=target_id, content=msg_content)
                            db.add(new_msg)
                            db.commit()
                            await manager.send_personal_message(json.dumps({
                                "type": "message",
                                "sender_id": client_id,
                                "message": msg_content,
                                "created_at": new_msg.created_at,
                            }), target_id)
                    finally:
                        db.close()

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