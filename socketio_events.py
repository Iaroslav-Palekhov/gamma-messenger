"""
WebSocket события для мессенджера (Flask-SocketIO).

Комнаты:
  chat_{chat_id}   — личный чат
  group_{group_id} — групповой чат
  user_{user_id}   — личная комната пользователя (статус, уведомления)

Устанавливаемые пакеты:
  pip install flask-socketio==5.3.6 simple-websocket
"""

from flask import request
from flask_login import current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from datetime import datetime

from models import db, User, Chat, Group, GroupMember, Message, BlockedUser
from utils import format_file_size, get_file_category, get_file_icon

socketio = SocketIO(
    cors_allowed_origins="*",
    async_mode="threading",   # совместимо со стандартным Flask
    ping_timeout=30,
    ping_interval=15,
    logger=False,
    engineio_logger=False,
)

# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

def _is_blocked(user_a: int, user_b: int) -> bool:
    return BlockedUser.query.filter(
        ((BlockedUser.blocker_id == user_a) & (BlockedUser.blocked_id == user_b)) |
        ((BlockedUser.blocker_id == user_b) & (BlockedUser.blocked_id == user_a))
    ).first() is not None


def _serialize_message(msg: Message, current_user_id: int, app) -> dict:
    """Сериализует объект Message в dict для отправки по WS."""
    from flask import url_for

    sender = msg.sender

    file_url = None
    if msg.file_path:
        file_url = url_for("download_file", filepath=msg.file_path, _external=False)
    elif msg.image_path:
        file_url = url_for("download_file", filepath=msg.image_path, _external=False)

    reply_to_data = None
    if msg.reply_to:
        r = msg.reply_to
        reply_to_data = {
            "id": r.id,
            "sender_id": r.sender_id,
            "sender_name": r.sender.username if r.sender else "Unknown",
            "content": r.content[:100] if r.content else None,
            "has_image": bool(r.image_path),
            "has_file": bool(r.file_path),
            "file_name": r.file_name,
        }

    forwarded_from_data = None
    if msg.is_forwarded and msg.forwarded_from:
        orig = msg.forwarded_from
        forwarded_from_data = {
            "id": orig.id,
            "sender_id": orig.sender_id,
            "sender_name": orig.sender.username if orig.sender else "Unknown",
            "show_sender": msg.show_forward_sender,
        }

    return {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "sender_name": sender.username if sender else "Unknown",
        "sender_username": sender.username if sender else "Unknown",
        "sender_avatar": url_for(
            "static",
            filename=f"uploads/{sender.avatar}" if sender and sender.avatar else "uploads/avatars/default.png",
            _external=False,
        ),
        "content": msg.content,
        "image_path": url_for("download_file", filepath=msg.image_path, _external=False) if msg.image_path else None,
        "file_path": file_url,
        "file_name": msg.file_name,
        "file_type": msg.file_type,
        "file_size": format_file_size(msg.file_size) if msg.file_size else None,
        "file_category": msg.file_category or (get_file_category(msg.file_name) if msg.file_name else None),
        "file_icon": get_file_icon(msg.file_name) if msg.file_name else "📎",
        "timestamp": msg.timestamp.strftime("%H:%M"),
        "is_read": msg.is_read,
        "is_edited": msg.is_edited,
        "reply_to": reply_to_data,
        "is_forwarded": msg.is_forwarded,
        "forwarded_from": forwarded_from_data,
        "show_forward_sender": msg.show_forward_sender,
        "link_url": msg.link_url,
        "link_title": msg.link_title,
        "link_description": msg.link_description,
        "link_image": msg.link_image,
    }


# ──────────────────────────────────────────────
# Подключение / отключение
# ──────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    if not current_user.is_authenticated:
        return False  # отклоняем неавторизованных

    # Личная комната пользователя
    join_room(f"user_{current_user.id}")

    # Обновляем статус
    current_user.status = "online"
    current_user.last_seen = datetime.utcnow()
    db.session.commit()

    # Оповещаем контакты
    _broadcast_status(current_user.id, "online")


@socketio.on("disconnect")
def on_disconnect():
    if not current_user.is_authenticated:
        return

    current_user.status = "offline"
    current_user.last_seen = datetime.utcnow()
    db.session.commit()

    _broadcast_status(current_user.id, "offline", current_user.last_seen.strftime("%H:%M %d.%m.%Y"))


def _broadcast_status(user_id: int, status: str, last_seen: str = None):
    """Рассылает обновление статуса всем личным чатам пользователя."""
    chats = Chat.query.filter(
        (Chat.user1_id == user_id) | (Chat.user2_id == user_id)
    ).all()
    for chat in chats:
        other_id = chat.user2_id if chat.user1_id == user_id else chat.user1_id
        payload = {"user_id": user_id, "status": status}
        if last_seen:
            payload["last_seen"] = last_seen
        socketio.emit("user_status", payload, to=f"user_{other_id}")


# ──────────────────────────────────────────────
# Комнаты
# ──────────────────────────────────────────────

@socketio.on("join_chat")
def on_join_chat(data):
    """Клиент заходит в личный чат."""
    if not current_user.is_authenticated:
        return
    chat_id = data.get("chat_id")
    if not chat_id:
        return
    chat = Chat.query.get(chat_id)
    if not chat:
        return
    if chat.user1_id != current_user.id and chat.user2_id != current_user.id:
        return
    join_room(f"chat_{chat_id}")


@socketio.on("leave_chat")
def on_leave_chat(data):
    if not current_user.is_authenticated:
        return
    chat_id = data.get("chat_id")
    if chat_id:
        leave_room(f"chat_{chat_id}")


@socketio.on("join_group")
def on_join_group(data):
    """Клиент заходит в групповой чат."""
    if not current_user.is_authenticated:
        return
    group_id = data.get("group_id")
    if not group_id:
        return
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not membership:
        return
    join_room(f"group_{group_id}")


@socketio.on("leave_group")
def on_leave_group(data):
    if not current_user.is_authenticated:
        return
    group_id = data.get("group_id")
    if group_id:
        leave_room(f"group_{group_id}")


# ──────────────────────────────────────────────
# Отправка сообщения
# ──────────────────────────────────────────────

@socketio.on("send_message")
def on_send_message(data):
    """
    Обрабатывает ТОЛЬКО текстовые сообщения через WS.
    Файлы по-прежнему отправляются через HTTP POST /send_message
    (multipart/form-data нельзя передать через WS).
    """
    if not current_user.is_authenticated:
        return

    chat_id = data.get("chat_id")
    group_id = data.get("group_id")
    content = (data.get("content") or "").strip()
    reply_to_id = data.get("reply_to_id")

    if not content:
        return

    if len(content) > 4000:
        emit("error", {"message": "Сообщение слишком длинное"})
        return

    msg = Message(
        sender_id=current_user.id,
        content=content,
        reply_to_id=reply_to_id or None,
    )

    if chat_id:
        chat = Chat.query.get(chat_id)
        if not chat:
            return
        if chat.user1_id != current_user.id and chat.user2_id != current_user.id:
            return
        receiver_id = chat.user2_id if chat.user1_id == current_user.id else chat.user1_id
        if _is_blocked(current_user.id, receiver_id):
            emit("error", {"message": "blocked"})
            return
        msg.chat_id = chat_id
        msg.receiver_id = receiver_id
        chat.last_message_at = datetime.utcnow()

    elif group_id:
        group = Group.query.get(group_id)
        if not group:
            return
        membership = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
        if not membership:
            return
        msg.group_id = group_id
        group.last_message_at = datetime.utcnow()
    else:
        return

    db.session.add(msg)
    db.session.commit()

    from flask import current_app as _app
    payload = _serialize_message(msg, current_user.id, _app)

    if chat_id:
        # Рассылаем обоим участникам чата
        socketio.emit("new_message", payload, to=f"chat_{chat_id}")
        # Уведомление в личную комнату получателя (для списка чатов)
        _emit_chat_update(chat_id, msg, receiver_id)
    elif group_id:
        socketio.emit("new_message", payload, to=f"group_{group_id}")
        _emit_group_update(group_id, msg)

    # Запустить получение превью ссылки в фоне (через HTTP threading)
    _schedule_link_preview(msg.id, content, chat_id, group_id, _app)


def _emit_chat_update(chat_id: int, msg: Message, receiver_id: int):
    """Отправляет обновление списка чатов получателю."""
    from flask import url_for
    sender = msg.sender
    preview = msg.content[:30] if msg.content else ("📷 Фото" if msg.image_path else "📎 Файл")
    payload = {
        "chat_id": chat_id,
        "type": "private",
        "sender_id": msg.sender_id,
        "preview": preview,
        "timestamp": msg.timestamp.strftime("%H:%M"),
    }
    socketio.emit("chat_updated", payload, to=f"user_{receiver_id}")
    # Себе тоже (чтобы список чатов обновился на другой вкладке)
    socketio.emit("chat_updated", payload, to=f"user_{msg.sender_id}")


def _emit_group_update(group_id: int, msg: Message):
    """Отправляет обновление группового чата всем участникам."""
    members = GroupMember.query.filter_by(group_id=group_id).all()
    preview = msg.content[:30] if msg.content else ("📷 Фото" if msg.image_path else "📎 Файл")
    payload = {
        "group_id": group_id,
        "type": "group",
        "sender_id": msg.sender_id,
        "sender_name": msg.sender.username if msg.sender else "Unknown",
        "preview": preview,
        "timestamp": msg.timestamp.strftime("%H:%M"),
    }
    for m in members:
        socketio.emit("chat_updated", payload, to=f"user_{m.user_id}")


def _schedule_link_preview(msg_id: int, content: str, chat_id, group_id, app):
    """Запускает парсинг превью ссылки в фоне и рассылает результат по WS."""
    import threading
    from utils import contains_url, extract_urls_from_text, extract_link_preview

    if not contains_url(content):
        return

    urls = extract_urls_from_text(content)
    if not urls:
        return

    def _worker():
        with app.app_context():
            try:
                preview = extract_link_preview(urls[0])
                if not preview:
                    return
                msg = Message.query.get(msg_id)
                if not msg:
                    return
                msg.link_url = preview["url"]
                msg.link_title = preview["title"]
                msg.link_description = preview["description"]
                msg.link_image = preview["image"]
                msg.link_fetched_at = datetime.utcnow()
                db.session.commit()
                # Рассылаем превью в нужную комнату
                payload = {
                    "message_id": msg_id,
                    "link_url": preview["url"],
                    "link_title": preview["title"],
                    "link_description": preview["description"],
                    "link_image": preview["image"],
                }
                if chat_id:
                    socketio.emit("link_preview_ready", payload, to=f"chat_{chat_id}")
                elif group_id:
                    socketio.emit("link_preview_ready", payload, to=f"group_{group_id}")
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()


# ──────────────────────────────────────────────
# Статус «печатает»
# ──────────────────────────────────────────────

@socketio.on("typing")
def on_typing(data):
    if not current_user.is_authenticated:
        return
    chat_id = data.get("chat_id")
    group_id = data.get("group_id")
    if chat_id:
        chat = Chat.query.get(chat_id)
        if not chat:
            return
        payload = {"user_id": current_user.id, "username": current_user.username, "chat_id": chat_id}
        socketio.emit("typing", payload, to=f"chat_{chat_id}", include_self=False)
    elif group_id:
        membership = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
        if not membership:
            return
        payload = {"user_id": current_user.id, "username": current_user.username, "group_id": group_id}
        socketio.emit("typing", payload, to=f"group_{group_id}", include_self=False)


# ──────────────────────────────────────────────
# Прочтение сообщений
# ──────────────────────────────────────────────

@socketio.on("messages_read")
def on_messages_read(data):
    """Клиент сообщает, что прочитал сообщения в чате."""
    if not current_user.is_authenticated:
        return
    chat_id = data.get("chat_id")
    if not chat_id:
        return
    # Уведомляем отправителей непрочитанных сообщений
    unread = Message.query.filter_by(
        chat_id=chat_id,
        receiver_id=current_user.id,
        is_read=False,
    ).all()
    sender_ids = set()
    for m in unread:
        m.is_read = True
        sender_ids.add(m.sender_id)
    db.session.commit()
    for sid in sender_ids:
        socketio.emit("messages_read", {"chat_id": chat_id, "reader_id": current_user.id}, to=f"user_{sid}")


# ──────────────────────────────────────────────
# Удаление / редактирование (уведомления)
# ──────────────────────────────────────────────

def broadcast_message_deleted(message_id: int, chat_id: int = None, group_id: int = None):
    payload = {"message_id": message_id}
    if chat_id:
        socketio.emit("message_deleted", payload, to=f"chat_{chat_id}")
    elif group_id:
        socketio.emit("message_deleted", payload, to=f"group_{group_id}")


def broadcast_message_edited(message_id: int, new_content: str, chat_id: int = None, group_id: int = None):
    payload = {"message_id": message_id, "content": new_content}
    if chat_id:
        socketio.emit("message_edited", payload, to=f"chat_{chat_id}")
    elif group_id:
        socketio.emit("message_edited", payload, to=f"group_{group_id}")


# ──────────────────────────────────────────────
# Heartbeat
# ──────────────────────────────────────────────

@socketio.on("heartbeat")
def on_heartbeat():
    if not current_user.is_authenticated:
        return
    current_user.status = "online"
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
