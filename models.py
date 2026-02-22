from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    avatar = db.Column(db.String(200), default='avatars/default.png')
    bio = db.Column(db.String(200), default='')
    status = db.Column(db.String(50), default='online')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    owned_groups = db.relationship('Group', backref='owner', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    icon = db.Column(db.String(200), default='group_icons/default.png')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship('GroupMember', backref='group', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('group_id', 'user_id', name='unique_group_member'),)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship('Message', backref='chat', lazy=True, cascade='all, delete-orphan')
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(200), nullable=True)
    file_path = db.Column(db.String(200), nullable=True)
    file_name = db.Column(db.String(200), nullable=True)
    file_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    file_category = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)

    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    forwarded_from_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    is_forwarded = db.Column(db.Boolean, default=False)
    show_forward_sender = db.Column(db.Boolean, default=True)

    reply_to = db.relationship('Message', foreign_keys=[reply_to_id], remote_side=[id], backref='replies')
    forwarded_from = db.relationship('Message', foreign_keys=[forwarded_from_id], remote_side=[id], backref='forwarded_copies')

    is_pinned = db.Column(db.Boolean, default=False)
    pinned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    pinned_at = db.Column(db.DateTime, nullable=True)

    link_url = db.Column(db.String(500), nullable=True)
    link_title = db.Column(db.String(200), nullable=True)
    link_description = db.Column(db.Text, nullable=True)
    link_image = db.Column(db.String(500), nullable=True)
    link_fetched_at = db.Column(db.DateTime, nullable=True)

class ForwardedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    forwarded_message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    forwarded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    forwarded_to_chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=True)
    forwarded_to_group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    show_sender = db.Column(db.Boolean, default=True)
    forwarded_at = db.Column(db.DateTime, default=datetime.utcnow)

    original_message = db.relationship('Message', foreign_keys=[original_message_id])
    forwarded_message = db.relationship('Message', foreign_keys=[forwarded_message_id])
    forwarded_by = db.relationship('User', foreign_keys=[forwarded_by_id])


class PasswordReset(db.Model):
    """Модель для токенов сброса пароля"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))
