from flask import render_template, request, jsonify, redirect, url_for, send_from_directory, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import mimetypes
import secrets

from models import User, Group, GroupMember, Chat, Message, ForwardedMessage, PasswordReset, UserSession
from utils import (
    compress_image, get_file_category, get_file_icon,
    format_file_size, is_file_too_large, save_file,
    extract_link_preview, contains_url, extract_urls_from_text
)

def register_routes(app, db, login_manager):

    # ============================================================
    # ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ СЕССИЙ
    # ============================================================

    def _parse_user_agent(ua_string):
        """Разбирает User-Agent строку в читаемый вид."""
        try:
            import user_agents as ua_lib
            ua = ua_lib.parse(ua_string)
            browser  = f"{ua.browser.family} {ua.browser.version_string}".strip()
            os_info  = f"{ua.os.family} {ua.os.version_string}".strip()
            if ua.is_mobile:
                device_type = 'mobile'
            elif ua.is_tablet:
                device_type = 'tablet'
            else:
                device_type = 'desktop'
            return browser, os_info, device_type
        except Exception:
            short_ua = (ua_string[:80] if ua_string else 'Неизвестно')
            return short_ua, 'Неизвестно', 'desktop'

    def _get_client_ip():
        """Получает реальный IP клиента с учётом прокси."""
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.remote_addr or '0.0.0.0'

    def _create_session_record(user_id, session_token, is_current=False):
        """Создаёт запись о новой сессии в БД."""
        ua_string = request.user_agent.string or ''
        browser, os_info, device_type = _parse_user_agent(ua_string)

        sess = UserSession(
            user_id=user_id,
            session_token=session_token,
            ip_address=_get_client_ip(),
            user_agent=ua_string[:500],
            browser=browser[:100],
            os=os_info[:100],
            device_type=device_type,
            is_active=True,
            is_current=is_current
        )
        db.session.add(sess)
        db.session.commit()
        return sess

    # ============================================================
    # ИНДЕКС
    # ============================================================

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('chats'))
        return redirect(url_for('login'))

    # ============================================================
    # АВТОРИЗАЦИЯ
    # ============================================================

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('chats'))

        if request.method == 'POST':
            email    = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')

            if not email or not password or not username:
                return render_template('register.html', error='Заполните все поля')

            if User.query.filter_by(email=email).first():
                return render_template('register.html', error='Пользователь с такой почтой уже существует')

            if User.query.filter_by(username=username).first():
                return render_template('register.html', error='Имя пользователя уже занято')

            hashed_password = generate_password_hash(password)
            user = User(email=email, username=username, password=hashed_password)

            db.session.add(user)
            db.session.commit()

            login_user(user)

            # Создаём запись сессии
            tok = secrets.token_hex(32)
            session['session_token'] = tok
            _create_session_record(user.id, tok, is_current=True)

            return redirect(url_for('chats'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('chats'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter(
                (User.email == username) | (User.username == username)
            ).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                user.status   = 'online'
                user.last_seen = datetime.utcnow()
                db.session.commit()

                # Создаём запись сессии
                tok = secrets.token_hex(32)
                session['session_token'] = tok
                _create_session_record(user.id, tok, is_current=True)

                return redirect(url_for('chats'))
            else:
                return render_template('login.html', error='Неверный email/username или пароль')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        # Завершаем текущую сессию в БД
        current_token = session.get('session_token')
        if current_token:
            sess = UserSession.query.filter_by(session_token=current_token).first()
            if sess:
                sess.end_session()

        current_user.status    = 'offline'
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        logout_user()
        return redirect(url_for('login'))

    # ============================================================
    # ЧАТЫ
    # ============================================================

    @app.route('/chats')
    @login_required
    def chats():
        user_chats = Chat.query.filter(
            (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
        ).order_by(Chat.last_message_at.desc()).all()

        chats_data = []
        for chat in user_chats:
            other_user   = chat.user2 if chat.user1_id == current_user.id else chat.user1
            last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp.desc()).first()
            unread_count = Message.query.filter_by(
                chat_id=chat.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()

            chats_data.append({
                'id': chat.id,
                'type': 'private',
                'other_user': other_user,
                'last_message': last_message,
                'unread_count': unread_count,
                'last_message_time': chat.last_message_at
            })

        user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
        for membership in user_groups:
            group        = membership.group
            last_message = Message.query.filter_by(group_id=group.id).order_by(Message.timestamp.desc()).first()
            unread_count = Message.query.filter_by(
                group_id=group.id,
                is_read=False
            ).filter(Message.sender_id != current_user.id).count()

            chats_data.append({
                'id': group.id,
                'type': 'group',
                'group': group,
                'last_message': last_message,
                'unread_count': unread_count,
                'last_message_time': group.last_message_at
            })

        chats_data.sort(key=lambda x: x['last_message_time'], reverse=True)
        return render_template('chats.html', chats=chats_data)

    @app.route('/start_chat', methods=['POST'])
    @login_required
    def start_chat():
        username = request.form.get('username')

        if not username or username == current_user.username:
            return redirect(url_for('chats'))

        other_user = User.query.filter_by(username=username).first()
        if not other_user:
            return redirect(url_for('chats'))

        existing_chat = Chat.query.filter(
            ((Chat.user1_id == current_user.id) & (Chat.user2_id == other_user.id)) |
            ((Chat.user1_id == other_user.id) & (Chat.user2_id == current_user.id))
        ).first()

        if existing_chat:
            return redirect(url_for('chat', chat_id=existing_chat.id))

        new_chat = Chat(user1_id=current_user.id, user2_id=other_user.id)
        db.session.add(new_chat)
        db.session.commit()

        return redirect(url_for('chat', chat_id=new_chat.id))

    @app.route('/chat/<int:chat_id>')
    @login_required
    def chat(chat_id):
        chat_obj = Chat.query.get_or_404(chat_id)
        if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
            return redirect(url_for('chats'))

        messages   = Message.query.filter_by(chat_id=chat_id, is_deleted=False).order_by(Message.timestamp).all()
        other_user = chat_obj.user2 if chat_obj.user1_id == current_user.id else chat_obj.user1

        unread_messages = Message.query.filter_by(
            chat_id=chat_id,
            receiver_id=current_user.id,
            is_read=False
        ).all()

        for msg in unread_messages:
            msg.is_read = True

        db.session.commit()

        pinned_messages_raw = Message.query.filter_by(
            chat_id=chat_id, is_pinned=True, is_deleted=False
        ).order_by(Message.pinned_at.desc()).all()

        pinned_messages = []
        for msg in pinned_messages_raw:
            sender = User.query.get(msg.sender_id)
            pinned_messages.append({
                'id': msg.id,
                'content': msg.content,
                'sender_name': sender.username if sender else 'Unknown',
                'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
                'has_image': bool(msg.image_path),
                'has_file': bool(msg.file_path),
                'file_name': msg.file_name
            })

        return render_template('chat.html', chat=chat_obj, messages=messages,
                               other_user=other_user, pinned_messages=pinned_messages)

    @app.route('/chat/<int:chat_id>/delete', methods=['POST'])
    @login_required
    def delete_chat(chat_id):
        chat = Chat.query.get_or_404(chat_id)

        if chat.user1_id != current_user.id and chat.user2_id != current_user.id:
            return jsonify({'error': 'Нет доступа'}), 403

        try:
            messages = Message.query.filter_by(chat_id=chat_id).all()
            for message in messages:
                ForwardedMessage.query.filter(
                    (ForwardedMessage.original_message_id == message.id) |
                    (ForwardedMessage.forwarded_message_id == message.id)
                ).delete()

            Message.query.filter_by(chat_id=chat_id).delete()
            db.session.delete(chat)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Ошибка при удалении чата: {str(e)}'}), 500

    @app.route('/api/get_chats_data')
    @login_required
    def get_chats_data():
        """API endpoint для получения обновлённых данных чатов"""
        user_chats = Chat.query.filter(
            (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
        ).order_by(Chat.last_message_at.desc()).all()

        chats_data = []
        for chat in user_chats:
            other_user   = chat.user2 if chat.user1_id == current_user.id else chat.user1
            last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp.desc()).first()
            unread_count = Message.query.filter_by(
                chat_id=chat.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()

            last_message_preview = ''
            if last_message:
                if last_message.content:
                    prefix = 'Вы: ' if last_message.sender_id == current_user.id else ''
                    last_message_preview = f"{prefix}{last_message.content[:30]}"
                elif last_message.image_path:
                    last_message_preview = '📷 Фото'
                elif last_message.file_path:
                    last_message_preview = f'📎 {last_message.file_name[:20] if last_message.file_name else "Файл"}'
            else:
                last_message_preview = 'Нет сообщений'

            chats_data.append({
                'id': chat.id,
                'type': 'private',
                'other_user_id': other_user.id,
                'other_username': other_user.username,
                'other_avatar': url_for('static', filename=f'uploads/{other_user.avatar}'),
                'other_status': other_user.status,
                'last_message': last_message_preview,
                'last_message_time': chat.last_message_at.strftime('%H:%M') if chat.last_message_at else '',
                'unread_count': unread_count,
                'chat_url': url_for('chat', chat_id=chat.id)
            })

        user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
        for membership in user_groups:
            group        = membership.group
            last_message = Message.query.filter_by(group_id=group.id).order_by(Message.timestamp.desc()).first()
            unread_count = Message.query.filter_by(
                group_id=group.id,
                is_read=False
            ).filter(Message.sender_id != current_user.id).count()

            last_message_preview = ''
            if last_message:
                if last_message.content:
                    prefix = 'Вы: ' if last_message.sender_id == current_user.id else f'{last_message.sender.username if last_message.sender else "Пользователь"}: '
                    last_message_preview = f"{prefix}{last_message.content[:30]}"
                elif last_message.image_path:
                    last_message_preview = '📷 Фото'
                elif last_message.file_path:
                    last_message_preview = f'📎 {last_message.file_name[:20] if last_message.file_name else "Файл"}'
            else:
                last_message_preview = 'Нет сообщений'

            chats_data.append({
                'id': group.id,
                'type': 'group',
                'group_name': group.name,
                'group_icon': url_for('static', filename=f'uploads/{group.icon}'),
                'members_count': len(group.members),
                'last_message': last_message_preview,
                'last_message_time': group.last_message_at.strftime('%H:%M') if group.last_message_at else '',
                'unread_count': unread_count,
                'chat_url': url_for('group_chat', group_id=group.id)
            })

        chats_data.sort(key=lambda x: x['last_message_time'] or '', reverse=True)
        total_unread = sum(c['unread_count'] for c in chats_data)

        return jsonify({
            'chats': chats_data,
            'total_unread': total_unread
        })

    # ============================================================
    # ПРОФИЛЬ
    # ============================================================

    @app.route('/profile/<int:user_id>')
    @login_required
    def profile(user_id):
        user = User.query.get_or_404(user_id)
        return render_template('profile.html', profile_user=user)

    @app.route('/profile/edit', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        if request.method == 'POST':
            username = request.form.get('username')
            bio      = request.form.get('bio')
            avatar   = request.files.get('avatar')

            if username:
                existing_user = User.query.filter_by(username=username).first()
                if existing_user and existing_user.id != current_user.id:
                    return jsonify({'error': 'Имя пользователя уже занято'}), 400
                current_user.username = username

            if bio is not None:
                current_user.bio = bio

            if avatar and avatar.filename:
                try:
                    filepath, _ = save_file(avatar, 'avatar', app)
                    current_user.avatar = filepath
                except Exception as e:
                    return jsonify({'error': f'Ошибка обработки изображения: {str(e)}'}), 400

            db.session.commit()
            return jsonify({'success': True})

        return render_template('edit_profile.html')

    # ============================================================
    # БЕЗОПАСНОСТЬ
    # ============================================================

    @app.route('/security')
    @login_required
    def security():
        sessions = UserSession.query.filter_by(
            user_id=current_user.id
        ).order_by(
            UserSession.is_active.desc(),
            UserSession.last_active.desc()
        ).limit(20).all()

        current_token = session.get('session_token')
        for s in sessions:
            s.is_current = (s.session_token == current_token)

        return render_template('security.html', sessions=sessions)

    @app.route('/security/change_password', methods=['POST'])
    @login_required
    def change_password():
        current_password = request.form.get('current_password', '').strip()
        new_password     = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'Заполните все поля'}), 400

        if not check_password_hash(current_user.password, current_password):
            return jsonify({'error': 'Неверный текущий пароль'}), 400

        if new_password != confirm_password:
            return jsonify({'error': 'Новые пароли не совпадают'}), 400

        if len(new_password) < 8:
            return jsonify({'error': 'Пароль должен быть минимум 8 символов'}), 400

        if new_password == current_password:
            return jsonify({'error': 'Новый пароль совпадает со старым'}), 400

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        try:
            from security import SecurityAudit
            SecurityAudit.log_password_reset(current_user.id, current_user.username)
        except Exception:
            pass

        return jsonify({'success': True, 'message': 'Пароль успешно изменён'})

    @app.route('/security/terminate_session/<int:session_id>', methods=['POST'])
    @login_required
    def terminate_session(session_id):
        sess = UserSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first_or_404()

        current_token = session.get('session_token')
        if sess.session_token == current_token:
            return jsonify({'error': 'Нельзя завершить текущую сессию. Используйте "Выйти".'}), 400

        sess.end_session()
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/security/terminate_all_sessions', methods=['POST'])
    @login_required
    def terminate_all_sessions():
        """Завершает все сессии кроме текущей."""
        current_token    = session.get('session_token')
        sessions_to_end  = UserSession.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).all()

        ended = 0
        for s in sessions_to_end:
            if s.session_token != current_token:
                s.end_session()
                ended += 1

        db.session.commit()
        return jsonify({'success': True, 'ended': ended})

    # ============================================================
    # ГРУППЫ
    # ============================================================

    @app.route('/groups')
    @login_required
    def groups():
        user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
        groups_data = []

        for membership in user_groups:
            group        = membership.group
            last_message = Message.query.filter_by(group_id=group.id).order_by(Message.timestamp.desc()).first()
            unread_count = Message.query.filter_by(
                group_id=group.id,
                is_read=False
            ).filter(Message.sender_id != current_user.id).count()

            groups_data.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'icon': group.icon,
                'members_count': len(group.members),
                'last_message': last_message,
                'unread_count': unread_count,
                'role': membership.role,
                'last_message_time': group.last_message_at
            })

        return render_template('groups.html', groups=groups_data)

    @app.route('/group/create', methods=['POST'])
    @login_required
    def create_group():
        name        = request.form.get('name')
        description = request.form.get('description', '')
        icon        = request.files.get('icon')

        if not name:
            return jsonify({'error': 'Название группы обязательно'}), 400

        group = Group(
            name=name,
            description=description,
            owner_id=current_user.id
        )

        if icon and icon.filename:
            try:
                filepath, _ = save_file(icon, 'group_icon', app)
                group.icon = filepath
            except Exception as e:
                return jsonify({'error': f'Ошибка обработки иконки: {str(e)}'}), 400

        db.session.add(group)
        db.session.flush()

        owner_member = GroupMember(
            group_id=group.id,
            user_id=current_user.id,
            role='owner'
        )
        db.session.add(owner_member)
        db.session.commit()

        return redirect(url_for('group_chat', group_id=group.id))

    @app.route('/group/<int:group_id>')
    @login_required
    def group_chat(group_id):
        group = Group.query.get_or_404(group_id)

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not membership:
            return redirect(url_for('groups'))

        messages = Message.query.filter_by(group_id=group_id, is_deleted=False).order_by(Message.timestamp).all()

        unread_messages = Message.query.filter_by(
            group_id=group_id,
            is_read=False
        ).filter(Message.sender_id != current_user.id).all()

        for msg in unread_messages:
            msg.is_read = True

        db.session.commit()

        pinned_messages_raw = Message.query.filter_by(
            group_id=group_id, is_pinned=True, is_deleted=False
        ).order_by(Message.pinned_at.desc()).all()

        pinned_messages = []
        for msg in pinned_messages_raw:
            sender = User.query.get(msg.sender_id)
            pinned_messages.append({
                'id': msg.id,
                'content': msg.content,
                'sender_name': sender.username if sender else 'Unknown',
                'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
                'has_image': bool(msg.image_path),
                'has_file': bool(msg.file_path),
                'file_name': msg.file_name
            })

        return render_template('group_chat.html', group=group, messages=messages,
                               membership=membership, pinned_messages=pinned_messages)

    @app.route('/group/<int:group_id>/members')
    @login_required
    def group_members(group_id):
        group = Group.query.get_or_404(group_id)

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not membership:
            return redirect(url_for('groups'))

        members = GroupMember.query.filter_by(group_id=group_id).all()
        return render_template('group_members.html', group=group, members=members, current_membership=membership)

    @app.route('/group/<int:group_id>/add_member', methods=['POST'])
    @login_required
    def add_group_member(group_id):
        group = Group.query.get_or_404(group_id)

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not membership or membership.role not in ['owner', 'admin']:
            return jsonify({'error': 'Недостаточно прав'}), 403

        username = request.form.get('username')
        user     = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404

        existing = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=user.id
        ).first()

        if existing:
            return jsonify({'error': 'Пользователь уже в группе'}), 400

        new_member = GroupMember(
            group_id=group_id,
            user_id=user.id,
            role='member'
        )

        db.session.add(new_member)
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/group/<int:group_id>/remove_member/<int:user_id>', methods=['POST'])
    @login_required
    def remove_group_member(group_id, user_id):
        group = Group.query.get_or_404(group_id)

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not membership or membership.role not in ['owner', 'admin']:
            return jsonify({'error': 'Недостаточно прав'}), 403

        if user_id == group.owner_id:
            return jsonify({'error': 'Нельзя удалить владельца группы'}), 400

        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=user_id
        ).first()

        if not member:
            return jsonify({'error': 'Участник не найден'}), 404

        db.session.delete(member)
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/group/<int:group_id>/change_role/<int:user_id>', methods=['POST'])
    @login_required
    def change_group_role(group_id, user_id):
        group = Group.query.get_or_404(group_id)

        if current_user.id != group.owner_id:
            return jsonify({'error': 'Только владелец может назначать админов'}), 403

        new_role = request.form.get('role')
        if new_role not in ['admin', 'member']:
            return jsonify({'error': 'Некорректная роль'}), 400

        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=user_id
        ).first()

        if not member:
            return jsonify({'error': 'Участник не найден'}), 404

        member.role = new_role
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/group/<int:group_id>/edit', methods=['POST'])
    @login_required
    def edit_group(group_id):
        group = Group.query.get_or_404(group_id)

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if not membership or membership.role not in ['owner', 'admin']:
            return jsonify({'error': 'Недостаточно прав'}), 403

        name        = request.form.get('name')
        description = request.form.get('description')
        icon        = request.files.get('icon')

        if name:
            group.name = name

        if description is not None:
            group.description = description

        if icon and icon.filename:
            try:
                filepath, _ = save_file(icon, 'group_icon', app)
                group.icon = filepath
            except Exception as e:
                return jsonify({'error': f'Ошибка обработки иконки: {str(e)}'}), 400

        db.session.commit()
        return redirect(url_for('group_chat', group_id=group.id))

    @app.route('/group/<int:group_id>/delete', methods=['POST'])
    @login_required
    def delete_group(group_id):
        group = Group.query.get_or_404(group_id)

        if current_user.id != group.owner_id:
            return jsonify({'error': 'Только владелец может удалить группу'}), 403

        try:
            messages = Message.query.filter_by(group_id=group_id).all()
            for message in messages:
                ForwardedMessage.query.filter(
                    (ForwardedMessage.original_message_id == message.id) |
                    (ForwardedMessage.forwarded_message_id == message.id)
                ).delete()

            Message.query.filter_by(group_id=group_id).delete()
            GroupMember.query.filter_by(group_id=group_id).delete()
            db.session.delete(group)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Ошибка при удалении группы: {str(e)}'}), 500

    @app.route('/group/<int:group_id>/leave', methods=['POST'])
    @login_required
    def leave_group(group_id):
        group = Group.query.get_or_404(group_id)

        if current_user.id == group.owner_id:
            return jsonify({'error': 'Владелец не может покинуть группу. Передайте права или удалите группу.'}), 400

        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if membership:
            db.session.delete(membership)
            db.session.commit()

        return jsonify({'success': True})

    # ============================================================
    # СООБЩЕНИЯ
    # ============================================================

    @app.route('/send_message', methods=['POST'])
    @login_required
    def send_message():
        chat_id     = request.form.get('chat_id')
        group_id    = request.form.get('group_id')
        content     = request.form.get('content')
        file        = request.files.get('file')
        reply_to_id = request.form.get('reply_to_id')

        message = Message(
            sender_id=current_user.id,
            content=content if content else None,
            reply_to_id=reply_to_id if reply_to_id else None
        )

        if content and contains_url(content):
            urls = extract_urls_from_text(content)
            if urls:
                first_url    = urls[0]
                preview_data = extract_link_preview(first_url)

                if preview_data:
                    message.link_url         = preview_data['url']
                    message.link_title       = preview_data['title']
                    message.link_description = preview_data['description']
                    message.link_image       = preview_data['image']
                    message.link_fetched_at  = datetime.utcnow()

        if chat_id:
            chat_obj = Chat.query.get_or_404(chat_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа'}), 403

            receiver_id         = chat_obj.user2_id if chat_obj.user1_id == current_user.id else chat_obj.user1_id
            message.chat_id     = chat_id
            message.receiver_id = receiver_id
            chat_obj.last_message_at = datetime.utcnow()

        elif group_id:
            group      = Group.query.get_or_404(group_id)
            membership = GroupMember.query.filter_by(
                group_id=group_id,
                user_id=current_user.id
            ).first()

            if not membership:
                return jsonify({'error': 'Нет доступа'}), 403

            message.group_id        = group_id
            group.last_message_at   = datetime.utcnow()

        if file and file.filename:
            filename      = file.filename
            file_category = get_file_category(filename)
            message.file_category = file_category
            message.file_name     = filename
            message.file_type     = file.content_type or mimetypes.guess_type(filename)[0] or 'application/octet-stream'

            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            if is_file_too_large(file_size, app):
                return jsonify({'error': f'Файл слишком большой. Максимальный размер: {app.config["MAX_CONTENT_LENGTH"] / (1024*1024)} MB'}), 400

            try:
                filepath, size = save_file(file, file_category, app)
                if file_category == 'image':
                    message.image_path = filepath
                else:
                    message.file_path = filepath
                message.file_size = size
            except Exception as e:
                return jsonify({'error': f'Ошибка сохранения файла: {str(e)}'}), 400

        db.session.add(message)
        db.session.commit()

        return jsonify({
            'success': True,
            'message_id': message.id,
            'timestamp': message.timestamp.strftime('%H:%M'),
            'content': message.content,
            'image_path': url_for('download_file', filepath=message.image_path) if message.image_path else None,
            'file_path': url_for('download_file', filepath=message.file_path) if message.file_path else None,
            'file_name': message.file_name,
            'file_size': format_file_size(message.file_size) if message.file_size else None,
            'file_category': message.file_category,
            'file_icon': get_file_icon(message.file_name) if message.file_name else None,
            'link_url': message.link_url,
            'link_title': message.link_title,
            'link_description': message.link_description,
            'link_image': message.link_image,
            'is_forwarded': message.is_forwarded,
            'reply_to_id': message.reply_to_id
        })

    @app.route('/forward_message', methods=['POST'])
    def forward_message():
        message_id      = request.form.get('message_id')
        target_type     = request.form.get('target_type')
        target_id       = request.form.get('target_id')
        show_sender     = request.form.get('show_sender', 'true').lower() == 'true'
        additional_text = request.form.get('additional_text', '')

        original_message = Message.query.get_or_404(message_id)

        if original_message.chat_id:
            chat = Chat.query.get(original_message.chat_id)
            if not chat or (chat.user1_id != current_user.id and chat.user2_id != current_user.id):
                return jsonify({'error': 'Нет доступа к оригинальному сообщению'}), 403
        elif original_message.group_id:
            membership = GroupMember.query.filter_by(
                group_id=original_message.group_id,
                user_id=current_user.id
            ).first()
            if not membership:
                return jsonify({'error': 'Нет доступа к оригинальному сообщению'}), 403

        if original_message.content and additional_text:
            forwarded_content = f"{additional_text}\n\n{original_message.content}"
        elif original_message.content:
            forwarded_content = original_message.content
        elif additional_text:
            forwarded_content = additional_text
        else:
            forwarded_content = None

        forwarded_message = Message(
            sender_id=current_user.id,
            content=forwarded_content,
            is_forwarded=True,
            forwarded_from_id=original_message.id,
            show_forward_sender=show_sender
        )

        if original_message.image_path:
            forwarded_message.image_path = original_message.image_path
        elif original_message.file_path:
            forwarded_message.file_path     = original_message.file_path
            forwarded_message.file_name     = original_message.file_name
            forwarded_message.file_type     = original_message.file_type
            forwarded_message.file_size     = original_message.file_size
            forwarded_message.file_category = original_message.file_category

        if target_type == 'chat':
            chat_obj = Chat.query.get_or_404(target_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа к чату'}), 403

            receiver_id = chat_obj.user2_id if chat_obj.user1_id == current_user.id else chat_obj.user1_id
            forwarded_message.chat_id     = target_id
            forwarded_message.receiver_id = receiver_id
            chat_obj.last_message_at      = datetime.utcnow()

        elif target_type == 'group':
            group      = Group.query.get_or_404(target_id)
            membership = GroupMember.query.filter_by(
                group_id=target_id,
                user_id=current_user.id
            ).first()

            if not membership:
                return jsonify({'error': 'Нет доступа к группе'}), 403

            forwarded_message.group_id  = target_id
            group.last_message_at       = datetime.utcnow()

        db.session.add(forwarded_message)
        db.session.flush()

        forwarded_record = ForwardedMessage(
            original_message_id=original_message.id,
            forwarded_message_id=forwarded_message.id,
            forwarded_by_id=current_user.id,
            forwarded_to_chat_id=forwarded_message.chat_id,
            forwarded_to_group_id=forwarded_message.group_id,
            show_sender=show_sender
        )

        db.session.add(forwarded_record)
        db.session.commit()

        return jsonify({
            'success': True,
            'message_id': forwarded_message.id,
            'timestamp': forwarded_message.timestamp.strftime('%H:%M')
        })

    @app.route('/get_chats_and_groups_for_forward')
    @login_required
    def get_chats_and_groups_for_forward():
        user_chats = Chat.query.filter(
            (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
        ).order_by(Chat.last_message_at.desc()).all()

        chats_data = []
        for chat in user_chats:
            other_user = chat.user2 if chat.user1_id == current_user.id else chat.user1
            chats_data.append({
                'id': chat.id,
                'type': 'chat',
                'name': other_user.username,
                'avatar': url_for('static', filename=f'uploads/{other_user.avatar}'),
                'last_message_time': chat.last_message_at.strftime('%H:%M')
            })

        user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
        groups_data = []
        for membership in user_groups:
            group = membership.group
            groups_data.append({
                'id': group.id,
                'type': 'group',
                'name': group.name,
                'avatar': url_for('static', filename=f'uploads/{group.icon}'),
                'members_count': len(group.members),
                'last_message_time': group.last_message_at.strftime('%H:%M')
            })

        all_targets = chats_data + groups_data
        all_targets.sort(key=lambda x: x['last_message_time'], reverse=True)
        return jsonify(all_targets)

    @app.route('/get_messages/<int:chat_id>')
    @login_required
    def get_messages(chat_id):
        last_id  = request.args.get('last_id', 0, type=int)
        is_group = request.args.get('is_group', False, type=bool)

        if is_group:
            group      = Group.query.get_or_404(chat_id)
            membership = GroupMember.query.filter_by(
                group_id=chat_id,
                user_id=current_user.id
            ).first()

            if not membership:
                return jsonify({'error': 'Нет доступа'}), 403

            messages = Message.query.filter(
                Message.group_id == chat_id,
                Message.id > last_id,
                Message.is_deleted == False
            ).order_by(Message.timestamp).all()

            for msg in messages:
                if msg.sender_id != current_user.id and not msg.is_read:
                    msg.is_read = True

            db.session.commit()
        else:
            chat_obj = Chat.query.get_or_404(chat_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа'}), 403

            messages = Message.query.filter(
                Message.chat_id == chat_id,
                Message.id > last_id,
                Message.is_deleted == False
            ).order_by(Message.timestamp).all()

            for msg in messages:
                if msg.receiver_id == current_user.id and not msg.is_read:
                    msg.is_read = True

            db.session.commit()

        messages_data = []
        for msg in messages:
            sender = User.query.get(msg.sender_id)

            file_url = None
            if msg.file_path:
                file_url = url_for('download_file', filepath=msg.file_path)
            elif msg.image_path:
                file_url = url_for('download_file', filepath=msg.image_path)

            file_size_formatted = format_file_size(msg.file_size) if msg.file_size else None
            file_icon           = get_file_icon(msg.file_name) if msg.file_name else '📎'

            reply_to_data = None
            if msg.reply_to_id:
                reply_msg = Message.query.get(msg.reply_to_id)
                if reply_msg:
                    reply_sender = User.query.get(reply_msg.sender_id)
                    reply_to_data = {
                        'id': reply_msg.id,
                        'sender_id': reply_msg.sender_id,
                        'sender_name': reply_sender.username if reply_sender else 'Unknown',
                        'content': reply_msg.content[:100] if reply_msg.content else None,
                        'has_image': bool(reply_msg.image_path),
                        'has_file': bool(reply_msg.file_path),
                        'file_name': reply_msg.file_name
                    }

            forwarded_from_data = None
            if msg.is_forwarded and msg.forwarded_from_id:
                original_msg = Message.query.get(msg.forwarded_from_id)
                if original_msg:
                    original_sender = User.query.get(original_msg.sender_id)
                    forwarded_from_data = {
                        'id': original_msg.id,
                        'sender_id': original_msg.sender_id,
                        'sender_name': original_sender.username if original_sender else 'Unknown',
                        'show_sender': msg.show_forward_sender
                    }

            messages_data.append({
                'id': msg.id,
                'sender_id': msg.sender_id,
                'sender_name': sender.username if sender else 'Unknown',
                'sender_username': sender.username if sender else 'Unknown',
                'sender_avatar': url_for('static', filename=f'uploads/{sender.avatar}') if sender else url_for('static', filename='uploads/avatars/default.png'),
                'content': msg.content,
                'image_path': url_for('download_file', filepath=msg.image_path) if msg.image_path else None,
                'file_path': file_url,
                'file_name': msg.file_name,
                'file_type': msg.file_type,
                'file_size': file_size_formatted,
                'file_category': msg.file_category or get_file_category(msg.file_name) if msg.file_name else None,
                'file_icon': file_icon,
                'timestamp': msg.timestamp.strftime('%H:%M'),
                'is_read': msg.is_read,
                'is_edited': msg.is_edited,
                'reply_to': reply_to_data,
                'is_forwarded': msg.is_forwarded,
                'forwarded_from': forwarded_from_data,
                'show_forward_sender': msg.show_forward_sender,
                'link_url': msg.link_url,
                'link_title': msg.link_title,
                'link_description': msg.link_description,
                'link_image': msg.link_image,
            })

        return jsonify(messages_data)

    @app.route('/download/<path:filepath>')
    @login_required
    def download_file(filepath):
        directory = os.path.join(app.config['UPLOAD_FOLDER'], os.path.dirname(filepath))
        filename  = os.path.basename(filepath)
        return send_from_directory(directory, filename, as_attachment=True)

    @app.route('/delete_message/<int:message_id>', methods=['POST'])
    @login_required
    def delete_message(message_id):
        message = Message.query.get_or_404(message_id)
        if message.sender_id != current_user.id:
            return jsonify({'error': 'Нет прав для удаления этого сообщения'}), 403
        message.is_deleted = True
        message.content    = None
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/edit_message/<int:message_id>', methods=['POST'])
    @login_required
    def edit_message(message_id):
        message = Message.query.get_or_404(message_id)
        if message.sender_id != current_user.id:
            return jsonify({'error': 'Нет прав для редактирования этого сообщения'}), 403
        new_content = request.form.get('content', '').strip()
        if not new_content:
            return jsonify({'error': 'Текст сообщения не может быть пустым'}), 400
        message.content   = new_content
        message.is_edited = True
        db.session.commit()
        return jsonify({'success': True, 'content': new_content})

    @app.route('/get_unread_counts')
    @login_required
    def get_unread_counts():
        private_chats = Chat.query.filter(
            (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
        ).all()

        total_unread = 0

        for chat in private_chats:
            unread = Message.query.filter_by(
                chat_id=chat.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()
            total_unread += unread

        user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
        for membership in user_groups:
            unread = Message.query.filter_by(
                group_id=membership.group_id,
                is_read=False
            ).filter(Message.sender_id != current_user.id).count()
            total_unread += unread

        return jsonify({'unread_count': total_unread})

    # ============================================================
    # ЗАКРЕПЛЕНИЕ СООБЩЕНИЙ
    # ============================================================

    @app.route('/pin_message/<int:message_id>', methods=['POST'])
    @login_required
    def pin_message(message_id):
        message = Message.query.get_or_404(message_id)
        if message.chat_id:
            chat_obj = Chat.query.get(message.chat_id)
            if not chat_obj or (chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id):
                return jsonify({'error': 'Нет доступа'}), 403
        elif message.group_id:
            membership = GroupMember.query.filter_by(group_id=message.group_id, user_id=current_user.id).first()
            if not membership or membership.role not in ['owner', 'admin']:
                return jsonify({'error': 'Только администраторы могут закреплять сообщения'}), 403
        message.is_pinned    = True
        message.pinned_by_id = current_user.id
        message.pinned_at    = datetime.utcnow()
        db.session.commit()
        sender = User.query.get(message.sender_id)
        return jsonify({
            'success': True, 'message_id': message.id,
            'content': message.content,
            'sender_name': sender.username if sender else 'Unknown',
            'timestamp': message.timestamp.strftime('%H:%M'),
            'has_image': bool(message.image_path),
            'has_file': bool(message.file_path),
            'file_name': message.file_name
        })

    @app.route('/unpin_message/<int:message_id>', methods=['POST'])
    @login_required
    def unpin_message(message_id):
        message = Message.query.get_or_404(message_id)
        if message.chat_id:
            chat_obj = Chat.query.get(message.chat_id)
            if not chat_obj or (chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id):
                return jsonify({'error': 'Нет доступа'}), 403
        elif message.group_id:
            membership = GroupMember.query.filter_by(group_id=message.group_id, user_id=current_user.id).first()
            if not membership or membership.role not in ['owner', 'admin']:
                return jsonify({'error': 'Только администраторы могут откреплять сообщения'}), 403
        message.is_pinned    = False
        message.pinned_by_id = None
        message.pinned_at    = None
        db.session.commit()
        return jsonify({'success': True})

    @app.route('/get_pinned_messages/<int:context_id>')
    @login_required
    def get_pinned_messages(context_id):
        is_group = request.args.get('is_group', 'false').lower() == 'true'
        if is_group:
            membership = GroupMember.query.filter_by(group_id=context_id, user_id=current_user.id).first()
            if not membership:
                return jsonify({'error': 'Нет доступа'}), 403
            pinned = Message.query.filter_by(group_id=context_id, is_pinned=True, is_deleted=False).order_by(Message.pinned_at.desc()).all()
        else:
            chat_obj = Chat.query.get_or_404(context_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа'}), 403
            pinned = Message.query.filter_by(chat_id=context_id, is_pinned=True, is_deleted=False).order_by(Message.pinned_at.desc()).all()
        result = []
        for msg in pinned:
            sender = User.query.get(msg.sender_id)
            result.append({
                'id': msg.id, 'content': msg.content,
                'sender_name': sender.username if sender else 'Unknown',
                'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
                'has_image': bool(msg.image_path),
                'has_file': bool(msg.file_path),
                'file_name': msg.file_name
            })
        return jsonify(result)

    # ============================================================
    # ПОИСК В ЧАТЕ
    # ============================================================

    @app.route('/search_messages/<int:context_id>')
    @login_required
    def search_messages(context_id):
        is_group  = request.args.get('is_group', 'false').lower() == 'true'
        query_str = request.args.get('q', '').strip()
        if not query_str:
            return jsonify([])

        if is_group:
            membership = GroupMember.query.filter_by(group_id=context_id, user_id=current_user.id).first()
            if not membership:
                return jsonify({'error': 'Нет доступа'}), 403
            messages = Message.query.filter(
                Message.group_id == context_id,
                Message.content.ilike(f'%{query_str}%'),
                Message.is_deleted == False
            ).order_by(Message.timestamp.desc()).limit(50).all()
        else:
            chat_obj = Chat.query.get_or_404(context_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа'}), 403
            messages = Message.query.filter(
                Message.chat_id == context_id,
                Message.content.ilike(f'%{query_str}%'),
                Message.is_deleted == False
            ).order_by(Message.timestamp.desc()).limit(50).all()

        result = []
        for msg in messages:
            sender = User.query.get(msg.sender_id)
            result.append({
                'id': msg.id, 'content': msg.content,
                'sender_name': sender.username if sender else 'Unknown',
                'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M'),
                'is_mine': msg.sender_id == current_user.id
            })
        return jsonify(result)

    # ============================================================
    # ВОССТАНОВЛЕНИЕ ПАРОЛЯ
    # ============================================================

    from datetime import timedelta

    @app.route('/forgot_password', methods=['GET', 'POST'])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('chats'))

        if request.method == 'POST':
            username = request.form.get('username')
            email    = request.form.get('email')

            if not username or not email:
                return render_template('forgot_password.html', error='Заполните все поля')

            user = User.query.filter_by(username=username, email=email).first()

            if not user:
                return render_template('forgot_password.html',
                                       success='Если данные верны, инструкции отправлены на email')

            PasswordReset.query.filter_by(user_id=user.id, used=False).delete()

            token = secrets.token_urlsafe(32)

            reset_request = PasswordReset(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )

            db.session.add(reset_request)
            db.session.commit()

            return redirect(url_for('reset_password', token=token))

        return render_template('forgot_password.html')

    @app.route('/reset_password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('chats'))

        reset_request = PasswordReset.query.filter_by(token=token, used=False).first()

        if not reset_request:
            return render_template('forgot_password.html',
                                   error='Недействительная ссылка для сброса пароля')

        if reset_request.expires_at < datetime.utcnow():
            reset_request.used = True
            db.session.commit()
            return render_template('forgot_password.html',
                                   error='Срок действия ссылки истек')

        if request.method == 'POST':
            new_password     = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not new_password or not confirm_password:
                return render_template('reset_password.html', error='Заполните все поля', token=token)

            if new_password != confirm_password:
                return render_template('reset_password.html', error='Пароли не совпадают', token=token)

            if len(new_password) < 8:
                return render_template('reset_password.html',
                                       error='Пароль должен быть минимум 8 символов', token=token)

            user = User.query.get(reset_request.user_id)
            if not user:
                return render_template('forgot_password.html', error='Пользователь не найден')

            user.password        = generate_password_hash(new_password)
            reset_request.used   = True
            db.session.commit()

            try:
                from security import SecurityAudit
                SecurityAudit.log_password_reset(user.id, user.username)
            except Exception:
                pass

            return render_template('login.html',
                                   success='Пароль успешно изменен. Теперь вы можете войти.')

        return render_template('reset_password.html', token=token)

    # ============================================================
    # МЕДИАГАЛЕРЕЯ
    # ============================================================

    @app.route('/get_media/<int:context_id>')
    @login_required
    def get_media(context_id):
        is_group   = request.args.get('is_group', 'false').lower() == 'true'
        media_type = request.args.get('type', 'images')
        if is_group:
            membership = GroupMember.query.filter_by(group_id=context_id, user_id=current_user.id).first()
            if not membership:
                return jsonify({'error': 'Нет доступа'}), 403
            base_query = Message.query.filter(Message.group_id == context_id, Message.is_deleted == False)
        else:
            chat_obj = Chat.query.get_or_404(context_id)
            if chat_obj.user1_id != current_user.id and chat_obj.user2_id != current_user.id:
                return jsonify({'error': 'Нет доступа'}), 403
            base_query = Message.query.filter(Message.chat_id == context_id, Message.is_deleted == False)

        result = []
        if media_type == 'images':
            msgs = base_query.filter(Message.image_path != None).order_by(Message.timestamp.desc()).limit(100).all()
            for msg in msgs:
                sender = User.query.get(msg.sender_id)
                result.append({
                    'id': msg.id,
                    'url': url_for('download_file', filepath=msg.image_path),
                    'sender_name': sender.username if sender else 'Unknown',
                    'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M')
                })
        elif media_type == 'files':
            msgs = base_query.filter(Message.file_path != None).order_by(Message.timestamp.desc()).limit(100).all()
            for msg in msgs:
                sender = User.query.get(msg.sender_id)
                result.append({
                    'id': msg.id,
                    'url': url_for('download_file', filepath=msg.file_path),
                    'file_name': msg.file_name,
                    'file_size': format_file_size(msg.file_size) if msg.file_size else None,
                    'file_icon': get_file_icon(msg.file_name) if msg.file_name else '📎',
                    'sender_name': sender.username if sender else 'Unknown',
                    'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M')
                })
        elif media_type == 'links':
            msgs = base_query.filter(Message.link_url != None).order_by(Message.timestamp.desc()).limit(100).all()
            for msg in msgs:
                sender = User.query.get(msg.sender_id)
                result.append({
                    'id': msg.id,
                    'url': msg.link_url,
                    'title': msg.link_title,
                    'description': msg.link_description,
                    'image': msg.link_image,
                    'sender_name': sender.username if sender else 'Unknown',
                    'timestamp': msg.timestamp.strftime('%d.%m.%Y %H:%M')
                })
        return jsonify(result)

    return app
