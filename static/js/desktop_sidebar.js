/* desktop_sidebar.js
   Sidebar that loads chats via API and handles navigation
   without iframes — just normal page loads, sidebar persists
   by being rendered on every page (chat.html, group_chat.html, chats.html)
*/

// Called on DOMContentLoaded from each page
function dsStartLiveChats() {
    if (typeof io !== 'undefined') {
        const socket = io({ transports: ['websocket', 'polling'], reconnectionDelay: 1000 });
        socket.on('connect', () => { socket.emit('heartbeat'); dsFetchAndRender(); });
        socket.on('chat_updated', () => dsFetchAndRender());
        socket.on('disconnect', () => setTimeout(() => setInterval(dsFetchAndRender, 5000), 2000));
    } else {
        setInterval(dsFetchAndRender, 5000);
    }
    dsFetchAndRender();
}

function dsFetchAndRender() {
    fetch('/api/get_chats_data')
        .then(r => r.ok ? r.json() : null)
        .then(data => { if (data) dsRenderChats(data.chats); })
        .catch(() => {});
}

function dsRenderChats(chats) {
    const list = document.getElementById('dsChatsList');
    if (!list) return;
    const scroll = list.scrollTop;

    // Detect current chat URL for active highlighting
    const currentUrl = window.location.pathname;

    let html = '';
    if (chats && chats.length > 0) {
        chats.forEach(c => {
            const isActive = currentUrl === new URL(c.chat_url, window.location.origin).pathname;
            const activeClass = isActive ? ' ds-active' : '';

            if (c.type === 'private') {
                html += `
                <a href="${c.chat_url}" class="ds-chat-item${activeClass}" data-chat-id="${c.id}" data-name="${dsEscape(c.other_username)}" data-type="private">
                    <div class="ds-chat-ava">
                        <img src="${c.other_avatar}" alt="" onerror="this.src='/static/uploads/avatars/default.png'">
                        <span class="ds-status ${c.other_status}"></span>
                        ${c.unread_count > 0 ? `<span class="ds-badge">${c.unread_count}</span>` : ''}
                    </div>
                    <div class="ds-chat-info">
                        <div class="ds-chat-row">
                            <span class="ds-chat-name">${dsEscape(c.other_username)}</span>
                            <span class="ds-chat-time">${c.last_message_time}</span>
                        </div>
                        <div class="ds-chat-preview-row">
                            <span class="ds-preview-text">${c.last_message}</span>
                            ${c.unread_count > 0 ? `<span class="ds-unread-count">${c.unread_count}</span>` : ''}
                        </div>
                    </div>
                    <button class="ds-delete-btn" onclick="event.preventDefault();event.stopPropagation();dsDeleteChat(${c.id},'${dsEscape(c.other_username)}')" title="Удалить">
                        <svg width="14" height="14" viewBox="0 0 1024 1024"><use xlink:href="#icon-delete"></use></svg>
                    </button>
                </a>`;
            } else if (c.type === 'group') {
                html += `
                <a href="${c.chat_url}" class="ds-chat-item${activeClass}" data-chat-id="${c.id}" data-name="${dsEscape(c.group_name)}" data-type="group">
                    <div class="ds-chat-ava">
                        <img src="${c.group_icon}" alt="" onerror="this.src='/static/uploads/group_icons/default.png'">
                        ${c.unread_count > 0 ? `<span class="ds-badge">${c.unread_count}</span>` : ''}
                    </div>
                    <div class="ds-chat-info">
                        <div class="ds-chat-row">
                            <span class="ds-chat-name">${dsEscape(c.group_name)}</span>
                            <span class="ds-chat-time">${c.last_message_time}</span>
                        </div>
                        <div class="ds-chat-preview-row">
                            <span class="ds-preview-text">${c.last_message}</span>
                            ${c.unread_count > 0 ? `<span class="ds-unread-count">${c.unread_count}</span>` : ''}
                        </div>
                    </div>
                </a>`;
            }
        });
    } else {
        html = `<div class="ds-empty">
            <svg width="48" height="48" viewBox="0 0 1024 1024" style="opacity:0.25;"><use xlink:href="#icon-chat"></use></svg>
            <p>Нет чатов</p>
        </div>`;
    }

    if (list.innerHTML !== html) {
        list.innerHTML = html;
        list.scrollTop = scroll;
    }
}

function dsEscape(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function dsDeleteChat(chatId, chatName) {
    if (!confirm(`Удалить чат с ${chatName}? Все сообщения будут удалены.`)) return;
    fetch(`/chat/${chatId}/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            dsFetchAndRender();
            // If we deleted the currently open chat, go to chats list
            if (window.location.pathname.includes(`/chat/${chatId}`)) {
                window.location.href = '/chats';
            }
        } else {
            alert(data.error || 'Ошибка');
        }
    });
}

function dsFilterChats(q) {
    const query = q.toLowerCase();
    document.querySelectorAll('.ds-chat-item').forEach(item => {
        const name = (item.dataset.name || '').toLowerCase();
        item.style.display = name.includes(query) ? '' : 'none';
    });
}
