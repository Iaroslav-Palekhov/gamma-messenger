// Дополнительные функции JavaScript

// Закрытие модальных окон при клике вне их
document.addEventListener('DOMContentLoaded', function() {
    // Для модального окна изображений
    const imageModal = document.getElementById('imageModal');
    if (imageModal) {
        imageModal.addEventListener('click', function(e) {
            if (e.target === this || e.target.classList.contains('close-modal')) {
                this.style.display = 'none';
            }
        });
    }
    
    // Для формы нового чата
    const newChatForm = document.querySelector('.new-chat-form');
    const overlay = document.querySelector('.overlay');
    
    if (newChatForm && overlay) {
        overlay.addEventListener('click', function() {
            newChatForm.style.display = 'none';
            this.style.display = 'none';
        });
    }
});

// Функция для плавной прокрутки
function smoothScrollToBottom(element) {
    element.scrollTo({
        top: element.scrollHeight,
        behavior: 'smooth'
    });
}

// Форматирование времени
function formatTime(date) {
    return date.toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Валидация email
function isValidEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

// Уведомления
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 10px;
        color: white;
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    
    if (type === 'success') {
        notification.style.background = 'linear-gradient(135deg, #2ed573 0%, #1abc9c 100%)';
    } else if (type === 'error') {
        notification.style.background = 'linear-gradient(135deg, #ff4757 0%, #ff3838 100%)';
    } else {
        notification.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Анимации
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Функция для обработки ошибок загрузки изображений
function handleImageError(img) {
    img.onerror = null;
    img.src = '/static/images/default-error.png';
    img.alt = 'Не удалось загрузить изображение';
}

// Добавляем обработчики ко всем изображениям
document.addEventListener('DOMContentLoaded', function() {
    const images = document.querySelectorAll('img');
    images.forEach(img => {
        img.addEventListener('error', function() {
            handleImageError(this);
        });
    });
});
