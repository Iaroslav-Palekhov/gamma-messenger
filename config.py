import os
import secrets
from datetime import timedelta


def _get_or_create_secret_key():
    env_key = os.environ.get('FLASK_SECRET_KEY')
    if env_key:
        return env_key
    key_file = '.secret_key'
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            key = f.read().strip()
            if len(key) >= 32:
                return key
    key = secrets.token_hex(64)
    try:
        with open(key_file, 'w') as f:
            f.write(key)
        os.chmod(key_file, 0o600)
        print(f"[SECURITY] Создан новый SECRET_KEY -> {key_file}")
    except Exception:
        pass
    return key


class Config:
    # Базовые настройки
    SECRET_KEY = _get_or_create_secret_key()
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Загрузка файлов
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB
    ALLOWED_EXTENSIONS = None

    # Сессии и куки
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True       # JS не может читать cookie
    SESSION_COOKIE_SAMESITE = 'Lax'     # Защита от CSRF
    SESSION_COOKIE_SECURE = False        # True только при HTTPS
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = False

    # Безопасность
    PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER', 'papirus-pepper-change-this-in-production')
    MESSAGE_ENCRYPTION_KEY = os.environ.get('MESSAGE_ENCRYPTION_KEY')
    MAX_MESSAGE_LENGTH = 4000
    MAX_USERNAME_LENGTH = 50
    MIN_PASSWORD_LENGTH = 8
    RATELIMIT_ENABLED = True

    # Продакшен: раскомментируй при HTTPS:
    # SESSION_COOKIE_SECURE = True
    # REMEMBER_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
