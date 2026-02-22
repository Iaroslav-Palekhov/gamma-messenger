from flask import Flask
from flask_login import LoginManager
from config import Config
from models import db, User
from routing import register_routes
from utils import create_upload_folders, create_default_avatars
from security import init_security
import os

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Инициализация расширений
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Создаём папки для загрузок
    with app.app_context():
        create_upload_folders(app)
        create_default_avatars(app)
        db.create_all()

    # Регистрируем маршруты
    register_routes(app, db, login_manager)

    # Инициализируем модуль безопасности (после регистрации маршрутов!)
    init_security(app)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=2200)
