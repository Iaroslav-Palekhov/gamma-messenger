import os
from datetime import timedelta

class Config:
    SECRET_KEY = 'your-secret-key-change-this-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024
    
    ALLOWED_EXTENSIONS = None

    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
