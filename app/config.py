import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "ith_vallya_secret_ann_pulle"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(BASE_DIR, "threats.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

    # Flask-JWT-Extended Configuration
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "ith_vallya_jwt_secret_ann_pulle"  # Secret key for JWT
    JWT_TOKEN_LOCATION = ["cookies"]  # Store JWT tokens in cookies
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  # Token expiration time (1 hour)
    JWT_COOKIE_SECURE = False  # Set to True in production (HTTPS only)
    JWT_COOKIE_CSRF_PROTECT = False  # Disable CSRF protection for simplicity
    JWT_ACCESS_COOKIE_PATH = '/'  # Make the cookie available for all routes
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)  # Refresh token expiration time (30 days)