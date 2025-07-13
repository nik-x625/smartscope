import os

class Config:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/smartscope")
    SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
    DEBUG = os.getenv("DEBUG", "True") == "True"
    PORT = int(os.getenv("PORT", 8000))
    HOST = os.getenv("HOST", "0.0.0.0")
    # JWT settings
    from datetime import timedelta
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=60)  # 60 minutes
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)    # 7 days 