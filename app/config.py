"""
Configuration settings for the SmartScope Backend application
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # MongoDB settings
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/smartscope'
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # File upload settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/data/uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB default
    ALLOWED_EXTENSIONS = {
        'images': {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'},
        'documents': {'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'},
        'spreadsheets': {'xls', 'xlsx', 'csv', 'ods'},
        'presentations': {'ppt', 'pptx', 'odp'},
        'archives': {'zip', 'rar', '7z', 'tar', 'gz'},
        'code': {'py', 'js', 'html', 'css', 'json', 'xml', 'sql', 'md'}
    }
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Security settings
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
    PASSWORD_REQUIRE_UPPERCASE = os.environ.get('PASSWORD_REQUIRE_UPPERCASE', 'False').lower() == 'true'
    PASSWORD_REQUIRE_LOWERCASE = os.environ.get('PASSWORD_REQUIRE_LOWERCASE', 'False').lower() == 'true'
    PASSWORD_REQUIRE_DIGIT = os.environ.get('PASSWORD_REQUIRE_DIGIT', 'False').lower() == 'true'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/smartscope_dev'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    # In production, ensure these are set via environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    
    def __init__(self):
        super().__init__()
        # Only validate in production environment
        if os.environ.get('FLASK_ENV') == 'production':
            if not self.SECRET_KEY or not self.JWT_SECRET_KEY:
                raise ValueError("SECRET_KEY and JWT_SECRET_KEY must be set in production")

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/smartscope_test'
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or '/tmp/test_uploads'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# Set default config class
Config = DevelopmentConfig
