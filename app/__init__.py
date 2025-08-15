"""
Flask Application Factory
This module creates and configures the Flask application instance.
"""

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flasgger import Swagger
import os

def create_app(config_name='default'):
    """Application factory function"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name == 'default':
        app.config.from_object('app.config.DevelopmentConfig')
    else:
        # Map environment names to config class names
        config_mapping = {
            'development': 'DevelopmentConfig',
            'production': 'ProductionConfig',
            'testing': 'TestingConfig'
        }
        config_class = config_mapping.get(config_name, config_name)
        app.config.from_object(f'app.config.{config_class}')
    
    # Initialize extensions
    jwt = JWTManager(app)
    CORS(app)
    
    # Configure Swagger
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec_1',
                "route": '/apispec_1.json',
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/apidocs/"
    }
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "SmartScope Backend API",
            "description": "Backend API for SmartScope application with file management, document management, and user authentication",
            "version": "1.0.0",
            "contact": {
                "name": "SmartScope Team"
            }
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\""
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ]
    }
    
    swagger = Swagger(app, config=swagger_config, template=swagger_template)
    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Set MongoDB URI in app config for models to access
    app.config['MONGO_URI'] = app.config.get('MONGO_URI', 'mongodb://localhost:27017/smartscope')
    
    # Register blueprints
    from app.api.auth import auth_bp
    from app.api.users import user_bp
    from app.api.documents import document_bp
    from app.api.files import files_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(user_bp, url_prefix='/api/user')
    app.register_blueprint(document_bp, url_prefix='/api/documents')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {'status': 'healthy', 'message': 'SmartScope Backend is running'}
    
    return app
