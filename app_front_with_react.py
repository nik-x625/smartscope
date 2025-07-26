from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response, session, flash
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from bson import ObjectId
import re
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import configuration and database
from config import Config
from database import mongo, DatabaseService

# Models
from models_for_documents.models import Section, Chapter, DocumentTemplate
from models_for_flask_login.models import User
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
import time
from flask_cors import CORS
from flasgger import Swagger



from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_jwt_extended.exceptions import JWTExtendedException, NoAuthorizationError, JWTDecodeError

from flask import Blueprint


# Create a logger
# if the name is not specified, the root logger will be used and it will propagate to all other loggers, like MongoDB logs
logger = logging.getLogger('smartscope')

def create_app(config_class=Config):
    # Create and configure the app
    app = Flask(__name__, static_folder='static')
    CORS(app, resources={r"/*": {"origins": "*"}})
    app.config.from_object(config_class)
    # Add a secret key for JWT
    app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this!


    # Initialize MongoDB
    mongo.init_app(app)

    # Setup logging
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create a file handler
    file_handler = RotatingFileHandler(
        'logs/app.log', maxBytes=5000000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.DEBUG)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(logging.DEBUG)

    # Set up the root logger
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'

    @login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(mongo, user_id)

    jwt = JWTManager(app)

    # Custom JWT error handlers to ensure all JWT errors return 401
    @jwt.invalid_token_loader
    def custom_invalid_token_loader(reason):
        logger.warning(f'Invalid token: {reason}')
        return jsonify({'msg': 'Invalid or expired token', 'error': reason}), 401

    @jwt.unauthorized_loader
    def custom_unauthorized_loader(reason):
        logger.warning(f'Unauthorized: {reason}')
        return jsonify({'msg': 'Missing or invalid authorization', 'error': reason}), 401

    @jwt.expired_token_loader
    def custom_expired_token_loader(jwt_header, jwt_payload):
        logger.warning('Expired token')
        return jsonify({'msg': 'Token has expired'}), 401

    # Create and register blueprints
    auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
    user_bp = Blueprint('user', __name__, url_prefix='/api/user')
    
    # Initialize rate limiter first
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
    
    # Define auth routes
    @auth_bp.route('/register', methods=['POST'])
    def auth_register():
        """
        Register a new user (with email verification)
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - email
                - password
                - name
              properties:
                email:
                  type: string
                  example: user@example.com
                password:
                  type: string
                  example: StrongPassword123!
                name:
                  type: string
                  example: John Doe
        responses:
          201:
            description: Registration successful, verification email sent
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Registration successful. Please check your email to verify your account."
          400:
            description: Invalid input or user already exists
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Email already exists"
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()

        # Validate email format
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return jsonify({'error': 'Invalid email format'}), 400
        # Validate password strength
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password):
            return jsonify({'error': 'Password must be at least 8 characters and include upper, lower, and number'}), 400
        # Validate name
        if not name:
            return jsonify({'error': 'Name is required'}), 400
        # Check if user exists
        if User.get_by_email(mongo, email):
            return jsonify({'error': 'Email already exists'}), 400

        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        # Create verification token
        verification_token = serializer.dumps(email, salt='email-verify')
        # Create user
        user = User(
            username=email,  # Use email as username for now
            email=email,
            password=None,  # We'll set hash directly
            name=name,
            is_verified=False,
            verification_token=verification_token,
            verification_sent_at=datetime.utcnow()
        )
        user.password_hash = password_hash
        mongo.db.users.insert_one(user.to_dict())

        # Send verification email (mock)
        verification_url = f"https://your-frontend-app/verify-email?token={verification_token}"
        logger.info(f"Send verification email to {email}: {verification_url}")
        # TODO: Integrate Flask-Mail or other email backend

        return jsonify({'message': 'Registration successful. Please check your email to verify your account.'}), 201

    @auth_bp.route('/login', methods=['POST'])
    @limiter.limit("5 per minute")
    def auth_login():
        """
        User login to obtain JWT tokens.
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                  example: user@example.com
                password:
                  type: string
                  example: StrongPassword123!
        responses:
          200:
            description: JWT tokens returned
            schema:
              type: object
              properties:
                access_token:
                  type: string
                refresh_token:
                  type: string
          401:
            description: Invalid credentials or unverified email
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Invalid credentials or email not verified"
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        user = User.get_by_email(mongo, email)
        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401
        if not user.is_verified:
            return jsonify({'error': 'Email not verified'}), 401
        access_token = create_access_token(identity=str(user._id))
        refresh_token = create_refresh_token(identity=str(user._id))
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

    @auth_bp.route('/forgot-password', methods=['POST'])
    def forgot_password():
        """
        Request a password reset email.
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  example: user@example.com
        responses:
          200:
            description: If email exists, a reset link is sent (generic message)
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "If the email exists, a password reset link has been sent."
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        user = User.get_by_email(mongo, email)
        if user:
            reset_token = serializer.dumps(email, salt='reset-password')
            mongo.db.users.update_one({'_id': user._id}, {'$set': {'reset_token': reset_token, 'reset_sent_at': datetime.utcnow()}})
            reset_url = f"https://your-frontend-app/reset-password?token={reset_token}"
            logger.info(f"Send password reset email to {email}: {reset_url}")
            # TODO: Integrate Flask-Mail or other email backend
        return jsonify({'message': 'If the email exists, a password reset link has been sent.'}), 200

    @auth_bp.route('/reset-password', methods=['POST'])
    def reset_password():
        """
        Reset password using a valid reset token.
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - token
                - newPassword
              properties:
                token:
                  type: string
                  example: "reset-token-string"
                newPassword:
                  type: string
                  example: "NewStrongPassword123!"
        responses:
          200:
            description: Password reset successful
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Password has been reset successfully."
          400:
            description: Invalid or expired token, or weak password
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Invalid or expired token"
        """
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('newPassword', '')
        # Validate password strength
        if len(new_password) < 8 or not re.search(r"[A-Z]", new_password) or not re.search(r"[a-z]", new_password) or not re.search(r"[0-9]", new_password):
            return jsonify({'error': 'Password must be at least 8 characters and include upper, lower, and number'}), 400
        try:
            email = serializer.loads(token, salt='reset-password', max_age=3600)
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 400
        user = User.get_by_email(mongo, email)
        if not user or user.reset_token != token:
            return jsonify({'error': 'Invalid or expired token'}), 400
        # Update password
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        mongo.db.users.update_one({'_id': user._id}, {'$set': {'password_hash': password_hash}, '$unset': {'reset_token': '', 'reset_sent_at': ''}})
        logger.info(f'Password reset for user {email}')
        return jsonify({'message': 'Password has been reset successfully.'}), 200

    @auth_bp.route('/verify-email', methods=['GET'])
    def verify_email():
        """
        Verify email address using a verification token.
        ---
        tags:
          - Auth
        parameters:
          - in: query
            name: token
            required: true
            type: string
            description: Email verification token
        responses:
          200:
            description: Email verified successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Email verified successfully."
          400:
            description: Invalid or expired token
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Invalid or expired token"
        """
        token = request.args.get('token', '')
        try:
            email = serializer.loads(token, salt='email-verify', max_age=86400)
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 400
        user = User.get_by_email(mongo, email)
        if not user or user.verification_token != token:
            return jsonify({'error': 'Invalid or expired token'}), 400
        if user.is_verified:
            return jsonify({'message': 'Email already verified.'}), 200
        # Mark user as verified
        mongo.db.users.update_one({'_id': user._id}, {'$set': {'is_verified': True}, '$unset': {'verification_token': '', 'verification_sent_at': ''}})
        logger.info(f'Email verified for user {email}')
        return jsonify({'message': 'Email verified successfully.'}), 200

    @auth_bp.route('/resend-verification', methods=['POST'])
    def resend_verification():
        """
        Resend email verification link.
        ---
        tags:
          - Auth
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  example: user@example.com
        responses:
          200:
            description: If email exists and not verified, a verification link is sent (generic message)
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "If the email exists and is not verified, a verification link has been sent."
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        user = User.get_by_email(mongo, email)
        if user and not user.is_verified:
            verification_token = serializer.dumps(email, salt='email-verify')
            mongo.db.users.update_one({'_id': user._id}, {'$set': {'verification_token': verification_token, 'verification_sent_at': datetime.utcnow()}})
            verification_url = f"https://your-frontend-app/verify-email?token={verification_token}"
            logger.info(f"Resend verification email to {email}: {verification_url}")
            # TODO: Integrate Flask-Mail or other email backend
        return jsonify({'message': 'If the email exists and is not verified, a verification link has been sent.'}), 200

    @auth_bp.route('/refresh-token', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh_token():
        """
        Refresh access token using a valid refresh token.
        ---
        tags:
          - Auth
        security:
          - Bearer: []
        responses:
          200:
            description: Returns a new access token
            schema:
              type: object
              properties:
                access_token:
                  type: string
                  example: "new_access_token"
              examples:
                application/json: {"access_token": "new_access_token"}
          401:
            description: Unauthorized, missing or invalid refresh token
            schema:
              type: object
              properties:
                msg:
                  type: string
                  example: "Invalid or expired token"
        """
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token), 200

    @auth_bp.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        """
        Logout user (invalidate token).
        ---
        tags:
          - Auth
        security:
          - Bearer: []
        responses:
          200:
            description: Logout successful
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Logout successful"
          401:
            description: Unauthorized, missing or invalid token
        """
        # TODO: Implement token blacklisting if needed
        # For now, just return success (client should discard tokens)
        logger.info(f'User logout: {get_jwt_identity()}')
        return jsonify({'message': 'Logout successful'}), 200

    # Define user routes
    @user_bp.route('/me', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        """
        Get current user's profile.
        ---
        tags:
          - User
        security:
          - Bearer: []
        responses:
          200:
            description: Returns the current user's profile
            schema:
              type: object
              properties:
                _id:
                  type: string
                  example: "60c72b2f9b1e8b001c8e4b8a"
                username:
                  type: string
                  example: "user@example.com"
                email:
                  type: string
                  example: "user@example.com"
                name:
                  type: string
                  example: "John Doe"
                avatar_url:
                  type: string
                  example: "https://example.com/avatar.jpg"
                is_verified:
                  type: boolean
                  example: true
                created_at:
                  type: string
                  format: date-time
                  example: "2024-05-01T12:00:00Z"
          401:
            description: Unauthorized, missing or invalid JWT
        """
        user_id = get_jwt_identity()
        user = User.get_by_id(mongo, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        profile = user.to_dict()
        # Remove sensitive fields
        profile.pop('password_hash', None)
        profile.pop('verification_token', None)
        profile.pop('verification_sent_at', None)
        profile.pop('reset_token', None)
        profile.pop('reset_sent_at', None)
        return jsonify(profile), 200

    @user_bp.route('/me', methods=['PUT'])
    @jwt_required()
    def update_user_profile():
        """
        Update current user's profile.
        ---
        tags:
          - User
        security:
          - Bearer: []
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "John Doe"
                avatar_url:
                  type: string
                  example: "https://example.com/avatar.jpg"
        responses:
          200:
            description: Profile updated successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Profile updated successfully"
          400:
            description: Invalid input
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Invalid input"
          401:
            description: Unauthorized, missing or invalid JWT
        """
        user_id = get_jwt_identity()
        user = User.get_by_id(mongo, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        data = request.get_json()
        name = data.get('name', '').strip() if data.get('name') else None
        avatar_url = data.get('avatar_url', '').strip() if data.get('avatar_url') else None
        # Validate name
        if name is not None and not name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        # Update profile
        update_data = {}
        if name is not None:
            update_data['name'] = name
        if avatar_url is not None:
            update_data['avatar_url'] = avatar_url
        if update_data:
            mongo.db.users.update_one({'_id': user._id}, {'$set': update_data})
            logger.info(f'Profile updated for user {user.email}')
        return jsonify({'message': 'Profile updated successfully'}), 200

    @user_bp.route('/change-password', methods=['POST'])
    @jwt_required()
    def change_password():
        """
        Change user's password.
        ---
        tags:
          - User
        security:
          - Bearer: []
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - current_password
                - new_password
              properties:
                current_password:
                  type: string
                  example: "OldPassword123!"
                new_password:
                  type: string
                  example: "NewStrongPassword123!"
        responses:
          200:
            description: Password changed successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Password changed successfully"
          400:
            description: Invalid current password or weak new password
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Invalid current password"
          401:
            description: Unauthorized, missing or invalid JWT
        """
        user_id = get_jwt_identity()
        user = User.get_by_id(mongo, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        # Verify current password
        if not bcrypt.check_password_hash(user.password_hash, current_password):
            return jsonify({'error': 'Invalid current password'}), 400
        # Validate new password strength
        if len(new_password) < 8 or not re.search(r"[A-Z]", new_password) or not re.search(r"[a-z]", new_password) or not re.search(r"[0-9]", new_password):
            return jsonify({'error': 'Password must be at least 8 characters and include upper, lower, and number'}), 400
        # Update password
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        mongo.db.users.update_one({'_id': user._id}, {'$set': {'password_hash': password_hash}})
        logger.info(f'Password changed for user {user.email}')
        return jsonify({'message': 'Password changed successfully'}), 200
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)

    # limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

    return app, auth_bp, user_bp, limiter

# Create the app instance and blueprints
app, auth_bp, user_bp, limiter = create_app()

# Add Swagger securityDefinitions for Bearer token
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "SmartScope API",
        "description": "API documentation for SmartScope backend",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
        }
    },
    "security": [
        {"Bearer": []}
    ]
}

swagger = Swagger(app, template=swagger_template)

db_service = DatabaseService(mongo)

bcrypt = Bcrypt(app)
serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

# Add custom template filters




@app.route('/')
@login_required
def index():
    """
    Root page (dashboard)
    ---
    tags:
      - UI
    summary: Render the main dashboard page (HTML)
    responses:
      200:
        description: Dashboard HTML page
        examples:
          text/html: "<html>...dashboard...</html>"
      302:
        description: Redirect to login if not authenticated
    """
    logger.info('Accessing root page, redirecting to dashboard')
    return render_template('index.html')



@app.route('/api/register', methods=['POST'])
def api_register():
    """
    Register a new user
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              example: alice
            email:
              type: string
              example: alice@example.com
            password:
              type: string
              example: secret
    responses:
      201:
        description: Registration successful    
      400:
        description: Username or email already exists
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check for missing fields
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if username or email already exists
    if User.get_by_username(mongo, username):
        return jsonify({'error': 'Username already exists'}), 400
    if User.get_by_email(mongo, email):
        return jsonify({'error': 'Email already exists'}), 400

    user = User(username=username, email=email, password=password)
    mongo.db.users.insert_one(user.to_dict())
    login_user(user)
    return jsonify({'message': 'Registration successful'}), 201


'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # Check if username or email already exists
        if User.get_by_username(mongo, username):
            return render_template('register.html', error="Username already exists")
        if User.get_by_email(mongo, email):
            return render_template('register.html', error="Email already exists")
        user = User(username=username, email=email, password=password)
        mongo.db.users.insert_one(user.to_dict())
        login_user(user)
        return redirect(url_for('registration_success'))
    return render_template('register.html')
'''




def ensure_ids(items):
    processed = []
    for item in items:
        if 'id' not in item:
            # Generate a new unique ID for each item
            item['id'] = str(ObjectId())
        if 'children' in item and item['children']:
            # Recursively ensure nested items (children) have IDs as well
            item['children'] = ensure_ids(item['children'])
        processed.append(item)
    return processed



'''
@app.route('/save_document', methods=['POST'])
@login_required
def save_document():
    """Save the current draft document and change its status to saved"""
    user_id = current_user._id

    try:
        # Find the draft document
        draft_doc = mongo.db.documents.find_one(
            {'user_id': user_id, 'doc_status': 'draft'})
        if not draft_doc:
            logger.warning(f"No draft document found for user {user_id}")
            return jsonify({'status': 'error', 'message': 'No draft document found'}), 404

        # Update the document status to saved
        result = mongo.db.documents.update_one(
            # Use the specific document ID to ensure we only update this one
            {'_id': draft_doc['_id']},
            {
                '$set': {
                    'doc_status': 'saved',
                    'updated_at': datetime.now(),
                    'saved_at': datetime.now()
                }
            }
        )

        if result.modified_count > 0:
            logger.info(
                f"Document {draft_doc['_id']} saved successfully for user {user_id}")
            return jsonify({'status': 'success', 'message': 'Document saved successfully'})
        else:
            logger.warning(
                f"Failed to save document {draft_doc['_id']} for user {user_id}")
            return jsonify({'status': 'error', 'message': 'Failed to save document'}), 500

    except Exception as e:
        logger.error(f"Error saving document: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500
'''




# JWT login route
@app.route('/api/login', methods=['POST'])
def api_login():
    """
    User login to obtain JWT tokens.
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              example: alice
            password:
              type: string
              example: secret
    responses:
      200:
        description: JWT tokens returned
        schema:
          type: object
          properties:
            access_token:
              type: string
            refresh_token:
              type: string
      401:
        description: Invalid credentials
        schema:
          type: object
          properties:
            msg:
              type: string
              example: Bad username or password
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.get_by_username(mongo, username)
    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user._id))
        refresh_token = create_refresh_token(identity=str(user._id))
        from flask_jwt_extended.utils import decode_token
        from datetime import datetime
        decoded = decode_token(access_token)
        expires_timestamp = decoded['exp']
        expires_in = expires_timestamp - int(datetime.utcnow().timestamp())
        return jsonify(
            access_token=access_token,
            refresh_token=refresh_token,
            expiresIn=expires_in
        ), 200
    return jsonify({"msg": "Bad username or password"}), 401


@app.route('/api/get_documents', methods=['GET'])
@jwt_required()
def get_documents():
    """
    Get documents for the authenticated user
    ---
    tags:
      - Documents
    security:
      - Bearer: []
    responses:
      200:
        description: Returns a list of documents for the authenticated user
        schema:
          type: array
          items:
            type: object
            properties:
              _id:
                type: string
                example: "60c72b2f9b1e8b001c8e4b8a"
              title:
                type: string
                example: "My Document"
            examples:
              application/json: [{"_id": "...", "title": "..."}]
      401:
        description: Unauthorized, missing or invalid JWT
    """
    user_id = get_jwt_identity()

    logger.info(f'user_id: {user_id}')

    # Fetch documents for this user from MongoDB
    user_documents = list(mongo.db.documents.find({'user_id': user_id}))
    # Convert ObjectId to string for JSON serialization
    for doc in user_documents:
        doc['_id'] = str(doc['_id'])
        if 'user_id' in doc:
            doc['user_id'] = str(doc['user_id'])
        if 'created_at' in doc:
            doc['created_at'] = str(doc['created_at'])
        if 'updated_at' in doc:
            doc['updated_at'] = str(doc['updated_at'])

    logger.info(f'user_documents: {user_documents}')
    
    return jsonify(user_documents), 200


@app.route('/api/get_document', methods=['GET'])
@jwt_required()
def get_document():
    """
    Get a specific document for the authenticated user by document ID
    ---
    tags:
      - Documents
    security:
      - Bearer: []
    parameters:
      - in: query
        name: document_id
        required: true
        type: string
        description: The ID of the document to retrieve
    responses:
      200:
        description: Returns the document for the authenticated user
        schema:
          type: object
          properties:
            _id:
              type: string
              example: "60c72b2f9b1e8b001c8e4b8a"
            title:
              type: string
              example: "Research Report 2024"
            content:
              type: object
              properties:
                sections:
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        type: string
                        example: "sec-1"
                      title:
                        type: string
                        example: "Introduction"
                      content:
                        type: string
                        example: "This section introduces the research topic."
                      children:
                        type: array
                        items:
                          type: object
                          properties:
                            id:
                              type: string
                              example: "sec-1-1"
                            title:
                              type: string
                              example: "Background"
                            content:
                              type: string
                              example: "Background information goes here."
            user_id:
              type: string
              example: "60c72b2f9b1e8b001c8e4b8b"
            doc_status:
              type: string
              example: "saved"
            created_at:
              type: string
              format: date-time
              example: "2024-05-01T12:00:00Z"
            updated_at:
              type: string
              format: date-time
              example: "2024-05-02T15:30:00Z"
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI"]
        examples:
          application/json: {
            "_id": "60c72b2f9b1e8b001c8e4b8a",
            "title": "Research Report 2024",
            "content": {
              "sections": [
                {
                  "id": "sec-1",
                  "title": "Introduction",
                  "content": "This section introduces the research topic.",
                  "children": [
                    {
                      "id": "sec-1-1",
                      "title": "Background",
                      "content": "Background information goes here."
                    }
                  ]
                },
                {
                  "id": "sec-2",
                  "title": "Methods",
                  "content": "Description of research methods.",
                  "children": []
                }
              ]
            },
            "user_id": "60c72b2f9b1e8b001c8e4b8b",
            "doc_status": "saved",
            "created_at": "2024-05-01T12:00:00Z",
            "updated_at": "2024-05-02T15:30:00Z",
            "tags": ["research", "2024", "AI"]
          }
      400:
        description: Bad request - missing document_id parameter
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "No document_id provided"
      401:
        description: Unauthorized, missing or invalid JWT
      404:
        description: Document not found
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Document not found"
    """
    from bson import ObjectId
    user_id = get_jwt_identity()
    document_id = request.args.get('document_id')
    if not document_id:
        return jsonify({'status': 'error', 'message': 'No document_id provided'}), 400
    try:
        doc = mongo.db.documents.find_one({'_id': ObjectId(document_id), 'user_id': user_id})
        if not doc:
            return jsonify({'status': 'error', 'message': 'Document not found'}), 404
        # Convert ObjectId to string for JSON serialization
        doc['_id'] = str(doc['_id'])
        if 'user_id' in doc:
            doc['user_id'] = str(doc['user_id'])
        if 'created_at' in doc:
            doc['created_at'] = str(doc['created_at'])
        if 'updated_at' in doc:
            doc['updated_at'] = str(doc['updated_at'])
        return jsonify(doc), 200
    except Exception as e:
        logger.error(f"Error fetching document {document_id} for user {user_id}: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh endpoint to obtain a new access token using a valid refresh token.
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    summary: Obtain a new access token using a valid refresh token
    responses:
      200:
        description: Returns a new access token
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: "new_token"
        examples:
          application/json: {"access_token": "new_token"}
      401:
        description: Unauthorized, missing or invalid refresh token
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Invalid or expired token"
    """
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token), 200



# @app.route('/api/users')
# @jwt_required()
# def get_users():
#     """
#     Get list of users
#     ---
#     responses:
#       200:
#         description: A list of users
#         examples:
#           application/json: [{"id": 1, "name": "Alice"}]
#     """
#     return jsonify([{"id": 1, "name": "Alice"}])


@app.route('/api/set_document', methods=['POST'])
@jwt_required()
def set_document():
    """
    Create or update a document for the authenticated user.
    ---
    tags:
      - Documents
    security:
      - Bearer: []
    parameters:
      - in: body
        name: document
        required: true
        schema:
          type: object
          description: The document JSON to store
          properties:
            title:
              type: string
              example: "Research Report 2024"
            content:
              type: object
              properties:
                sections:
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        type: string
                        example: "sec-1"
                      title:
                        type: string
                        example: "Introduction"
                      content:
                        type: string
                        example: "This section introduces the research topic."
                      children:
                        type: array
                        items:
                          type: object
                          properties:
                            id:
                              type: string
                              example: "sec-1-1"
                            title:
                              type: string
                              example: "Background"
                            content:
                              type: string
                              example: "Background information goes here."
            doc_status:
              type: string
              example: "saved"
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI"]
        examples:
          application/json: {
            "title": "Research Report 2024",
            "content": {
              "sections": [
                {
                  "id": "sec-1",
                  "title": "Introduction",
                  "content": "This section introduces the research topic.",
                  "children": [
                    {
                      "id": "sec-1-1",
                      "title": "Background",
                      "content": "Background information goes here."
                    }
                  ]
                },
                {
                  "id": "sec-2",
                  "title": "Methods",
                  "content": "Description of research methods.",
                  "children": []
                }
              ]
            },
            "doc_status": "saved",
            "tags": ["research", "2024", "AI"]
          }
    responses:
      200:
        description: Document saved successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: success
            document_id:
              type: string
              example: "60c72b2f9b1e8b001c8e4b8a"
      400:
        description: Invalid input
      401:
        description: Unauthorized, missing or invalid JWT
    """
    user_id = get_jwt_identity()

    logger.info(f'in the set_document route, user_id: {user_id}')

    data = request.get_json()

    logger.info(f'in the set_document route, data: {data}')

    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400

    # Attach user_id to the document
    data['user_id'] = user_id

    from bson import ObjectId
    from datetime import datetime
    doc_id = data.get('_id')
    now = datetime.utcnow()
    if doc_id:
        # Update existing document
        existing_doc = mongo.db.documents.find_one({'_id': ObjectId(doc_id), 'user_id': user_id})
        if not existing_doc:
            return jsonify({'status': 'error', 'message': 'Document not found'}), 404
        data['_id'] = ObjectId(doc_id)
        # Preserve created_at, update updated_at
        data['created_at'] = existing_doc.get('created_at', now)
        data['updated_at'] = now
        result = mongo.db.documents.replace_one({'_id': ObjectId(doc_id), 'user_id': user_id}, data, upsert=True)
        logger.info(f'in the set_document route, mongodb update result: {result}')
        return jsonify({'status': 'success', 'document_id': str(doc_id)}), 200
    else:
        # Insert new document
        data['created_at'] = now
        data['updated_at'] = now
        result = mongo.db.documents.insert_one(data)
        logger.info(f'in the set_document route, new document insert attempt, mongodb insert result: {result}')
        return jsonify({'status': 'success', 'document_id': str(result.inserted_id)}), 200


@app.route('/api/delete_user', methods=['DELETE'])
@jwt_required()
def api_delete_user():
    """
    Delete the authenticated user and all their data.
    ---
    tags:
      - User
    security:
      - Bearer: []
    summary: Delete the authenticated user and all their documents/templates
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: "User deleted successfully"
        examples:
          application/json: {"message": "User deleted successfully"}
      401:
        description: Unauthorized
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Invalid or expired token"
      500:
        description: Error deleting user
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Error deleting user: ..."
    """
    user_id = get_jwt_identity()
    try:
        # Delete user's documents
        mongo.db.documents.delete_many({'user_id': user_id})
        # Delete user's templates
        mongo.db.templates.delete_many({'user_id': user_id})
        # Delete user (fix: convert user_id to ObjectId)
        mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        logger.error(f'Error deleting user {user_id}: {str(e)}', exc_info=True)
        return jsonify({'error': f'Error deleting user: {str(e)}'}), 500


@app.errorhandler(JWTExtendedException)
def handle_jwt_errors(e):
    logger.warning(f'JWT error: {str(e)}')
    return jsonify({'msg': 'Invalid or expired token', 'error': str(e)}), 401

@app.errorhandler(NoAuthorizationError)
def handle_no_auth_error(e):
    logger.warning(f'NoAuthorizationError: {str(e)}')
    return jsonify({'msg': 'Missing or invalid authorization', 'error': str(e)}), 401

@app.errorhandler(JWTDecodeError)
def handle_jwt_decode_error(e):
    logger.warning(f'JWTDecodeError: {str(e)}')
    return jsonify({'msg': 'Malformed JWT', 'error': str(e)}), 401

@app.errorhandler(422)
def handle_unprocessable_entity(e):
    # This is for malformed JWTs and similar issues
    logger.warning(f'422 error: {str(e)}')
    # Try to extract the error message from the Werkzeug HTTPException
    try:
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException) and hasattr(e, 'data'):
            data = e.data
            if isinstance(data, dict) and 'msg' in data:
                # If the error message is about JWT, return 401
                if 'jwt' in data['msg'].lower() or 'token' in data['msg'].lower():
                    return jsonify({'msg': data['msg'], 'error': str(e)}), 401
    except Exception as ex:
        logger.warning(f'Error inspecting 422 exception: {ex}')
    # Fallback: always return 401 for 422
    return jsonify({'msg': 'Invalid or malformed request', 'error': str(e)}), 401


# Register blueprints
# app.register_blueprint(auth_bp)
# app.register_blueprint(user_bp)

# limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

if __name__ == '__main__':
    app.logger.info('Starting Flask application')
    app.run(host=Config.HOST, debug=Config.DEBUG, port=9000)

