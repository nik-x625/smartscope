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
    
    # Load JWT secret from environment or use default (should be changed in production)
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')

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

    # Initialize JWT
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

    # Initialize rate limiter
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
    
    # Create and register blueprints
    auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
    user_bp = Blueprint('user', __name__, url_prefix='/api/user')
    
    # Define auth routes
    @auth_bp.route('/register', methods=['POST'])
    def auth_register():
        """
        Register a new user account with email verification.
        
        Creates a new user account and sends a verification email. The user must verify their email
        before they can log in. Password must meet security requirements.
        ---
        tags:
          - Authentication
        summary: Register a new user account
        description: |
          Register a new user account with email verification. The account will be created but marked
          as unverified until the user clicks the verification link sent to their email address.
          
          **Password Requirements:**
          - Minimum 8 characters
          - Must contain uppercase letter
          - Must contain lowercase letter  
          - Must contain number
        parameters:
          - in: body
            name: body
            required: true
            description: User registration data
            schema:
              type: object
              required:
                - email
                - password
                - name
              properties:
                email:
                  type: string
                  format: email
                  description: User's email address (will be used as username)
                  example: "john.doe@example.com"
                password:
                  type: string
                  minLength: 8
                  description: User's password (must meet security requirements)
                  example: "StrongPassword123!"
                name:
                  type: string
                  minLength: 1
                  description: User's full name
                  example: "John Doe"
        responses:
          201:
            description: User account created successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Success message with verification instructions
                  example: "Registration successful. Please check your email to verify your account."
          400:
            description: Invalid input data or user already exists
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Specific error message
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
        logger.info(f"Send verification email to {email}")  # Removed sensitive URL from log
        # TODO: Integrate Flask-Mail or other email backend

        return jsonify({'message': 'Registration successful. Please check your email to verify your account.'}), 201

    @auth_bp.route('/login', methods=['POST'])
    @limiter.limit("5 per minute")
    def auth_login():
        """
        Authenticate user and obtain JWT tokens.
        
        Validates user credentials and returns JWT access and refresh tokens for API authentication.
        Only verified users can log in. Rate limited to 5 attempts per minute.
        ---
        tags:
          - Authentication
        summary: User login with JWT token generation
        description: |
          Authenticate a user with their email and password. Returns JWT tokens for API access.
          
          **Requirements:**
          - User account must exist
          - Email must be verified
          - Password must be correct
          - Rate limited to prevent brute force attacks
        parameters:
          - in: body
            name: body
            required: true
            description: User login credentials
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                  format: email
                  description: User's email address
                  example: "john.doe@example.com"
                password:
                  type: string
                  description: User's password
                  example: "StrongPassword123!"
        responses:
          200:
            description: Authentication successful
            schema:
              type: object
              properties:
                access_token:
                  type: string
                  description: JWT access token for API authentication
                  example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                refresh_token:
                  type: string
                  description: JWT refresh token for obtaining new access tokens
                  example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          401:
            description: Authentication failed
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Specific authentication error
                  example: "Invalid credentials or email not verified"
          429:
            description: Too many login attempts
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Rate limit exceeded message
                  example: "Too many login attempts. Please try again later."
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
        
        Sends a password reset link to the user's email address if the account exists.
        For security reasons, the response is always the same regardless of whether the email exists.
        ---
        tags:
          - Authentication
        summary: Request password reset email
        description: |
          Initiates the password reset process by sending a reset link to the user's email.
          
          **Security Note:** The response is intentionally generic to prevent email enumeration attacks.
          The same message is returned whether the email exists or not.
        parameters:
          - in: body
            name: body
            required: true
            description: Password reset request data
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  format: email
                  description: Email address to send reset link to
                  example: "john.doe@example.com"
        responses:
          200:
            description: Password reset email sent (if account exists)
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Generic success message for security
                  example: "If the email exists, a password reset link has been sent."
        """
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        user = User.get_by_email(mongo, email)
        if user:
            reset_token = serializer.dumps(email, salt='reset-password')
            mongo.db.users.update_one({'_id': user._id}, {'$set': {'reset_token': reset_token, 'reset_sent_at': datetime.utcnow()}})
            reset_url = f"https://your-frontend-app/reset-password?token={reset_token}"
            logger.info(f"Send password reset email to {email}")
            # TODO: Integrate Flask-Mail or other email backend
        return jsonify({'message': 'If the email exists, a password reset link has been sent.'}), 200

    @auth_bp.route('/reset-password', methods=['POST'])
    def reset_password():
        """
        Reset user password using a valid reset token.
        
        Allows users to set a new password using a token received via email.
        The token expires after 1 hour for security.
        ---
        tags:
          - Authentication
        summary: Reset password with token
        description: |
          Resets the user's password using a valid reset token received via email.
          
          **Password Requirements:**
          - Minimum 8 characters
          - Must contain uppercase letter
          - Must contain lowercase letter
          - Must contain number
          
          **Token Security:**
          - Tokens expire after 1 hour
          - Tokens are single-use
          - Invalid tokens return generic error for security
        parameters:
          - in: body
            name: body
            required: true
            description: Password reset data
            schema:
              type: object
              required:
                - token
                - newPassword
              properties:
                token:
                  type: string
                  description: Password reset token from email
                  example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                newPassword:
                  type: string
                  minLength: 8
                  description: New password (must meet security requirements)
                  example: "NewStrongPassword123!"
        responses:
          200:
            description: Password reset successful
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Success confirmation message
                  example: "Password has been reset successfully."
          400:
            description: Invalid token or weak password
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Specific error message
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
        Verify user's email address using a verification token.
        
        Completes the email verification process started during registration.
        Users must verify their email before they can log in.
        ---
        tags:
          - Authentication
        summary: Verify email address
        description: |
          Verifies the user's email address using a token sent during registration.
          
          **Process:**
          1. User clicks verification link from email
          2. Token is validated
          3. Account is marked as verified
          4. User can now log in
          
          **Token Security:**
          - Tokens expire after 24 hours
          - Tokens are single-use
          - Invalid tokens return generic error for security
        parameters:
          - in: query
            name: token
            required: true
            type: string
            description: Email verification token from registration email
            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        responses:
          200:
            description: Email verification successful
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Success confirmation message
                  example: "Email verified successfully."
          400:
            description: Invalid or expired verification token
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Specific error message
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
          - Authentication
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
            logger.info(f"Resend verification email to {email}")
            # TODO: Integrate Flask-Mail or other email backend
        return jsonify({'message': 'If the email exists and is not verified, a verification link has been sent.'}), 200

    @auth_bp.route('/refresh-token', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh_token():
        """
        Refresh access token using a valid refresh token.
        ---
        tags:
          - Authentication
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
        
        Logs out the current user. In a production environment, this should implement
        token blacklisting for enhanced security. Currently, the client is responsible
        for discarding the token.
        ---
        tags:
          - Authentication
        summary: Logout current user
        description: |
          Logs out the authenticated user. The client should discard the JWT token
          after receiving a successful response.
          
          **Security Note:** For enhanced security in production, implement token
          blacklisting using Redis or a similar mechanism to invalidate tokens
          server-side.
        responses:
          200:
            description: Logout successful
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Success confirmation message
                  example: "Logout successful"
          401:
            description: Unauthorized, missing or invalid token
            schema:
              type: object
              properties:
                msg:
                  type: string
                  description: Authentication error message
                  example: "Missing or invalid authorization"
        """
        user_id = get_jwt_identity()
        logger.info(f'User logout: {user_id}')
        
        # TODO: Implement token blacklisting for enhanced security
        # Example with Redis:
        # redis_client.setex(f"blacklist:{jwt_token}", 3600, "blacklisted")
        
        return jsonify({'message': 'Logout successful'}), 200

    # Define user routes
    @user_bp.route('/profile', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        """
        Retrieve the current user's profile information.
        
        Returns the authenticated user's profile data including personal information,
        account status, and timestamps. Sensitive data like password hashes are excluded.
        ---
        tags:
          - User Management
        security:
          - Bearer: []
        summary: Get current user profile
        description: |
          Retrieves the complete profile information for the currently authenticated user.
          
          **Returned Data:**
          - Personal information (name, email, username)
          - Account status (verification status)
          - Timestamps (creation date)
          - Avatar URL (if set)
          
          **Security:** Sensitive fields like password hashes and tokens are excluded.
        responses:
          200:
            description: User profile retrieved successfully
            schema:
              type: object
              properties:
                _id:
                  type: string
                  description: Unique user identifier
                  example: "60c72b2f9b1e8b001c8e4b8a"
                username:
                  type: string
                  format: email
                  description: User's email address (used as username)
                  example: "john.doe@example.com"
                email:
                  type: string
                  format: email
                  description: User's email address
                  example: "john.doe@example.com"
                name:
                  type: string
                  description: User's full name
                  example: "John Doe"
                avatar_url:
                  type: string
                  format: uri
                  description: URL to user's avatar image
                  example: "https://example.com/avatar.jpg"
                is_verified:
                  type: boolean
                  description: Whether the user's email has been verified
                  example: true
                created_at:
                  type: string
                  format: date-time
                  description: Account creation timestamp
                  example: "2024-05-01T12:00:00Z"
          401:
            description: Authentication required
            schema:
              type: object
              properties:
                msg:
                  type: string
                  description: Authentication error message
                  example: "Missing or invalid authorization"
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

    @user_bp.route('/profile', methods=['PUT'])
    @jwt_required()
    def update_user_profile():
        """
        Update the current user's profile information.
        
        Allows users to modify their personal information including name and avatar URL.
        Only non-sensitive fields can be updated through this endpoint.
        ---
        tags:
          - User Management
        security:
          - Bearer: []
        summary: Update user profile
        description: |
          Updates the authenticated user's profile information.
          
          **Updatable Fields:**
          - `name`: User's full name
          - `avatar_url`: URL to user's avatar image
          
          **Security:** Email and other sensitive fields cannot be updated through this endpoint.
        parameters:
          - in: body
            name: body
            required: true
            description: Profile update data
            schema:
              type: object
              properties:
                name:
                  type: string
                  minLength: 1
                  description: User's full name
                  example: "John Doe"
                avatar_url:
                  type: string
                  format: uri
                  description: URL to user's avatar image
                  example: "https://example.com/avatar.jpg"
        responses:
          200:
            description: Profile updated successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Success confirmation message
                  example: "Profile updated successfully"
          400:
            description: Invalid input data
            schema:
              type: object
              properties:
                error:
                  type: string
                  description: Specific validation error
                  example: "Name cannot be empty"
          401:
            description: Authentication required
            schema:
              type: object
              properties:
                msg:
                  type: string
                  description: Authentication error message
                  example: "Missing or invalid authorization"
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
          - User Management
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

    @user_bp.route('/profile', methods=['DELETE'])
    @jwt_required()
    def delete_user():
        """
        Delete the authenticated user and all their data.
        ---
        tags:
          - User Management
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
            logger.info(f'User {user_id} deleted successfully')
            return jsonify({'message': 'User deleted successfully'}), 200
        except Exception as e:
            logger.error(f'Error deleting user {user_id}: {str(e)}', exc_info=True)
            return jsonify({'error': f'Error deleting user: {str(e)}'}), 500
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)

    # Create instances for use within the function
    bcrypt = Bcrypt(app)
    serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

    return app, auth_bp, user_bp, limiter, bcrypt, serializer

# Create the app instance and blueprints
app, auth_bp, user_bp, limiter, bcrypt, serializer = create_app()

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
    ],
    "consumes": [
        "application/json"
    ],
    "produces": [
        "application/json"
    ]
}

swagger = Swagger(app, template=swagger_template)

db_service = DatabaseService(mongo)

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











@app.route('/api/documents', methods=['GET'])
@jwt_required()
def get_documents():
    """
    Retrieve all documents for the authenticated user.
    
    Returns a list of all documents owned by the current user, including metadata
    such as title, status, timestamps, and tags. Documents are returned in reverse
    chronological order (newest first).
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    summary: Get user's documents
    description: |
      Retrieves all documents belonging to the authenticated user.
      
      **Returned Data:**
      - Document metadata (ID, title, status)
      - Timestamps (creation and last update)
      - Tags and categorization
      - User ownership information
      
      **Document Status Values:**
      - `draft`: Work in progress
      - `saved`: Completed and saved
      - `published`: Publicly available
      
      **Security:** Only returns documents owned by the authenticated user.
    responses:
      200:
        description: Documents retrieved successfully
        schema:
          type: array
          items:
            type: object
            properties:
              _id:
                type: string
                description: Unique document identifier
                example: "60c72b2f9b1e8b001c8e4b8a"
              title:
                type: string
                description: Document title
                example: "Research Report 2024"
              doc_status:
                type: string
                enum: [draft, saved, published]
                description: Current status of the document
                example: "saved"
              created_at:
                type: string
                format: date-time
                description: Document creation timestamp
                example: "2024-05-01T12:00:00Z"
              updated_at:
                type: string
                format: date-time
                description: Last modification timestamp
                example: "2024-05-02T15:30:00Z"
              tags:
                type: array
                items:
                  type: string
                description: Document tags for categorization
                example: ["research", "2024", "AI"]
            examples:
              application/json: [
                {
                  "_id": "60c72b2f9b1e8b001c8e4b8a",
                  "title": "Research Report 2024",
                  "doc_status": "saved",
                  "created_at": "2024-05-01T12:00:00Z",
                  "updated_at": "2024-05-02T15:30:00Z",
                  "tags": ["research", "2024", "AI"]
                }
              ]
      401:
        description: Authentication required
        schema:
          type: object
          properties:
            msg:
              type: string
              description: Authentication error message
              example: "Missing or invalid authorization"
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            status:
              type: string
              description: Error status
              example: "error"
            message:
              type: string
              description: Error message
              example: "Internal server error"
    """
    user_id = get_jwt_identity()

    logger.info(f'GET /api/documents - user_id: {user_id}')

    try:
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

        logger.info(f'Found {len(user_documents)} documents for user {user_id}')
        
        return jsonify(user_documents), 200
    except Exception as e:
        logger.error(f'Error fetching documents for user {user_id}: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/documents/<document_id>', methods=['GET'])
@jwt_required()
def get_document(document_id):
    """
    Get a specific document for the authenticated user by document ID
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: document_id
        required: true
        type: string
        description: The ID of the document to retrieve
        example: "60c72b2f9b1e8b001c8e4b8a"
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
        description: Bad request - invalid document_id format
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Invalid document ID format"
      401:
        description: Unauthorized, missing or invalid JWT
      403:
        description: Forbidden - trying to access another user's document
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Access denied"
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
    user_id = get_jwt_identity()
    
    logger.info(f'GET /api/documents/{document_id} - user_id: {user_id}')
    
    # Validate document_id format
    try:
        object_id = ObjectId(document_id)
    except Exception:
        return jsonify({'status': 'error', 'message': 'Invalid document ID format'}), 400
    
    try:
        doc = mongo.db.documents.find_one({'_id': object_id})
        if not doc:
            return jsonify({'status': 'error', 'message': 'Document not found'}), 404
        
        # Check if user owns this document
        if doc.get('user_id') != user_id:
            logger.warning(f'User {user_id} attempted to access document {document_id} owned by {doc.get("user_id")}')
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Convert ObjectId to string for JSON serialization
        doc['_id'] = str(doc['_id'])
        if 'user_id' in doc:
            doc['user_id'] = str(doc['user_id'])
        if 'created_at' in doc:
            doc['created_at'] = str(doc['created_at'])
        if 'updated_at' in doc:
            doc['updated_at'] = str(doc['updated_at'])
        
        logger.info(f'Document {document_id} retrieved successfully for user {user_id}')
        return jsonify(doc), 200
    except Exception as e:
        logger.error(f"Error fetching document {document_id} for user {user_id}: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500






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


@app.route('/api/documents', methods=['POST'])
@jwt_required()
def create_document():
    """
    Create a new document for the authenticated user.
    
    Creates a new document with server-generated ID and associates it with the current user.
    The document will be created with draft status by default.
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    summary: Create new document
    description: |
      Creates a new document and assigns it to the authenticated user.
      
      **Document Structure:**
      - Hierarchical content with sections and subsections
      - Rich text content support
      - Metadata (title, status, tags)
      
      **Content Requirements:**
      - Must have a title
      - Must have content with sections array
      - Sections can have nested children
      
      **Default Values:**
      - Status: `draft`
      - Created/Updated timestamps: Current time
      - Owner: Current authenticated user
    parameters:
      - in: body
        name: document
        required: true
        description: Document data to create
        schema:
          type: object
          required:
            - title
            - content
          properties:
            title:
              type: string
              minLength: 1
              description: Document title
              example: "Research Report 2024"
            content:
              type: object
              description: Document content structure
              required:
                - sections
              properties:
                sections:
                  type: array
                  description: Array of document sections
                  items:
                    type: object
                    properties:
                      id:
                        type: string
                        description: Unique section identifier
                        example: "sec-1"
                      title:
                        type: string
                        description: Section title
                        example: "Introduction"
                      content:
                        type: string
                        description: Section content text
                        example: "This section introduces the research topic."
                      children:
                        type: array
                        description: Nested subsections
                        items:
                          type: object
                          properties:
                            id:
                              type: string
                              description: Unique subsection identifier
                              example: "sec-1-1"
                            title:
                              type: string
                              description: Subsection title
                              example: "Background"
                            content:
                              type: string
                              description: Subsection content text
                              example: "Background information goes here."
            doc_status:
              type: string
              enum: [draft, saved, published]
              default: draft
              description: Document status
              example: "draft"
            tags:
              type: array
              items:
                type: string
              description: Document tags for categorization
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
            "doc_status": "draft",
            "tags": ["research", "2024", "AI"]
          }
    responses:
      201:
        description: Document created successfully
        schema:
          type: object
          properties:
            status:
              type: string
              description: Success status
              example: "success"
            message:
              type: string
              description: Success message
              example: "Document created successfully"
            document_id:
              type: string
              description: Generated document identifier
              example: "60c72b2f9b1e8b001c8e4b8a"
      400:
        description: Invalid input data
        schema:
          type: object
          properties:
            status:
              type: string
              description: Error status
              example: "error"
            message:
              type: string
              description: Specific validation error
              example: "Missing required fields: title, content"
      401:
        description: Authentication required
        schema:
          type: object
          properties:
            msg:
              type: string
              description: Authentication error message
              example: "Missing or invalid authorization"
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            status:
              type: string
              description: Error status
              example: "error"
            message:
              type: string
              description: Error message
              example: "Internal server error"
    """
    user_id = get_jwt_identity()
    data = request.get_json()

    logger.info(f'POST /api/documents - user_id: {user_id}')

    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400

    # Validate required fields
    required_fields = ['title', 'content']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({
            'status': 'error', 
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        }), 400

    # Validate content structure
    content = data.get('content')
    if not isinstance(content, dict):
        return jsonify({
            'status': 'error',
            'message': 'Content must be an object'
        }), 400
    
    if 'sections' not in content:
        return jsonify({
            'status': 'error',
            'message': 'Content must contain sections array'
        }), 400

    # Attach user_id to the document
    data['user_id'] = user_id

    from datetime import datetime
    now = datetime.utcnow()
    data['created_at'] = now
    data['updated_at'] = now

    # Create new document (server generates ID)
    try:
        result = mongo.db.documents.insert_one(data)
        
        if result.inserted_id:
            logger.info(f'Document created successfully for user {user_id} with ID {result.inserted_id}')
            return jsonify({
                'status': 'success',
                'message': 'Document created successfully',
                'document_id': str(result.inserted_id)
            }), 201
        else:
            logger.error(f'Failed to create document for user {user_id}')
            return jsonify({'status': 'error', 'message': 'Failed to create document'}), 500
    except Exception as e:
        logger.error(f'Error creating document for user {user_id}: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/documents/<document_id>', methods=['PUT'])
@jwt_required()
def put_document(document_id):
    """
    Create or update a document with a specific ID for the authenticated user.
    This endpoint follows REST best practices where PUT is used for idempotent operations.
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: document_id
        required: true
        type: string
        description: The ID of the document to create or update
        example: "60c72b2f9b1e8b001c8e4b8a"
      - in: body
        name: document
        required: true
        schema:
          type: object
          description: The complete document JSON to store
          required:
            - title
            - content
          properties:
            title:
              type: string
              example: "Research Report 2024"
              description: The title of the document
            content:
              type: object
              description: The document content structure
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
              enum: [draft, saved, published]
              example: "saved"
              description: The status of the document
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI"]
              description: Tags associated with the document
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
        description: Document updated successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Document updated successfully"
            document_id:
              type: string
              example: "60c72b2f9b1e8b001c8e4b8a"
      201:
        description: Document created successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Document created successfully"
            document_id:
              type: string
              example: "60c72b2f9b1e8b001c8e4b8a"
      400:
        description: Invalid input or missing required fields
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Missing required fields: title, content"
      401:
        description: Unauthorized, missing or invalid JWT
      403:
        description: Forbidden - trying to access another user's document
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Access denied"
      404:
        description: Document not found (when trying to update)
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
    user_id = get_jwt_identity()
    data = request.get_json()

    logger.info(f'PUT /api/documents/{document_id} - user_id: {user_id}')

    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400

    # Validate required fields
    required_fields = ['title', 'content']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({
            'status': 'error', 
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        }), 400

    # Validate content structure
    content = data.get('content')
    if not isinstance(content, dict):
        return jsonify({
            'status': 'error',
            'message': 'Content must be an object'
        }), 400
    
    if 'sections' not in content:
        return jsonify({
            'status': 'error',
            'message': 'Content must contain sections array'
        }), 400

    # Validate document_id format
    try:
        object_id = ObjectId(document_id)
    except Exception:
        return jsonify({'status': 'error', 'message': 'Invalid document ID format'}), 400

    # Attach user_id to the document
    data['user_id'] = user_id
    data['_id'] = object_id

    from datetime import datetime
    now = datetime.utcnow()

    # Check if document exists
    existing_doc = mongo.db.documents.find_one({'_id': object_id})
    
    if existing_doc:
        # Check if user owns this document
        if existing_doc.get('user_id') != user_id:
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Update existing document
        data['created_at'] = existing_doc.get('created_at', now)
        data['updated_at'] = now
        result = mongo.db.documents.replace_one({'_id': object_id}, data)
        
        # Check if document was updated (modified_count) or if it was already identical (matched_count)
        if result.modified_count > 0 or result.matched_count > 0:
            logger.info(f'Document {document_id} updated successfully for user {user_id}')
            return jsonify({
                'status': 'success',
                'message': 'Document updated successfully',
                'document_id': document_id
            }), 200
        else:
            logger.error(f'Failed to update document {document_id} for user {user_id}')
            return jsonify({'status': 'error', 'message': 'Failed to update document'}), 500
    else:
        # Create new document with specified ID
        data['created_at'] = now
        data['updated_at'] = now
        result = mongo.db.documents.insert_one(data)
        
        if result.inserted_id:
            logger.info(f'Document {document_id} created successfully for user {user_id}')
            return jsonify({
                'status': 'success',
                'message': 'Document created successfully',
                'document_id': document_id
            }), 201
        else:
            logger.error(f'Failed to create document {document_id} for user {user_id}')
            return jsonify({'status': 'error', 'message': 'Failed to create document'}), 500


@app.route('/api/documents/<document_id>', methods=['DELETE'])
@jwt_required()
def delete_document(document_id):
    """
    Delete a specific document for the authenticated user.
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: document_id
        required: true
        type: string
        description: The ID of the document to delete
        example: "60c72b2f9b1e8b001c8e4b8a"
    responses:
      200:
        description: Document deleted successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Document deleted successfully"
      401:
        description: Unauthorized, missing or invalid JWT
      403:
        description: Forbidden - trying to access another user's document
        schema:
          type: object
          properties:
            status:
              type: string
              example: "error"
            message:
              type: string
              example: "Access denied"
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
    user_id = get_jwt_identity()
    
    logger.info(f'DELETE /api/documents/{document_id} - user_id: {user_id}')

    # Validate document_id format
    try:
        object_id = ObjectId(document_id)
    except Exception:
        return jsonify({'status': 'error', 'message': 'Invalid document ID format'}), 400

    # Check if document exists and user owns it
    existing_doc = mongo.db.documents.find_one({'_id': object_id})
    
    if not existing_doc:
        return jsonify({'status': 'error', 'message': 'Document not found'}), 404
    
    if existing_doc.get('user_id') != user_id:
        logger.warning(f'User {user_id} attempted to delete document {document_id} owned by {existing_doc.get("user_id")}')
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    # Delete the document
    try:
        result = mongo.db.documents.delete_one({'_id': object_id})
        
        if result.deleted_count > 0:
            logger.info(f'Document {document_id} deleted successfully for user {user_id}')
            return jsonify({
                'status': 'success',
                'message': 'Document deleted successfully'
            }), 200
        else:
            logger.error(f'Failed to delete document {document_id} for user {user_id}')
            return jsonify({'status': 'error', 'message': 'Failed to delete document'}), 500
    except Exception as e:
        logger.error(f'Error deleting document {document_id} for user {user_id}: {str(e)}', exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


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

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limiting errors"""
    logger.warning(f'Rate limit exceeded: {str(e)}')
    return jsonify({
        'error': 'Rate limit exceeded', 
        'message': 'Too many requests. Please try again later.',
        'retry_after': getattr(e, 'retry_after', None)
    }), 429

if __name__ == '__main__':
    app.logger.info('Starting Flask application')
    app.run(host=Config.HOST, debug=Config.DEBUG, port=9000)

