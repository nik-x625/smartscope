"""
Authentication Blueprint
Handles user registration, login, logout, and auth verification
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import re
from app.models.user_models import User
from app.services.auth_service import AuthService
from app.utils.validators import validate_email, validate_password, validate_name

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def auth_register():
    """
    User registration endpoint
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
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
              description: User's email address
              example: "user@example.com"
            password:
              type: string
              description: User's password
              example: "StrongPassword123!"
            name:
              type: string
              description: User's full name
              example: "John Doe"
    responses:
      201:
        description: User registered successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Account is ready to use"
            user_id:
              type: string
              example: "507f1f77bcf86cd799439011"
      400:
        description: Bad request - validation error
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Email already exists"
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        
        # Validation
        if not email or not password or not name:
            return jsonify({'error': 'Email, password, and name are required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not validate_name(name):
            return jsonify({'error': 'Name contains invalid characters'}), 400
        
        # TODO: Re-enable password validation when development progresses
        # if not validate_password(password):
        #     return jsonify({'error': 'Password does not meet requirements'}), 400
        
        # Check if user already exists
        existing_user = User.find_by_email(email)
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_password,
            name=name
        )
        
        new_user.save()
        
        return jsonify({
            'status': 'success',
            'message': 'Account is ready to use',
            'user_id': str(new_user.id)
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/login', methods=['POST'])
def auth_login():
    """
    User login endpoint
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
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
              example: "user@example.com"
            password:
              type: string
              description: User's password
              example: "StrongPassword123!"
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Login successful"
            access_token:
              type: string
              example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            refresh_token:
              type: string
              example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            user:
              type: object
              properties:
                id:
                  type: string
                  example: "507f1f77bcf86cd799439011"
                email:
                  type: string
                  example: "user@example.com"
                name:
                  type: string
                  example: "John Doe"
      401:
        description: Invalid credentials
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Invalid email or password"
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = User.find_by_email(email)
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate tokens
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'name': user.name
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def auth_refresh():
    """
    Refresh access token endpoint
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Token refreshed successfully
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
      401:
        description: Invalid refresh token
    """
    try:
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/check', methods=['GET'])
@jwt_required()
def auth_check():
    """
    Authentication check endpoint
    ---
    tags:
      - Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: User is authenticated
        schema:
          type: object
          properties:
            authenticated:
              type: boolean
              example: true
            user:
              type: object
              properties:
                id:
                  type: string
                  example: "507f1f77bcf86cd799439011"
                email:
                  type: string
                  example: "user@example.com"
                name:
                  type: string
                  example: "John Doe"
            exp:
              type: integer
              example: 1640995200
      401:
        description: Invalid or missing token
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get token expiration from JWT
        from flask_jwt_extended import get_jwt
        jwt_data = get_jwt()
        exp = jwt_data.get('exp')
        
        return jsonify({
            'authenticated': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'name': user.name
            },
            'exp': exp
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Auth check error: {str(e)}")
        return jsonify({'error': 'Authentication check failed'}), 500
