"""
Authentication service for SmartScope Backend
"""

from app.models.user_models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token

class AuthService:
    """Service class for authentication business logic"""
    
    @staticmethod
    def register_user(email, password, name):
        """Register a new user"""
        # Check if user already exists
        existing_user = User.find_by_email(email)
        if existing_user:
            return False, "Email already exists"
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_password,
            name=name
        )
        
        if new_user.save():
            return True, str(new_user.id)
        else:
            return False, "Failed to create user"
    
    @staticmethod
    def authenticate_user(email, password):
        """Authenticate user login"""
        user = User.find_by_email(email)
        if not user:
            return None, "Invalid email or password"
        
        if not check_password_hash(user.password, password):
            return None, "Invalid email or password"
        
        return user, None
    
    @staticmethod
    def generate_tokens(user_id):
        """Generate JWT tokens for user"""
        access_token = create_access_token(identity=str(user_id))
        refresh_token = create_refresh_token(identity=str(user_id))
        
        return access_token, refresh_token
    
    @staticmethod
    def get_user_info(user_id):
        """Get user information by ID"""
        user = User.find_by_id(user_id)
        if not user:
            return None
        
        return {
            'id': str(user.id),
            'email': user.email,
            'name': user.name,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None
        }
