"""
User models for SmartScope Backend
"""

from datetime import datetime
from bson import ObjectId
from pymongo import MongoClient
from flask import current_app
import os

def get_db():
    """Get database connection from Flask app context or environment"""
    if current_app:
        # Use Flask app configuration
        return current_app.config.get('MONGO_URI', 'mongodb://localhost:27017/smartscope')
    else:
        # Fallback to environment variable
        return os.environ.get('MONGO_URI', 'mongodb://localhost:27017/smartscope')

def get_db_client():
    """Get MongoDB client"""
    uri = get_db()
    return MongoClient(uri)

def get_db_instance():
    """Get database instance"""
    client = get_db_client()
    return client.get_database()

class User:
    """User model for authentication and user management"""
    
    def __init__(self, email, password, name, _id=None, created_at=None, updated_at=None):
        self.email = email
        self.password = password
        self.name = name
        self._id = _id
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
    
    @property
    def id(self):
        return str(self._id) if self._id else None
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'email': self.email,
            'password': self.password,
            'name': self.name,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    def save(self):
        """Save user to database"""
        db = get_db_instance()
        if self._id:
            # Update existing user
            result = db.users.update_one(
                {'_id': self._id},
                {'$set': self.to_dict()}
            )
            return result.modified_count > 0
        else:
            # Create new user
            user_data = self.to_dict()
            result = db.users.insert_one(user_data)
            self._id = result.inserted_id
            return True
    
    def delete(self):
        """Delete user from database"""
        if self._id:
            db = get_db_instance()
            result = db.users.delete_one({'_id': self._id})
            return result.deleted_count > 0
        return False
    
    @classmethod
    def find_by_id(cls, user_id):
        """Find user by ID"""
        try:
            db = get_db_instance()
            user_data = db.users.find_one({'_id': ObjectId(user_id)})
            if user_data:
                return cls(
                    email=user_data['email'],
                    password=user_data['password'],
                    name=user_data['name'],
                    _id=user_data['_id'],
                    created_at=user_data.get('created_at'),
                    updated_at=user_data.get('updated_at')
                )
        except Exception:
            pass
        return None
    
    @classmethod
    def find_by_email(cls, email):
        """Find user by email"""
        db = get_db_instance()
        user_data = db.users.find_one({'email': email})
        if user_data:
            return cls(
                email=user_data['email'],
                password=user_data['password'],
                name=user_data['name'],
                _id=user_data['_id'],
                created_at=user_data.get('created_at'),
                updated_at=user_data.get('updated_at')
            )
        return None
    
    @classmethod
    def find_all(cls):
        """Find all users"""
        db = get_db_instance()
        users = []
        for user_data in db.users.find():
            user = cls(
                email=user_data['email'],
                password=user_data['password'],
                name=user_data['name'],
                _id=user_data['_id'],
                created_at=user_data.get('created_at'),
                updated_at=user_data.get('updated_at')
            )
            users.append(user)
        return users
