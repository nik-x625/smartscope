from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from datetime import datetime

class User(UserMixin):
    def __init__(self, username, email, password=None, roles=None, _id=None, created_at=None):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password) if password else None
        self.roles = roles or ["user"]
        self._id = _id if _id else ObjectId()
        self.created_at = created_at if created_at else datetime.utcnow()
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self._id)
    
    def has_role(self, role):
        return role in self.roles
    
    def to_dict(self):
        return {
            "_id": self._id,
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "roles": self.roles,
            "created_at": self.created_at
        }
    
    @staticmethod
    def get_by_id(mongo, user_id):
        user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User.from_dict(user_data)
        return None
    
    @staticmethod
    def get_by_username(mongo, username):
        user_data = mongo.db.users.find_one({"username": username})
        if user_data:
            return User.from_dict(user_data)
        return None
    
    @staticmethod
    def get_by_email(mongo, email):
        user_data = mongo.db.users.find_one({"email": email})
        if user_data:
            return User.from_dict(user_data)
        return None
    
    @staticmethod
    def from_dict(user_data):
        user = User(
            username=user_data.get('username'),
            email=user_data.get('email'),
            roles=user_data.get('roles'),
            _id=user_data.get('_id'),
            created_at=user_data.get('created_at')
        )
        user.password_hash = user_data.get('password_hash')
        return user 