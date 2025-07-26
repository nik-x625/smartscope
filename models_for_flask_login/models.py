from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from datetime import datetime

class User(UserMixin):
    def __init__(self, username, email, password=None, roles=None, _id=None, created_at=None, is_verified=False, name=None, avatar_url=None, verification_token=None, verification_sent_at=None, reset_token=None, reset_sent_at=None):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password) if password else None
        self.roles = roles or ["user"]
        self._id = _id if _id else ObjectId()
        self.created_at = created_at if created_at else datetime.utcnow()
        self.is_verified = is_verified
        self.name = name
        self.avatar_url = avatar_url
        self.verification_token = verification_token
        self.verification_sent_at = verification_sent_at
        self.reset_token = reset_token
        self.reset_sent_at = reset_sent_at
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
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
            "created_at": self.created_at,
            "is_verified": self.is_verified,
            "name": self.name,
            "avatar_url": self.avatar_url,
            "verification_token": self.verification_token,
            "verification_sent_at": self.verification_sent_at,
            "reset_token": self.reset_token,
            "reset_sent_at": self.reset_sent_at
        }
    
    def update_profile(self, name=None, avatar_url=None):
        if name is not None:
            self.name = name
        if avatar_url is not None:
            self.avatar_url = avatar_url
    
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
            created_at=user_data.get('created_at'),
            is_verified=user_data.get('is_verified', False),
            name=user_data.get('name'),
            avatar_url=user_data.get('avatar_url'),
            verification_token=user_data.get('verification_token'),
            verification_sent_at=user_data.get('verification_sent_at'),
            reset_token=user_data.get('reset_token'),
            reset_sent_at=user_data.get('reset_sent_at')
        )
        user.password_hash = user_data.get('password_hash')
        return user 