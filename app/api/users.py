"""
Users Blueprint
Handles user profile management
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash
from app.models.user_models import User
from app.utils.validators import validate_name

user_bp = Blueprint('user', __name__)

@user_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    """
    Get user profile endpoint
    ---
    tags:
      - User Management
    security:
      - Bearer: []
    responses:
      200:
        description: User profile retrieved successfully
        schema:
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
            created_at:
              type: string
              example: "2024-01-01T00:00:00"
      404:
        description: User not found
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': str(user.id),
            'email': user.email,
            'name': user.name,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get profile error: {str(e)}")
        return jsonify({'error': 'Failed to get profile'}), 500

@user_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    """
    Update user profile endpoint
    ---
    tags:
      - User Management
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            name:
              type: string
              description: New user name
              example: "John Smith"
            password:
              type: string
              description: New password (optional)
              example: "NewPassword123!"
    responses:
      200:
        description: Profile updated successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "Profile updated successfully"
      400:
        description: Bad request
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update name if provided
        if 'name' in data:
            new_name = data['name'].strip()
            if not validate_name(new_name):
                return jsonify({'error': 'Invalid name format'}), 400
            user.name = new_name
        
        # Update password if provided
        if 'password' in data:
            new_password = data['password']
            if new_password:
                # TODO: Re-enable password validation when development progresses
                # if not validate_password(new_password):
                #     return jsonify({'error': 'Password does not meet requirements'}), 400
                user.password = generate_password_hash(new_password)
        
        # Update timestamp
        from datetime import datetime
        user.updated_at = datetime.utcnow()
        
        # Save changes
        if user.save():
            return jsonify({
                'status': 'success',
                'message': 'Profile updated successfully'
            }), 200
        else:
            return jsonify({'error': 'Failed to update profile'}), 500
        
    except Exception as e:
        current_app.logger.error(f"Update profile error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

@user_bp.route('/profile', methods=['DELETE'])
@jwt_required()
def delete_user_profile():
    """
    Delete user profile endpoint
    ---
    tags:
      - User Management
    security:
      - Bearer: []
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "User deleted successfully"
      404:
        description: User not found
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Delete user files from database
        from pymongo import MongoClient
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        # Delete file metadata
        db.files.delete_many({'user_id': current_user_id})
        
        # Delete user
        if user.delete():
            return jsonify({
                'status': 'success',
                'message': 'User deleted successfully'
            }), 200
        else:
            return jsonify({'error': 'Failed to delete user'}), 500
        
    except Exception as e:
        current_app.logger.error(f"Delete profile error: {str(e)}")
        return jsonify({'error': 'Failed to delete user'}), 500
