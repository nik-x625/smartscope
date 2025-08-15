"""
Files Blueprint
Handles file upload, download, and management
"""

from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime

files_bp = Blueprint('files', __name__)

@files_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    """
    File upload endpoint
    ---
    tags:
      - File Management
    security:
      - Bearer: []
    parameters:
      - in: formData
        name: file
        type: file
        required: true
        description: File to upload
    responses:
      201:
        description: File uploaded successfully
        schema:
          type: object
          properties:
            status:
              type: string
              example: "success"
            message:
              type: string
              example: "File uploaded successfully"
            file_id:
              type: string
              example: "507f1f77bcf86cd799439011"
            filename:
              type: string
              example: "document.pdf"
      400:
        description: Bad request
        schema:
          type: object
          properties:
            error:
              type: string
              example: "No file provided"
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file size before processing
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > current_app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'File too large'}), 413
        
        # Get current user
        current_user_id = get_jwt_identity()
        
        # Validate file type
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        allowed_extensions = set()
        for category in current_app.config['ALLOWED_EXTENSIONS'].values():
            allowed_extensions.update(category)
        
        if file_extension not in allowed_extensions:
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        file_id = str(uuid.uuid4())
        
        # Get user info for filename
        from app.models.user_models import User
        user = User.find_by_id(current_user_id)
        username_safe = secure_filename(user.name) if user else 'unknown'
        
        # Create descriptive filename: timestamp__username__fileid__originalname.ext
        stored_name = f"{timestamp}__{username_safe}__{file_id}__{filename}"
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], stored_name)
        
        # Save file
        file.save(file_path)
        
        # Store file metadata in database
        from pymongo import MongoClient
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        file_metadata = {
            'file_id': file_id,
            'user_id': current_user_id,
            'original_filename': filename,
            'stored_filename': stored_name,
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_type': file_extension,
            'uploaded_at': datetime.utcnow()
        }
        
        db.files.insert_one(file_metadata)
        
        return jsonify({
            'status': 'success',
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': filename
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"File upload error: {str(e)}")
        return jsonify({'error': 'File upload failed'}), 500

@files_bp.route('/<file_id>', methods=['GET'])
@jwt_required()
def get_file_metadata(file_id):
    """
    Get file metadata endpoint
    ---
    tags:
      - File Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        required: true
        type: string
        description: File ID to get metadata for
    responses:
      200:
        description: File metadata retrieved successfully
        schema:
          type: object
          properties:
            file_id:
              type: string
              example: "507f1f77bcf86cd799439011"
            filename:
              type: string
              example: "document.pdf"
            size:
              type: integer
              example: 1048576
            file_type:
              type: string
              example: "pdf"
            uploaded_at:
              type: string
              example: "2024-01-01T00:00:00"
      404:
        description: File not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Get file metadata
        from pymongo import MongoClient
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        file_info = db.files.find_one({'file_id': file_id})
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Check ownership
        if file_info['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({
            'file_id': file_info['file_id'],
            'filename': file_info['original_filename'],
            'original_filename': file_info['original_filename'],  # Keep both for compatibility
            'size': file_info['file_size'],
            'file_type': file_info['file_type'],
            'uploaded_at': file_info['uploaded_at'].isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get file metadata error: {str(e)}")
        return jsonify({'error': 'Failed to get file metadata'}), 500

@files_bp.route('/<file_id>/download', methods=['GET'])
@jwt_required()
def download_file(file_id):
    """
    File download endpoint
    ---
    tags:
      - File Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        required: true
        type: string
        description: File ID to download
    responses:
      200:
        description: File downloaded successfully
      404:
        description: File not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Get file metadata
        from pymongo import MongoClient
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        file_info = db.files.find_one({'file_id': file_id})
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Check ownership
        if file_info['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        file_path = file_info['file_path']
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_info['original_filename']
        )
        
    except Exception as e:
        current_app.logger.error(f"File download error: {str(e)}")
        return jsonify({'error': 'File download failed'}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    """
    File deletion endpoint
    ---
    tags:
      - File Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: file_id
        required: true
        type: string
        description: File ID to delete
    responses:
      200:
        description: File deleted successfully
      404:
        description: File not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Get file metadata
        from pymongo import MongoClient
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        file_info = db.files.find_one({'file_id': file_id})
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Check ownership
        if file_info['user_id'] != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Delete from filesystem
        file_path = file_info['file_path']
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        db.files.delete_one({'file_id': file_id})
        
        return jsonify({
            'status': 'success',
            'message': 'File deleted successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"File deletion error: {str(e)}")
        return jsonify({'error': 'File deletion failed'}), 500
