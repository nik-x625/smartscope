"""
Documents Blueprint
Handles document creation, retrieval, and management
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from pymongo import MongoClient
from datetime import datetime

document_bp = Blueprint('document', __name__)

@document_bp.route('', methods=['POST'])
@jwt_required()
def create_document():
    """
    Create document endpoint
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - title
            - content
          properties:
            title:
              type: string
              description: Document title
              example: "Research Report 2024"
            content:
              type: object
              description: Document content structure
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
                      effort:
                        type: number
                        format: float
                        minimum: 0
                        example: 8.0
                        description: Effort in hours for this section
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
                            effort:
                              type: number
                              format: float
                              minimum: 0
                              example: 4.0
                              description: Effort in hours for this subsection
            doc_status:
              type: string
              example: "draft"
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI"]
    responses:
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
              example: "507f1f77bcf86cd799439011"
      400:
        description: Bad request
    """
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['title', 'content']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create document
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        document_data = {
            'user_id': current_user_id,
            'title': data['title'],
            'content': data['content'],
            'doc_status': data.get('doc_status', 'draft'),
            'tags': data.get('tags', []),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = db.documents.insert_one(document_data)
        
        return jsonify({
            'status': 'success',
            'message': 'Document created successfully',
            'document_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Create document error: {str(e)}")
        return jsonify({'error': 'Failed to create document'}), 500

@document_bp.route('/<document_id>', methods=['GET'])
@jwt_required()
def get_document(document_id):
    """
    Get document endpoint
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
        description: Document ID to retrieve
    responses:
      200:
        description: Document retrieved successfully
        schema:
          type: object
          properties:
            id:
              type: string
              example: "507f1f77bcf86cd799439011"
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
                      effort:
                        type: number
                        format: float
                        minimum: 0
                        example: 8.0
                        description: Effort in hours for this section
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
                            effort:
                              type: number
                              format: float
                              minimum: 0
                              example: 4.0
                              description: Effort in hours for this subsection
            doc_status:
              type: string
              example: "draft"
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI"]
      404:
        description: Document not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        from bson import ObjectId
        document = db.documents.find_one({
            '_id': ObjectId(document_id),
            'user_id': current_user_id
        })
        
        if not document:
            return jsonify({'error': 'Document not found'}), 404
        
        # Convert ObjectId to string
        document['id'] = str(document['_id'])
        del document['_id']
        
        return jsonify(document), 200
        
    except Exception as e:
        current_app.logger.error(f"Get document error: {str(e)}")
        return jsonify({'error': 'Failed to get document'}), 500

@document_bp.route('', methods=['GET'])
@jwt_required()
def get_documents():
    """
    Get user documents endpoint
    ---
    tags:
      - Document Management
    security:
      - Bearer: []
    responses:
      200:
        description: Documents retrieved successfully
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: string
                example: "507f1f77bcf86cd799439011"
              title:
                type: string
                example: "Research Report 2024"
              doc_status:
                type: string
                example: "draft"
              tags:
                type: array
                items:
                  type: string
                example: ["research", "2024", "AI"]
    """
    try:
        current_user_id = get_jwt_identity()
        
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        documents = list(db.documents.find(
            {'user_id': current_user_id},
            {'content': 0}  # Exclude content for list view
        ))
        
        # Convert ObjectIds to strings
        for doc in documents:
            doc['id'] = str(doc['_id'])
            del doc['_id']
        
        return jsonify(documents), 200
        
    except Exception as e:
        current_app.logger.error(f"Get documents error: {str(e)}")
        return jsonify({'error': 'Failed to get documents'}), 500

@document_bp.route('/<document_id>', methods=['PUT'])
@jwt_required()
def update_document(document_id):
    """
    Update document endpoint
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
        description: Document ID to update
      - in: body
        name: body
        schema:
          type: object
          properties:
            title:
              type: string
              example: "Updated Research Report 2024"
            content:
              type: object
            doc_status:
              type: string
              example: "published"
            tags:
              type: array
              items:
                type: string
              example: ["research", "2024", "AI", "updated"]
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
      404:
        description: Document not found
    """
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        from bson import ObjectId
        # Check if document exists and belongs to user
        existing_doc = db.documents.find_one({
            '_id': ObjectId(document_id),
            'user_id': current_user_id
        })
        
        if not existing_doc:
            return jsonify({'error': 'Document not found'}), 404
        
        # Update document
        update_data = {
            'updated_at': datetime.utcnow()
        }
        
        if 'title' in data:
            update_data['title'] = data['title']
        if 'content' in data:
            update_data['content'] = data['content']
        if 'doc_status' in data:
            update_data['doc_status'] = data['doc_status']
        if 'tags' in data:
            update_data['tags'] = data['tags']
        
        result = db.documents.update_one(
            {'_id': ObjectId(document_id)},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            return jsonify({
                'status': 'success',
                'message': 'Document updated successfully'
            }), 200
        else:
            return jsonify({'error': 'No changes made'}), 400
        
    except Exception as e:
        current_app.logger.error(f"Update document error: {str(e)}")
        return jsonify({'error': 'Failed to update document'}), 500

@document_bp.route('/<document_id>', methods=['DELETE'])
@jwt_required()
def delete_document(document_id):
    """
    Delete document endpoint
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
        description: Document ID to delete
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
      404:
        description: Document not found
    """
    try:
        current_user_id = get_jwt_identity()
        
        client = MongoClient(current_app.config['MONGO_URI'])
        db = client.get_database()
        
        from bson import ObjectId
        result = db.documents.delete_one({
            '_id': ObjectId(document_id),
            'user_id': current_user_id
        })
        
        if result.deleted_count > 0:
            return jsonify({
                'status': 'success',
                'message': 'Document deleted successfully'
            }), 200
        else:
            return jsonify({'error': 'Document not found'}), 404
        
    except Exception as e:
        current_app.logger.error(f"Delete document error: {str(e)}")
        return jsonify({'error': 'Failed to delete document'}), 500
