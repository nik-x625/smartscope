from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response, session, flash
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from bson import ObjectId

# Import configuration and database
from config import Config
from database import mongo, DatabaseService

# Models
from models_for_documents.models import Section, Chapter, DocumentTemplate
from models_for_flask_login.models import User
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
import time

from flasgger import Swagger



from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)


# Create a logger
# if the name is not specified, the root logger will be used and it will propagate to all other loggers, like MongoDB logs
logger = logging.getLogger('smartscope')


def create_app(config_class=Config):
    # Create and configure the app
    app = Flask(__name__, static_folder='static')
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

    return app


# Create the app instance
app = create_app()

# Add Swagger securityDefinitions for Bearer token
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "SmartScope API",
        "description": "API documentation for SmartScope",
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

# Add custom template filters




@app.route('/')
@login_required
def index():
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
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    user = User(username=username, email=email, password=password)

    # Save to database
    mongo.db.users.insert_one(user.to_dict())


    # Log in the user
    login_user(user)

    return jsonify({'message': 'Registration successful'}), 201




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

    logger.info(f'user_documents: {user_documents}')
    
    return jsonify(user_documents), 200


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh endpoint to obtain a new access token using a valid refresh token.
    ---
    security:
      - Bearer: []
    responses:
      200:
        description: Returns a new access token
        examples:
          application/json: {"access_token": "new_token"}
      401:
        description: Unauthorized, missing or invalid refresh token
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

    # If _id is provided, update; else, insert new
    from bson import ObjectId
    doc_id = data.get('_id')
    if doc_id:
        # Update existing document
        data['_id'] = ObjectId(doc_id)
        result = mongo.db.documents.replace_one({'_id': ObjectId(doc_id), 'user_id': user_id}, data, upsert=True)
        logger.info(f'in the set_document route, mongodb update result: {result}')
        return jsonify({'status': 'success', 'document_id': str(doc_id)}), 200
    else:
        # Insert new document
        result = mongo.db.documents.insert_one(data)
        logger.info(f'in the set_document route, new document insert attempt, mongodb insert result: {result}')
        return jsonify({'status': 'success', 'document_id': str(result.inserted_id)}), 200


if __name__ == '__main__':
    app.logger.info('Starting Flask application')
    app.run(host=Config.HOST, debug=Config.DEBUG, port=9000)

