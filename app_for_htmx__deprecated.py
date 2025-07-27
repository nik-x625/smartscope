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

# Create a logger
# if the name is not specified, the root logger will be used and it will propagate to all other loggers, like MongoDB logs
logger = logging.getLogger('smartscope')


def create_app(config_class=Config):
    # Create and configure the app
    app = Flask(__name__, static_folder='static')
    app.config.from_object(config_class)

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

    return app


# Create the app instance
app = create_app()
db_service = DatabaseService(mongo)

# Add custom template filters


@app.template_filter('date')
def date_filter(value, format='%Y-%m-%d %H:%M'):
    """Format a datetime object to a string using the given format."""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return value
    return value.strftime(format)


@app.template_filter('time_ago')
def time_ago_filter(value):
    """Format a datetime object to show how long ago it was."""
    if not value:
        return ""

    now = datetime.now()
    diff = now - value

    # Convert to seconds
    seconds = diff.total_seconds()

    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    else:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"

# Helper function to find and update a nested document item by ID


def update_document_item(structure, item_id, content=None, title=None):
    """Recursively search and update an item in the document structure"""
    for item in structure:
        if str(item.get('id')) == str(item_id):
            if content is not None:
                item['content'] = content
            if title is not None:
                item['title'] = title
            return True

        # If this item has children, search there too
        if 'children' in item and item['children']:
            if update_document_item(item['children'], item_id, content, title):
                return True

    return False

# Basic routes


@app.route('/')
@login_required
def index():
    logger.info('Accessing root page, redirecting to dashboard')
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    logger.info('Accessing dashboard page')
    # Get document and template counts
    documents_count = mongo.db.documents.count_documents({})
    templates_count = mongo.db.templates.count_documents({})

    # Get recent documents (limit to 5)
    recent_documents = list(
        mongo.db.documents.find().sort('created_at', -1).limit(5))

    return render_template('dashboard.html',
                           documents_count=documents_count,
                           templates_count=templates_count,
                           recent_documents=recent_documents)


@app.route('/users')
def users():
    logger.info('Accessing users page')
    return render_template('users.html')


@app.route('/settings')
def settings():
    logger.info('Accessing settings page')
    return render_template('settings.html')


@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Delete user account and all associated data"""
    password = request.form.get('password')
    confirmation = request.form.get('confirm')

    # Verify password and confirmation
    if not password or not confirmation:
        logger.warning(
            f'Account deletion attempt missing password or confirmation for user: {current_user.username}')
        return render_template('settings.html', error="Password and confirmation required to delete account")

    # Verify correct password
    if not current_user.check_password(password):
        logger.warning(
            f'Account deletion attempt with incorrect password for user: {current_user.username}')
        return render_template('settings.html', error="Incorrect password")

    user_id = current_user._id
    username = current_user.username

    try:
        # Delete all user data
        # 1. Delete user's documents
        mongo.db.documents.delete_many({'user_id': user_id})

        # 2. Delete user's templates
        mongo.db.templates.delete_many({'user_id': user_id})

        # 3. Delete temp documents
        mongo.db.documents.delete_many({'user_id': user_id})

        # 4. Finally delete the user account
        mongo.db.users.delete_one({'_id': user_id})

        logger.info(f'Successfully deleted account for user: {username}')

        # Log the user out
        logout_user()

        # Clear all cookies
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('session_id')

        # Add flash message to be displayed after redirect
        flash('Your account has been successfully deleted', 'success')

        return response

    except Exception as e:
        logger.error(
            f'Error deleting account for user {username}: {str(e)}', exc_info=True)
        return render_template('settings.html', error=f"Error deleting account: {str(e)}")

# Template routes


@app.route('/templates')
def templates():
    logger.info('Accessing templates page')
    templates = list(mongo.db.templates.find())
    return render_template('templates.html', templates=templates)


@app.route('/templates-list')
def templates_list():
    templates = list(mongo.db.templates.find())
    return render_template('templates_list.html', templates=templates)


@app.route('/delete-template/<template_id>', methods=['DELETE'])
def delete_template(template_id):
    try:
        logger.info(f'Deleting template: {template_id}')
        result = mongo.db.templates.delete_one({'_id': ObjectId(template_id)})
        if result.deleted_count:
            logger.info(f'Successfully deleted template: {template_id}')
            templates = list(mongo.db.templates.find())
            return render_template('templates_list.html', templates=templates)
        else:
            logger.warning(f'Template not found for deletion: {template_id}')
            templates = list(mongo.db.templates.find())
            return render_template('templates_list.html', templates=templates)
    except Exception as e:
        logger.error(f'Error deleting template: {str(e)}', exc_info=True)
        templates = list(mongo.db.templates.find())
        return render_template('templates_list.html', templates=templates)


@app.route('/edit-template/<template_id>')
def edit_template(template_id):
    try:
        logger.info(f'Fetching template for edit: {template_id}')
        template = mongo.db.templates.find_one({'_id': ObjectId(template_id)})
        if template:
            return render_template('template_form.html', template=template)
        logger.warning(f'Template not found for edit: {template_id}')
        return '', 404
    except Exception as e:
        logger.error(
            f'Error fetching template for edit: {str(e)}', exc_info=True)
        return '', 500


@app.route('/template-form')
def template_form():
    return render_template('template_form.html')


@app.route('/create-template', methods=['POST'])
def create_template():
    try:
        # Get form data
        template_data = {
            'title': request.form.get('title'),
            'product': request.form.get('product'),
            'version': request.form.get('version'),
            'status': request.form.get('status'),
            'introduction': request.form.get('introduction'),
            'project_overview': request.form.get('project_overview'),
            'scope': request.form.get('scope')
        }

        # Insert into MongoDB
        result = mongo.db.templates.insert_one(template_data)

        if result.inserted_id:
            # Successfully saved
            templates = list(mongo.db.templates.find())
            return render_template('templates.html', templates=templates, message="Template created successfully!")
        else:
            # Failed to save
            return render_template('templates.html', templates=list(mongo.db.templates.find()), error="Failed to create template. Please try again.")

    except Exception as e:
        logger.error(f"Error creating template: {str(e)}")
        return render_template('templates.html', templates=list(mongo.db.templates.find()), error="An error occurred. Please try again.")

# Authentication routes


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user by username
        user = User.get_by_username(mongo, username)

        # Check if user exists and password is correct
        if user and user.check_password(password):
            # Log in the user
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        logger.warning(f'Failed login attempt for username: {username}')
        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('session_id')
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if username or email already exists
        if User.get_by_username(mongo, username):
            return render_template('register.html', error="Username already exists")

        if User.get_by_email(mongo, email):
            return render_template('register.html', error="Email already exists")

        # Create new user
        user = User(username=username, email=email, password=password)

        # Save to database
        mongo.db.users.insert_one(user.to_dict())

        # Log in the user
        login_user(user)

        # Redirect to success page instead of dashboard
        return redirect(url_for('registration_success'))

    return render_template('register.html')


@app.route('/registration-success')
@login_required
def registration_success():
    """Display registration success page"""
    logger.info(
        f'User {current_user.username} viewing registration success page')
    return render_template('registration_success.html')

# Document routes


@app.route('/docs')
def docs():
    documents = list(mongo.db.documents.find())
    return render_template('docs_list.html', documents=documents, now=datetime.now())


@app.route('/create-edit-doc', methods=['GET', 'POST'])
@login_required
def create_edit_doc():
    """
    Route handler for document creation and editing functionality.
    """
    user_id = current_user._id

    # Check if we're editing an existing document
    doc_id = request.args.get('doc_id')

    if doc_id:
        # Load the existing document from the database
        existing_doc = mongo.db.documents.find_one({'_id': ObjectId(doc_id)})

        if existing_doc:
            if existing_doc.get('doc_status') == 'saved':
                # If the document is 'saved', load it directly into the editor (no need to create a new draft)
                draft_doc = existing_doc
                logger.info(
                    f"Loading saved document {doc_id} for user {user_id}")
            else:
                # If the document is a draft or not saved, continue with the draft document
                draft_doc = existing_doc
                logger.info(
                    f"Using existing draft document {doc_id} for user {user_id}")
        else:
            # If the document is not found, log the error and redirect to the documents list
            logger.warning(f"Document {doc_id} not found")
            return redirect(url_for('docs'))
    else:
        # No document ID provided means we're either creating a new document or working with drafts

        # Fetch all drafts for the current user
        draft_docs = list(mongo.db.documents.find(
            {'user_id': user_id, 'doc_status': 'draft'}))

        if len(draft_docs) > 0:
            # If there are existing drafts, use the most recent one
            draft_doc = max(draft_docs, key=lambda x: x.get(
                'updated_at', datetime.min))
            logger.info(
                f"Using existing draft document {draft_doc['_id']} for user {user_id}")
        else:
            # No drafts exist, create a new draft document
            doc = DocumentTemplate(
                title="proposal draft 1",
                chapters=[
                    Chapter(
                        title="Chapter 1: Project Overview",
                        content="This chapter provides an overview of the project."
                    ),
                    Chapter(
                        title="Chapter 2: Project Activities",
                        content="This chapter details the main activities.",
                        sections=[
                            Section(
                                title="2.1: Software Installation",
                                content="How the software was installed."
                            ),
                            Section(
                                title="2.2: Software Tests",
                                content="Testing approach and results."
                            )
                        ]
                    ),
                    Chapter(
                        title="Chapter 3: Acceptance",
                        content="Acceptance procedures and criteria."
                    ),
                    Chapter(
                        title="Chapter 4: Final Payment",
                        content="Final financial arrangements."
                    )
                ]
            )

            # Convert the document structure to a dictionary and ensure each item has an ID
            doc_dict = doc.to_dict()
            structure = ensure_ids(doc_dict['children'])

            # Create a new draft document to insert into the database
            draft_doc = {
                'user_id': user_id,
                'title': doc_dict['title'],
                'structure': structure,
                'created_at': datetime.now(),
                'updated_at': datetime.now(),
                'doc_status': 'draft'
            }

            mongo.db.documents.insert_one(draft_doc)
            logger.info(f"Created new draft document for user {user_id}")

        # Update the last activity timestamp for the draft document
        mongo.db.documents.update_one(
            {'_id': draft_doc['_id']},
            {'$set': {'last_activity': datetime.now()}}
        )

    # Set a response with the document structure for rendering in the editor
    response = make_response(render_template(
        'create_edit_doc.html',
        document=draft_doc.get('structure', []),
        doc_id=str(draft_doc['_id']),
        # Pass the document title
        doc_title=draft_doc.get('title', 'Untitled Document')
    ))
    return response

# Ensure that each item in the structure has an 'id', especially for nested children (chapters/sections)


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


@app.route('/auto_save_document', methods=['POST'])
def auto_save_document():
    """Auto-save document content as user types"""
    user_id = current_user._id
    if not user_id:
        logger.warning("Auto-save attempted without user ID")
        return "<span class='text-danger'>No user found</span>", 400

    try:
        # Get form data instead of JSON data
        item_id = request.form.get('item_id')
        title = request.form.get('title')
        content = request.form.get('content')

        logger.debug(f"Auto-save for item {item_id} for user {user_id}")

        # Find the document
        draft_doc = mongo.db.documents.find_one(
            {'user_id': user_id, 'doc_status': 'draft'})
        if not draft_doc:
            logger.warning(f"Auto-save: Document not found for user {user_id}")
            return "<span class='text-danger'>Document not found</span>", 404

        # Update the specific item in the structure
        updated = update_document_item(
            draft_doc['structure'], item_id, content, title)

        if updated:
            # Update the document in the database
            mongo.db.documents.update_one(
                {'user_id': user_id, 'doc_status': 'draft'},
                {
                    '$set': {
                        'structure': draft_doc['structure'],
                        'updated_at': datetime.now(),
                        'last_activity': datetime.now()
                    }
                }
            )
            timestamp = datetime.now().strftime('%H:%M:%S')
            logger.debug(
                f"Document auto-saved successfully for item {item_id}")
            return f"<span class='text-success'>Saved at {timestamp}</span>"

        logger.warning(
            f"Auto-save: Item {item_id} not found in document structure")
        return "<span class='text-danger'>Item not found in document</span>", 404

    except Exception as e:
        logger.error(f"Error during auto-save: {str(e)}", exc_info=True)
        return f"<span class='text-danger'>Error saving: {str(e)}</span>", 500

# this has been called when the user clicks on a document item to edit


@app.route('/get_document', methods=['GET'])
def get_document_item():
    """Get specific document item content for editing"""
    doc_id = request.args.get('doc_id')
    item_id = request.args.get('item_id')
    user_id = current_user._id

    if not doc_id or not item_id:
        return "Missing required parameters", 400

    try:
        # Find the document using both user_id and doc_id
        draft_doc = mongo.db.documents.find_one({
            '_id': ObjectId(doc_id),
            'user_id': user_id
        })

        logger.info(f"Looking for item {item_id} in document {doc_id}")
        if not draft_doc:
            logger.error(f"Document {doc_id} not found for user {user_id}")
            return "<p>Document not found. Check the system logs for more details.</p>", 404

        # Find the specific item (helper function)
        def find_item(items, target_id):
            for item in items:
                if str(item.get('id')) == str(target_id):
                    return item
                if 'children' in item and item['children']:
                    found = find_item(item['children'], target_id)
                    if found:
                        return found
            return None

        item = find_item(draft_doc['structure'], item_id)
        logger.info(f"Item found through get_document method is: {item}")
        if item:
            # Render the editor with this item's content
            return render_template('partials/document_editor.html',
                                   item=item,
                                   doc_id=doc_id,
                                   user_id=user_id)

        logger.error(
            f"Document section {item_id} not found in document {doc_id}")
        return "<p>Document section not found. Check the system logs for more details.</p>", 404

    except Exception as e:
        logger.error(f"Error getting document item: {str(e)}", exc_info=True)
        return f"<p>Error loading content: {str(e)}</p>", 500


@app.route('/add_document_item', methods=['POST'])
def add_document_item():
    """Add a new chapter or section to the document"""
    user_id = current_user._id
    if not user_id:
        return jsonify({'status': 'error', 'message': 'No user found'}), 400

    try:
        parent_id = request.form.get('parent_id', None)  # None for root level
        title = request.form.get('title', 'New Section')

        # Find the document
        draft_doc = mongo.db.documents.find_one(
            {'user_id': user_id, 'doc_status': 'draft'})
        if not draft_doc:
            return jsonify({'status': 'error', 'message': 'Document not found'}), 404

        # Create new item
        new_item = {
            'id': str(ObjectId()),
            'title': title,
            'content': '',
            'children': []
        }

        # If parent_id is None, add to root level
        if not parent_id:
            draft_doc['structure'].append(new_item)
            logger.info(f"Added new root-level item {new_item['id']}")
        else:
            # Find the parent and add to its children
            def add_to_parent(items, parent_id, new_item):
                for item in items:
                    if str(item.get('id')) == str(parent_id):
                        if 'children' not in item:
                            item['children'] = []
                        item['children'].append(new_item)
                        return True
                    if 'children' in item and item['children']:
                        if add_to_parent(item['children'], parent_id, new_item):
                            return True
                return False

            if not add_to_parent(draft_doc['structure'], parent_id, new_item):
                return jsonify({'status': 'error', 'message': 'Parent item not found'}), 404

            logger.info(
                f"Added new item {new_item['id']} under parent {parent_id}")

        # Update the document
        mongo.db.documents.update_one(
            {'user_id': user_id, 'doc_status': 'draft'},
            {
                '$set': {
                    'structure': draft_doc['structure'],
                    'updated_at': datetime.now(),
                    'last_activity': datetime.now()
                }
            }
        )

        # Return the HTML for the new item
        return render_template('partials/document_item.html',
                               item=new_item,
                               is_new=True)

    except Exception as e:
        logger.error(f"Error adding document item: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Schedule the cleanup task to run daily if using a task scheduler
# For example, if using APScheduler:
#
# from apscheduler.schedulers.background import BackgroundScheduler
# scheduler = BackgroundScheduler()
# scheduler.add_job(cleanup_inactive_documents, 'interval', hours=24)
# scheduler.start()


@app.route('/delete-doc/<doc_id>', methods=['DELETE'])
def delete_doc(doc_id):
    mongo.db.documents.delete_one({'_id': ObjectId(doc_id)})
    documents = list(mongo.db.documents.find())
    return render_template('docs_list.html', documents=documents)


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


@app.route('/edit-title-form')
def edit_title_form():
    """Return the title edit form"""
    doc_id = request.args.get('doc_id')
    doc_title = request.args.get('doc_title')
    action = request.args.get('action')

    if action == 'cancel':
        # Return the title display template
        return render_template('partials/_title.html', doc_id=doc_id, doc_title=doc_title)

    # Return the edit form template
    return render_template('partials/_title_edit_form.html', doc_id=doc_id, doc_title=doc_title)

# this route is called when the user clicks on the edit title button


@app.route("/edit-title", methods=["POST"])
def edit_title():
    doc_id = request.form.get('doc_id')
    current_title = request.form.get('current_title')
    new_title = request.form.get("title", "").strip()

    if not new_title:
        return "Title is required", 400

    logger.info(
        f"Updating title for doc_id: {doc_id} from '{current_title}' to '{new_title}'")

    try:
        # First verify the document exists and has the current title
        doc = mongo.db.documents.find_one({
            '_id': ObjectId(doc_id),
            'title': current_title
        })

        if not doc:
            logger.warning(f"Document {doc_id} not found or title mismatch")
            return "Document not found or title mismatch", 404

        # Update the document in MongoDB
        result = mongo.db.documents.update_one(
            {'_id': ObjectId(doc_id)},
            {
                '$set': {
                    'title': new_title,
                    'updated_at': datetime.now()
                }
            }
        )

        if result.modified_count > 0:
            # Verify the update was successful
            updated_doc = mongo.db.documents.find_one(
                {'_id': ObjectId(doc_id)})
            if updated_doc and updated_doc.get('title') == new_title:
                logger.info(
                    f"Successfully updated title for document {doc_id}")
                return render_template("partials/_title.html", doc_id=doc_id, doc_title=new_title)
            else:
                logger.error(
                    f"Update verification failed for document {doc_id}")
                return "Update verification failed", 500
        else:
            logger.warning(f"No changes made to document {doc_id}")
            return "Failed to update title", 400

    except Exception as e:
        logger.error(f"Error updating document title: {str(e)}", exc_info=True)
        return str(e), 500


### chatbot related tests

# this has been called from flask route /send_message, which by itself is triggered by the user sending a message to the chat box
def get_bot_response(message):
    # In a real application, you might integrate with an AI service here
    responses = {
        "hello": "Hi there! How can I help you today?",
        "how are you": "I'm just a bot, but I'm functioning well. How about you?",
        "bye": "Goodbye! Have a great day!",
        "help": "I can answer simple questions. Just type your message in the chat box."
    }

    message = message.lower()

    # Check if the message contains any of our keywords
    for key in responses:
        if key in message:
            return responses[key]

    # Default response
    return "I'm not sure how to respond to that. Can you try asking something else?"


# this has been called from index.html, a JS script in the index.html file
@app.route('/bot')
def bot():
    return render_template('bot-main.html')

# this has been called from bot-main.html, a JS script in the bot-main.html file
@app.route('/send_message', methods=['POST'])
def send_message():
    logger.info('in the bot route - send_message')
    try:
        # Get the message from the form
        user_message = request.form.get('message', '')
        logger.info(f'user_message: {user_message}')
        if not user_message.strip():
            logger.info('Message cannot be empty')
            return "Message cannot be empty", 400

        # Add a small delay to simulate processing (optional)
        time.sleep(1.2)

        # Get bot response
        logger.info('getting bot response')
        bot_response = get_bot_response(user_message)
        logger.info(f'bot_response: {bot_response}')

        # Return the message template with both user message and bot response


        return render_template('bot-message.html',
                               user_message=user_message,
                               bot_response=bot_response)
    except Exception as e:
        app.logger.error(f"Error processing message: {str(e)}")
        return "An error occurred", 500


if __name__ == '__main__':
    app.logger.info('Starting Flask application')
    app.run(host=Config.HOST, debug=Config.DEBUG, port=Config.PORT)

