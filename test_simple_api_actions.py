import pytest
import requests
import uuid
import sys
import os

# Add the current directory to Python path so tests can import the app module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Base URL for the API running in Docker container
BASE_URL = "http://localhost:9000"
API_BASE = f"{BASE_URL}/api"

@pytest.fixture
def client():
    """Create a requests session for making HTTP calls"""
    return requests.Session()

@pytest.fixture
def test_user():
    """Generate unique test user data for each test"""
    unique_id = str(uuid.uuid4())[:8]
    return {
        'email': f'testuser{unique_id}@example.com',
        'password': 'StrongPassword123!',
        'name': f'Test User {unique_id}'
    }

def get_access_token(client, test_user):
    """Helper function to register and login a user, returning access token"""
    # Register user
    register_data = {
        'email': test_user['email'],
        'password': test_user['password'],
        'name': test_user['name']
    }
    register_resp = client.post(f"{API_BASE}/auth/register", json=register_data)
    assert register_resp.status_code == 201
    assert 'Account is ready to use' in register_resp.json()['message']
    
    # Login to get access token
    login_data = {
        'email': test_user['email'],
        'password': test_user['password']
    }
    
    login_resp = client.post(f"{API_BASE}/auth/login", json=login_data)
    
    assert login_resp.status_code == 200
    assert 'access_token' in login_resp.json()
    
    return login_resp.json()['access_token']

def cleanup_user(client, test_user):
    """Helper function to clean up test user"""
    try:
        # Login to get token for deletion
        login_data = {
            'email': test_user['email'],
            'password': test_user['password']
        }
        login_resp = client.post(f"{API_BASE}/auth/login", json=login_data)
        if login_resp.status_code == 200:
            access_token = login_resp.json()['access_token']
            headers = {'Authorization': f'Bearer {access_token}'}
            # Delete user
            client.delete(f"{API_BASE}/user/profile", headers=headers)
    except Exception:
        pass  # Ignore cleanup errors

@pytest.fixture(autouse=True)
def auto_cleanup(client, test_user):
    """Automatically clean up test user after each test"""
    yield
    cleanup_user(client, test_user)

def test_register_success(client, test_user):
    """Test user registration"""
    register_data = {
        'email': test_user['email'],
        'password': test_user['password'],
        'name': test_user['name']
    }
    
    response = client.post(f"{API_BASE}/auth/register", json=register_data)
    
    assert response.status_code == 201
    data = response.json()
    assert 'message' in data
    assert 'Account is ready to use' in data['message']

def test_login_success(client, test_user):
    """Test user login"""
    # First register the user
    register_data = {
        'email': test_user['email'],
        'password': test_user['password'],
        'name': test_user['name']
    }
    register_resp = client.post(f"{API_BASE}/auth/register", json=register_data)
    assert register_resp.status_code == 201
    
    # Then login
    login_data = {
        'email': test_user['email'],
        'password': test_user['password']
    }
    
    response = client.post(f"{API_BASE}/auth/login", json=login_data)
    
    assert response.status_code == 200
    data = response.json()
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert len(data['access_token']) > 0
    assert len(data['refresh_token']) > 0

def test_create_document_success(client, test_user):
    """Test creating a document"""
    # Get access token
    access_token = get_access_token(client, test_user)
    headers = {'Authorization': f'Bearer {access_token}'}
    
    # Create document
    document_data = {
        'title': 'Test Document',
        'content': {
            'sections': [
                {
                    'id': 'sec-1',
                    'title': 'Introduction',
                    'content': 'This is a test document.',
                    'children': []
                }
            ]
        },
        'doc_status': 'draft',
        'tags': ['test', 'simple']
    }
    
    response = client.post(f"{API_BASE}/documents", json=document_data, headers=headers)
    
    assert response.status_code == 201
    data = response.json()
    assert data['status'] == 'success'
    assert 'Document created successfully' in data['message']
    assert 'document_id' in data
    assert len(data['document_id']) > 0

def test_get_documents_success(client, test_user):
    """Test getting user's documents"""
    # Get access token
    access_token = get_access_token(client, test_user)
    headers = {'Authorization': f'Bearer {access_token}'}
    
    # Create a document first
    document_data = {
        'title': 'Test Document for Get',
        'content': {
            'sections': [
                {
                    'id': 'sec-1',
                    'title': 'Introduction',
                    'content': 'This is a test document for get operation.',
                    'children': []
                }
            ]
        },
        'doc_status': 'draft',
        'tags': ['test', 'get']
    }
    
    create_resp = client.post(f"{API_BASE}/documents", json=document_data, headers=headers)
    assert create_resp.status_code == 201
    
    # Get documents
    response = client.get(f"{API_BASE}/documents", headers=headers)
    
    assert response.status_code == 200
    documents = response.json()
    assert isinstance(documents, list)
    assert len(documents) >= 1
    
    # Check that our created document is in the list
    found_document = False
    for doc in documents:
        if doc['title'] == 'Test Document for Get':
            found_document = True
            assert doc['doc_status'] == 'draft'
            assert 'test' in doc['tags']
            assert 'get' in doc['tags']
            break
    
    assert found_document, "Created document should be in the documents list" 


def test_auth_check_unauthorized(client):
    """Auth check should return 401 without token"""
    response = client.get(f"{API_BASE}/auth/check")
    assert response.status_code == 401


def test_auth_check_authorized(client, test_user):
    """Auth check should return authenticated info with valid token"""
    access_token = get_access_token(client, test_user)
    headers = {"Authorization": f"Bearer {access_token}"}

    response = client.get(f"{API_BASE}/auth/check", headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert data.get('authenticated') is True
    assert 'user' in data
    assert data['user']['email'] == test_user['email']
    assert 'exp' in data and isinstance(data['exp'], int)

def test_document_with_effort_tracking(client, test_user):
    """Test document creation with effort tracking"""
    access_token = get_access_token(client, test_user)
    headers = {'Authorization': f'Bearer {access_token}'}
    
    # Create a document with effort values
    document_data = {
        "title": "Test Document with Effort",
        "content": {
            "sections": [
                {
                    "id": "sec-1",
                    "title": "Introduction",
                    "content": "This is the introduction section.",
                    "effort": 8.0,
                    "children": [
                        {
                            "id": "sec-1-1",
                            "title": "Background",
                            "content": "Background information.",
                            "effort": 4.0
                        }
                    ]
                },
                {
                    "id": "sec-2",
                    "title": "Methods",
                    "content": "Research methods description.",
                    "effort": 12.0,
                    "children": []
                }
            ]
        },
        "doc_status": "draft",
        "tags": ["test", "effort"]
    }
    
    # Create document
    response = client.post(f"{API_BASE}/documents", json=document_data, headers=headers)
    assert response.status_code == 201
    
    data = response.json()
    assert data["status"] == "success"
    document_id = data["document_id"]
    
    # Retrieve and verify effort values
    get_response = client.get(f"{API_BASE}/documents/{document_id}", headers=headers)
    assert get_response.status_code == 200
    
    doc_data = get_response.json()
    assert doc_data["content"]["sections"][0]["effort"] == 8.0
    assert doc_data["content"]["sections"][0]["children"][0]["effort"] == 4.0
    assert doc_data["content"]["sections"][1]["effort"] == 12.0
    
    # Clean up
    cleanup_user(client, test_user)