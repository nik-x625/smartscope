import pytest
import requests
import uuid
import os
import time
from pathlib import Path

# Base URL for the API running in Docker container
BASE_URL = "http://localhost:9000"
API_BASE = f"{BASE_URL}/api"

# Constants
UPLOAD_FOLDER = Path.cwd() / "uploads"
TEST_FILES = {
    "image": {"path": "uploads_test/sample_img1.jpeg", "content_type": "image/jpeg", "size": 5446210},
    "document": {"path": "uploads_test/sample_file1.zip", "content_type": "application/zip", "size": 10677628},
    "unsupported": {"path": "uploads_test/test_unsupported.exe", "content_type": "application/octet-stream", "size": 1024},
    "large": {"path": "uploads_test/test_large_file.png", "content_type": "image/png", "size": 16 * 1024 * 1024},  # 16MB
}

# --- Helper Functions ---

def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

def get_access_token(client, test_user):
    """Helper function to register and login a user, returning access token"""
    # Register user
    register_data = {
        'email': test_user['email'],
        'password': test_user['password'],
        'name': test_user['name']
    }
    
    # Try registration with retry logic
    max_retries = 3
    for attempt in range(max_retries):
        register_resp = client.post(f"{API_BASE}/auth/register", json=register_data)
        if register_resp.status_code == 201:
            break
        elif register_resp.status_code == 400 and "already exists" in register_resp.json().get('error', ''):
            # User already exists, try to login directly
            try:
                login_data = {
                    'email': test_user['email'],
                    'password': test_user['password']
                }
                login_resp = client.post(f"{API_BASE}/auth/login", json=login_data)
                if login_resp.status_code == 200:
                    return login_resp.json()['access_token']
            except:
                pass
            
            # If login fails, generate new user data and retry
            unique_id = str(uuid.uuid4())[:8]
            timestamp = int(time.time() * 1000) % 100000
            test_user['email'] = f'testuser{unique_id}{timestamp}@example.com'
            test_user['name'] = f'Test User {unique_id}{timestamp}'
            register_data = {
                'email': test_user['email'],
                'password': test_user['password'],
                'name': test_user['name']
            }
        else:
            # Other error, fail the test
            assert register_resp.status_code == 201, f"Registration failed: {register_resp.json()}"
    
    # Final check
    assert register_resp.status_code == 201, f"Registration failed after {max_retries} attempts: {register_resp.json()}"
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

def upload_test_file(client, token, file_path, content_type, size):
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, content_type)}
        response = client.post(f"{API_BASE}/files/upload", headers=auth_headers(token), files=files)
    response.raise_for_status()
    data = response.json()
    # Allow small size tolerance
    assert abs(data["size"] - size) < 1000
    return data["file_id"]

def delete_test_file(client, token, file_id):
    try:
        response = client.delete(f"{API_BASE}/files/{file_id}", headers=auth_headers(token))
        response.raise_for_status()
    except Exception as e:
        print(f"Warning: Could not delete file {file_id}. Error: {e}")

def cleanup_user(client, test_user):
    """Clean up test user after test"""
    try:
        # Try to login first
        login_data = {
            'email': test_user['email'],
            'password': test_user['password']
        }
        login_resp = client.post(f"{API_BASE}/auth/login", json=login_data)
        
        if login_resp.status_code == 200:
            access_token = login_resp.json()['access_token']
            headers = auth_headers(access_token)
            
            # Get user's files and delete them
            files_resp = client.get(f"{API_BASE}/files", headers=headers)
            if files_resp.status_code == 200:
                files = files_resp.json()
                for file_info in files:
                    file_id = file_info.get('_id') or file_info.get('file_id')
                    if file_id:
                        client.delete(f"{API_BASE}/files/{file_id}", headers=headers)
            
            # Delete user profile
            client.delete(f"{API_BASE}/user/profile", headers=headers)
    except Exception as e:
        print(f"Warning: Could not cleanup user {test_user['email']}: {e}")

# --- Fixtures ---

@pytest.fixture
def client():
    """Create a requests session for making HTTP calls"""
    return requests.Session()

@pytest.fixture
def test_user():
    """Generate unique test user data for each test"""
    unique_id = str(uuid.uuid4())[:8]
    timestamp = int(time.time() * 1000) % 100000
    return {
        'email': f'testuser{unique_id}{timestamp}@example.com',
        'password': 'StrongPassword123!',
        'name': f'Test User {unique_id}{timestamp}'
    }

# Removed unused fixture

@pytest.fixture(scope="session", autouse=True)
def session_cleanup():
    """Cleanup leftover files/users after the entire test session."""
    yield
    print("Session cleanup completed.")

# --- Tests ---

@pytest.mark.parametrize("file_type", ["image", "document"])
def test_upload_file_success(client, test_user, file_type):
    """Test successful file upload for different file types"""
    token = get_access_token(client, test_user)
    file_info = TEST_FILES[file_type]
    file_id = upload_test_file(client, token, file_info["path"], file_info["content_type"], file_info["size"])
    assert file_id
    
    # Clean up
    delete_test_file(client, token, file_id)
    cleanup_user(client, test_user)

def test_upload_unsupported_file_type(client, test_user):
    """Test rejection of unsupported file types"""
    token = get_access_token(client, test_user)
    file_info = TEST_FILES["unsupported"]
    
    # Create a test file with unsupported extension
    test_file_path = "uploads_test/test_unsupported.exe"
    with open(test_file_path, "wb") as f:
        f.write(b"fake executable content")
    
    try:
        with open(test_file_path, "rb") as f:
            files = {"file": (file_info["path"], f, file_info["content_type"])}
            response = client.post(f"{API_BASE}/files/upload", headers=auth_headers(token), files=files)
        assert response.status_code == 400
        assert "File type not allowed" in response.json()["error"]
    finally:
        # Clean up test file
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
        cleanup_user(client, test_user)

def test_upload_large_file_rejection(client, test_user):
    """Test rejection of files exceeding size limit"""
    token = get_access_token(client, test_user)
    file_info = TEST_FILES["large"]
    
    # Create a large test file
    test_file_path = "uploads_test/test_large_file.png"
    with open(test_file_path, "wb") as f:
        f.write(b"x" * (16 * 1024 * 1024))  # 16MB
    
    try:
        with open(test_file_path, "rb") as f:
            files = {"file": (file_info["path"], f, file_info["content_type"])}
            response = client.post(f"{API_BASE}/files/upload", headers=auth_headers(token), files=files)
        assert response.status_code == 413  # Payload Too Large
    finally:
        # Clean up test file
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
        cleanup_user(client, test_user)

def test_file_deletion(client, test_user):
    """Test successful file deletion"""
    token = get_access_token(client, test_user)
    file_id = upload_test_file(client, token, TEST_FILES["image"]["path"], TEST_FILES["image"]["content_type"], TEST_FILES["image"]["size"])
    
    # Delete file
    response = client.delete(f"{API_BASE}/files/{file_id}", headers=auth_headers(token))
    assert response.status_code == 200
    assert "File deleted" in response.json()["message"]
    
    # Verify file is gone
    meta_response = client.get(f"{API_BASE}/files/{file_id}", headers=auth_headers(token))
    assert meta_response.status_code == 404
    
    cleanup_user(client, test_user)

def test_unauthorized_file_upload(client):
    """Test file upload without authentication"""
    file_info = TEST_FILES["image"]
    with open(file_info["path"], "rb") as f:
        files = {"file": (os.path.basename(file_info["path"]), f, file_info["content_type"])}
        response = client.post(f"{API_BASE}/files/upload", files=files)  # No token
    assert response.status_code == 401

def test_file_metadata_retrieval(client, test_user):
    """Test successful file metadata retrieval"""
    token = get_access_token(client, test_user)
    file_id = upload_test_file(client, token, TEST_FILES["image"]["path"], TEST_FILES["image"]["content_type"], TEST_FILES["image"]["size"])
    
    # Get metadata
    response = client.get(f"{API_BASE}/files/{file_id}", headers=auth_headers(token))
    assert response.status_code == 200
    
    data = response.json()
    assert data["file_id"] == file_id
    assert data["original_filename"] == os.path.basename(TEST_FILES["image"]["path"])
    assert data["content_type"] == TEST_FILES["image"]["content_type"]
    assert data["size"] == TEST_FILES["image"]["size"]
    assert "created_at" in data
    
    # Clean up
    delete_test_file(client, token, file_id)
    cleanup_user(client, test_user)

def test_file_download(client, test_user):
    """Test successful file download"""
    token = get_access_token(client, test_user)
    file_id = upload_test_file(client, token, TEST_FILES["image"]["path"], TEST_FILES["image"]["content_type"], TEST_FILES["image"]["size"])
    
    # Download file
    response = client.get(f"{API_BASE}/files/{file_id}/download", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.headers["content-type"] == TEST_FILES["image"]["content_type"]
    assert len(response.content) == TEST_FILES["image"]["size"]
    
    # Clean up
    delete_test_file(client, token, file_id)
    cleanup_user(client, test_user)
