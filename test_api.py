import pytest
from app_front_with_react import app
from flask import json
from app_front_with_react import mongo

TEST_USER = {
    'username': 'testuser_for_api_unit_tests_374435734865',
    'email': 'testuser_for_api_unit_tests_374435734865@example.com',
    'password': 'jg45geg545fe6hdfgd4ejudsdse'
}

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def cleanup_user(client):
    # Ensure user is deleted before and after each test
    client.post('/api/login', json={
        'username': TEST_USER['username'],
        'password': TEST_USER['password']
    })
    client.delete('/api/delete_user', headers={
        'Authorization': f'Bearer {get_access_token(client)}'
    })
    yield
    # Try to delete again in case user was recreated
    client.post('/api/login', json={
        'username': TEST_USER['username'],
        'password': TEST_USER['password']
    })
    client.delete('/api/delete_user', headers={
        'Authorization': f'Bearer {get_access_token(client)}'
    })

def register_user(client):
    return client.post('/api/register', json=TEST_USER)

def login_user(client):
    return client.post('/api/login', json={
        'username': TEST_USER['username'],
        'password': TEST_USER['password']
    })

def get_access_token(client):
    login_resp = login_user(client)
    if login_resp.status_code == 200:
        return login_resp.get_json().get('access_token')
    return None

def get_refresh_token(client):
    login_resp = login_user(client)
    if login_resp.status_code == 200:
        return login_resp.get_json().get('refresh_token')
    return None

# Test user registration endpoint
# Checks that a new user can be registered and receives a success message

def test_api_register(client):
    response = register_user(client)
    assert response.status_code == 201
    assert 'Registration successful' in response.get_data(as_text=True)

# Test user login endpoint
# Checks that a registered user can log in and receives access and refresh tokens

def test_api_login(client):
    register_user(client)
    response = login_user(client)
    assert response.status_code == 200
    data = response.get_json()
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert 'expiresIn' in data

# Test get_documents endpoint without authentication
# Checks that accessing documents without a token returns 401 Unauthorized

def test_api_get_documents_unauthorized(client):
    response = client.get('/api/get_documents')
    assert response.status_code == 401

# Test get_documents endpoint with authentication
# Checks that a logged-in user can fetch their documents (should return a list)

def test_api_get_documents(client):
    register_user(client)
    access_token = get_access_token(client)
    response = client.get('/api/get_documents', headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)

# Test set_document and get_documents endpoints
# Checks that a user can create a document and then retrieve it

def test_api_set_document_and_get(client):
    register_user(client)
    access_token = get_access_token(client)
    doc = {'title': 'My Test Doc', 'content': 'Some content'}
    set_resp = client.post('/api/set_document', json=doc, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert set_resp.status_code == 200
    doc_id = set_resp.get_json()['document_id']
    get_resp = client.get('/api/get_documents', headers={
        'Authorization': f'Bearer {access_token}'
    })
    docs = get_resp.get_json()
    assert any(d['_id'] == doc_id for d in docs)

# Test refresh endpoint
# Checks that a user can use their refresh token to obtain a new access token

def test_api_refresh(client):
    register_user(client)
    refresh_token = get_refresh_token(client)
    response = client.post('/api/refresh', headers={
        'Authorization': f'Bearer {refresh_token}'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'access_token' in data

# Test set_document endpoint without authentication
# Checks that creating a document without a token returns 401 Unauthorized

def test_api_set_document_unauthorized(client):
    doc = {'title': 'Should Fail', 'content': 'No auth'}
    response = client.post('/api/set_document', json=doc)
    assert response.status_code == 401

# Test CORS headers on backend
# Checks that CORS headers are present in preflight (OPTIONS) and normal requests

def test_cors_headers_present(client):
    origin = 'http://localhost:6060'
    response = client.options('/api/login', headers={
        'Origin': origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
    })
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] in ('*', origin)
    assert 'Access-Control-Allow-Methods' in response.headers
    assert 'POST' in response.headers['Access-Control-Allow-Methods']
    assert 'OPTIONS' in response.headers['Access-Control-Allow-Methods']
    assert 'Access-Control-Allow-Headers' in response.headers
    assert 'Content-Type' in response.headers['Access-Control-Allow-Headers']
    response = client.post('/api/login', json={
        'username': TEST_USER['username'],
        'password': TEST_USER['password']
    }, headers={'Origin': origin})
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] in ('*', origin)

# Test delete user endpoint
# Checks that a user can delete themselves and is removed from the database

def test_api_delete_user(client):
    register_user(client)
    access_token = get_access_token(client)
    response = client.delete('/api/delete_user', headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert response.status_code == 200
    assert 'User deleted successfully' in response.get_data(as_text=True)
    # Check if user still exists
    user = mongo.db.users.find_one({'username': TEST_USER['username']})
    print("User after deletion:", user)
    # Try to login again, should fail
    login_resp = login_user(client)
    assert login_resp.status_code == 401 or login_resp.status_code == 400 