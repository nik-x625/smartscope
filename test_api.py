import pytest
from app_front_with_react import app
from flask import json
from app_front_with_react import mongo
from datetime import datetime
import time

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

def register_user(client, user=TEST_USER):
    return client.post('/api/register', json=user)

def login_user(client, user=TEST_USER):
    return client.post('/api/login', json={
        'username': user['username'],
        'password': user['password']
    })

def get_access_token(client, user=TEST_USER):
    login_resp = login_user(client, user)
    if login_resp.status_code == 200:
        return login_resp.get_json().get('access_token')
    return None

def get_refresh_token(client, user=TEST_USER):
    login_resp = login_user(client, user)
    if login_resp.status_code == 200:
        return login_resp.get_json().get('refresh_token')
    return None

# --- Registration ---
def test_api_register(client):
    response = register_user(client)
    assert response.status_code == 201
    assert 'Registration successful' in response.get_data(as_text=True)

def test_api_register_duplicate_username(client):
    register_user(client)
    user2 = TEST_USER.copy()
    user2['email'] = 'other@example.com'
    resp = register_user(client, user2)
    assert resp.status_code == 400
    assert 'Username already exists' in resp.get_data(as_text=True)

def test_api_register_duplicate_email(client):
    register_user(client)
    user2 = TEST_USER.copy()
    user2['username'] = 'otheruser'
    resp = register_user(client, user2)
    assert resp.status_code == 400
    assert 'Email already exists' in resp.get_data(as_text=True)

def test_api_register_missing_fields(client):
    resp = client.post('/api/register', json={'username': 'a'})
    assert resp.status_code == 400

def test_api_register_empty(client):
    resp = client.post('/api/register', json={})
    assert resp.status_code == 400

# --- Login ---
def test_api_login(client):
    register_user(client)
    response = login_user(client)
    assert response.status_code == 200
    data = response.get_json()
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert 'expiresIn' in data

def test_api_login_bad_password(client):
    register_user(client)
    resp = login_user(client, {**TEST_USER, 'password': 'wrong'})
    assert resp.status_code == 401
    assert 'Bad username or password' in resp.get_data(as_text=True)

def test_api_login_missing_fields(client):
    resp = client.post('/api/login', json={'username': TEST_USER['username']})
    assert resp.status_code == 401 or resp.status_code == 400

# --- JWT-protected endpoints ---
def test_api_get_documents_unauthorized(client):
    response = client.get('/api/get_documents')
    assert response.status_code == 401

def test_api_set_document_unauthorized(client):
    doc = {'title': 'Should Fail', 'content': 'No auth'}
    response = client.post('/api/set_document', json=doc)
    assert response.status_code == 401

def test_api_get_document_unauthorized(client):
    response = client.get('/api/get_document?document_id=123')
    assert response.status_code == 401

# --- set_document, get_documents, get_document ---
def test_api_set_and_get_document_full_flow(client):
    register_user(client)
    access_token = get_access_token(client)
    doc = {
        'title': 'Research Report 2024',
        'content': {
            'sections': [
                {
                    'id': 'sec-1',
                    'title': 'Introduction',
                    'content': 'Intro text',
                    'children': [
                        {
                            'id': 'sec-1-1',
                            'title': 'Background',
                            'content': 'Background info'
                        }
                    ]
                },
                {
                    'id': 'sec-2',
                    'title': 'Methods',
                    'content': 'Methods text',
                    'children': []
                }
            ]
        },
        'doc_status': 'saved',
        'tags': ['research', '2024', 'AI']
    }
    # Create document
    set_resp = client.post('/api/set_document', json=doc, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert set_resp.status_code == 200
    doc_id = set_resp.get_json()['document_id']
    # Get all documents
    get_resp = client.get('/api/get_documents', headers={
        'Authorization': f'Bearer {access_token}'
    })
    docs = get_resp.get_json()
    found = [d for d in docs if d['_id'] == doc_id]
    assert found
    d = found[0]
    assert d['title'] == doc['title']
    assert d['doc_status'] == doc['doc_status']
    assert d['tags'] == doc['tags']
    assert 'created_at' in d and 'updated_at' in d
    # Get single document
    get_one = client.get(f'/api/get_document?document_id={doc_id}', headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert get_one.status_code == 200
    d2 = get_one.get_json()
    assert d2['title'] == doc['title']
    assert d2['doc_status'] == doc['doc_status']
    assert d2['tags'] == doc['tags']
    assert 'created_at' in d2 and 'updated_at' in d2
    # created_at and updated_at should be close
    created = datetime.fromisoformat(d2['created_at'].replace('Z', '+00:00')) if 'Z' in d2['created_at'] else datetime.fromisoformat(d2['created_at'])
    updated = datetime.fromisoformat(d2['updated_at'].replace('Z', '+00:00')) if 'Z' in d2['updated_at'] else datetime.fromisoformat(d2['updated_at'])
    assert abs((created - updated).total_seconds()) < 2
    # Update document
    time.sleep(1)
    doc_update = doc.copy()
    doc_update['_id'] = doc_id
    doc_update['title'] = 'Updated Title'
    set_resp2 = client.post('/api/set_document', json=doc_update, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert set_resp2.status_code == 200
    get_one2 = client.get(f'/api/get_document?document_id={doc_id}', headers={
        'Authorization': f'Bearer {access_token}'
    })
    d3 = get_one2.get_json()
    assert d3['title'] == 'Updated Title'
    # created_at should not change, updated_at should be newer
    created2 = datetime.fromisoformat(d3['created_at'].replace('Z', '+00:00')) if 'Z' in d3['created_at'] else datetime.fromisoformat(d3['created_at'])
    updated2 = datetime.fromisoformat(d3['updated_at'].replace('Z', '+00:00')) if 'Z' in d3['updated_at'] else datetime.fromisoformat(d3['updated_at'])
    assert created2 == created
    assert updated2 > updated

def test_api_set_document_missing_fields(client):
    register_user(client)
    access_token = get_access_token(client)
    # Missing title
    doc = {'content': {}}
    resp = client.post('/api/set_document', json=doc, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert resp.status_code in (200, 400)  # Accepts minimal doc or returns error
    # Missing content
    doc = {'title': 'No Content'}
    resp = client.post('/api/set_document', json=doc, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert resp.status_code in (200, 400)
    # Empty body
    resp = client.post('/api/set_document', json={}, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert resp.status_code == 400

def test_api_get_document_not_found(client):
    register_user(client)
    access_token = get_access_token(client)
    resp = client.get('/api/get_document?document_id=000000000000000000000000', headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert resp.status_code == 404
    assert 'Document not found' in resp.get_data(as_text=True)

# --- Refresh ---
def test_api_refresh(client):
    register_user(client)
    refresh_token = get_refresh_token(client)
    response = client.post('/api/refresh', headers={
        'Authorization': f'Bearer {refresh_token}'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert 'access_token' in data

def test_api_refresh_invalid_token(client):
    resp = client.post('/api/refresh', headers={
        'Authorization': 'Bearer invalidtoken'
    })
    assert resp.status_code == 401

# --- Delete user ---
def test_api_delete_user(client):
    register_user(client)
    access_token = get_access_token(client)
    # Create a document
    doc = {'title': 'To be deleted', 'content': {}}
    set_resp = client.post('/api/set_document', json=doc, headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert set_resp.status_code == 200
    # Delete user
    response = client.delete('/api/delete_user', headers={
        'Authorization': f'Bearer {access_token}'
    })
    assert response.status_code == 200
    assert 'User deleted successfully' in response.get_data(as_text=True)
    # User and docs should be gone
    user = mongo.db.users.find_one({'username': TEST_USER['username']})
    assert user is None
    docs = list(mongo.db.documents.find({'user_id': str(user) if user else None}))
    assert not docs
    # Try to login again, should fail
    login_resp = login_user(client)
    assert login_resp.status_code == 401 or login_resp.status_code == 400

def test_api_delete_user_unauthorized(client):
    resp = client.delete('/api/delete_user')
    assert resp.status_code == 401

# --- CORS ---
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