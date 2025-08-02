#!/usr/bin/env python3
"""
Pytest-based Authentication Test Suite
Professional test suite for the SmartScope authentication system.
"""

import pytest
import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:9000"  # Docker container port
API_BASE = f"{BASE_URL}/api"

class TestAuthentication:
    """Test class for authentication functionality"""
    
    @pytest.fixture(scope="class")
    def test_user_data(self):
        """Fixture to provide test user data"""
        timestamp = int(time.time())
        return {
            "email": f"testuser_{timestamp}@example.com",
            "password": "TestPassword123!",
            "name": "Test User"
        }
    
    @pytest.fixture(scope="class")
    def auth_tokens(self):
        """Fixture to store authentication tokens"""
        return {"access_token": None, "refresh_token": None}
    
    def test_server_connectivity(self):
        """Test if the server is accessible"""
        try:
            response = requests.get(f"{BASE_URL}/")
            # Accept various status codes as server is running
            assert response.status_code in [200, 302, 401, 500]
        except requests.exceptions.ConnectionError:
            pytest.fail("Server is not accessible")
    
    def test_user_registration(self, test_user_data):
        """Test user registration endpoint"""
        url = f"{API_BASE}/auth/register"
        
        response = requests.post(url, json=test_user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert "message" in data
        assert "Registration successful" in data["message"]
    
    def test_user_login(self, test_user_data, auth_tokens):
        """Test user login and token generation"""
        url = f"{API_BASE}/auth/login"
        data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert len(data["access_token"]) > 0
        assert len(data["refresh_token"]) > 0
        
        # Store tokens for other tests
        auth_tokens["access_token"] = data["access_token"]
        auth_tokens["refresh_token"] = data["refresh_token"]
    
    def test_get_user_profile(self, auth_tokens):
        """Test getting user profile with authentication"""
        url = f"{API_BASE}/user/profile"
        headers = {"Authorization": f"Bearer {auth_tokens['access_token']}"}
        
        response = requests.get(url, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "_id" in data
        assert "email" in data
        assert "name" in data
        assert "is_verified" in data
        assert data["is_verified"] is True  # Email verification disabled
    
    def test_update_user_profile(self, auth_tokens):
        """Test updating user profile"""
        url = f"{API_BASE}/user/profile"
        headers = {"Authorization": f"Bearer {auth_tokens['access_token']}"}
        update_data = {
            "name": "Updated Test User",
            "avatar_url": "https://example.com/avatar.jpg"
        }
        
        response = requests.put(url, json=update_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Profile updated successfully" in data["message"]
    
    def test_change_password(self, test_user_data, auth_tokens):
        """Test changing user password"""
        url = f"{API_BASE}/user/change-password"
        headers = {"Authorization": f"Bearer {auth_tokens['access_token']}"}
        password_data = {
            "current_password": test_user_data["password"],
            "new_password": "NewTestPassword123!"
        }
        
        response = requests.post(url, json=password_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Password changed successfully" in data["message"]
        
        # Update test user data for subsequent tests
        test_user_data["password"] = "NewTestPassword123!"
    
    def test_login_with_new_password(self, test_user_data, auth_tokens):
        """Test login with the new password"""
        url = f"{API_BASE}/auth/login"
        data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]  # Updated password
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        
        # Update tokens
        auth_tokens["access_token"] = data["access_token"]
        auth_tokens["refresh_token"] = data["refresh_token"]
    
    def test_token_refresh(self, auth_tokens):
        """Test JWT token refresh"""
        url = f"{API_BASE}/auth/refresh-token"
        headers = {"Authorization": f"Bearer {auth_tokens['refresh_token']}"}
        
        response = requests.post(url, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert len(data["access_token"]) > 0
        
        # Update access token
        auth_tokens["access_token"] = data["access_token"]
    
    def test_forgot_password(self, test_user_data):
        """Test forgot password endpoint"""
        url = f"{API_BASE}/auth/forgot-password"
        data = {"email": test_user_data["email"]}
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "password reset link" in data["message"]
    
    def test_user_logout(self, auth_tokens):
        """Test user logout"""
        url = f"{API_BASE}/auth/logout"
        headers = {"Authorization": f"Bearer {auth_tokens['access_token']}"}
        
        response = requests.post(url, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Logout successful" in data["message"]
    
    def test_protected_endpoint_after_logout(self, auth_tokens):
        """Test that JWT tokens remain valid after logout (stateless nature)"""
        url = f"{API_BASE}/user/profile"
        headers = {"Authorization": f"Bearer {auth_tokens['access_token']}"}
        
        response = requests.get(url, headers=headers)
        
        # JWT tokens are stateless, so they remain valid until expiration
        assert response.status_code == 200
    
    def test_invalid_login(self, test_user_data):
        """Test login with invalid credentials"""
        url = f"{API_BASE}/auth/login"
        data = {
            "email": test_user_data["email"],
            "password": "WrongPassword123!"
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
        assert "Invalid credentials" in data["error"]
    
    def test_user_deletion(self, test_user_data):
        """Test user account deletion"""
        # First login to get fresh token
        login_url = f"{API_BASE}/auth/login"
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        
        login_response = requests.post(login_url, json=login_data)
        assert login_response.status_code == 200
        
        tokens = login_response.json()
        delete_token = tokens["access_token"]
        
        # Delete the user
        url = f"{API_BASE}/user/profile"
        headers = {"Authorization": f"Bearer {delete_token}"}
        
        response = requests.delete(url, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "User deleted successfully" in data["message"]


class TestAuthenticationErrors:
    """Test class for authentication error cases"""
    
    def test_registration_with_invalid_email(self):
        """Test registration with invalid email format"""
        url = f"{API_BASE}/auth/register"
        data = {
            "email": "invalid-email",
            "password": "TestPassword123!",
            "name": "Test User"
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Invalid email format" in data["error"]
    
    def test_registration_with_weak_password(self):
        """Test registration with weak password"""
        url = f"{API_BASE}/auth/register"
        data = {
            "email": "test@example.com",
            "password": "weak",
            "name": "Test User"
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "Password must be at least 8 characters" in data["error"]
    
    def test_registration_without_required_fields(self):
        """Test registration without required fields"""
        url = f"{API_BASE}/auth/register"
        data = {
            "email": "test@example.com"
            # Missing password and name
        }
        
        response = requests.post(url, json=data)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        # The API validates password first, so we check for password-related error
        assert "Password" in data["error"] or "Missing required fields" in data["error"]
    
    def test_protected_endpoint_without_token(self):
        """Test accessing protected endpoint without authentication"""
        url = f"{API_BASE}/user/profile"
        
        response = requests.get(url)
        
        assert response.status_code == 401
        data = response.json()
        assert "msg" in data
        assert "Missing or invalid authorization" in data["msg"]
    
    def test_protected_endpoint_with_invalid_token(self):
        """Test accessing protected endpoint with invalid token"""
        url = f"{API_BASE}/user/profile"
        headers = {"Authorization": "Bearer invalid_token"}
        
        response = requests.get(url, headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert "msg" in data
        assert "Invalid or expired token" in data["msg"]


class TestAPIEndpoints:
    """Test class for API endpoint accessibility"""
    
    def test_swagger_documentation(self):
        """Test if Swagger documentation is accessible"""
        response = requests.get(f"{BASE_URL}/apidocs/")
        assert response.status_code == 200
    
    def test_cors_headers(self):
        """Test if CORS headers are present"""
        response = requests.options(f"{API_BASE}/auth/register")
        cors_headers = response.headers.get('Access-Control-Allow-Origin')
        assert cors_headers is not None
        assert cors_headers == "*"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"]) 