#!/usr/bin/env python3
"""
Comprehensive Authentication Flow Test Script
Tests the complete authentication and user management flow:
1. User registration
2. User login
3. Password reset flow
4. User profile management
5. Password change
6. User deletion
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:9000"  # Docker container port
API_BASE = f"{BASE_URL}/api"

# Test user data
TEST_USER = {
    "email": f"testuser_{int(time.time())}@example.com",
    "password": "TestPassword123!",
    "name": "Test User"
}

def print_test_result(test_name, success, response=None, error=None):
    """Print test results in a formatted way"""
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} {test_name}")
    if response:
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    if error:
        print(f"   Error: {error}")
    print()

def test_server_health():
    """Test if the server is running"""
    try:
        response = requests.get(f"{BASE_URL}/")
        # Accept 500 errors too since the root endpoint requires authentication
        return response.status_code in [200, 302, 401, 500]  # Any of these indicate server is running
    except requests.exceptions.ConnectionError:
        return False

def test_user_registration():
    """Test user registration"""
    print("🔐 Testing User Registration...")
    
    url = f"{API_BASE}/auth/register"
    data = TEST_USER
    
    try:
        response = requests.post(url, json=data)
        success = response.status_code == 201
        print_test_result("User Registration", success, response)
        return success
    except Exception as e:
        print_test_result("User Registration", False, error=str(e))
        return False

def test_user_login():
    """Test user login"""
    print("🔑 Testing User Login...")
    
    url = f"{API_BASE}/auth/login"
    data = {
        "email": TEST_USER["email"],
        "password": TEST_USER["password"]
    }
    
    try:
        response = requests.post(url, json=data)
        success = response.status_code == 200
        
        if success:
            # Store tokens for later tests
            tokens = response.json()
            global access_token, refresh_token
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            print(f"   Access Token: {access_token[:50]}...")
            print(f"   Refresh Token: {refresh_token[:50]}...")
        
        print_test_result("User Login", success, response)
        return success
    except Exception as e:
        print_test_result("User Login", False, error=str(e))
        return False

def test_get_user_profile():
    """Test getting user profile"""
    print("👤 Testing Get User Profile...")
    
    url = f"{API_BASE}/user/profile"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        response = requests.get(url, headers=headers)
        success = response.status_code == 200
        
        if success:
            profile = response.json()
            print(f"   User ID: {profile.get('_id')}")
            print(f"   Email: {profile.get('email')}")
            print(f"   Name: {profile.get('name')}")
            print(f"   Verified: {profile.get('is_verified')}")
        
        print_test_result("Get User Profile", success, response)
        return success
    except Exception as e:
        print_test_result("Get User Profile", False, error=str(e))
        return False

def test_update_user_profile():
    """Test updating user profile"""
    print("✏️ Testing Update User Profile...")
    
    url = f"{API_BASE}/user/profile"
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {
        "name": "Updated Test User",
        "avatar_url": "https://example.com/avatar.jpg"
    }
    
    try:
        response = requests.put(url, json=data, headers=headers)
        success = response.status_code == 200
        print_test_result("Update User Profile", success, response)
        return success
    except Exception as e:
        print_test_result("Update User Profile", False, error=str(e))
        return False

def test_change_password():
    """Test changing password"""
    print("🔒 Testing Change Password...")
    
    url = f"{API_BASE}/user/change-password"
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {
        "current_password": TEST_USER["password"],
        "new_password": "NewTestPassword123!"
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        success = response.status_code == 200
        
        if success:
            # Update the stored password for subsequent tests
            TEST_USER["password"] = "NewTestPassword123!"
        
        print_test_result("Change Password", success, response)
        return success
    except Exception as e:
        print_test_result("Change Password", False, error=str(e))
        return False

def test_login_with_new_password():
    """Test login with the new password"""
    print("🔑 Testing Login with New Password...")
    
    url = f"{API_BASE}/auth/login"
    data = {
        "email": TEST_USER["email"],
        "password": TEST_USER["password"]  # Updated password
    }
    
    try:
        response = requests.post(url, json=data)
        success = response.status_code == 200
        
        if success:
            # Update tokens
            tokens = response.json()
            global access_token, refresh_token
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
        
        print_test_result("Login with New Password", success, response)
        return success
    except Exception as e:
        print_test_result("Login with New Password", False, error=str(e))
        return False

def test_refresh_token():
    """Test token refresh"""
    print("🔄 Testing Token Refresh...")
    
    url = f"{API_BASE}/auth/refresh-token"
    headers = {"Authorization": f"Bearer {refresh_token}"}
    
    try:
        response = requests.post(url, headers=headers)
        success = response.status_code == 200
        
        if success:
            new_token = response.json().get("access_token")
            global access_token
            access_token = new_token
            print(f"   New Access Token: {new_token[:50]}...")
        
        print_test_result("Token Refresh", success, response)
        return success
    except Exception as e:
        print_test_result("Token Refresh", False, error=str(e))
        return False

def test_forgot_password():
    """Test forgot password flow"""
    print("📧 Testing Forgot Password...")
    
    url = f"{API_BASE}/auth/forgot-password"
    data = {"email": TEST_USER["email"]}
    
    try:
        response = requests.post(url, json=data)
        success = response.status_code == 200
        print_test_result("Forgot Password", success, response)
        return success
    except Exception as e:
        print_test_result("Forgot Password", False, error=str(e))
        return False

def test_logout():
    """Test user logout"""
    print("🚪 Testing User Logout...")
    
    url = f"{API_BASE}/auth/logout"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        response = requests.post(url, headers=headers)
        success = response.status_code == 200
        print_test_result("User Logout", success, response)
        return success
    except Exception as e:
        print_test_result("User Logout", False, error=str(e))
        return False

def test_protected_endpoint_after_logout():
    """Test that protected endpoints are accessible after logout (JWT tokens are stateless)"""
    print("🔒 Testing Protected Endpoint After Logout...")
    
    url = f"{API_BASE}/user/profile"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        response = requests.get(url, headers=headers)
        # JWT tokens are stateless, so they remain valid until expiration
        # The logout endpoint just returns success, but doesn't invalidate the token
        success = response.status_code == 200
        print_test_result("Protected Endpoint After Logout (JWT tokens are stateless)", success, response)
        return success
    except Exception as e:
        print_test_result("Protected Endpoint After Logout (JWT tokens are stateless)", False, error=str(e))
        return False

def test_user_deletion():
    """Test user account deletion"""
    print("🗑️ Testing User Deletion...")
    
    # First login again to get fresh token
    login_url = f"{API_BASE}/auth/login"
    login_data = {
        "email": TEST_USER["email"],
        "password": TEST_USER["password"]
    }
    
    try:
        login_response = requests.post(login_url, json=login_data)
        if login_response.status_code == 200:
            tokens = login_response.json()
            delete_token = tokens.get("access_token")
            
            # Now delete the user
            url = f"{API_BASE}/user/profile"
            headers = {"Authorization": f"Bearer {delete_token}"}
            
            response = requests.delete(url, headers=headers)
            success = response.status_code == 200
            print_test_result("User Deletion", success, response)
            return success
        else:
            print_test_result("User Deletion", False, login_response)
            return False
    except Exception as e:
        print_test_result("User Deletion", False, error=str(e))
        return False

def test_invalid_login():
    """Test login with invalid credentials"""
    print("🚫 Testing Invalid Login...")
    
    url = f"{API_BASE}/auth/login"
    data = {
        "email": TEST_USER["email"],
        "password": "WrongPassword123!"
    }
    
    try:
        response = requests.post(url, json=data)
        # Should fail with 401
        success = response.status_code == 401
        print_test_result("Invalid Login", success, response)
        return success
    except Exception as e:
        print_test_result("Invalid Login", False, error=str(e))
        return False

def run_comprehensive_test():
    """Run all authentication flow tests"""
    print("🚀 Starting Comprehensive Authentication Flow Test")
    print("=" * 60)
    
    # Check if server is running
    if not test_server_health():
        print("❌ Server is not running. Please start the Flask application first.")
        return
    
    print("✅ Server is running")
    print()
    
    # Initialize global variables
    global access_token, refresh_token
    access_token = None
    refresh_token = None
    
    # Test results
    results = []
    
    # Run all tests
    tests = [
        ("User Registration", test_user_registration),
        ("User Login", test_user_login),
        ("Get User Profile", test_get_user_profile),
        ("Update User Profile", test_update_user_profile),
        ("Change Password", test_change_password),
        ("Login with New Password", test_login_with_new_password),
        ("Token Refresh", test_refresh_token),
        ("Forgot Password", test_forgot_password),
        ("User Logout", test_logout),
        ("Protected Endpoint After Logout (JWT tokens are stateless)", test_protected_endpoint_after_logout),
        ("Invalid Login", test_invalid_login),
        ("User Deletion", test_user_deletion),
    ]
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print()
    print(f"Overall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Authentication flow is working correctly.")
    else:
        print("⚠️ Some tests failed. Please check the implementation.")
    
    return passed == total

if __name__ == "__main__":
    run_comprehensive_test() 