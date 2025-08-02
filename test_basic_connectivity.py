#!/usr/bin/env python3
"""
Basic Connectivity Test Script
Quick test to verify the server is running and basic endpoints are accessible.
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:9000"  # Docker container port
API_BASE = f"{BASE_URL}/api"

def test_server_connectivity():
    """Test basic server connectivity"""
    print("🔍 Testing Server Connectivity...")
    
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:100]}...")
        return True
    except requests.exceptions.ConnectionError:
        print("   ❌ Cannot connect to server")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_swagger_docs():
    """Test if Swagger documentation is accessible"""
    print("📚 Testing Swagger Documentation...")
    
    try:
        response = requests.get(f"{BASE_URL}/apidocs/")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Swagger docs accessible")
        else:
            print("   ⚠️ Swagger docs not accessible")
        return response.status_code == 200
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_health_endpoint():
    """Test if there's a health endpoint"""
    print("🏥 Testing Health Endpoint...")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Health endpoint accessible")
        else:
            print("   ⚠️ No health endpoint found")
        return response.status_code == 200
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_api_base():
    """Test API base endpoint"""
    print("🔌 Testing API Base...")
    
    try:
        response = requests.get(f"{API_BASE}/")
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 401, 404]:
            print("   ✅ API base accessible")
        else:
            print("   ⚠️ API base not accessible")
        return True
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_cors():
    """Test CORS headers"""
    print("🌐 Testing CORS Headers...")
    
    try:
        response = requests.options(f"{API_BASE}/auth/register")
        cors_headers = response.headers.get('Access-Control-Allow-Origin')
        print(f"   CORS Origin: {cors_headers}")
        if cors_headers:
            print("   ✅ CORS headers present")
        else:
            print("   ⚠️ No CORS headers found")
        return cors_headers is not None
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def run_basic_tests():
    """Run basic connectivity tests"""
    print("🚀 Starting Basic Connectivity Tests")
    print("=" * 50)
    
    tests = [
        ("Server Connectivity", test_server_connectivity),
        ("Swagger Documentation", test_swagger_docs),
        ("Health Endpoint", test_health_endpoint),
        ("API Base", test_api_base),
        ("CORS Headers", test_cors),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 BASIC TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print()
    print(f"Overall Result: {passed}/{total} tests passed")
    
    if passed >= 3:  # At least server connectivity and API base should work
        print("✅ Basic connectivity is working!")
        print("You can now run the comprehensive authentication tests.")
    else:
        print("❌ Basic connectivity issues detected.")
        print("Please check if the Flask server is running on localhost:5000")
    
    return passed >= 3

if __name__ == "__main__":
    run_basic_tests() 