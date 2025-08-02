# Authentication Flow Testing

This directory contains comprehensive test scripts to verify that all authentication and user management functionality is working correctly.

## 🚀 Quick Start

### 1. Start the Flask Server
First, make sure your Flask application is running:

```bash
python app_main.py
```

The server should start on `http://localhost:9000` (Docker container)

### 2. Run Basic Connectivity Tests
Test if the server is running and accessible:

```bash
python test_basic_connectivity.py
```

This will check:
- ✅ Server connectivity
- ✅ Swagger documentation
- ✅ API base endpoints
- ✅ CORS headers

### 3. Run Comprehensive Authentication Tests

#### Option A: Basic Test Script
```bash
python3 test_auth_flow.py
```

#### Option B: Professional Pytest Suite (Recommended)
First, install pytest dependencies:
```bash
pip install -r requirements-test.txt
```

Then run the pytest suite:
```bash
# Run all tests
pytest test_auth_pytest.py -v

# Run with HTML report
pytest test_auth_pytest.py --html=report.html --self-contained-html

# Run with coverage
pytest test_auth_pytest.py --cov=. --cov-report=html

# Run specific test class
pytest test_auth_pytest.py::TestAuthentication -v

# Run specific test
pytest test_auth_pytest.py::TestAuthentication::test_user_registration -v
```

## 📋 What the Tests Cover

### Basic Connectivity Tests (`test_basic_connectivity.py`)
- Server connectivity
- Swagger documentation access
- API base endpoint accessibility
- CORS headers verification

### Basic Test Script (`test_auth_flow.py`)
- ✅ User registration
- ✅ User login with JWT tokens
- ✅ Get user profile
- ✅ Update user profile
- ✅ Change password
- ✅ Login with new password
- ✅ Token refresh
- ✅ Forgot password flow
- ✅ User logout
- ✅ Protected endpoint access after logout
- ✅ Invalid login attempts
- ✅ User account deletion

### Professional Pytest Suite (`test_auth_pytest.py`)
- ✅ **TestAuthentication Class**: Complete authentication flow
- ✅ **TestAuthenticationErrors Class**: Error handling and validation
- ✅ **TestAPIEndpoints Class**: API accessibility and CORS
- ✅ **Fixtures**: Reusable test data and setup
- ✅ **Proper Assertions**: Detailed failure messages
- ✅ **Test Isolation**: Independent test execution
- ✅ **HTML Reports**: Professional test reporting
- ✅ **Coverage Reports**: Code coverage analysis

## 🔧 Test Configuration

### Server Configuration
- **Base URL**: `http://localhost:9000` (Docker container)
- **API Base**: `http://localhost:9000/api`
- **Test User**: Automatically generated with timestamp

### Test User Data
The test script creates a unique test user for each run:
- **Email**: `testuser_{timestamp}@example.com`
- **Password**: `TestPassword123!`
- **Name**: `Test User`

## 📊 Expected Results

### Basic Connectivity Tests
All tests should pass if the server is running correctly:
- ✅ Server Connectivity
- ✅ Swagger Documentation
- ✅ API Base
- ✅ CORS Headers

### Comprehensive Authentication Tests
All 12 tests should pass for a fully functional authentication system:
- ✅ User Registration
- ✅ User Login
- ✅ Get User Profile
- ✅ Update User Profile
- ✅ Change Password
- ✅ Login with New Password
- ✅ Token Refresh
- ✅ Forgot Password
- ✅ User Logout
- ✅ Protected Endpoint After Logout
- ✅ Invalid Login
- ✅ User Deletion

## 🐛 Troubleshooting

### Common Issues

1. **Server Not Running**
   ```
   ❌ Server is not running. Please start the Flask application first.
   ```
   **Solution**: Start the Flask server with `python app_main.py`

2. **Connection Refused**
   ```
   ❌ Cannot connect to server
   ```
   **Solution**: Check if the server is running on the correct port (9000)

3. **MongoDB Connection Issues**
   ```
   ❌ Database connection failed
   ```
   **Solution**: Ensure MongoDB is running and accessible

4. **JWT Token Issues**
   ```
   ❌ Invalid or expired token
   ```
   **Solution**: Check JWT configuration in `app_main.py`

### Debug Mode
To see detailed error messages, run the Flask server in debug mode:

```bash
export FLASK_ENV=development
python app_main.py
```

## 📝 Test Output Example

```
🚀 Starting Comprehensive Authentication Flow Test
============================================================
✅ Server is running

🔐 Testing User Registration...
✅ PASS User Registration
   Status: 201
   Response: {'message': 'Registration successful. Account is ready to use.'}

🔑 Testing User Login...
✅ PASS User Login
   Status: 200
   Response: {'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...', 'refresh_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'}

...

============================================================
📊 TEST SUMMARY
============================================================
✅ PASS User Registration
✅ PASS User Login
✅ PASS Get User Profile
✅ PASS Update User Profile
✅ PASS Change Password
✅ PASS Login with New Password
✅ PASS Token Refresh
✅ PASS Forgot Password
✅ PASS User Logout
✅ PASS Protected Endpoint After Logout
✅ PASS Invalid Login
✅ PASS User Deletion

Overall Result: 12/12 tests passed
🎉 All tests passed! Authentication flow is working correctly.
```

## 🔄 Running Tests Multiple Times

The test scripts are designed to be run multiple times safely:
- Each run creates a unique test user
- Previous test users are cleaned up automatically
- No conflicts between test runs

## 📚 Additional Notes

- **Email Verification**: Currently disabled for development (as configured)
- **Rate Limiting**: Login is rate-limited to 5 attempts per minute
- **Password Requirements**: Minimum 8 characters with uppercase, lowercase, and number
- **JWT Tokens**: Access tokens for API calls, refresh tokens for renewal

## 🛠️ Customization

To test with different configurations:

1. **Change Server URL**: Modify `BASE_URL` in test scripts
2. **Test Different Users**: Modify `TEST_USER` data
3. **Add Custom Tests**: Extend the test functions in `test_auth_flow.py`
4. **Test Specific Endpoints**: Create focused test functions

## 📞 Support

If tests fail, check:
1. Flask server is running
2. MongoDB is accessible
3. All dependencies are installed
4. Network connectivity to localhost:9000 