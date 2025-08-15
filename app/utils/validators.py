"""
Validation utilities for SmartScope Backend
"""

import re

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False
    
    # Check minimum length
    if len(password) < 8:
        return False
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # Check for at least one digit
    if not re.search(r'\d', password):
        return False
    
    return True

def validate_name(name):
    """Validate user name"""
    if not name:
        return False
    
    # Check for minimum length
    if len(name.strip()) < 2:
        return False
    
    # Check for valid characters (letters, digits, spaces, hyphens, apostrophes)
    pattern = r'^[a-zA-Z0-9\s\-\']+$'
    return bool(re.match(pattern, name))

def validate_filename(filename):
    """Validate filename for security"""
    if not filename:
        return False
    
    # Check for dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\\', '/']
    for char in dangerous_chars:
        if char in filename:
            return False
    
    # Check for reserved names (Windows)
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                     'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                     'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    
    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        return False
    
    return True
