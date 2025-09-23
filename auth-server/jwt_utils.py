"""
JWT Utilities and Authentication Decorators

This module provides utilities for creating, validating, and managing JWT tokens,
as well as decorators for protecting routes and extracting user information.
"""

import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from models import User, TokenBlocklist, UserSession

def create_access_token(user_id, username, role, scopes=None, client_id=None):
    """
    Create a JWT access token
    
    Access tokens are short-lived tokens that contain user identity and permissions.
    They are used by clients to access protected resources on behalf of the user.
    
    Args:
        user_id (int): ID of the user
        username (str): Username of the user
        role (str): Role of the user
        scopes (list): List of granted scopes/permissions
        client_id (str): ID of the client requesting the token
        
    Returns:
        str: Encoded JWT access token
    """
    now = datetime.utcnow()
    jti = secrets.token_urlsafe(32)  # Unique token identifier
    
    # Standard JWT claims
    payload = {
        'iss': 'auth-server',  # Issuer
        'sub': str(user_id),   # Subject (user ID)
        'aud': client_id or 'default',  # Audience
        'exp': now + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],  # Expiration
        'iat': now,  # Issued at
        'jti': jti,  # JWT ID (unique identifier)
        'type': 'access'  # Token type
    }
    
    # Custom claims for our application
    payload.update({
        'username': username,
        'role': role,
        'scopes': scopes or [],
        'client_id': client_id
    })
    
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

def create_refresh_token(user_id, client_id=None):
    """
    Create a JWT refresh token
    
    Refresh tokens are long-lived tokens used to obtain new access tokens
    without requiring the user to log in again.
    
    Args:
        user_id (int): ID of the user
        client_id (str): ID of the client
        
    Returns:
        str: Encoded JWT refresh token
    """
    now = datetime.utcnow()
    jti = secrets.token_urlsafe(32)
    
    payload = {
        'iss': 'auth-server',
        'sub': str(user_id),
        'aud': client_id or 'default',
        'exp': now + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
        'iat': now,
        'jti': jti,
        'type': 'refresh'
    }
    
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

def create_id_token(user_id, username, client_id, nonce=None):
    """
    Create an OpenID Connect ID token
    
    ID tokens are used in OpenID Connect flows to provide identity information
    about the authenticated user to the client application.
    
    Args:
        user_id (int): ID of the user
        username (str): Username of the user
        client_id (str): ID of the client
        nonce (str): Nonce value for replay protection
        
    Returns:
        str: Encoded JWT ID token
    """
    now = datetime.utcnow()
    jti = secrets.token_urlsafe(32)
    
    payload = {
        'iss': 'auth-server',
        'sub': str(user_id),
        'aud': client_id,
        'exp': now + timedelta(minutes=60),  # ID tokens typically expire in 1 hour
        'iat': now,
        'jti': jti,
        'type': 'id_token',
        'preferred_username': username,
        'email': f"{username}@example.com",  # Mock email for demo
        'email_verified': True
    }
    
    if nonce:
        payload['nonce'] = nonce
    
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')

def verify_token(token, token_type='access'):
    """
    Verify and decode a JWT token
    
    Args:
        token (str): The JWT token to verify
        token_type (str): Expected token type ('access', 'refresh', or 'id_token')
        
    Returns:
        dict: Decoded token payload if valid, None if invalid
    """
    try:
        # Decode the token
        payload = jwt.decode(
            token, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithms=['HS256']
        )
        
        # Check if token is blocked (revoked)
        if TokenBlocklist.is_token_blocked(payload.get('jti')):
            return None
        
        # Verify token type
        if payload.get('type') != token_type:
            return None
        
        return payload
        
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """
    Decorator to require a valid access token
    
    This decorator extracts the access token from the Authorization header,
    verifies it, and passes the user information to the decorated function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Access token is required'}), 401
        
        # Verify the token
        payload = verify_token(token, 'access')
        if not payload:
            return jsonify({'error': 'Invalid or expired access token'}), 401
        
        # Add user info to request context
        request.current_user = {
            'id': int(payload['sub']),
            'username': payload['username'],
            'role': payload['role'],
            'scopes': payload.get('scopes', []),
            'client_id': payload.get('client_id')
        }
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """
    Decorator to require admin role
    
    This decorator checks that the authenticated user has admin privileges.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user'):
            return jsonify({'error': 'Authentication required'}), 401
        
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    
    return decorated

def scope_required(required_scopes):
    """
    Decorator to require specific OAuth scopes
    
    Args:
        required_scopes (list): List of required scopes
        
    Returns:
        function: Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_scopes = request.current_user.get('scopes', [])
            
            # Check if user has all required scopes
            if not all(scope in user_scopes for scope in required_scopes):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_scopes': required_scopes,
                    'user_scopes': user_scopes
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator

def revoke_token(token):
    """
    Revoke a token by adding it to the blocklist
    
    Args:
        token (str): The JWT token to revoke
        
    Returns:
        bool: True if token was successfully revoked, False otherwise
    """
    try:
        # Decode token to get JTI and expiration
        payload = jwt.decode(
            token, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithms=['HS256'],
            options={'verify_exp': False}  # Don't verify expiration for revoked tokens
        )
        
        jti = payload.get('jti')
        user_id = int(payload.get('sub'))
        token_type = payload.get('type', 'access')
        exp_timestamp = payload.get('exp')
        
        if not jti or not exp_timestamp:
            return False
        
        # Convert expiration timestamp to datetime
        expires_at = datetime.fromtimestamp(exp_timestamp)
        
        # Add to blocklist
        blocklist_entry = TokenBlocklist(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires_at=expires_at
        )
        
        from database import db
        db.session.add(blocklist_entry)
        db.session.commit()
        
        return True
        
    except jwt.InvalidTokenError:
        return False

def get_user_from_token(token):
    """
    Extract user information from a token without verifying it
    
    This is useful for introspection endpoints where we want to return
    token information even if the token is expired or invalid.
    
    Args:
        token (str): The JWT token
        
    Returns:
        dict: Token payload or None if invalid
    """
    try:
        payload = jwt.decode(
            token, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithms=['HS256'],
            options={'verify_exp': False}  # Don't verify expiration
        )
        return payload
    except jwt.InvalidTokenError:
        return None
