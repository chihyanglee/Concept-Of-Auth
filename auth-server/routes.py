"""
Core Authentication Routes

This module implements Phase 1 of the PRD: Core User Authentication
- User Registration
- User Login  
- User Logout

Each endpoint includes detailed comments explaining the authentication concepts.
"""

from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import check_password_hash
from models import User, TokenBlocklist, UserSession
from jwt_utils import create_access_token, create_refresh_token, revoke_token, token_required, extract_bearer_token
from database import db
import logging

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# Configure logging for educational purposes
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    User Registration Endpoint
    
    This endpoint demonstrates the first step in user authentication:
    creating a user account with secure password storage.
    
    Security considerations:
    - Passwords are hashed using Werkzeug's secure hashing
    - Usernames must be unique to prevent conflicts
    - Input validation prevents common attacks
    
    Request Body:
    {
        "username": "string",
        "password": "string",
        "role": "string" (optional, defaults to "user")
    }
    
    Returns:
    {
        "message": "User registered successfully",
        "user": {
            "id": 1,
            "username": "testuser",
            "role": "user"
        }
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'error': 'Username and password are required'
            }), 400
        
        username = data['username'].strip()
        password = data['password']
        # New users always get the 'user' role. Only admins can elevate
        # roles via PUT /admin/users/<id>/role. Allowing callers to set
        # their own role here would completely bypass RBAC.
        role = 'user'
        
        # Basic validation
        if len(username) < 3:
            return jsonify({
                'error': 'Username must be at least 3 characters long'
            }), 400
        
        if len(password) < 6:
            return jsonify({
                'error': 'Password must be at least 6 characters long'
            }), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({
                'error': 'Username already exists'
            }), 409
        
        # Create new user
        # Note: The User model constructor automatically hashes the password
        user = User(username=username, password=password, role=role)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username} with role: {role}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({
            'error': 'Registration failed'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User Login Endpoint
    
    This endpoint demonstrates the core authentication process:
    1. Verify user credentials (username/password)
    2. Generate JWT tokens (access + refresh)
    3. Create user session for tracking
    
    The returned tokens contain:
    - Access Token: Short-lived token for API access (15 minutes)
    - Refresh Token: Long-lived token for getting new access tokens (7 days)
    
    Security considerations:
    - Passwords are verified using secure hashing
    - Tokens contain user identity and permissions
    - Session tracking enables logout from all devices
    
    Request Body:
    {
        "username": "string",
        "password": "string"
    }
    
    Returns:
    {
        "access_token": "jwt_token_string",
        "refresh_token": "jwt_token_string", 
        "token_type": "Bearer",
        "expires_in": 900,
        "user": {
            "id": 1,
            "username": "testuser",
            "role": "user"
        }
    }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'error': 'Username and password are required'
            }), 400
        
        username = data['username'].strip()
        password = data['password']
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({
                'error': 'Invalid username or password'
            }), 401
        
        # Update last login timestamp
        user.update_last_login()
        
        # Create user session for tracking
        device_info = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr
        user_session = UserSession(
            user_id=user.id,
            device_info=device_info,
            ip_address=ip_address
        )
        db.session.add(user_session)
        db.session.commit()
        
        # Generate JWT tokens
        # Access token contains user identity and permissions
        access_token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
            scopes=['read', 'write']  # Default scopes for direct login
        )
        
        # Refresh token is used to get new access tokens
        refresh_token = create_refresh_token(
            user_id=user.id
        )
        
        logger.info(f"User logged in successfully: {username}")
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        db.session.rollback()
        return jsonify({
            'error': 'Login failed'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    User Logout Endpoint
    
    This endpoint demonstrates secure logout by:
    1. Revoking the current access token (adding to blocklist)
    2. Revoking the refresh token
    3. Ending the user session
    
    Security considerations:
    - Tokens are added to a blocklist to prevent reuse
    - Both access and refresh tokens are revoked
    - Session is marked as inactive
    
    Request Headers:
    Authorization: Bearer <access_token>
    
    Request Body (optional):
    {
        "refresh_token": "string"  # If provided, will also revoke refresh token
    }
    
    Returns:
    {
        "message": "Logged out successfully"
    }
    """
    try:
        # Extract access token using the shared utility
        access_token = extract_bearer_token()
        if not access_token:
            return jsonify({
                'error': 'Authorization header with Bearer token required'
            }), 401
        
        # Revoke access token
        if not revoke_token(access_token):
            return jsonify({
                'error': 'Invalid access token'
            }), 401
        
        # Check if refresh token is provided in request body
        data = request.get_json() or {}
        refresh_token = data.get('refresh_token')
        
        if refresh_token:
            # Revoke refresh token as well
            revoke_token(refresh_token)
        
        # Get user ID from token to end session
        from jwt_utils import get_user_from_token
        token_payload = get_user_from_token(access_token)
        
        if token_payload:
            user_id = int(token_payload['sub'])
            
            # End the current session
            current_session = UserSession.query.filter_by(
                user_id=user_id,
                is_active=True
            ).order_by(UserSession.created_at.desc()).first()
            
            if current_session:
                current_session.is_active = False
                db.session.commit()
        
        logger.info(f"User logged out successfully")
        
        return jsonify({
            'message': 'Logged out successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({
            'error': 'Logout failed'
        }), 500

@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Token Refresh Endpoint
    
    This endpoint demonstrates token refresh functionality:
    1. Verify the refresh token
    2. Generate a new access token
    3. Optionally generate a new refresh token (rotation)
    
    This allows clients to maintain user sessions without requiring
    the user to log in again.
    
    Request Body:
    {
        "refresh_token": "string"
    }
    
    Returns:
    {
        "access_token": "new_jwt_token_string",
        "refresh_token": "new_jwt_token_string",  # Optional rotation
        "token_type": "Bearer",
        "expires_in": 900
    }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('refresh_token'):
            return jsonify({
                'error': 'Refresh token is required'
            }), 400
        
        refresh_token = data['refresh_token']
        
        # Verify refresh token
        from jwt_utils import verify_token
        payload = verify_token(refresh_token, 'refresh')
        
        if not payload:
            return jsonify({
                'error': 'Invalid or expired refresh token'
            }), 401
        
        # Get user information
        user_id = int(payload['sub'])
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        # Generate new access token
        new_access_token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
            scopes=['read', 'write']
        )
        
        # Optionally rotate refresh token for enhanced security
        rotate_refresh = data.get('rotate_refresh', False)
        new_refresh_token = None
        
        if rotate_refresh:
            new_refresh_token = create_refresh_token(user_id=user.id)
            # Revoke old refresh token
            revoke_token(refresh_token)
        
        response_data = {
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }
        
        if new_refresh_token:
            response_data['refresh_token'] = new_refresh_token
        
        logger.info(f"Token refreshed for user: {user.username}")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({
            'error': 'Token refresh failed'
        }), 500

@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user():
    """
    Get Current User Information

    This endpoint demonstrates how to extract user information from
    a valid access token. It's protected by the @token_required decorator,
    which validates the JWT and populates request.current_user.

    Request Headers:
    Authorization: Bearer <access_token>

    Returns:
    {
        "user": {
            "id": 1,
            "username": "testuser",
            "role": "user",
            "scopes": ["read", "write"]
        }
    }
    """
    return jsonify({
        'user': request.current_user
    }), 200
