"""
OAuth 2.0 and OpenID Connect Routes

This module implements Phase 2 of the PRD: Delegated Authorization
- Authorization Code Flow with PKCE
- Token Exchange
- UserInfo Endpoint
- Token Introspection
- Token Revocation

Each endpoint includes detailed comments explaining OAuth 2.0 and OIDC concepts.
"""

from flask import Blueprint, request, jsonify, redirect, url_for, render_template_string
from urllib.parse import urlencode, parse_qs, urlparse
from models import User, Client, AuthorizationCode, TokenBlocklist
from jwt_utils import create_access_token, create_refresh_token, create_id_token, verify_token, revoke_token, get_user_from_token
from database import db
import logging
import secrets
import hashlib
import base64

# Create blueprint for OAuth routes
oauth_bp = Blueprint('oauth', __name__)

logger = logging.getLogger(__name__)

# Simple HTML templates for OAuth flows
AUTHORIZATION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorize Application</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .app-info { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .scopes { background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .buttons { margin: 30px 0; }
        button { padding: 10px 20px; margin: 0 10px; border: none; border-radius: 5px; cursor: pointer; }
        .approve { background: #4CAF50; color: white; }
        .deny { background: #f44336; color: white; }
    </style>
</head>
<body>
    <h2>Authorize Application</h2>
    
    <div class="app-info">
        <h3>{{ client_name }}</h3>
        <p><strong>Client ID:</strong> {{ client_id }}</p>
        <p><strong>Redirect URI:</strong> {{ redirect_uri }}</p>
    </div>
    
    <div class="scopes">
        <h4>This application is requesting the following permissions:</h4>
        <ul>
            {% for scope in scopes %}
            <li><strong>{{ scope }}</strong> - {{ scope_descriptions.get(scope, 'No description available') }}</li>
            {% endfor %}
        </ul>
    </div>
    
    <p>Do you want to authorize this application?</p>
    
    <div class="buttons">
        <form method="POST" style="display: inline;">
            <input type="hidden" name="authorize" value="true">
            <input type="hidden" name="client_id" value="{{ client_id }}">
            <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
            <input type="hidden" name="state" value="{{ state }}">
            <input type="hidden" name="scopes" value="{{ ' '.join(scopes) }}">
            <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
            <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
            <button type="submit" class="approve">Authorize</button>
        </form>
        
        <form method="POST" style="display: inline;">
            <input type="hidden" name="authorize" value="false">
            <input type="hidden" name="client_id" value="{{ client_id }}">
            <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
            <input type="hidden" name="state" value="{{ state }}">
            <button type="submit" class="deny">Deny</button>
        </form>
    </div>
</body>
</html>
"""

@oauth_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """
    OAuth 2.0 Authorization Endpoint
    
    This endpoint implements the first step of the OAuth 2.0 Authorization Code flow.
    It handles user authentication and consent for third-party applications.
    
    OAuth 2.0 Flow:
    1. Client redirects user to this endpoint with client_id, redirect_uri, etc.
    2. User authenticates (if not already logged in)
    3. User grants/denies permission to the client
    4. Server redirects back to client with authorization code or error
    
    Security Features:
    - PKCE (Proof Key for Code Exchange) support for enhanced security
    - State parameter for CSRF protection
    - Scope validation
    - Redirect URI validation
    
    GET Parameters:
    - client_id: OAuth client identifier
    - redirect_uri: Where to redirect after authorization
    - response_type: Must be "code" for Authorization Code flow
    - scope: Space-separated list of requested permissions
    - state: CSRF protection token
    - code_challenge: PKCE code challenge (optional)
    - code_challenge_method: PKCE method (S256 or plain)
    
    Returns:
    - HTML form for user consent (GET)
    - Redirect to client with authorization code (POST - approve)
    - Redirect to client with error (POST - deny)
    """
    if request.method == 'GET':
        # Extract OAuth parameters
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type')
        scope = request.args.get('scope', '')
        state = request.args.get('state')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method', 'S256')
        
        # Validate required parameters
        if not all([client_id, redirect_uri, response_type]):
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Missing required parameters'
            }), 400
        
        if response_type != 'code':
            return jsonify({
                'error': 'unsupported_response_type',
                'error_description': 'Only authorization code flow is supported'
            }), 400
        
        # Validate client
        client = Client.query.get(client_id)
        if not client:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Unknown client'
            }), 400
        
        # Validate redirect URI
        if not client.is_valid_redirect_uri(redirect_uri):
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Invalid redirect URI'
            }), 400
        
        # Parse and validate scopes
        requested_scopes = [s.strip() for s in scope.split() if s.strip()]
        allowed_scopes = client.get_scopes()
        
        # Filter scopes to only include allowed ones
        granted_scopes = [s for s in requested_scopes if s in allowed_scopes]
        
        # Check if user is authenticated
        auth_header = request.headers.get('Authorization')
        current_user = None
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                payload = verify_token(token, 'access')
                if payload:
                    current_user = User.query.get(int(payload['sub']))
            except:
                pass
        
        # If not authenticated, redirect to login
        if not current_user:
            login_url = url_for('auth.login') + '?' + urlencode({
                'redirect_to': request.url
            })
            return redirect(login_url)
        
        # Scope descriptions for user understanding
        scope_descriptions = {
            'read': 'Read your basic profile information',
            'write': 'Modify your profile information',
            'openid': 'Authenticate you using OpenID Connect',
            'profile': 'Access your profile information',
            'email': 'Access your email address'
        }
        
        # Render authorization page
        return render_template_string(AUTHORIZATION_TEMPLATE,
            client_name=client.client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=granted_scopes,
            scope_descriptions=scope_descriptions,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
    
    else:  # POST - Handle user decision
        authorize = request.form.get('authorize') == 'true'
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        state = request.form.get('state')
        scopes = request.form.get('scopes', '')
        code_challenge = request.form.get('code_challenge')
        code_challenge_method = request.form.get('code_challenge_method', 'S256')
        
        # Get current user (should be authenticated at this point)
        auth_header = request.headers.get('Authorization')
        current_user = None
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                payload = verify_token(token, 'access')
                if payload:
                    current_user = User.query.get(int(payload['sub']))
            except:
                pass
        
        if not current_user:
            return jsonify({
                'error': 'access_denied',
                'error_description': 'User not authenticated'
            }), 401
        
        if not authorize:
            # User denied authorization
            error_params = {
                'error': 'access_denied',
                'error_description': 'User denied the request'
            }
            if state:
                error_params['state'] = state
            
            redirect_url = redirect_uri + '?' + urlencode(error_params)
            return redirect(redirect_url)
        
        # User approved authorization - create authorization code
        auth_code = AuthorizationCode(
            user_id=current_user.id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        
        db.session.add(auth_code)
        db.session.commit()
        
        logger.info(f"Authorization code created for user {current_user.username} and client {client_id}")
        
        # Redirect back to client with authorization code
        success_params = {
            'code': auth_code.code
        }
        if state:
            success_params['state'] = state
        
        redirect_url = redirect_uri + '?' + urlencode(success_params)
        return redirect(redirect_url)

@oauth_bp.route('/token', methods=['POST'])
def token():
    """
    OAuth 2.0 Token Endpoint
    
    This endpoint handles multiple OAuth 2.0 flows:
    1. Authorization Code Exchange (Authorization Code flow)
    2. Refresh Token Exchange
    3. Client Credentials Flow (Phase 3)
    
    The endpoint determines which flow to use based on the grant_type parameter.
    
    Authorization Code Exchange:
    - Exchanges authorization code for access token and refresh token
    - Validates PKCE code verifier if PKCE was used
    - Issues ID token if openid scope was requested
    
    Request Body (Authorization Code):
    {
        "grant_type": "authorization_code",
        "code": "authorization_code",
        "redirect_uri": "redirect_uri",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "code_verifier": "code_verifier"  // Required if PKCE was used
    }
    
    Request Body (Refresh Token):
    {
        "grant_type": "refresh_token",
        "refresh_token": "refresh_token",
        "client_id": "client_id",
        "client_secret": "client_secret"
    }
    
    Request Body (Client Credentials):
    {
        "grant_type": "client_credentials",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "scope": "scope1 scope2"
    }
    
    Returns:
    {
        "access_token": "jwt_token",
        "refresh_token": "jwt_token",  // Not for client_credentials
        "id_token": "jwt_token",       // Only if openid scope
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": "granted_scopes"
    }
    """
    try:
        data = request.get_json() or request.form.to_dict()
        grant_type = data.get('grant_type')
        
        if grant_type == 'authorization_code':
            return handle_authorization_code_exchange(data)
        elif grant_type == 'refresh_token':
            return handle_refresh_token_exchange(data)
        elif grant_type == 'client_credentials':
            return handle_client_credentials_flow(data)
        else:
            return jsonify({
                'error': 'unsupported_grant_type',
                'error_description': f'Grant type {grant_type} not supported'
            }), 400
            
    except Exception as e:
        logger.error(f"Token endpoint error: {str(e)}")
        return jsonify({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }), 500

def handle_authorization_code_exchange(data):
    """Handle authorization code exchange for access token"""
    code = data.get('code')
    redirect_uri = data.get('redirect_uri')
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    code_verifier = data.get('code_verifier')
    
    # Validate required parameters
    if not all([code, redirect_uri, client_id, client_secret]):
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }), 400
    
    # Validate client
    client = Client.query.get(client_id)
    if not client or not client.check_secret(client_secret):
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Invalid client credentials'
        }), 401
    
    # Find authorization code
    auth_code = AuthorizationCode.query.filter_by(code=code).first()
    if not auth_code or not auth_code.is_valid():
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid or expired authorization code'
        }), 400
    
    # Validate redirect URI
    if auth_code.redirect_uri != redirect_uri:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Redirect URI mismatch'
        }), 400
    
    # Validate PKCE if used
    if auth_code.code_challenge and not auth_code.verify_pkce(code_verifier):
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid code verifier'
        }), 400
    
    # Get user
    user = User.query.get(auth_code.user_id)
    if not user:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'User not found'
        }), 400
    
    # Mark authorization code as used
    auth_code.mark_used()
    
    # Parse granted scopes
    granted_scopes = auth_code.scopes.split() if auth_code.scopes else []
    
    # Generate tokens
    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        scopes=granted_scopes,
        client_id=client_id
    )
    
    refresh_token = create_refresh_token(
        user_id=user.id,
        client_id=client_id
    )
    
    response_data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 900,
        'scope': ' '.join(granted_scopes)
    }
    
    # Add ID token if openid scope was granted
    if 'openid' in granted_scopes:
        response_data['id_token'] = create_id_token(
            user_id=user.id,
            username=user.username,
            client_id=client_id
        )
    
    logger.info(f"Tokens issued for user {user.username} via client {client_id}")
    
    return jsonify(response_data), 200

def handle_refresh_token_exchange(data):
    """Handle refresh token exchange for new access token"""
    refresh_token = data.get('refresh_token')
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    
    if not all([refresh_token, client_id, client_secret]):
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }), 400
    
    # Validate client
    client = Client.query.get(client_id)
    if not client or not client.check_secret(client_secret):
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Invalid client credentials'
        }), 401
    
    # Verify refresh token
    payload = verify_token(refresh_token, 'refresh')
    if not payload:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'Invalid or expired refresh token'
        }), 400
    
    # Get user
    user_id = int(payload['sub'])
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'User not found'
        }), 400
    
    # Generate new access token
    new_access_token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        scopes=payload.get('scopes', []),
        client_id=client_id
    )
    
    return jsonify({
        'access_token': new_access_token,
        'token_type': 'Bearer',
        'expires_in': 900
    }), 200

def handle_client_credentials_flow(data):
    """Handle client credentials flow for machine-to-machine authentication"""
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    scope = data.get('scope', '')
    
    if not all([client_id, client_secret]):
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }), 400
    
    # Validate client
    client = Client.query.get(client_id)
    if not client or not client.check_secret(client_secret):
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Invalid client credentials'
        }), 401
    
    # Parse requested scopes
    requested_scopes = [s.strip() for s in scope.split() if s.strip()]
    allowed_scopes = client.get_scopes()
    
    # Filter scopes to only include allowed ones
    granted_scopes = [s for s in requested_scopes if s in allowed_scopes]
    
    # Generate access token for client (no user context)
    access_token = create_access_token(
        user_id=None,  # No user for client credentials
        username=client_id,
        role='client',
        scopes=granted_scopes,
        client_id=client_id
    )
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 900,
        'scope': ' '.join(granted_scopes)
    }), 200

@oauth_bp.route('/userinfo', methods=['GET'])
def userinfo():
    """
    OpenID Connect UserInfo Endpoint
    
    This endpoint returns claims about the authenticated user.
    It's part of the OpenID Connect specification and provides
    user identity information to clients.
    
    The endpoint validates the access token and returns user information
    based on the scopes granted to the client.
    
    Request Headers:
    Authorization: Bearer <access_token>
    
    Returns:
    {
        "sub": "user_id",
        "preferred_username": "username",
        "email": "email@example.com",
        "email_verified": true,
        "role": "user"
    }
    """
    # Extract access token
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Authorization header required'
        }), 401
    
    try:
        access_token = auth_header.split(' ')[1]
    except IndexError:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Invalid authorization header format'
        }), 401
    
    # Verify access token
    payload = verify_token(access_token, 'access')
    if not payload:
        return jsonify({
            'error': 'invalid_token',
            'error_description': 'Invalid or expired access token'
        }), 401
    
    # Get user information
    user_id = int(payload['sub'])
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({
            'error': 'invalid_token',
            'error_description': 'User not found'
        }), 401
    
    # Build userinfo response based on granted scopes
    userinfo_data = {
        'sub': str(user.id),  # Subject identifier
        'preferred_username': user.username
    }
    
    scopes = payload.get('scopes', [])
    
    if 'profile' in scopes:
        userinfo_data.update({
            'name': user.username,
            'updated_at': int(user.created_at.timestamp()) if user.created_at else None
        })
    
    if 'email' in scopes:
        userinfo_data.update({
            'email': f"{user.username}@example.com",  # Mock email
            'email_verified': True
        })
    
    # Add custom claims
    userinfo_data['role'] = user.role
    
    return jsonify(userinfo_data), 200

@oauth_bp.route('/introspect', methods=['POST'])
def introspect():
    """
    OAuth 2.0 Token Introspection Endpoint
    
    This endpoint allows clients to check the status and metadata of a token.
    It's useful for resource servers to validate tokens before processing requests.
    
    The endpoint returns information about the token including:
    - Whether the token is active
    - Token type and expiration
    - User information
    - Granted scopes
    
    Request Body:
    {
        "token": "token_to_introspect",
        "token_type_hint": "access"  // Optional hint
    }
    
    Returns:
    {
        "active": true,
        "scope": "read write",
        "client_id": "client_id",
        "username": "username",
        "exp": 1234567890,
        "iat": 1234567890,
        "sub": "user_id",
        "aud": "client_id",
        "iss": "auth-server",
        "token_type": "access"
    }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('token'):
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Token parameter is required'
            }), 400
        
        token = data['token']
        token_type_hint = data.get('token_type_hint', 'access')
        
        # Get token payload (without expiration check for introspection)
        payload = get_user_from_token(token)
        
        if not payload:
            return jsonify({'active': False}), 200
        
        # Check if token is blocked
        if TokenBlocklist.is_token_blocked(payload.get('jti')):
            return jsonify({'active': False}), 200
        
        # Check if token has expired
        import time
        current_time = int(time.time())
        if payload.get('exp', 0) < current_time:
            return jsonify({'active': False}), 200
        
        # Build introspection response
        response_data = {
            'active': True,
            'scope': ' '.join(payload.get('scopes', [])),
            'client_id': payload.get('client_id'),
            'username': payload.get('username'),
            'exp': payload.get('exp'),
            'iat': payload.get('iat'),
            'sub': payload.get('sub'),
            'aud': payload.get('aud'),
            'iss': payload.get('iss'),
            'token_type': payload.get('type', token_type_hint)
        }
        
        # Add user role if available
        if 'role' in payload:
            response_data['role'] = payload['role']
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Token introspection error: {str(e)}")
        return jsonify({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }), 500

@oauth_bp.route('/revoke', methods=['POST'])
def revoke():
    """
    OAuth 2.0 Token Revocation Endpoint
    
    This endpoint allows clients to revoke access or refresh tokens.
    Revoked tokens are added to the blocklist and cannot be used again.
    
    This is useful for:
    - Logout functionality
    - Security incidents
    - User-initiated token revocation
    
    Request Body:
    {
        "token": "token_to_revoke",
        "token_type_hint": "access"  // Optional hint
    }
    
    Returns:
    {
        "message": "Token revoked successfully"
    }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('token'):
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Token parameter is required'
            }), 400
        
        token = data['token']
        
        # Revoke the token
        if revoke_token(token):
            logger.info("Token revoked successfully")
            return jsonify({
                'message': 'Token revoked successfully'
            }), 200
        else:
            return jsonify({
                'error': 'invalid_token',
                'error_description': 'Invalid token'
            }), 400
            
    except Exception as e:
        logger.error(f"Token revocation error: {str(e)}")
        return jsonify({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }), 500
