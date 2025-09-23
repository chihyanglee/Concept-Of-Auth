"""
Database Models for Auth Server

This module defines the SQLAlchemy models that represent our authentication and authorization data.
Each model includes detailed comments explaining the purpose and security considerations.
"""

from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import hashlib
import base64

# Import database instance
from database import db

class User(db.Model):
    """
    User Model - Represents authenticated users in the system
    
    This model stores user credentials and role information. Key security considerations:
    - Passwords are NEVER stored in plain text, only hashed versions
    - Usernames must be unique to prevent conflicts
    - Roles determine what permissions a user has
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def __init__(self, username, password, role='user'):
        """
        Initialize a new user with hashed password
        
        Args:
            username (str): Unique username for the user
            password (str): Plain text password (will be hashed)
            role (str): User role (user, admin, etc.)
        """
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
    
    def check_password(self, password):
        """
        Verify a password against the stored hash
        
        Args:
            password (str): Plain text password to verify
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        """Convert user to dictionary for JSON serialization (excludes sensitive data)"""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Client(db.Model):
    """
    OAuth Client Model - Represents third-party applications that can authenticate users
    
    This model stores OAuth client credentials and configuration. Key concepts:
    - client_id: Public identifier for the application
    - client_secret: Secret key for confidential clients (must be kept secret)
    - redirect_uris: Allowed callback URLs for authorization flows
    - scopes: Permissions the client can request
    """
    __tablename__ = 'clients'
    
    client_id = db.Column(db.String(100), primary_key=True)
    client_secret = db.Column(db.String(255), nullable=False)
    redirect_uris = db.Column(db.Text)  # JSON string of allowed URIs
    scopes = db.Column(db.Text)  # Space-separated list of scopes
    client_name = db.Column(db.String(200))
    client_type = db.Column(db.String(50), default='confidential')  # confidential or public
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, client_id, client_secret, redirect_uris=None, scopes=None, 
                 client_name=None, client_type='confidential'):
        """
        Initialize a new OAuth client
        
        Args:
            client_id (str): Unique identifier for the client
            client_secret (str): Secret key for the client
            redirect_uris (str): Comma-separated list of allowed redirect URIs
            scopes (str): Space-separated list of allowed scopes
            client_name (str): Human-readable name for the client
            client_type (str): Type of client (confidential or public)
        """
        self.client_id = client_id
        self.client_secret = generate_password_hash(client_secret)  # Hash the secret
        self.redirect_uris = redirect_uris or ''
        self.scopes = scopes or ''
        self.client_name = client_name or client_id
        self.client_type = client_type
    
    def check_secret(self, secret):
        """Verify client secret"""
        return check_password_hash(self.client_secret, secret)
    
    def get_redirect_uris(self):
        """Get list of allowed redirect URIs"""
        if not self.redirect_uris:
            return []
        return [uri.strip() for uri in self.redirect_uris.split(',')]
    
    def get_scopes(self):
        """Get list of allowed scopes"""
        if not self.scopes:
            return []
        return [scope.strip() for scope in self.scopes.split(' ')]
    
    def is_valid_redirect_uri(self, uri):
        """Check if a redirect URI is allowed for this client"""
        return uri in self.get_redirect_uris()

class AuthorizationCode(db.Model):
    """
    Authorization Code Model - Stores temporary authorization codes for OAuth flow
    
    Authorization codes are short-lived tokens used in the OAuth 2.0 Authorization Code flow.
    They are exchanged for access tokens and must be used quickly to prevent replay attacks.
    """
    __tablename__ = 'authorization_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    client_id = db.Column(db.String(100), db.ForeignKey('clients.client_id'), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    scopes = db.Column(db.Text)  # Space-separated list of granted scopes
    code_challenge = db.Column(db.String(255))  # PKCE code challenge
    code_challenge_method = db.Column(db.String(10), default='S256')  # PKCE method
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, user_id, client_id, redirect_uri, scopes=None, 
                 code_challenge=None, code_challenge_method='S256'):
        """
        Initialize a new authorization code
        
        Args:
            user_id (int): ID of the user who authorized the client
            client_id (str): ID of the client requesting authorization
            redirect_uri (str): Redirect URI provided by the client
            scopes (str): Space-separated list of granted scopes
            code_challenge (str): PKCE code challenge (optional)
            code_challenge_method (str): PKCE method (S256 or plain)
        """
        self.code = secrets.token_urlsafe(32)  # Generate secure random code
        self.user_id = user_id
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scopes or ''
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.expires_at = datetime.utcnow() + timedelta(minutes=10)  # 10 minute expiry
    
    def is_expired(self):
        """Check if the authorization code has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        """Check if the code is valid (not expired and not used)"""
        return not self.is_expired() and not self.used
    
    def verify_pkce(self, code_verifier):
        """
        Verify PKCE code verifier against stored challenge
        
        PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks
        by requiring the client to prove it knows the code verifier that generated the challenge.
        
        Args:
            code_verifier (str): The code verifier from the client
            
        Returns:
            bool: True if verification succeeds, False otherwise
        """
        if not self.code_challenge:
            return True  # No PKCE required
        
        if self.code_challenge_method == 'S256':
            # SHA256 hash of code_verifier, base64url encoded
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip('=')
            return challenge == self.code_challenge
        elif self.code_challenge_method == 'plain':
            return code_verifier == self.code_challenge
        
        return False
    
    def mark_used(self):
        """Mark the authorization code as used"""
        self.used = True
        db.session.commit()

class TokenBlocklist(db.Model):
    """
    Token Blocklist Model - Stores revoked JWT tokens
    
    When users logout or tokens are revoked, we add them to this blocklist.
    This prevents revoked tokens from being used even if they haven't expired yet.
    We store the JTI (JWT ID) claim which uniquely identifies each token.
    """
    __tablename__ = 'token_blocklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(100), unique=True, nullable=False, index=True)
    token_type = db.Column(db.String(20), nullable=False)  # 'access' or 'refresh'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, jti, token_type, user_id, expires_at):
        """
        Initialize a new blocklist entry
        
        Args:
            jti (str): JWT ID claim from the token
            token_type (str): Type of token ('access' or 'refresh')
            user_id (int): ID of the user who owned the token
            expires_at (datetime): When the token would naturally expire
        """
        self.jti = jti
        self.token_type = token_type
        self.user_id = user_id
        self.expires_at = expires_at
    
    def is_expired(self):
        """Check if the blocked token has expired (can be cleaned up)"""
        return datetime.utcnow() > self.expires_at
    
    @staticmethod
    def is_token_blocked(jti):
        """
        Check if a token JTI is in the blocklist
        
        Args:
            jti (str): JWT ID to check
            
        Returns:
            bool: True if token is blocked, False otherwise
        """
        return TokenBlocklist.query.filter_by(jti=jti).first() is not None

class UserSession(db.Model):
    """
    User Session Model - Tracks active user sessions for session management
    
    This model helps implement session management features like:
    - Limiting concurrent logins per user
    - Tracking active sessions
    - Implementing "logout from all devices" functionality
    """
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    device_info = db.Column(db.String(200))  # Browser, device type, etc.
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def __init__(self, user_id, device_info=None, ip_address=None, expires_in_hours=24):
        """
        Initialize a new user session
        
        Args:
            user_id (int): ID of the user
            device_info (str): Information about the device/browser
            ip_address (str): IP address of the client
            expires_in_hours (int): Session duration in hours
        """
        self.user_id = user_id
        self.session_token = secrets.token_urlsafe(32)
        self.device_info = device_info
        self.ip_address = ip_address
        self.expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
    
    def is_expired(self):
        """Check if the session has expired"""
        return datetime.utcnow() > self.expires_at
    
    def update_activity(self):
        """Update the last activity timestamp"""
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    @staticmethod
    def get_active_sessions(user_id):
        """Get all active sessions for a user"""
        return UserSession.query.filter_by(
            user_id=user_id, 
            is_active=True
        ).filter(UserSession.expires_at > datetime.utcnow()).all()
    
    @staticmethod
    def revoke_all_sessions(user_id):
        """Revoke all active sessions for a user (logout from all devices)"""
        sessions = UserSession.query.filter_by(user_id=user_id, is_active=True).all()
        for session in sessions:
            session.is_active = False
        db.session.commit()


