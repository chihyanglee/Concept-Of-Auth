"""
Admin Routes

This module provides administrative endpoints for managing users, clients, and system information.
These endpoints are protected by admin role requirements and demonstrate RBAC concepts.
"""

from flask import Blueprint, request, jsonify
from models import User, Client, TokenBlocklist, UserSession, AuthorizationCode
from jwt_utils import token_required, admin_required
from database import db
import logging

# Create blueprint for admin routes
admin_bp = Blueprint('admin', __name__)

logger = logging.getLogger(__name__)

@admin_bp.route('/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    """
    List all users (Admin only)
    
    This endpoint demonstrates role-based access control (RBAC).
    Only users with admin role can access this endpoint.
    
    Returns:
    {
        "users": [
            {
                "id": 1,
                "username": "user1",
                "role": "user",
                "created_at": "2024-01-01T00:00:00",
                "last_login": "2024-01-01T12:00:00"
            }
        ]
    }
    """
    try:
        users = User.query.all()
        return jsonify({
            'users': [user.to_dict() for user in users]
        }), 200
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve users'
        }), 500

@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@token_required
@admin_required
def get_user(user_id):
    """
    Get specific user information (Admin only)
    
    Returns detailed information about a specific user.
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        return jsonify({
            'user': user.to_dict()
        }), 200
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve user'
        }), 500

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_user_role(user_id):
    """
    Update user role (Admin only)
    
    This endpoint demonstrates how RBAC can be dynamically managed.
    Admins can change user roles to grant or revoke permissions.
    
    Request Body:
    {
        "role": "admin"  // or "user"
    }
    
    Returns:
    {
        "message": "User role updated successfully",
        "user": {
            "id": 1,
            "username": "user1",
            "role": "admin"
        }
    }
    """
    try:
        data = request.get_json()
        if not data or not data.get('role'):
            return jsonify({
                'error': 'Role is required'
            }), 400
        
        new_role = data['role']
        if new_role not in ['user', 'admin']:
            return jsonify({
                'error': 'Invalid role. Must be "user" or "admin"'
            }), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        logger.info(f"User {user.username} role changed from {old_role} to {new_role} by admin {request.current_user['username']}")
        
        return jsonify({
            'message': 'User role updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating user role: {str(e)}")
        db.session.rollback()
        return jsonify({
            'error': 'Failed to update user role'
        }), 500

@admin_bp.route('/clients', methods=['GET'])
@token_required
@admin_required
def list_clients():
    """
    List all OAuth clients (Admin only)
    
    Returns information about all registered OAuth clients.
    """
    try:
        clients = Client.query.all()
        client_data = []
        
        for client in clients:
            client_data.append({
                'client_id': client.client_id,
                'client_name': client.client_name,
                'client_type': client.client_type,
                'redirect_uris': client.get_redirect_uris(),
                'scopes': client.get_scopes(),
                'created_at': client.created_at.isoformat() if client.created_at else None
            })
        
        return jsonify({
            'clients': client_data
        }), 200
    except Exception as e:
        logger.error(f"Error listing clients: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve clients'
        }), 500

@admin_bp.route('/clients', methods=['POST'])
@token_required
@admin_required
def create_client():
    """
    Create new OAuth client (Admin only)
    
    This endpoint allows admins to register new OAuth clients.
    
    Request Body:
    {
        "client_id": "new-client",
        "client_secret": "secret123",
        "client_name": "New Application",
        "redirect_uris": "http://localhost:3000/callback,https://app.example.com/callback",
        "scopes": "read write openid profile",
        "client_type": "confidential"
    }
    
    Returns:
    {
        "message": "Client created successfully",
        "client": {
            "client_id": "new-client",
            "client_name": "New Application",
            "redirect_uris": ["http://localhost:3000/callback"],
            "scopes": ["read", "write", "openid", "profile"]
        }
    }
    """
    try:
        data = request.get_json()
        
        required_fields = ['client_id', 'client_secret', 'client_name']
        if not all(field in data for field in required_fields):
            return jsonify({
                'error': 'Missing required fields: client_id, client_secret, client_name'
            }), 400
        
        client_id = data['client_id']
        
        # Check if client already exists
        if Client.query.get(client_id):
            return jsonify({
                'error': 'Client ID already exists'
            }), 409
        
        # Create new client
        client = Client(
            client_id=client_id,
            client_secret=data['client_secret'],
            client_name=data['client_name'],
            redirect_uris=data.get('redirect_uris', ''),
            scopes=data.get('scopes', ''),
            client_type=data.get('client_type', 'confidential')
        )
        
        db.session.add(client)
        db.session.commit()
        
        logger.info(f"New OAuth client created: {client_id} by admin {request.current_user['username']}")
        
        return jsonify({
            'message': 'Client created successfully',
            'client': {
                'client_id': client.client_id,
                'client_name': client.client_name,
                'client_type': client.client_type,
                'redirect_uris': client.get_redirect_uris(),
                'scopes': client.get_scopes()
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating client: {str(e)}")
        db.session.rollback()
        return jsonify({
            'error': 'Failed to create client'
        }), 500

@admin_bp.route('/sessions', methods=['GET'])
@token_required
@admin_required
def list_sessions():
    """
    List all active user sessions (Admin only)
    
    This endpoint shows all active user sessions across the system.
    Useful for monitoring and security purposes.
    """
    try:
        sessions = UserSession.query.filter_by(is_active=True).all()
        session_data = []
        
        for session in sessions:
            user = User.query.get(session.user_id)
            session_data.append({
                'id': session.id,
                'user_id': session.user_id,
                'username': user.username if user else 'Unknown',
                'device_info': session.device_info,
                'ip_address': session.ip_address,
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'expires_at': session.expires_at.isoformat()
            })
        
        return jsonify({
            'sessions': session_data
        }), 200
    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve sessions'
        }), 500

@admin_bp.route('/sessions/<int:user_id>/revoke-all', methods=['POST'])
@token_required
@admin_required
def revoke_all_user_sessions(user_id):
    """
    Revoke all sessions for a specific user (Admin only)
    
    This endpoint allows admins to force logout a user from all devices.
    Useful for security incidents or account management.
    
    Returns:
    {
        "message": "All sessions revoked for user"
    }
    """
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        UserSession.revoke_all_sessions(user_id)
        
        logger.info(f"All sessions revoked for user {user.username} by admin {request.current_user['username']}")
        
        return jsonify({
            'message': f'All sessions revoked for user {user.username}'
        }), 200
        
    except Exception as e:
        logger.error(f"Error revoking sessions: {str(e)}")
        return jsonify({
            'error': 'Failed to revoke sessions'
        }), 500

@admin_bp.route('/blocklist', methods=['GET'])
@token_required
@admin_required
def list_blocked_tokens():
    """
    List blocked tokens (Admin only)
    
    Shows all tokens that have been revoked and added to the blocklist.
    Useful for security monitoring and debugging.
    """
    try:
        blocked_tokens = TokenBlocklist.query.all()
        token_data = []
        
        for token in blocked_tokens:
            token_data.append({
                'jti': token.jti,
                'token_type': token.token_type,
                'user_id': token.user_id,
                'expires_at': token.expires_at.isoformat(),
                'revoked_at': token.revoked_at.isoformat(),
                'is_expired': token.is_expired()
            })
        
        return jsonify({
            'blocked_tokens': token_data
        }), 200
    except Exception as e:
        logger.error(f"Error listing blocked tokens: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve blocked tokens'
        }), 500

@admin_bp.route('/stats', methods=['GET'])
@token_required
@admin_required
def get_system_stats():
    """
    Get system statistics (Admin only)
    
    Returns various statistics about the auth server for monitoring purposes.
    """
    try:
        stats = {
            'total_users': User.query.count(),
            'total_clients': Client.query.count(),
            'active_sessions': UserSession.query.filter_by(is_active=True).count(),
            'blocked_tokens': TokenBlocklist.query.count(),
            'pending_auth_codes': AuthorizationCode.query.filter_by(used=False).count()
        }
        
        return jsonify({
            'stats': stats
        }), 200
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve system statistics'
        }), 500
