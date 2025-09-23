"""
Swagger/OpenAPI Configuration

This module configures Swagger UI for interactive API documentation.
It provides a comprehensive view of all authentication and authorization endpoints.
"""

from flasgger import Swagger, swag_from
from flask import Flask

def configure_swagger(app: Flask):
    """
    Configure Swagger UI for the Flask application
    
    This creates an interactive API documentation interface at /api/docs
    that allows users to explore and test all authentication endpoints.
    """
    
    # Swagger configuration
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs"
    }
    
    # Swagger template with API information
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Auth Server API",
            "description": """
            # Educational Authentication and Authorization Server
            
            This API demonstrates comprehensive authentication and authorization concepts including:
            
            ## Core Authentication (Phase 1)
            - User registration and login
            - JWT-based session management
            - Secure logout with token revocation
            
            ## OAuth 2.0 & OpenID Connect (Phase 2)
            - Authorization Code flow with PKCE
            - Token exchange and refresh
            - UserInfo endpoint for identity information
            - Token introspection and revocation
            
            ## Client Credentials Flow (Phase 3)
            - Machine-to-machine authentication
            - Service-to-service communication
            
            ## Role-Based Access Control (Phase 4)
            - Admin endpoints for user management
            - Role-based permissions
            - Token claims for downstream services
            
            ## Advanced Security Features
            - PKCE (Proof Key for Code Exchange)
            - Token introspection for validation
            - Session management and concurrent login handling
            - Comprehensive token revocation
            
            ## Learning Concepts Covered
            - **Authentication vs Authorization**: Clear separation of identity verification and permission checking
            - **JWT Structure**: Understanding access tokens, refresh tokens, and ID tokens
            - **OAuth 2.0 Flows**: Authorization Code, Client Credentials, and PKCE
            - **OpenID Connect**: Identity layer on top of OAuth 2.0
            - **Security Best Practices**: Token expiration, revocation, and secure storage
            - **RBAC Implementation**: Role and permission management in tokens
            
            ## Default Credentials
            - **Admin User**: username: `admin`, password: `admin123`
            - **Demo Client**: client_id: `demo-client`, client_secret: `demo-secret`
            """,
            "version": "1.0.0",
            "contact": {
                "name": "Auth Server",
                "email": "admin@example.com"
            }
        },
        "host": "localhost:5000",
        "basePath": "/",
        "schemes": ["http", "https"],
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ],
        "tags": [
            {
                "name": "Authentication",
                "description": "Core user authentication endpoints"
            },
            {
                "name": "OAuth 2.0",
                "description": "OAuth 2.0 and OpenID Connect endpoints"
            },
            {
                "name": "Admin",
                "description": "Administrative endpoints (admin role required)"
            }
        ]
    }
    
    # Initialize Swagger
    swagger = Swagger(app, config=swagger_config, template=swagger_template)
    
    return swagger
