import os
from datetime import datetime, timedelta
from flask import Flask
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth_server.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  # Short-lived access tokens
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)    # Longer-lived refresh tokens

# Initialize extensions
from database import db
db.init_app(app)
CORS(app)

# Import models after db initialization
from models import User, Client, TokenBlocklist, AuthorizationCode, UserSession

# Import routes after models are defined
from routes import auth_bp
from oauth_routes import oauth_bp
from admin_routes import admin_bp
from swagger_config import configure_swagger

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(oauth_bp, url_prefix='/oauth')
app.register_blueprint(admin_bp, url_prefix='/admin')

# Configure Swagger documentation
configure_swagger(app)

@app.before_request
def create_tables():
    """Create database tables and seed initial data"""
    if not hasattr(app, '_tables_created'):
        db.create_all()
        
        # Create default admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password='admin123',  # Will be hashed by User constructor
                role='admin'
            )
            db.session.add(admin_user)
        
        # Create example OAuth client for testing
        if not Client.query.filter_by(client_id='demo-client').first():
            demo_client = Client(
                client_id='demo-client',
                client_secret='demo-secret',
                redirect_uris='http://localhost:3000/callback',
                scopes='read write openid profile',
                client_name='Demo Application'
            )
            db.session.add(demo_client)

        # ──────────────────────────────────────────────────────────────
        # Task Client App (task-client)
        # ──────────────────────────────────────────────────────────────
        # This is a "confidential client" — a server-side web application
        # that can securely store its client_secret. It uses the
        # Authorization Code flow to authenticate users via the auth server
        # and obtain access tokens on their behalf.
        #
        # - redirect_uris: where the auth server sends the user back after
        #   they approve the login. Must match exactly what the client sends
        #   in the authorization request (prevents open-redirect attacks).
        # - scopes: the permissions this client is allowed to request.
        #   'openid profile email' are standard OIDC scopes for identity,
        #   'read write' are resource-level scopes for the Task API.
        # ──────────────────────────────────────────────────────────────
        if not Client.query.filter_by(client_id='task-client').first():
            task_client = Client(
                client_id='task-client',
                client_secret='task-client-secret',
                redirect_uris='http://localhost:5001/callback',
                scopes='read write openid profile email',
                client_name='Task Manager App'
            )
            db.session.add(task_client)

        # ──────────────────────────────────────────────────────────────
        # Task Resource Service (task-service)
        # ──────────────────────────────────────────────────────────────
        # This is a machine-to-machine (M2M) client that represents the
        # Task Resource API itself. It uses the Client Credentials grant
        # — no user is involved, so there is no redirect_uri.
        #
        # Why does an API need its own client registration?
        # The resource server may need to call the auth server's
        # introspection or JWKS endpoints to validate tokens, or it may
        # need its own access token to call other services. Registering
        # it as a client gives it an identity the auth server recognises.
        #
        # - redirect_uris is empty because Client Credentials never
        #   redirects a browser — it is a direct back-channel exchange.
        # - scopes are limited to 'read write' (no OIDC scopes needed
        #   because there is no end-user identity involved).
        # ──────────────────────────────────────────────────────────────
        if not Client.query.filter_by(client_id='task-service').first():
            task_service = Client(
                client_id='task-service',
                client_secret='task-service-secret',
                redirect_uris='',
                scopes='read write',
                client_name='Task Resource Service'
            )
            db.session.add(task_service)

        db.session.commit()
        app._tables_created = True

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


