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
        
        db.session.commit()
        app._tables_created = True

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


