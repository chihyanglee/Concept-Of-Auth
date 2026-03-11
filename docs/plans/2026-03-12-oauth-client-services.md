# OAuth Client Services Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build two services (Task Client App + Task Resource API) that consume the existing auth server to demonstrate all OAuth 2.0 and OIDC flows in practice.

**Architecture:** Task Client App (port 5001) is a Flask web app with UI that performs OAuth authorization code flow with PKCE against the auth server (port 5000), then uses the obtained tokens to call the Task Resource API (port 5002). The Resource API validates JWTs and enforces scope-based permissions.

**Tech Stack:** Flask, SQLAlchemy, PyJWT, requests. uv for package management. SQLite for storage.

**IMPORTANT:** All code must be heavily commented explaining the auth concepts at play. This is a learning project.

---

### Task 1: Register Task Client and Task Service in Auth Server

**Files:**
- Modify: `auth-server/app.py:54-66`

**Step 1: Add the Task Client and Task Service as OAuth clients in the auth server seed data**

In `auth-server/app.py`, after the existing demo-client registration (line 63), add:

```python
        # Register the Task Client App as an OAuth client
        # This is what happens when a third-party app registers with an auth provider
        # (like registering your app with Google OAuth)
        if not Client.query.filter_by(client_id='task-client').first():
            task_client = Client(
                client_id='task-client',
                client_secret='task-client-secret',
                redirect_uris='http://localhost:5001/callback',
                scopes='read write openid profile email',
                client_name='Task Manager App'
            )
            db.session.add(task_client)

        # Register the Task Resource API as a client for client_credentials flow
        # This demonstrates machine-to-machine auth — the service authenticates
        # as itself (not on behalf of a user) to perform background operations
        if not Client.query.filter_by(client_id='task-service').first():
            task_service = Client(
                client_id='task-service',
                client_secret='task-service-secret',
                redirect_uris='',  # No redirect needed for client_credentials
                scopes='read write',
                client_name='Task Resource Service'
            )
            db.session.add(task_service)
```

**Step 2: Delete the existing auth server database to pick up new seed data**

Run: `rm -f auth-server/instance/auth_server.db`

**Step 3: Verify by starting auth server**

Run: `cd auth-server && uv run python app.py &`
Then: `curl -s http://localhost:5000/api/docs | head -5`
Expected: Swagger UI HTML
Kill: the background process

**Step 4: Commit**

```bash
git add auth-server/app.py
git commit -m "feat: register task-client and task-service OAuth clients in auth server seed data"
```

---

### Task 2: Scaffold Task Resource API

**Files:**
- Create: `task-resource-api/pyproject.toml`
- Create: `task-resource-api/database.py`
- Create: `task-resource-api/models.py`
- Create: `task-resource-api/app.py`

**Step 1: Create pyproject.toml**

Create `task-resource-api/pyproject.toml`:

```toml
[project]
name = "task-resource-api"
version = "0.1.0"
description = "Task Resource API - demonstrates JWT validation and scope enforcement as an OAuth resource server"
requires-python = ">=3.11"
dependencies = [
    "flask>=3.0.0",
    "flask-sqlalchemy>=3.1.0",
    "flask-cors>=4.0.0",
    "pyjwt>=2.8.0",
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**Step 2: Create database.py**

Create `task-resource-api/database.py`:

```python
"""
Database Setup for Task Resource API

This is a separate database from the auth server.
In a real microservices architecture, each service owns its own data.
The auth server manages identities; this service manages tasks.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
```

**Step 3: Create models.py**

Create `task-resource-api/models.py`:

```python
"""
Task Model for the Resource API

This model stores tasks that belong to users. Notice that we don't store
any user details here — we only store the user_id (the 'sub' claim from
the JWT). The auth server is the source of truth for user identity.

This separation is a key microservices pattern:
- Auth server owns: who the user is, what they can do
- Resource server owns: the user's data (tasks)
- They're connected by the user_id in the JWT's 'sub' claim
"""

from datetime import datetime
from database import db


class Task(db.Model):
    """
    Task Model

    Each task belongs to a user, identified by user_id.
    The user_id comes from the JWT 'sub' (subject) claim — we never
    ask users to provide their ID directly, because the JWT is the
    trusted source of identity.
    """

    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)

    # The user who owns this task.
    # This value comes from the JWT 'sub' claim, NOT from user input.
    # This ensures users can only see/modify their own tasks.
    user_id = db.Column(db.String(50), nullable=False, index=True)

    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert task to dictionary for JSON response"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "completed": self.completed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
```

**Step 4: Create app.py with JWT validation and scope enforcement**

Create `task-resource-api/app.py`:

```python
"""
Task Resource API — An OAuth 2.0 Resource Server

This service demonstrates what happens on the OTHER side of OAuth:
- The auth server issues tokens
- This service VALIDATES those tokens and enforces permissions

Key concepts demonstrated:
1. JWT self-validation: verifying the token signature without calling the auth server
2. Token introspection: asking the auth server to validate a token (alternative approach)
3. Scope enforcement: checking that the token has the required permissions
4. User scoping: using the JWT 'sub' claim to isolate user data
5. Client credentials: service-to-service authentication for background tasks

IMPORTANT: This service shares the JWT_SECRET_KEY with the auth server.
In production with HS256, this means both services must know the secret.
With RS256, only the auth server would have the private key, and this
service would verify using the public key (much better for microservices).
"""

import os
import logging
from datetime import datetime
from functools import wraps

import jwt
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

from database import db
from models import Task

# ============================================================
# App Configuration
# ============================================================

app = Flask(__name__)

# Database: separate from auth server — each service owns its data
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///tasks.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT secret must match the auth server's secret.
# In a real system with HS256, this is a security concern — if this
# service is compromised, the attacker can forge tokens.
# RS256 solves this: the resource server only needs the PUBLIC key.
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "jwt-secret-key-change-in-production"
)

# Auth server URL for token introspection and client credentials
app.config["AUTH_SERVER_URL"] = os.environ.get(
    "AUTH_SERVER_URL", "http://localhost:5000"
)

# Client credentials for service-to-service auth (client credentials flow)
# These are this service's own credentials, registered at the auth server
app.config["SERVICE_CLIENT_ID"] = "task-service"
app.config["SERVICE_CLIENT_SECRET"] = "task-service-secret"

db.init_app(app)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# JWT Validation — The Core of a Resource Server
# ============================================================
# A resource server's primary job is to validate access tokens.
# There are two approaches:
#
# 1. Self-validation (used here by default):
#    - Decode the JWT and verify the signature locally
#    - Fast: no network call needed
#    - Trade-off: can't check if the token was revoked (blocklisted)
#
# 2. Token introspection (also demonstrated here):
#    - Call the auth server's /oauth/introspect endpoint
#    - Slower: requires a network call per request
#    - Benefit: auth server checks the blocklist, so revoked tokens are rejected
#
# In production, you'd typically use self-validation for speed and
# accept the small window where a revoked token might still work
# (until it expires naturally). For high-security operations,
# you'd use introspection.
# ============================================================


def validate_token_locally(token):
    """
    Self-validate a JWT by verifying its signature locally.

    This is the fast path: no network call to the auth server.
    We decode the JWT using the shared secret key and verify:
    1. The signature is valid (token wasn't tampered with)
    2. The token hasn't expired
    3. The token type is 'access' (not a refresh or ID token)

    Limitation: we can't check if the token was revoked (blocklisted)
    because the blocklist lives in the auth server's database.

    Args:
        token: The JWT access token string

    Returns:
        dict: The decoded token payload, or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )

        # Ensure this is an access token, not a refresh token or ID token.
        # Without this check, someone could use a refresh token (which has
        # a much longer expiry) to access resources.
        if payload.get("type") != "access":
            logger.warning("Rejected non-access token type: %s", payload.get("type"))
            return None

        return payload

    except jwt.ExpiredSignatureError:
        logger.info("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token: %s", str(e))
        return None


def validate_token_via_introspection(token):
    """
    Validate a token by calling the auth server's introspection endpoint.

    This is the thorough path: the auth server checks everything including
    the blocklist. Use this for high-security operations where you need
    to ensure the token hasn't been revoked.

    OAuth 2.0 Token Introspection is defined in RFC 7662.
    The auth server returns {"active": true/false} along with token metadata.

    Args:
        token: The JWT access token string

    Returns:
        dict: The introspection response, or None if token is inactive
    """
    try:
        response = requests.post(
            f"{app.config['AUTH_SERVER_URL']}/oauth/introspect",
            json={"token": token, "token_type_hint": "access"},
            timeout=5,
        )

        if response.status_code != 200:
            logger.warning("Introspection request failed: %s", response.status_code)
            return None

        data = response.json()

        # The introspection response has an 'active' field.
        # If false, the token is invalid, expired, or revoked.
        if not data.get("active"):
            logger.info("Token is not active (expired or revoked)")
            return None

        return data

    except requests.RequestException as e:
        logger.error("Introspection request error: %s", str(e))
        return None


# ============================================================
# Authentication & Authorization Decorators
# ============================================================


def require_token(f):
    """
    Decorator: Require a valid access token.

    This is the resource server equivalent of auth server's @token_required.
    It extracts the Bearer token from the Authorization header and validates it.

    The validated token payload is attached to the request as request.token_payload
    so that route handlers can access user identity (sub) and permissions (scopes).

    Uses self-validation by default for performance.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract the token from the Authorization header.
        # OAuth 2.0 requires the format: "Bearer <token>"
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header required"}), 401

        try:
            scheme, token = auth_header.split(" ", 1)
            if scheme.lower() != "bearer":
                return jsonify({"error": "Bearer token required"}), 401
        except ValueError:
            return jsonify({"error": "Invalid Authorization header format"}), 401

        # Validate the token.
        # Default: self-validation (fast, but can't check blocklist)
        # To use introspection instead, the client can pass
        # ?introspect=true query parameter (for demonstration purposes)
        if request.args.get("introspect") == "true":
            payload = validate_token_via_introspection(token)
        else:
            payload = validate_token_locally(token)

        if not payload:
            return jsonify({"error": "Invalid or expired access token"}), 401

        # Attach the token payload to the request context.
        # Route handlers use this to:
        # - Get user ID: request.token_payload['sub']
        # - Check scopes: request.token_payload['scopes']
        request.token_payload = payload

        return f(*args, **kwargs)

    return decorated


def require_scope(*required_scopes):
    """
    Decorator: Require specific OAuth scopes.

    Scopes are the OAuth mechanism for limiting what a client can do.
    Even if the user has admin privileges, a client app can only do
    what its scopes allow.

    Example:
        @require_scope('read')      — needs 'read' scope
        @require_scope('read', 'write') — needs BOTH scopes

    Args:
        required_scopes: One or more scope strings that must ALL be present
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get the scopes from the validated token.
            # These were set when the token was issued, based on what
            # the user consented to in the OAuth authorization flow.
            token_scopes = request.token_payload.get("scopes", [])

            # For introspection responses, scopes come as a space-separated string
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()

            # Check that ALL required scopes are present.
            # This is an AND check — the token must have every listed scope.
            missing = [s for s in required_scopes if s not in token_scopes]
            if missing:
                return (
                    jsonify(
                        {
                            "error": "Insufficient scope",
                            "required": list(required_scopes),
                            "granted": token_scopes,
                            "missing": missing,
                        }
                    ),
                    403,
                )

            return f(*args, **kwargs)

        return decorated

    return decorator


# ============================================================
# Task Endpoints — Protected by OAuth tokens and scopes
# ============================================================


@app.route("/tasks", methods=["GET"])
@require_token
@require_scope("read")
def list_tasks():
    """
    List the authenticated user's tasks.

    This endpoint demonstrates user data isolation:
    - The user_id comes from the JWT 'sub' claim (set by the auth server)
    - We NEVER trust user-provided IDs for data access
    - Each user can only see their own tasks

    Requires: valid access token with 'read' scope
    """
    # Get the user ID from the token's 'sub' (subject) claim.
    # This is the user ID assigned by the auth server — it's trusted
    # because the JWT signature proves the auth server issued it.
    user_id = request.token_payload.get("sub")

    tasks = Task.query.filter_by(user_id=user_id).all()

    logger.info("User %s listed %d tasks", user_id, len(tasks))

    return jsonify({"tasks": [task.to_dict() for task in tasks]}), 200


@app.route("/tasks", methods=["POST"])
@require_token
@require_scope("write")
def create_task():
    """
    Create a new task for the authenticated user.

    The task's user_id is automatically set from the JWT — the client
    can't create tasks for other users, even if they try to pass a
    different user_id in the request body.

    Requires: valid access token with 'write' scope
    """
    data = request.get_json()

    if not data or not data.get("title"):
        return jsonify({"error": "Title is required"}), 400

    # user_id comes from the token, NOT from the request body.
    # This is a critical security pattern: never trust the client
    # to tell you who they are — the token tells you.
    user_id = request.token_payload.get("sub")

    task = Task(
        user_id=user_id,
        title=data["title"],
        completed=data.get("completed", False),
    )

    db.session.add(task)
    db.session.commit()

    logger.info("User %s created task: %s", user_id, task.title)

    return jsonify({"message": "Task created", "task": task.to_dict()}), 201


@app.route("/tasks/<int:task_id>", methods=["PUT"])
@require_token
@require_scope("write")
def update_task(task_id):
    """
    Update a task belonging to the authenticated user.

    Demonstrates ownership verification: even with a valid token,
    you can only modify YOUR tasks. The user_id from the token must
    match the task's owner.

    Requires: valid access token with 'write' scope
    """
    user_id = request.token_payload.get("sub")

    # Find the task AND verify ownership in a single query.
    # This prevents IDOR (Insecure Direct Object Reference) attacks
    # where a user tries to modify another user's task by guessing the ID.
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    if "title" in data:
        task.title = data["title"]
    if "completed" in data:
        task.completed = data["completed"]

    db.session.commit()

    logger.info("User %s updated task %d", user_id, task_id)

    return jsonify({"message": "Task updated", "task": task.to_dict()}), 200


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@require_token
@require_scope("write")
def delete_task(task_id):
    """
    Delete a task belonging to the authenticated user.

    Same ownership check as update — only the task owner can delete it.

    Requires: valid access token with 'write' scope
    """
    user_id = request.token_payload.get("sub")

    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({"error": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()

    logger.info("User %s deleted task %d", user_id, task_id)

    return jsonify({"message": "Task deleted"}), 200


# ============================================================
# Client Credentials Endpoint — Service-to-Service Auth
# ============================================================


@app.route("/tasks/cleanup", methods=["POST"])
def cleanup_completed_tasks():
    """
    Cleanup completed tasks — demonstrates Client Credentials flow.

    This endpoint is called by a background job or another service,
    NOT by a user. It authenticates using the Client Credentials flow:

    1. This service sends its client_id + client_secret to the auth server
    2. The auth server validates the credentials and returns an access token
    3. The token has role='client' (not a user role) and limited scopes

    This is machine-to-machine (M2M) authentication — no user is involved.

    In a real system, this might be a cron job that runs nightly to
    clean up old completed tasks.
    """
    # Step 1: Authenticate as a service using Client Credentials flow.
    # We send our client_id and client_secret to the auth server's
    # token endpoint with grant_type=client_credentials.
    try:
        token_response = requests.post(
            f"{app.config['AUTH_SERVER_URL']}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": app.config["SERVICE_CLIENT_ID"],
                "client_secret": app.config["SERVICE_CLIENT_SECRET"],
                "scope": "write",
            },
            timeout=5,
        )

        if token_response.status_code != 200:
            logger.error(
                "Client credentials auth failed: %s", token_response.text
            )
            return (
                jsonify({"error": "Service authentication failed"}),
                500,
            )

        # Step 2: We now have a service access token.
        # In a multi-service architecture, we'd use this token to call
        # other services. Here we just demonstrate obtaining it.
        service_token = token_response.json()
        logger.info(
            "Service authenticated successfully with scopes: %s",
            service_token.get("scope"),
        )

    except requests.RequestException as e:
        logger.error("Failed to reach auth server: %s", str(e))
        return jsonify({"error": "Auth server unavailable"}), 503

    # Step 3: Perform the cleanup operation.
    # In this case we're operating on our own database, so we don't
    # strictly need the token. But the pattern demonstrates how a
    # service would authenticate before performing privileged operations.
    completed_tasks = Task.query.filter_by(completed=True).all()
    count = len(completed_tasks)

    for task in completed_tasks:
        db.session.delete(task)

    db.session.commit()

    logger.info("Cleanup: removed %d completed tasks", count)

    return (
        jsonify(
            {
                "message": f"Cleaned up {count} completed tasks",
                "service_authenticated": True,
                "service_scopes": service_token.get("scope"),
            }
        ),
        200,
    )


# ============================================================
# Database Initialization
# ============================================================


@app.before_request
def create_tables():
    """Create database tables on first request"""
    if not hasattr(app, "_tables_created"):
        db.create_all()
        app._tables_created = True


if __name__ == "__main__":
    # Run on port 5002 (auth server is 5000, client app is 5001)
    app.run(debug=True, host="0.0.0.0", port=5002)
```

**Step 5: Install dependencies and verify**

Run: `cd task-resource-api && uv sync`
Run: `cd task-resource-api && uv run python app.py &`
Then: `curl -s http://localhost:5002/tasks` → should return 401
Kill: the background process

**Step 6: Commit**

```bash
git add task-resource-api/
git commit -m "feat: add task resource API with JWT validation and scope enforcement"
```

---

### Task 3: Scaffold Task Client App

**Files:**
- Create: `task-client-app/pyproject.toml`
- Create: `task-client-app/app.py`
- Create: `task-client-app/templates/base.html`
- Create: `task-client-app/templates/index.html`
- Create: `task-client-app/templates/dashboard.html`

**Step 1: Create pyproject.toml**

Create `task-client-app/pyproject.toml`:

```toml
[project]
name = "task-client-app"
version = "0.1.0"
description = "Task Client App - demonstrates OAuth 2.0 authorization code flow with PKCE as a client application"
requires-python = ">=3.11"
dependencies = [
    "flask>=3.0.0",
    "requests>=2.31.0",
    "pyjwt>=2.8.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**Step 2: Create base HTML template**

Create `task-client-app/templates/base.html`:

```html
<!--
  Base Template for Task Client App

  This is the client application — it's what end users interact with.
  The auth concepts happening behind the scenes:
  - The nav bar shows the logged-in user's name (from the OIDC ID token)
  - The logout button triggers token revocation
  - All pages check if the user has a valid session (tokens stored server-side)
-->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Task Manager - OAuth Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; }
        nav { background: #2c3e50; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        nav a { color: white; text-decoration: none; }
        nav .user-info { display: flex; align-items: center; gap: 15px; }
        .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        button, .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
        .btn-primary { background: #3498db; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn-small { padding: 5px 12px; font-size: 12px; }
        input[type="text"] { padding: 10px; border: 1px solid #ddd; border-radius: 5px; width: 100%; margin-bottom: 10px; font-size: 14px; }
        .task-list { list-style: none; }
        .task-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #eee; }
        .task-item:last-child { border-bottom: none; }
        .task-completed { text-decoration: line-through; color: #999; }
        .flash { padding: 12px 20px; border-radius: 5px; margin-bottom: 15px; }
        .flash-error { background: #fde8e8; color: #c0392b; }
        .flash-success { background: #e8f8e8; color: #27ae60; }
        .token-debug { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin-top: 15px; font-family: monospace; font-size: 12px; word-break: break-all; }
    </style>
</head>
<body>
    <nav>
        <a href="/"><strong>Task Manager</strong> (OAuth 2.0 Demo)</a>
        <div class="user-info">
            {% if user %}
                <!-- The username displayed here comes from the OIDC ID token.
                     This is the whole point of OIDC: the client app knows WHO
                     the user is, not just that they're authenticated. -->
                <span>Logged in as <strong>{{ user.username }}</strong> ({{ user.role }})</span>
                <form method="POST" action="/logout" style="display:inline;">
                    <button type="submit" class="btn btn-danger btn-small">Logout</button>
                </form>
            {% else %}
                <span>Not logged in</span>
            {% endif %}
        </div>
    </nav>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash flash-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

**Step 3: Create landing page template**

Create `task-client-app/templates/index.html`:

```html
<!--
  Landing Page — Where the OAuth flow begins

  When the user clicks "Login with Auth Server", they are redirected to
  the auth server's /oauth/authorize endpoint. This is step 1 of the
  Authorization Code flow.

  The login button doesn't send credentials to this app — it sends
  the user to the auth server. This is the core idea of OAuth:
  the client app never sees the user's password.
-->
{% extends "base.html" %}

{% block content %}
<div class="card" style="text-align: center; padding: 60px 25px;">
    <h1>Task Manager</h1>
    <p style="margin: 20px 0; color: #666;">
        A demo app that uses OAuth 2.0 to authenticate with the Auth Server
    </p>

    <!--
      This link starts the OAuth 2.0 Authorization Code flow with PKCE.
      The /login route in our app will:
      1. Generate a PKCE code_verifier and code_challenge
      2. Generate a state parameter for CSRF protection
      3. Redirect the user to the auth server's /oauth/authorize endpoint
    -->
    <a href="/login" class="btn btn-primary" style="font-size: 18px; padding: 15px 40px;">
        Login with Auth Server
    </a>

    <div style="margin-top: 40px; color: #999; font-size: 14px;">
        <p>This demonstrates the OAuth 2.0 Authorization Code flow with PKCE</p>
        <p>Your credentials are entered on the Auth Server (port 5000), not here</p>
    </div>
</div>
{% endblock %}
```

**Step 4: Create dashboard template**

Create `task-client-app/templates/dashboard.html`:

```html
<!--
  Dashboard — The authenticated experience

  This page is only accessible after completing the OAuth flow.
  It demonstrates:
  - User identity from OIDC (displaying username and role from the ID token)
  - Using access tokens to call the Resource API
  - Scope-limited operations (read tasks, create tasks)
-->
{% extends "base.html" %}

{% block content %}
<div class="card">
    <h2>Your Tasks</h2>
    <p style="color: #666; margin-bottom: 20px;">
        Tasks are stored in the Resource API (port 5002) and accessed using your OAuth access token
    </p>

    <!-- Create new task form -->
    <form method="POST" action="/tasks" style="display: flex; gap: 10px; margin-bottom: 20px;">
        <input type="text" name="title" placeholder="What needs to be done?" required>
        <button type="submit" class="btn btn-success">Add Task</button>
    </form>

    <!-- Task list -->
    {% if tasks %}
    <ul class="task-list">
        {% for task in tasks %}
        <li class="task-item">
            <span class="{{ 'task-completed' if task.completed else '' }}">
                {{ task.title }}
            </span>
            <div style="display: flex; gap: 8px;">
                {% if not task.completed %}
                <form method="POST" action="/tasks/{{ task.id }}/complete">
                    <button type="submit" class="btn btn-success btn-small">Done</button>
                </form>
                {% endif %}
                <form method="POST" action="/tasks/{{ task.id }}/delete">
                    <button type="submit" class="btn btn-danger btn-small">Delete</button>
                </form>
            </div>
        </li>
        {% endfor %}
    </ul>
    {% else %}
    <p style="color: #999; text-align: center; padding: 30px;">No tasks yet. Add one above!</p>
    {% endif %}
</div>

<!-- Token debug info (for learning purposes) -->
<div class="card">
    <h3>OAuth Debug Info</h3>
    <p style="color: #666; margin-bottom: 10px;">
        This section shows the tokens obtained through the OAuth flow (for learning only — never expose these in production)
    </p>

    {% if token_info %}
    <div class="token-debug">
        <p><strong>Access Token Claims:</strong></p>
        <pre>{{ token_info | tojson(indent=2) }}</pre>
    </div>
    {% endif %}

    {% if id_token_info %}
    <div class="token-debug">
        <p><strong>ID Token Claims (OIDC):</strong></p>
        <pre>{{ id_token_info | tojson(indent=2) }}</pre>
    </div>
    {% endif %}

    {% if userinfo %}
    <div class="token-debug">
        <p><strong>UserInfo Endpoint Response:</strong></p>
        <pre>{{ userinfo | tojson(indent=2) }}</pre>
    </div>
    {% endif %}
</div>
{% endblock %}
```

**Step 5: Create the main application**

Create `task-client-app/app.py`:

```python
"""
Task Client App — An OAuth 2.0 Client Application

This app demonstrates the CLIENT side of OAuth 2.0. It's what a real
third-party application does:

1. Redirects the user to the auth server for login (Authorization Code flow)
2. Receives the authorization code via callback
3. Exchanges the code for tokens (with PKCE verification)
4. Uses the access token to call protected APIs (Resource API)
5. Uses the ID token to know who the user is (OIDC)
6. Refreshes the access token when it expires
7. Revokes tokens on logout

This is the "App X wants to access your data" side of OAuth.
"""

import os
import hashlib
import base64
import secrets
import logging
from functools import wraps

import jwt
import requests
from flask import Flask, request, redirect, url_for, session, jsonify, flash, render_template

# ============================================================
# App Configuration
# ============================================================

app = Flask(__name__)

# Flask session secret (for storing tokens server-side)
# The Flask session is encrypted and stored in a cookie.
# Tokens are stored here so they never reach the browser directly.
app.secret_key = os.environ.get("FLASK_SECRET", "client-app-secret-change-in-production")

# OAuth 2.0 client configuration
# These values were registered with the auth server (see auth-server/app.py)
OAUTH_CONFIG = {
    "client_id": "task-client",
    "client_secret": "task-client-secret",
    "auth_server_url": os.environ.get("AUTH_SERVER_URL", "http://localhost:5000"),
    "resource_api_url": os.environ.get("RESOURCE_API_URL", "http://localhost:5002"),
    "redirect_uri": "http://localhost:5001/callback",
    "scopes": "read write openid profile email",
}

# JWT secret for decoding tokens (to display debug info)
# In production, a client wouldn't need this — it would treat tokens as opaque
# strings and just send them to APIs. We decode here for educational purposes.
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "jwt-secret-key-change-in-production")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# PKCE Helpers
# ============================================================
# PKCE (Proof Key for Code Exchange) prevents authorization code
# interception attacks. The client generates a random secret
# (code_verifier), hashes it (code_challenge), and sends the hash
# to the auth server. Later, when exchanging the code for tokens,
# the client sends the original secret. The auth server hashes it
# and verifies it matches — proving the same client that started
# the flow is finishing it.
# ============================================================


def generate_pkce_pair():
    """
    Generate a PKCE code_verifier and code_challenge pair.

    The code_verifier is a cryptographically random string (43-128 chars).
    The code_challenge is SHA256(code_verifier), base64url-encoded.

    Returns:
        tuple: (code_verifier, code_challenge)
    """
    # Generate a random code_verifier (the secret the client keeps)
    code_verifier = secrets.token_urlsafe(32)

    # Generate the code_challenge by hashing the verifier
    # This is what gets sent to the auth server in the authorize request
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    return code_verifier, code_challenge


# ============================================================
# Login Required Decorator
# ============================================================


def login_required(f):
    """
    Decorator: Require the user to be logged in.

    Checks if the session has tokens. If the access token is expired,
    attempts to refresh it automatically using the refresh token.
    This is how real apps maintain sessions — the user doesn't have
    to re-login every 15 minutes.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if "access_token" not in session:
            flash("Please log in first", "error")
            return redirect(url_for("index"))

        # Try to decode the access token to check if it's expired
        try:
            jwt.decode(session["access_token"], JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            # Access token expired — try to refresh it.
            # This is the refresh token flow in action:
            # instead of sending the user back to login, we silently
            # get a new access token using the refresh token.
            logger.info("Access token expired, attempting refresh...")
            if not refresh_access_token():
                # Refresh failed (refresh token also expired or revoked)
                session.clear()
                flash("Session expired, please log in again", "error")
                return redirect(url_for("index"))
            logger.info("Access token refreshed successfully")
        except jwt.InvalidTokenError:
            session.clear()
            flash("Invalid session, please log in again", "error")
            return redirect(url_for("index"))

        return f(*args, **kwargs)

    return decorated


def refresh_access_token():
    """
    Refresh the access token using the refresh token.

    This demonstrates the OAuth 2.0 Refresh Token flow:
    1. Send the refresh token to the auth server's token endpoint
    2. Receive a new access token
    3. Update the session with the new token

    Returns:
        bool: True if refresh was successful, False otherwise
    """
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return False

    try:
        response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OAUTH_CONFIG["client_id"],
                "client_secret": OAUTH_CONFIG["client_secret"],
            },
            timeout=5,
        )

        if response.status_code != 200:
            logger.warning("Token refresh failed: %s", response.text)
            return False

        data = response.json()
        session["access_token"] = data["access_token"]

        # If a new refresh token was returned (token rotation),
        # update it in the session
        if "refresh_token" in data:
            session["refresh_token"] = data["refresh_token"]

        return True

    except requests.RequestException as e:
        logger.error("Refresh request failed: %s", str(e))
        return False


def get_user_info():
    """
    Get current user info from session tokens.

    Decodes the access token (or ID token) to extract user identity.
    In production, you'd use the ID token for identity and treat
    the access token as opaque.

    Returns:
        dict: User info dict or None
    """
    token = session.get("id_token") or session.get("access_token")
    if not token:
        return None

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return {
            "username": payload.get("preferred_username") or payload.get("username"),
            "role": payload.get("role", "unknown"),
            "email": payload.get("email"),
        }
    except jwt.InvalidTokenError:
        return None


# ============================================================
# Routes
# ============================================================


@app.route("/")
def index():
    """
    Landing page.

    If the user is already logged in (has tokens in session),
    redirect to dashboard. Otherwise, show the login page.
    """
    if "access_token" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html", user=None)


@app.route("/login")
def login():
    """
    Start the OAuth 2.0 Authorization Code flow with PKCE.

    This is where the OAuth dance begins:
    1. Generate PKCE code_verifier (keep secret) and code_challenge (send to auth server)
    2. Generate a random state parameter (for CSRF protection)
    3. Redirect the user to the auth server's /oauth/authorize endpoint

    The user will see the auth server's login page, enter credentials,
    see the consent screen, and then be redirected back to our /callback.
    """
    # Step 1: Generate PKCE pair
    # code_verifier is stored in the session — we'll need it later
    # when exchanging the authorization code for tokens
    code_verifier, code_challenge = generate_pkce_pair()
    session["code_verifier"] = code_verifier

    # Step 2: Generate state for CSRF protection
    # We store it in the session and verify it matches when the
    # auth server redirects back to us
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state

    # Step 3: Build the authorization URL and redirect the user
    # All these parameters are defined in the OAuth 2.0 spec (RFC 6749)
    auth_url = (
        f"{OAUTH_CONFIG['auth_server_url']}/oauth/authorize"
        f"?response_type=code"  # We want an authorization code
        f"&client_id={OAUTH_CONFIG['client_id']}"  # Who we are
        f"&redirect_uri={OAUTH_CONFIG['redirect_uri']}"  # Where to send user back
        f"&scope={OAUTH_CONFIG['scopes']}"  # What permissions we want
        f"&state={state}"  # CSRF protection
        f"&code_challenge={code_challenge}"  # PKCE challenge
        f"&code_challenge_method=S256"  # PKCE method (SHA256)
    )

    logger.info("Starting OAuth flow, redirecting to auth server")
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """
    OAuth 2.0 callback — handle the authorization server's redirect.

    After the user authorizes our app on the auth server, they're
    redirected here with:
    - ?code=xxx — the authorization code (one-time use)
    - ?state=yyy — our CSRF token (must match what we sent)
    - ?error=zzz — if something went wrong

    We then exchange the authorization code for tokens by calling
    the auth server's /oauth/token endpoint (server-to-server).
    """
    # Check for errors (user denied access, or auth server error)
    error = request.args.get("error")
    if error:
        flash(f"Authorization failed: {error}", "error")
        return redirect(url_for("index"))

    # Step 1: Verify the state parameter to prevent CSRF attacks.
    # If an attacker tried to trick us into completing an OAuth flow
    # they initiated, the state won't match.
    state = request.args.get("state")
    if state != session.get("oauth_state"):
        flash("Invalid state parameter (possible CSRF attack)", "error")
        return redirect(url_for("index"))

    # Step 2: Get the authorization code
    code = request.args.get("code")
    if not code:
        flash("No authorization code received", "error")
        return redirect(url_for("index"))

    # Step 3: Exchange the authorization code for tokens.
    # This is a server-to-server call — the user's browser is NOT involved.
    # We send:
    # - The authorization code (proves the user authorized us)
    # - Our client credentials (proves we are who we say we are)
    # - The code_verifier (proves we started this flow — PKCE)
    # - The redirect_uri (must match the original request)
    code_verifier = session.pop("code_verifier", None)
    session.pop("oauth_state", None)

    try:
        token_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OAUTH_CONFIG["redirect_uri"],
                "client_id": OAUTH_CONFIG["client_id"],
                "client_secret": OAUTH_CONFIG["client_secret"],
                "code_verifier": code_verifier,
            },
            timeout=10,
        )

        if token_response.status_code != 200:
            logger.error("Token exchange failed: %s", token_response.text)
            flash("Failed to exchange authorization code for tokens", "error")
            return redirect(url_for("index"))

        # Step 4: Store the tokens in the server-side session.
        # NEVER store tokens in localStorage or non-httpOnly cookies
        # in a real app — they'd be vulnerable to XSS attacks.
        tokens = token_response.json()
        session["access_token"] = tokens["access_token"]
        session["refresh_token"] = tokens.get("refresh_token")
        session["id_token"] = tokens.get("id_token")

        logger.info("OAuth flow completed successfully")
        flash("Logged in successfully!", "success")
        return redirect(url_for("dashboard"))

    except requests.RequestException as e:
        logger.error("Token exchange request failed: %s", str(e))
        flash("Failed to connect to auth server", "error")
        return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Dashboard — show user info and tasks.

    Demonstrates:
    - Reading user identity from the OIDC ID token
    - Calling the Resource API with the access token
    - Calling the UserInfo endpoint for additional profile data
    """
    user = get_user_info()

    # Fetch tasks from the Resource API using the access token.
    # This is the access token in action: we send it as a Bearer token
    # to prove we're authorized to read this user's tasks.
    tasks = []
    try:
        response = requests.get(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=5,
        )
        if response.status_code == 200:
            tasks = response.json().get("tasks", [])
        else:
            flash(f"Failed to fetch tasks: {response.json().get('error', 'Unknown error')}", "error")
    except requests.RequestException as e:
        flash(f"Could not connect to Resource API: {str(e)}", "error")

    # Decode tokens for debug display (educational purposes only)
    token_info = None
    id_token_info = None
    try:
        token_info = jwt.decode(
            session["access_token"], JWT_SECRET, algorithms=["HS256"]
        )
    except jwt.InvalidTokenError:
        pass

    if session.get("id_token"):
        try:
            id_token_info = jwt.decode(
                session["id_token"], JWT_SECRET, algorithms=["HS256"]
            )
        except jwt.InvalidTokenError:
            pass

    # Call the UserInfo endpoint to demonstrate OIDC UserInfo
    # In a real app, you'd use this to get up-to-date profile info
    userinfo = None
    try:
        response = requests.get(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/userinfo",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=5,
        )
        if response.status_code == 200:
            userinfo = response.json()
    except requests.RequestException:
        pass

    return render_template(
        "dashboard.html",
        user=user,
        tasks=tasks,
        token_info=token_info,
        id_token_info=id_token_info,
        userinfo=userinfo,
    )


@app.route("/tasks", methods=["POST"])
@login_required
def create_task():
    """
    Create a new task via the Resource API.

    Sends a POST request to the Resource API with the access token.
    The Resource API validates the token and extracts the user_id
    from the JWT 'sub' claim — we don't need to tell it who we are.
    """
    title = request.form.get("title")
    if not title:
        flash("Task title is required", "error")
        return redirect(url_for("dashboard"))

    try:
        response = requests.post(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            json={"title": title},
            timeout=5,
        )

        if response.status_code == 201:
            flash("Task created!", "success")
        else:
            flash(f"Failed to create task: {response.json().get('error', 'Unknown error')}", "error")
    except requests.RequestException as e:
        flash(f"Could not connect to Resource API: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_task(task_id):
    """Mark a task as completed via the Resource API."""
    try:
        response = requests.put(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks/{task_id}",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            json={"completed": True},
            timeout=5,
        )

        if response.status_code == 200:
            flash("Task completed!", "success")
        else:
            flash(f"Failed to update task: {response.json().get('error', 'Unknown error')}", "error")
    except requests.RequestException as e:
        flash(f"Could not connect to Resource API: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    """Delete a task via the Resource API."""
    try:
        response = requests.delete(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks/{task_id}",
            headers={"Authorization": f"Bearer {session['access_token']}"},
            timeout=5,
        )

        if response.status_code == 200:
            flash("Task deleted!", "success")
        else:
            flash(f"Failed to delete task: {response.json().get('error', 'Unknown error')}", "error")
    except requests.RequestException as e:
        flash(f"Could not connect to Resource API: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    """
    Logout — revoke tokens and clear session.

    This demonstrates proper OAuth logout:
    1. Revoke the access token at the auth server (so it can't be reused)
    2. Revoke the refresh token (so no new access tokens can be obtained)
    3. Clear the local session

    Without revocation, the tokens would still be valid until they expire.
    Revocation adds them to the auth server's blocklist.
    """
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    # Step 1: Revoke the access token at the auth server
    if access_token:
        try:
            requests.post(
                f"{OAUTH_CONFIG['auth_server_url']}/oauth/revoke",
                json={"token": access_token, "token_type_hint": "access"},
                timeout=5,
            )
            logger.info("Access token revoked")
        except requests.RequestException:
            logger.warning("Failed to revoke access token")

    # Step 2: Revoke the refresh token at the auth server
    if refresh_token:
        try:
            requests.post(
                f"{OAUTH_CONFIG['auth_server_url']}/oauth/revoke",
                json={"token": refresh_token, "token_type_hint": "refresh"},
                timeout=5,
            )
            logger.info("Refresh token revoked")
        except requests.RequestException:
            logger.warning("Failed to revoke refresh token")

    # Step 3: Clear the local session
    session.clear()

    flash("Logged out successfully", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Run on port 5001 (auth server is 5000, resource API is 5002)
    app.run(debug=True, host="0.0.0.0", port=5001)
```

**Step 6: Install dependencies and verify**

Run: `cd task-client-app && uv sync`
Run: `cd task-client-app && uv run python app.py &`
Then: `curl -s http://localhost:5001/` should return HTML with "Login with Auth Server"
Kill: the background process

**Step 7: Commit**

```bash
git add task-client-app/
git commit -m "feat: add task client app with OAuth 2.0 authorization code flow and PKCE"
```

---

### Task 4: Update Auth Server to Handle Login During OAuth Flow

The current auth server's `/oauth/authorize` endpoint redirects unauthenticated users to login, but the login endpoint returns JSON (it's an API). We need a way for the OAuth authorize flow to work with the task client app. The simplest approach: the task client app will first login the user via the auth server's API, get tokens, and pass the access token when calling `/oauth/authorize`.

**Files:**
- Modify: `task-client-app/app.py` (update the login flow)
- Create: `task-client-app/templates/login.html`

**Step 1: Add login template**

Create `task-client-app/templates/login.html`:

```html
<!--
  Login Page — Authenticate with the Auth Server

  In a real OAuth flow, the auth server would have its own login UI.
  Since our auth server is API-only, this page collects credentials
  and authenticates the user via the auth server's /auth/login endpoint.

  After login, the user is redirected to the auth server's /oauth/authorize
  endpoint with their access token, so they can authorize our app.

  NOTE: In production OAuth, the client app NEVER handles user credentials.
  The user would enter credentials directly on the auth server's website.
  We're doing it here because our auth server doesn't have a web UI.
-->
{% extends "base.html" %}

{% block content %}
<div class="card" style="max-width: 400px; margin: 40px auto;">
    <h2 style="text-align: center; margin-bottom: 20px;">Login to Auth Server</h2>
    <p style="color: #666; text-align: center; margin-bottom: 20px;">
        Enter your Auth Server credentials (port 5000)
    </p>

    <form method="POST" action="/login">
        <!-- Store the OAuth state so we can continue the flow after login -->
        <input type="hidden" name="next" value="{{ next_url }}">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required
               style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; width: 100%; margin-bottom: 10px; font-size: 14px;">
        <button type="submit" class="btn btn-primary" style="width: 100%;">Login</button>
    </form>

    <p style="color: #999; text-align: center; margin-top: 15px; font-size: 12px;">
        Default: admin / admin123
    </p>
</div>
{% endblock %}
```

**Step 2: Update the login flow in app.py**

Replace the `login()` function in `task-client-app/app.py` with a two-phase login:

Replace this section in `task-client-app/app.py`:

```python
@app.route("/login")
def login():
```

With the following (replaces everything from `@app.route("/login")` to the end of the `login()` function):

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Start the OAuth 2.0 Authorization Code flow with PKCE.

    GET: Show the login form (since our auth server is API-only,
         we collect credentials here and authenticate via API).

    POST: Authenticate with the auth server, then redirect to
          the OAuth authorize endpoint with the user's access token.

    NOTE: In a real OAuth deployment, the auth server has its own
    login page. The client app would just redirect to /oauth/authorize
    and the auth server handles authentication. We're simulating both
    sides here because our auth server is API-only.
    """
    if request.method == "GET":
        # Step 1: Generate PKCE pair and state, store in session
        code_verifier, code_challenge = generate_pkce_pair()
        session["code_verifier"] = code_verifier

        state = secrets.token_urlsafe(16)
        session["oauth_state"] = state
        session["code_challenge"] = code_challenge

        return render_template("login.html", user=None, next_url="")

    # POST: Handle login form submission
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for("login"))

    # Step 2: Authenticate with the auth server's login API
    try:
        login_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/auth/login",
            json={"username": username, "password": password},
            timeout=5,
        )

        if login_response.status_code != 200:
            flash("Invalid credentials", "error")
            return redirect(url_for("login"))

        # We have the user's access token from the auth server
        user_token = login_response.json()["access_token"]

    except requests.RequestException as e:
        flash(f"Could not connect to auth server: {str(e)}", "error")
        return redirect(url_for("login"))

    # Step 3: Now redirect to the auth server's /oauth/authorize endpoint
    # with the user's access token in the Authorization header.
    # Since this is a redirect (browser), we need to call authorize ourselves
    # and handle the consent step.
    code_challenge = session.get("code_challenge")
    state = session.get("oauth_state")

    # For this demo, we'll auto-authorize by calling the authorize endpoint
    # server-side (simulating the user clicking "Authorize")
    try:
        # First, GET the authorize page (validates params)
        auth_response = requests.get(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": OAUTH_CONFIG["client_id"],
                "redirect_uri": OAUTH_CONFIG["redirect_uri"],
                "scope": OAUTH_CONFIG["scopes"],
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            headers={"Authorization": f"Bearer {user_token}"},
            allow_redirects=False,
            timeout=5,
        )

        # Then POST to approve the authorization
        approve_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/authorize",
            data={
                "authorize": "true",
                "client_id": OAUTH_CONFIG["client_id"],
                "redirect_uri": OAUTH_CONFIG["redirect_uri"],
                "state": state,
                "scopes": OAUTH_CONFIG["scopes"],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            headers={"Authorization": f"Bearer {user_token}"},
            allow_redirects=False,
            timeout=5,
        )

        # The auth server responds with a redirect to our callback URL
        # with the authorization code
        if approve_response.status_code in (302, 301):
            redirect_url = approve_response.headers.get("Location")
            return redirect(redirect_url)
        else:
            flash("Authorization failed", "error")
            return redirect(url_for("index"))

    except requests.RequestException as e:
        flash(f"OAuth authorization failed: {str(e)}", "error")
        return redirect(url_for("index"))
```

**Step 3: Commit**

```bash
git add task-client-app/
git commit -m "feat: add login UI and two-phase OAuth flow for API-only auth server"
```

---

### Task 5: Add Start Script and Update README

**Files:**
- Create: `start-all.sh`
- Modify: `README.md`

**Step 1: Create start-all.sh**

Create `start-all.sh`:

```bash
#!/bin/bash
# ============================================================
# Start all three services for the OAuth demo
#
# Services:
#   Auth Server     (port 5000) — issues tokens, manages users
#   Task Client App (port 5001) — web UI, OAuth client
#   Task Resource API (port 5002) — protected API, validates tokens
#
# Usage: ./start-all.sh
# Stop:  Ctrl+C (kills all three processes)
# ============================================================

set -e

echo "=== Concept-Of-Auth: Starting all services ==="
echo ""

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "Error: 'uv' is required. Install from https://docs.astral.sh/uv/"
    exit 1
fi

# Install dependencies for all services
echo "[1/3] Installing dependencies..."
(cd auth-server && uv sync --quiet)
(cd task-resource-api && uv sync --quiet)
(cd task-client-app && uv sync --quiet)

echo ""
echo "[2/3] Starting services..."
echo ""

# Trap Ctrl+C to kill all background processes
trap 'echo ""; echo "Stopping all services..."; kill 0; exit 0' SIGINT SIGTERM

# Start all three services in the background
(cd auth-server && uv run python app.py) &
(cd task-resource-api && uv run python app.py) &
(cd task-client-app && uv run python app.py) &

echo "=== All services started ==="
echo ""
echo "  Auth Server:      http://localhost:5000  (Swagger: http://localhost:5000/api/docs)"
echo "  Task Client App:  http://localhost:5001  (Open this in your browser)"
echo "  Task Resource API: http://localhost:5002"
echo ""
echo "  Default login:    admin / admin123"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for all background processes
wait
```

**Step 2: Make it executable**

Run: `chmod +x start-all.sh`

**Step 3: Update README.md to include the new services**

Add the following to `README.md` after the "Quick Start" section:

In `README.md`, after the existing Quick Start section (after the `Default credentials` lines), add:

```markdown
## Running All Services

To run the full OAuth demo (auth server + client app + resource API):

```bash
./start-all.sh
```

Then open http://localhost:5001 in your browser and click "Login with Auth Server."

| Service | Port | Role |
|---------|------|------|
| Auth Server | 5000 | Authorization server — issues tokens, manages users |
| Task Client App | 5001 | OAuth client — web UI that uses OAuth to authenticate |
| Task Resource API | 5002 | Resource server — validates tokens, serves protected data |
```

**Step 4: Commit**

```bash
git add start-all.sh README.md
git commit -m "feat: add start-all script and update README with multi-service setup"
```

---

### Task 6: End-to-End Smoke Test

**Step 1: Start all services**

Run: `./start-all.sh &`
Wait 3 seconds for services to start.

**Step 2: Test auth server is running**

Run: `curl -s http://localhost:5000/auth/login -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' | python3 -m json.tool`
Expected: JSON with `access_token` and `refresh_token`

**Step 3: Test resource API rejects unauthenticated requests**

Run: `curl -s http://localhost:5002/tasks`
Expected: `{"error": "Authorization header required"}` with 401

**Step 4: Test resource API accepts valid tokens**

Run the following:
```bash
TOKEN=$(curl -s http://localhost:5000/auth/login -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:5002/tasks -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```
Expected: `{"tasks": []}` with 200

**Step 5: Test client app is running**

Run: `curl -s http://localhost:5001/ | grep "Login with Auth Server"`
Expected: HTML containing "Login with Auth Server"

**Step 6: Test cleanup endpoint (client credentials flow)**

Run: `curl -s -X POST http://localhost:5002/tasks/cleanup | python3 -m json.tool`
Expected: JSON with `"service_authenticated": true`

**Step 7: Stop all services**

Kill the background processes.

**Step 8: Commit (if any fixes were needed)**

No commit needed if everything passes. If fixes were required, commit them.
