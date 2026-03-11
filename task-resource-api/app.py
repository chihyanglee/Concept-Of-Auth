"""
Task Resource API — An OAuth 2.0 Resource Server
=================================================

This is the CORE file of the Task Resource API. It demonstrates how a
"resource server" validates JWTs and enforces scopes to protect API endpoints.

In the OAuth 2.0 architecture, there are typically three parties:
  1. Authorization Server (our auth-server on port 5000)
     - Authenticates users, issues tokens, manages clients.
  2. Resource Server (THIS file, on port 5002)
     - Hosts protected resources (tasks), validates tokens, enforces scopes.
  3. Client Application (task-client-app on port 5001)
     - The frontend/app that users interact with. It obtains tokens from the
       auth server and presents them to the resource server.

=============================================================================
SELF-VALIDATION vs. INTROSPECTION — The Two Ways to Validate a Token
=============================================================================

When a request arrives with a Bearer token, the resource server needs to
answer: "Is this token valid, and what permissions does it grant?"

There are TWO approaches, each with trade-offs:

APPROACH 1: Local (Self) Validation
------------------------------------
  How it works:
    - Decode the JWT using the shared secret (HS256) or public key (RS256).
    - Check the 'exp' claim to see if it's expired.
    - Check the 'type' claim to ensure it's an access token.
    - Read the 'scopes' claim to determine permissions.

  Pros:
    + FAST — no network call, pure computation.
    + Works even if the auth server is down (decoupled).
    + Lower latency for every API request.

  Cons:
    - CANNOT check if the token has been revoked/blocklisted.
      If a user logs out or an admin revokes a token, the resource server
      won't know until the token naturally expires.
    - Requires the resource server to have the signing secret/key.
      With HS256 (symmetric), this means sharing the secret — risky.
      With RS256 (asymmetric), you only need the public key — much safer.

APPROACH 2: Token Introspection (RFC 7662)
-------------------------------------------
  How it works:
    - Send the token to the auth server's /oauth/introspect endpoint.
    - The auth server checks its database: is the token valid? Is it blocked?
    - Returns { "active": true/false, "scope": "...", "sub": "...", ... }

  Pros:
    + Can detect revoked/blocklisted tokens immediately.
    + The resource server doesn't need the signing secret at all.
    + Single source of truth — the auth server always has the final say.

  Cons:
    - SLOWER — every API request requires a network round-trip to the auth server.
    - Creates a dependency: if the auth server is down, the resource server
      can't validate tokens at all.
    - Higher load on the auth server (every resource request triggers an
      introspection call).

WHAT PRODUCTION SYSTEMS DO:
  Most real systems use a hybrid approach:
    1. Self-validate first (fast path) for most requests.
    2. Use introspection for sensitive operations or periodically.
    3. Use short-lived access tokens (15 min) so revocation lag is minimal.
    4. Cache introspection results for a few seconds to reduce load.

  In this demo, we default to local validation but allow introspection via
  a query parameter (?introspect=true) so you can see both in action.
=============================================================================
"""

import os
import jwt
import requests
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from database import db
from models import Task


# =============================================================================
# Application Configuration
# =============================================================================

app = Flask(__name__)

# Database: SQLite file in the current directory.
# This is completely separate from the auth server's database.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ─────────────────────────────────────────────────────────────────────────────
# JWT_SECRET_KEY — The shared secret for HS256 token validation
# ─────────────────────────────────────────────────────────────────────────────
# This MUST match the auth server's JWT_SECRET_KEY exactly. If they differ,
# the resource server will reject every token as having an invalid signature.
#
# THE HS256 SHARED SECRET PROBLEM:
#   HS256 (HMAC-SHA256) is a symmetric algorithm — the same key is used to
#   both SIGN and VERIFY tokens. This means:
#     - The auth server needs the key to sign tokens.    (makes sense)
#     - The resource server needs the key to verify them. (also makes sense)
#     - But ANYONE with the key can also FORGE tokens!    (that's the problem)
#
#   If a resource server is compromised, the attacker gets the signing key
#   and can create tokens for any user with any scopes.
#
# THE RS256 ALTERNATIVE:
#   RS256 (RSA-SHA256) is an asymmetric algorithm — it uses a key PAIR:
#     - Private key: held ONLY by the auth server, used to SIGN tokens.
#     - Public key: shared with all resource servers, used to VERIFY tokens.
#   If a resource server is compromised, the attacker only gets the public
#   key — they can verify tokens but NOT forge them. Much safer!
#
#   In production, the auth server publishes its public key at a JWKS
#   (JSON Web Key Set) endpoint, and resource servers fetch it from there.
#
# For this demo, we use HS256 with a shared secret for simplicity.
# ─────────────────────────────────────────────────────────────────────────────
app.config['JWT_SECRET_KEY'] = os.environ.get(
    'JWT_SECRET_KEY', 'jwt-secret-key-change-in-production'
)

# ─────────────────────────────────────────────────────────────────────────────
# Auth Server URL — Used for token introspection and client credentials
# ─────────────────────────────────────────────────────────────────────────────
# The resource server needs to talk to the auth server for:
#   1. Token introspection (POST /oauth/introspect) — optional validation path
#   2. Client credentials flow (POST /oauth/token) — for service-to-service auth
# ─────────────────────────────────────────────────────────────────────────────
AUTH_SERVER_URL = os.environ.get('AUTH_SERVER_URL', 'http://localhost:5000')

# ─────────────────────────────────────────────────────────────────────────────
# Service Client Credentials — This API's own identity
# ─────────────────────────────────────────────────────────────────────────────
# These credentials identify the Task Resource API as a client of the auth
# server. They are used in the Client Credentials flow for machine-to-machine
# operations (like the /tasks/cleanup endpoint).
#
# These must match a Client record in the auth server's database. The auth
# server's app.py seeds a 'task-service' client with these exact credentials.
# ─────────────────────────────────────────────────────────────────────────────
SERVICE_CLIENT_ID = 'task-service'
SERVICE_CLIENT_SECRET = 'task-service-secret'

# Initialize extensions
db.init_app(app)
CORS(app)


# =============================================================================
# JWT Validation Functions
# =============================================================================

def validate_token_locally(token):
    """
    APPROACH 1: Local (Self) Validation of a JWT
    =============================================

    This function decodes and validates the JWT entirely on this server,
    with no network call to the auth server.

    Step by step:
      1. jwt.decode() does three things:
         a. Verifies the signature using our shared secret key (HS256).
            If someone tampered with the token, the signature won't match.
         b. Checks the 'exp' claim — if the token is expired, it raises
            ExpiredSignatureError.
         c. Decodes the payload (base64url) and returns it as a dict.

      2. We then check that payload['type'] == 'access' to ensure this is
         an access token (not a refresh token or ID token being misused).

    What we CAN check:
      - Signature validity (was this token issued by someone with our key?)
      - Expiration (has the token's TTL passed?)
      - Token type (is this an access token?)
      - Scopes (what permissions were granted?)

    What we CANNOT check:
      - Revocation/blocklist (was this token explicitly revoked?)
        The blocklist lives in the auth server's database, and we don't
        have access to it. A revoked token will still pass local validation
        until it naturally expires.

    Args:
        token (str): The raw JWT string from the Authorization header.

    Returns:
        dict: The decoded token payload if valid.
        None: If the token is invalid for any reason.
    """
    try:
        # Decode and verify the JWT.
        # algorithms=['HS256'] prevents algorithm confusion attacks where
        # an attacker sends a token signed with 'none' or RS256 using the
        # public key as an HMAC secret.
        payload = jwt.decode(
            token,
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256'],
            # Disable audience verification because tokens may come from
            # different OAuth clients (task-client, demo-client, etc.) or
            # direct login (aud='default'). In production, you'd verify
            # the audience matches this service's expected identifier.
            options={"verify_aud": False}
        )

        # Ensure this is an access token, not a refresh token or ID token.
        # Why? Refresh tokens are meant for the /oauth/token endpoint only.
        # If we accepted refresh tokens here, an attacker who stole a
        # refresh token could use it as an access token — bad!
        if payload.get('type') != 'access':
            return None

        return payload

    except jwt.ExpiredSignatureError:
        # The token's 'exp' claim is in the past. The token was valid once
        # but has expired. The client should use their refresh token to get
        # a new access token.
        return None

    except jwt.InvalidTokenError:
        # Catch-all for any other JWT error: bad signature, malformed token,
        # missing required claims, etc.
        return None


def validate_token_via_introspection(token):
    """
    APPROACH 2: Token Introspection via the Auth Server (RFC 7662)
    ==============================================================

    This function sends the token to the auth server's introspection endpoint
    and asks: "Is this token valid?"

    The auth server checks EVERYTHING:
      - Signature validity
      - Expiration
      - Whether the token has been revoked/blocklisted
      - Whether the user still exists
      - Whether the client that requested the token is still valid

    This is the most thorough validation possible, but it requires a network
    round-trip to the auth server for EVERY request.

    The introspection response format (RFC 7662):
      {
        "active": true,          // THE key field — is the token usable?
        "scope": "read write",   // Space-separated string (NOT a list!)
        "sub": "42",             // Subject (user ID)
        "username": "alice",
        "client_id": "demo-client",
        "exp": 1234567890,
        "iat": 1234567890,
        "token_type": "access"
      }

    IMPORTANT FORMAT DIFFERENCE:
      - Local validation returns scopes as a LIST:   ["read", "write"]
        (because that's how our auth server stores them in the JWT)
      - Introspection returns scope as a STRING:      "read write"
        (because that's what RFC 7662 specifies)
      Our @require_scope decorator handles both formats.

    Args:
        token (str): The raw JWT string from the Authorization header.

    Returns:
        dict: The introspection response if the token is active.
        None: If the token is inactive, invalid, or the auth server is unreachable.
    """
    try:
        # POST the token to the auth server's introspection endpoint.
        # In production, this request itself should be authenticated
        # (e.g., with client credentials), but our demo auth server
        # accepts unauthenticated introspection requests for simplicity.
        response = requests.post(
            f'{AUTH_SERVER_URL}/oauth/introspect',
            json={'token': token},
            timeout=5  # Don't hang forever if the auth server is down
        )

        if response.status_code != 200:
            # The auth server returned an error. This could mean:
            #   - The auth server is misconfigured
            #   - Network issues
            #   - The introspection endpoint requires authentication
            return None

        data = response.json()

        # The 'active' field is the single most important field in the
        # introspection response. If it's False, the token MUST be rejected,
        # regardless of any other fields present.
        if not data.get('active'):
            return None

        return data

    except requests.exceptions.ConnectionError:
        # The auth server is unreachable. This is the main downside of
        # introspection — if the auth server is down, we can't validate
        # tokens at all. A production system might fall back to local
        # validation in this case.
        return None

    except requests.exceptions.Timeout:
        # The auth server didn't respond in time.
        return None

    except Exception:
        # Catch any other unexpected errors (JSON decode errors, etc.)
        return None


# =============================================================================
# Authentication & Authorization Decorators
# =============================================================================

def require_token(f):
    """
    Decorator: Require a Valid Bearer Token
    ========================================

    This decorator implements the "Resource Server" pattern from OAuth 2.0.
    Every protected endpoint should be wrapped with this decorator.

    What it does, step by step:
      1. Extracts the token from the Authorization header.
         The header format is: "Authorization: Bearer <token>"
         This is defined in RFC 6750 (Bearer Token Usage).

      2. Validates the token using one of two approaches:
         - Local validation (default): Fast, no network call.
         - Introspection (if ?introspect=true): Thorough, checks blocklist.
         The query parameter lets you test both approaches in this demo.

      3. Attaches the token payload to the request object as
         request.token_payload, so downstream code can access claims
         like 'sub' (user ID) and 'scopes'.

    Why "Bearer"?
      "Bearer" means "whoever bears (carries) this token gets access."
      It's like a concert ticket — the venue doesn't check your ID,
      just whether you have a valid ticket. This is why tokens must be
      kept secret: anyone who has the token can use it.

    Usage:
      @app.route('/protected')
      @require_token
      def protected():
          user_id = request.token_payload['sub']
          ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # ─── Step 1: Extract the token from the Authorization header ─────
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({
                'error': 'missing_token',
                'error_description': (
                    'No Authorization header found. '
                    'Send your access token as: Authorization: Bearer <token>'
                )
            }), 401

        # Split "Bearer <token>" into parts
        parts = auth_header.split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({
                'error': 'invalid_header',
                'error_description': (
                    'Authorization header must be in the format: Bearer <token>'
                )
            }), 401

        token = parts[1]

        # ─── Step 2: Validate the token ──────────────────────────────────
        # Check if the caller wants to use introspection instead of local
        # validation. In a real app, you'd configure this at the server level,
        # not per-request. The query param is just for demo purposes.
        use_introspection = request.args.get('introspect', '').lower() == 'true'

        if use_introspection:
            # Introspection path: ask the auth server
            payload = validate_token_via_introspection(token)
            if not payload:
                return jsonify({
                    'error': 'invalid_token',
                    'error_description': (
                        'Token introspection failed. The token may be expired, '
                        'revoked, or the auth server may be unreachable.'
                    ),
                    'validation_method': 'introspection'
                }), 401
        else:
            # Local validation path: decode the JWT ourselves
            payload = validate_token_locally(token)
            if not payload:
                return jsonify({
                    'error': 'invalid_token',
                    'error_description': (
                        'Token validation failed. The token may be expired, '
                        'malformed, or signed with a different key.'
                    ),
                    'validation_method': 'local'
                }), 401

        # ─── Step 3: Attach payload to request ───────────────────────────
        # This makes the token's claims available to the endpoint handler.
        # The most important claim is 'sub' (subject) — the user's ID.
        request.token_payload = payload

        return f(*args, **kwargs)

    return decorated


def require_scope(*required_scopes):
    """
    Decorator: Require Specific OAuth Scopes
    =========================================

    Scopes are OAuth 2.0's permission system. When a client requests a token,
    it asks for specific scopes (e.g., "read write"). The auth server may
    grant all, some, or none of the requested scopes. The resource server
    then checks that the token has the scopes needed for each endpoint.

    This is DIFFERENT from role-based access control (RBAC):
      - RBAC: "Is the user an admin?" (based on WHO they are)
      - Scopes: "Does the token have 'write' permission?" (based on WHAT
        the token was granted)

    A user might have admin role but a token with only 'read' scope — if the
    client only asked for 'read', that's all the token gets. This is the
    principle of LEAST PRIVILEGE: tokens should only have the permissions
    they actually need.

    FORMAT HANDLING:
      Scopes come in different formats depending on validation method:
      - Local validation: scopes are a LIST   -> ["read", "write"]
        (because our JWT stores them as a JSON array)
      - Introspection:    scope is a STRING   -> "read write"
        (because RFC 7662 returns a space-separated string)
      This decorator handles both formats transparently.

    Usage:
      @app.route('/tasks', methods=['POST'])
      @require_token
      @require_scope('write')
      def create_task():
          ...

    Args:
        *required_scopes: One or more scope strings that the token MUST have.
                          ALL listed scopes must be present (AND logic).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            payload = getattr(request, 'token_payload', None)

            if not payload:
                # This shouldn't happen if @require_token is applied first,
                # but we check defensively.
                return jsonify({
                    'error': 'missing_token',
                    'error_description': 'No token payload found. Apply @require_token before @require_scope.'
                }), 401

            # ─── Extract scopes from the token payload ───────────────────
            # Handle both formats:
            #   - Local validation:  payload['scopes'] = ["read", "write"]
            #   - Introspection:     payload['scope']  = "read write"
            token_scopes = payload.get('scopes', [])

            if isinstance(token_scopes, str):
                # Introspection format: space-separated string
                token_scopes = token_scopes.split()
            elif not isinstance(token_scopes, list):
                token_scopes = []

            # Also check the 'scope' key (singular) for introspection responses
            scope_string = payload.get('scope', '')
            if isinstance(scope_string, str) and scope_string:
                # Merge any scopes from the 'scope' field
                token_scopes = list(set(token_scopes + scope_string.split()))

            # ─── Check that ALL required scopes are present ──────────────
            missing_scopes = [s for s in required_scopes if s not in token_scopes]

            if missing_scopes:
                return jsonify({
                    'error': 'insufficient_scope',
                    'error_description': (
                        f'This endpoint requires the following scopes: '
                        f'{", ".join(required_scopes)}. '
                        f'Your token is missing: {", ".join(missing_scopes)}. '
                        f'Your token has: {", ".join(token_scopes) or "(none)"}.'
                    ),
                    'required_scopes': list(required_scopes),
                    'token_scopes': token_scopes,
                    'missing_scopes': missing_scopes,
                }), 403

            return f(*args, **kwargs)

        return decorated
    return decorator


# =============================================================================
# Database Initialization
# =============================================================================

@app.before_request
def create_tables():
    """
    Create database tables on first request.

    This is the same pattern used in the auth server. On the very first
    request, we create all tables defined by our SQLAlchemy models.
    In production, you'd use a migration tool like Alembic instead.
    """
    if not hasattr(app, '_tables_created'):
        db.create_all()
        app._tables_created = True


# =============================================================================
# Task Endpoints
# =============================================================================

@app.route('/tasks', methods=['GET'])
@require_token
@require_scope('read')
def list_tasks():
    """
    List Tasks for the Authenticated User
    ======================================

    GET /tasks
    Required scope: read

    This endpoint returns ONLY the tasks belonging to the authenticated user.
    User data isolation is enforced by filtering on the 'sub' claim from the JWT.

    Why filter by user_id from the token?
    ------------------------------------
    Every user should only see their own tasks. We enforce this by:
      1. Extracting the user_id from the VALIDATED JWT (request.token_payload['sub'])
      2. Filtering the database query: WHERE user_id = <token's sub claim>

    This means:
      - User A's token will only return User A's tasks.
      - Even if User A guesses User B's user_id, they can't pass it in —
        the filter always uses the token's 'sub' claim, not user input.

    This is a fundamental security pattern: NEVER trust the client to tell
    you who they are. Always derive identity from the validated token.
    """
    # Extract user_id from the validated token's 'sub' (subject) claim.
    # This is the user's unique identifier, set by the auth server when
    # the token was issued. It cannot be forged.
    user_id = request.token_payload['sub']

    # Query tasks belonging ONLY to this user
    tasks = Task.query.filter_by(user_id=user_id).order_by(Task.created_at.desc()).all()

    return jsonify({
        'tasks': [task.to_dict() for task in tasks],
        'count': len(tasks),
        'user_id': user_id,
    }), 200


@app.route('/tasks', methods=['POST'])
@require_token
@require_scope('write')
def create_task():
    """
    Create a New Task
    =================

    POST /tasks
    Required scope: write
    Request body: { "title": "Buy groceries" }

    CRITICAL SECURITY POINT — user_id comes from the token, NEVER the request body:
    ---------------------------------------------------------------------------------
    You might think: "Why not let the client send user_id in the JSON body?"

    Because the client could lie! A malicious client could send:
      { "title": "Steal data", "user_id": "42" }
    and create a task in someone else's account.

    Instead, we ALWAYS extract user_id from the validated JWT's 'sub' claim.
    The JWT is cryptographically signed by the auth server — the client
    cannot modify it without invalidating the signature.

    Even if the request body contains a 'user_id' field, we IGNORE it.
    """
    data = request.get_json()

    if not data or not data.get('title'):
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Request body must include a "title" field.'
        }), 400

    # ALWAYS get user_id from the token, NEVER from the request body.
    # Even if the client sends user_id in the body, we ignore it.
    user_id = request.token_payload['sub']

    task = Task(
        user_id=user_id,
        title=data['title'],
        # 'completed' defaults to False in the model
    )

    db.session.add(task)
    db.session.commit()

    return jsonify({
        'message': 'Task created successfully',
        'task': task.to_dict(),
    }), 201


@app.route('/tasks/<int:task_id>', methods=['PUT'])
@require_token
@require_scope('write')
def update_task(task_id):
    """
    Update an Existing Task
    =======================

    PUT /tasks/<id>
    Required scope: write
    Request body: { "title": "Updated title", "completed": true }

    IDOR PREVENTION — Ownership Check:
    -----------------------------------
    IDOR stands for "Insecure Direct Object Reference." It's a vulnerability
    where an attacker can access or modify another user's resources by
    guessing or enumerating IDs.

    Example of a VULNERABLE endpoint:
      task = Task.query.get(task_id)  # <-- WRONG! No ownership check!
      task.title = data['title']

    This would let User A update User B's tasks just by guessing the task ID.

    Our SAFE approach:
      task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    By filtering on BOTH task_id AND user_id (from the token), we ensure
    that a user can only modify their own tasks. If User A tries to update
    a task belonging to User B, the query returns None and we return 404.

    Why 404 instead of 403?
      We return 404 ("Not Found") instead of 403 ("Forbidden") to avoid
      leaking information. If we returned 403, the attacker would know the
      task EXISTS but belongs to someone else. By returning 404, we reveal
      nothing about whether the task exists at all.
    """
    user_id = request.token_payload['sub']

    # Filter by BOTH task_id AND user_id to prevent IDOR attacks.
    # This is the safe way to look up a resource.
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({
            'error': 'not_found',
            'error_description': 'Task not found.'
        }), 404

    data = request.get_json()
    if not data:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Request body is required.'
        }), 400

    # Update fields if provided
    if 'title' in data:
        task.title = data['title']
    if 'completed' in data:
        task.completed = bool(data['completed'])

    db.session.commit()

    return jsonify({
        'message': 'Task updated successfully',
        'task': task.to_dict(),
    }), 200


@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@require_token
@require_scope('write')
def delete_task(task_id):
    """
    Delete a Task
    =============

    DELETE /tasks/<id>
    Required scope: write

    Same IDOR prevention as update_task: we filter by both task_id and user_id
    so users can only delete their own tasks.
    """
    user_id = request.token_payload['sub']

    # Same ownership check as update_task — filter by both id and user_id
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({
            'error': 'not_found',
            'error_description': 'Task not found.'
        }), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({
        'message': 'Task deleted successfully',
        'task_id': task_id,
    }), 200


# =============================================================================
# Client Credentials Endpoint — Machine-to-Machine Auth
# =============================================================================

@app.route('/tasks/cleanup', methods=['POST'])
def cleanup_completed_tasks():
    """
    Cleanup Completed Tasks — Demonstrates Client Credentials Flow
    ==============================================================

    POST /tasks/cleanup

    This endpoint demonstrates MACHINE-TO-MACHINE (M2M) authentication using
    the OAuth 2.0 Client Credentials grant type.

    What is Client Credentials flow?
    ---------------------------------
    In the Authorization Code flow, a USER authenticates and grants permissions
    to a client application. But what if there's no user involved? What if one
    SERVICE needs to talk to another SERVICE?

    That's what Client Credentials is for:
      - No user is involved — no browser, no login screen, no consent.
      - The service authenticates as ITSELF using its client_id and client_secret.
      - The auth server issues an access token for the service (not for a user).
      - The token's 'sub' claim will be the client_id (or None), not a user ID.

    Use cases:
      - Nightly batch jobs (e.g., cleanup completed tasks)
      - Service-to-service communication in a microservices architecture
      - Background workers that process queued jobs
      - Health checks and monitoring

    How this endpoint works:
      1. This endpoint calls the auth server's /oauth/token with:
           grant_type=client_credentials
           client_id=task-service
           client_secret=task-service-secret
           scope=write
      2. The auth server verifies the service credentials and returns an
         access token.
      3. If authentication succeeds, we proceed with the cleanup operation.
      4. We delete all completed tasks across ALL users.

    Why authenticate at all for a cleanup job?
      Even internal operations should be authenticated to:
        - Maintain audit trails (who/what triggered the cleanup?)
        - Enforce access control (only authorized services can do this)
        - Follow zero-trust principles (never assume internal = trusted)
    """
    try:
        # ─── Step 1: Authenticate as a service using Client Credentials ──
        # We send our service credentials to the auth server to get a token.
        # This is a back-channel (server-to-server) request — no browser involved.
        token_response = requests.post(
            f'{AUTH_SERVER_URL}/oauth/token',
            json={
                'grant_type': 'client_credentials',
                'client_id': SERVICE_CLIENT_ID,
                'client_secret': SERVICE_CLIENT_SECRET,
                'scope': 'write',
            },
            timeout=5
        )

        if token_response.status_code != 200:
            return jsonify({
                'error': 'service_auth_failed',
                'error_description': (
                    'Failed to authenticate as task-service via Client Credentials. '
                    'Is the auth server running? Are the service credentials correct?'
                ),
                'auth_server_status': token_response.status_code,
            }), 500

        token_data = token_response.json()

        # ─── Step 2: Perform the cleanup ─────────────────────────────────
        # Now that we've proven our identity to the auth server, we proceed
        # with the privileged operation.
        completed_tasks = Task.query.filter_by(completed=True).all()
        deleted_count = len(completed_tasks)

        for task in completed_tasks:
            db.session.delete(task)

        db.session.commit()

        # ─── Step 3: Return the result ───────────────────────────────────
        return jsonify({
            'message': f'Cleanup complete. Deleted {deleted_count} completed task(s).',
            'deleted_count': deleted_count,
            'service_authenticated': True,
            'service_client_id': SERVICE_CLIENT_ID,
            'granted_scopes': token_data.get('scope', ''),
        }), 200

    except requests.exceptions.ConnectionError:
        return jsonify({
            'error': 'auth_server_unreachable',
            'error_description': (
                f'Cannot reach the auth server at {AUTH_SERVER_URL}. '
                'Make sure the auth server is running on port 5000.'
            ),
        }), 503

    except Exception as e:
        return jsonify({
            'error': 'cleanup_failed',
            'error_description': f'An unexpected error occurred: {str(e)}',
        }), 500


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == '__main__':
    # Run on port 5002 (auth server is on 5000, client app will be on 5001)
    app.run(debug=True, host='0.0.0.0', port=5002)
