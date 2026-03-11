"""
Task Client App — An OAuth 2.0 Client Application
===================================================

This is the MAIN file of the Task Client App. It demonstrates how a CLIENT
APPLICATION implements the OAuth 2.0 Authorization Code flow with PKCE to:

  1. Authenticate users via an external auth server (delegated authentication).
  2. Obtain access tokens to call protected Resource APIs.
  3. Use OpenID Connect (OIDC) to learn the user's identity.

In the OAuth 2.0 architecture, this app is the "Client" — it acts on behalf
of the user. It NEVER stores user passwords. Instead, it redirects users to
the auth server to log in and receives tokens back.

THE THREE SERVICES:
  - Auth Server   (port 5000): Authenticates users, issues tokens.
  - Client App    (port 5001): THIS file. User-facing web app.
  - Resource API  (port 5002): Hosts protected resources (tasks).

FLOW OVERVIEW (Authorization Code + PKCE):
  1. User clicks "Login" on the client app.
  2. Client generates PKCE code_verifier + code_challenge.
  3. Client redirects user to auth server's /oauth/authorize endpoint.
  4. User authenticates on the auth server and approves the client.
  5. Auth server redirects back to client with an authorization code.
  6. Client exchanges code + code_verifier for tokens at /oauth/token.
  7. Client uses access_token to call the Resource API.
  8. Client uses id_token to display user information (OIDC).

NOTE: Our auth server is API-only (no HTML login page), so this client
simulates the user-facing part of the auth flow. In production, you'd be
redirected to the auth server's own login page (like Google's login screen).
"""

import os
import json
import time
import secrets
import hashlib
import base64
import logging
from functools import wraps

import jwt
import requests
from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash, jsonify
)


# =============================================================================
# Flask Application Setup
# =============================================================================

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SECRET_KEY — Used by Flask to sign session cookies
# ─────────────────────────────────────────────────────────────────────────────
# Flask stores session data in a signed cookie. The SECRET_KEY is used to
# cryptographically sign the cookie so that users cannot tamper with it.
#
# If an attacker gets this key, they can forge session cookies and impersonate
# any user. In production, this MUST be a strong, randomly generated value
# stored in an environment variable or secrets manager — never hardcoded.
# ─────────────────────────────────────────────────────────────────────────────
app.secret_key = os.environ.get('SECRET_KEY', 'client-app-secret-key-change-in-production')

# ─────────────────────────────────────────────────────────────────────────────
# JWT_SECRET_KEY — Used ONLY for decoding tokens for debug display
# ─────────────────────────────────────────────────────────────────────────────
# In a real application, the client would NOT decode JWTs — it would treat
# access tokens as opaque strings and just send them to the Resource API.
#
# We decode them here purely for the educational "Debug Info" section on the
# dashboard, so you can see what claims the tokens contain.
#
# This must match the auth server's JWT_SECRET_KEY.
# ─────────────────────────────────────────────────────────────────────────────
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')

# Configure logging for educational messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# OAuth 2.0 Client Configuration
# =============================================================================
# These values identify THIS application to the auth server. They must match
# a Client record registered in the auth server's database.
#
# KEY CONCEPTS:
#   - client_id: A public identifier for this app. It's not secret — it
#     appears in URLs and authorization requests.
#   - client_secret: A secret shared between this app and the auth server.
#     NEVER expose this in client-side code (JavaScript). It's safe here
#     because this is a server-side app (Python/Flask).
#   - redirect_uri: Where the auth server sends the user after authorization.
#     This MUST match exactly what's registered in the auth server. If it
#     doesn't match, the auth server will reject the request. This prevents
#     "open redirect" attacks where an attacker tricks the auth server into
#     sending tokens to a malicious URL.
#   - scopes: The permissions this app requests:
#       - 'read':    Read tasks from the Resource API.
#       - 'write':   Create/update/delete tasks on the Resource API.
#       - 'openid':  Request an ID Token (OIDC — proves user identity).
#       - 'profile': Request profile claims (username, etc.) in the ID Token.
#       - 'email':   Request email claims in the ID Token.
# =============================================================================

OAUTH_CONFIG = {
    "client_id": "task-client",
    "client_secret": "task-client-secret",
    "auth_server_url": "http://localhost:5000",
    "resource_api_url": "http://localhost:5002",
    "redirect_uri": "http://localhost:5001/callback",
    "scopes": "read write openid profile email",
}


# =============================================================================
# PKCE (Proof Key for Code Exchange) Helpers
# =============================================================================
# PKCE (pronounced "pixy") is an extension to the Authorization Code flow
# that protects against authorization code interception attacks.
#
# THE PROBLEM PKCE SOLVES:
#   In the basic Authorization Code flow, the auth server sends an
#   authorization code to the client's redirect_uri. If an attacker
#   intercepts this code (e.g., via a malicious app registered with
#   the same custom URL scheme on a mobile device), they could exchange
#   it for tokens — because all they need is the code + client_secret.
#
# HOW PKCE WORKS:
#   1. BEFORE starting the flow, the client generates a random string
#      called the "code_verifier" (high entropy, 43-128 characters).
#   2. The client computes a "code_challenge" by hashing the verifier
#      with SHA-256 and base64url-encoding the result.
#   3. The client sends the code_challenge in the authorization request.
#   4. The auth server stores the code_challenge with the authorization code.
#   5. When exchanging the code for tokens, the client sends the original
#      code_verifier (NOT the challenge).
#   6. The auth server hashes the verifier and compares it to the stored
#      challenge. If they match, the exchange succeeds.
#
# WHY THIS IS SECURE:
#   Even if an attacker intercepts the authorization code, they don't have
#   the code_verifier (it was never sent over the redirect). Without the
#   verifier, they can't complete the token exchange. The code_challenge
#   is a one-way hash, so they can't reverse it to get the verifier.
#
# S256 METHOD:
#   code_challenge = BASE64URL(SHA256(code_verifier))
#   This is the recommended method. The "plain" method (where the challenge
#   equals the verifier) exists but provides no security benefit.
# =============================================================================

def generate_pkce_pair():
    """
    Generate a PKCE code_verifier and code_challenge pair.

    Returns:
        tuple: (code_verifier, code_challenge)
            - code_verifier:  A cryptographically random string (43 chars).
                              Stored in the session, sent later during token exchange.
            - code_challenge: SHA256 hash of the verifier, base64url-encoded.
                              Sent with the authorization request.
    """
    # Step 1: Generate the code_verifier — a high-entropy random string.
    # secrets.token_urlsafe(32) produces a 43-character URL-safe string.
    # The OAuth spec requires 43-128 characters.
    code_verifier = secrets.token_urlsafe(32)

    # Step 2: Compute the code_challenge using the S256 method.
    # S256 = BASE64URL(SHA256(ASCII(code_verifier)))
    #
    # Why SHA256?
    #   It's a one-way hash — you can go from verifier -> challenge, but
    #   not from challenge -> verifier. This means even if someone sees
    #   the challenge (it's in the authorization URL), they can't derive
    #   the verifier needed for the token exchange.
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()

    # Step 3: Base64url-encode the hash (RFC 4648 Section 5).
    # We must strip the '=' padding because the OAuth spec forbids it.
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    logger.info(
        f"PKCE pair generated: verifier length={len(code_verifier)}, "
        f"challenge length={len(code_challenge)}"
    )

    return code_verifier, code_challenge


# =============================================================================
# Token Management Utilities
# =============================================================================

def get_user_info():
    """
    Extract user information from the OIDC ID Token stored in the session.

    The ID Token is a JWT issued by the auth server when the 'openid' scope
    is requested. It contains identity claims about the user:
      - 'sub':                User ID (subject identifier)
      - 'preferred_username': The user's display name
      - 'username':           Alternative username claim
      - 'role':               User's role (custom claim from our auth server)

    We decode the ID Token here to populate the session with user info
    for display in the UI (nav bar, dashboard, etc.).

    Returns:
        dict: User info extracted from the ID Token, or a fallback dict.
    """
    id_token = session.get('id_token')
    if not id_token:
        # No ID token — fall back to decoding the access token.
        # The access token also contains user claims in our implementation,
        # but in production, access tokens might be opaque (not JWTs).
        access_token = session.get('access_token')
        if not access_token:
            return {'username': 'Unknown', 'role': 'unknown'}
        try:
            # Decode without verification — we just need the claims for display.
            # In production, you'd verify the signature. We skip it here because
            # this is just for UI display, not for security decisions.
            payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=['HS256'])
            return {
                'username': payload.get('username', 'Unknown'),
                'role': payload.get('role', 'user'),
                'user_id': payload.get('sub'),
            }
        except jwt.InvalidTokenError:
            return {'username': 'Unknown', 'role': 'unknown'}

    try:
        # Decode the ID Token to extract identity claims.
        payload = jwt.decode(id_token, JWT_SECRET_KEY, algorithms=['HS256'])
        return {
            'username': payload.get('preferred_username', payload.get('username', 'Unknown')),
            'role': payload.get('role', 'user'),
            'user_id': payload.get('sub'),
            'email': payload.get('email'),
        }
    except jwt.InvalidTokenError:
        return {'username': 'Unknown', 'role': 'unknown'}


def refresh_access_token():
    """
    Use the refresh token to obtain a new access token.

    WHY REFRESH TOKENS EXIST:
    -------------------------
    Access tokens are intentionally short-lived (e.g., 15 minutes) to limit
    the damage if one is stolen. But we don't want users to re-login every
    15 minutes. Refresh tokens solve this:

      - Access Token:  Short-lived (15 min). Sent with every API request.
                       If stolen, the attacker has a small window to use it.
      - Refresh Token: Long-lived (7 days). Stored securely, used ONLY to
                       get new access tokens from the auth server.

    THE REFRESH FLOW:
      1. Client detects the access token is expired (or gets a 401 from the API).
      2. Client sends the refresh token to the auth server's /oauth/token endpoint
         with grant_type=refresh_token.
      3. Auth server validates the refresh token and issues a new access token.
      4. Client stores the new access token and retries the API request.

    If the refresh token is also expired or revoked, the user must log in again.

    Returns:
        bool: True if refresh succeeded, False otherwise.
    """
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        logger.warning("No refresh token in session — cannot refresh.")
        return False

    try:
        # Call the auth server's token endpoint with grant_type=refresh_token.
        # We also send our client_id and client_secret to authenticate as
        # this OAuth client (the auth server needs to know WHO is refreshing).
        response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/token",
            json={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': OAUTH_CONFIG['client_id'],
                'client_secret': OAUTH_CONFIG['client_secret'],
            },
            timeout=5,
        )

        if response.status_code == 200:
            token_data = response.json()
            # Update the session with the new access token.
            session['access_token'] = token_data['access_token']
            # Update user info in case claims changed.
            session['user_info'] = get_user_info()
            logger.info("Access token refreshed successfully.")
            return True
        else:
            logger.warning(
                f"Token refresh failed: {response.status_code} — {response.text}"
            )
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Token refresh request failed: {e}")
        return False


def login_required(f):
    """
    Decorator: Require an authenticated session with a valid access token.

    This decorator protects routes that need a logged-in user. It checks:

      1. Is there an access_token in the Flask session?
         If not, the user hasn't logged in — redirect to /login.

      2. Is the access token expired?
         If yes, try to refresh it using the refresh token.
         If refresh fails, clear the session and redirect to /login.

    WHY CHECK EXPIRATION HERE?
      The Resource API will also reject expired tokens (with a 401). But
      checking here first provides a better user experience — we can
      silently refresh the token before making the API call, rather than
      showing the user an error and making them retry.

    Usage:
        @app.route('/dashboard')
        @login_required
        def dashboard():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = session.get('access_token')

        if not access_token:
            # No token in session — user is not logged in.
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))

        # Check if the access token is expired by decoding it.
        # We decode with verification to also catch invalid tokens.
        try:
            jwt.decode(access_token, JWT_SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            # Token is expired — try to refresh it.
            logger.info("Access token expired — attempting refresh.")
            if not refresh_access_token():
                # Refresh failed — session is dead, user must re-login.
                session.clear()
                flash('Your session has expired. Please log in again.', 'error')
                return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            # Token is invalid (corrupted, wrong signature, etc.).
            session.clear()
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# Routes
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# GET / — Landing Page
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """
    Landing page. If the user is already logged in (has an access_token in
    their session), redirect them to the dashboard. Otherwise, show the
    landing page with the "Login with Auth Server" button.
    """
    if session.get('access_token'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# ─────────────────────────────────────────────────────────────────────────────
# GET+POST /login — Two-Phase Login (OAuth Authorization Code + PKCE)
# ─────────────────────────────────────────────────────────────────────────────
# This route has two phases:
#
# PHASE 1 (GET): Prepare for the OAuth flow.
#   - Generate PKCE code_verifier and code_challenge.
#   - Generate a random 'state' parameter for CSRF protection.
#   - Store both in the session.
#   - Show the login form.
#
# PHASE 2 (POST): Execute the OAuth flow.
#   - Authenticate the user via the auth server's /auth/login API.
#   - Call the auth server's /oauth/authorize to get an authorization code.
#   - Redirect to our /callback with the authorization code.
#
# IN REAL OAUTH:
#   Phase 1 would redirect the browser to the auth server's /oauth/authorize.
#   The auth server would show its own login page, authenticate the user,
#   ask for consent, and redirect back to our /callback.
#
#   Because our auth server is API-only, we simulate this by:
#     1. Collecting credentials in our own form (NOT standard OAuth!).
#     2. Calling the auth server's /auth/login API to authenticate.
#     3. Calling /oauth/authorize with the user's token to get the code.
#     4. Redirecting to /callback as if the auth server did it.
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle the OAuth 2.0 Authorization Code flow with PKCE."""

    if request.method == 'GET':
        # ─── PHASE 1: Generate PKCE pair and state, show login form ──────

        # Generate PKCE parameters.
        # The code_verifier is stored in the session and NEVER sent to the
        # auth server during authorization. Only the code_challenge is sent.
        code_verifier, code_challenge = generate_pkce_pair()
        session['code_verifier'] = code_verifier
        session['code_challenge'] = code_challenge

        # Generate a random 'state' parameter for CSRF protection.
        # STATE PARAMETER — WHY IT MATTERS:
        #   Without a state parameter, an attacker could:
        #     1. Start an OAuth flow on their own machine.
        #     2. Get an authorization code from the auth server.
        #     3. Trick the victim into visiting /callback?code=<attacker's code>.
        #     4. The victim's client app would exchange the code and log in
        #        as the attacker — the attacker now has access to the victim's
        #        session (CSRF attack).
        #
        #   The state parameter prevents this:
        #     - We generate a random value and store it in the session.
        #     - We include it in the authorization request.
        #     - When the callback comes, we check that the state matches.
        #     - An attacker can't forge this because they don't have access
        #       to the victim's session.
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state

        logger.info(
            f"Login GET: PKCE and state generated. "
            f"State={state[:8]}..., Challenge={code_challenge[:8]}..."
        )

        return render_template('login.html', next_url=request.args.get('next', ''))

    # ─── PHASE 2: Execute the OAuth flow ─────────────────────────────────
    # The user has submitted the login form with their credentials.

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('login'))

    # ── Step 1: Authenticate user via auth server's /auth/login API ──────
    # In real OAuth, the auth server handles this on its own login page.
    # We're calling the API because our auth server is API-only.
    #
    # IMPORTANT: In production, a client app should NEVER handle user
    # credentials. The whole point of OAuth is that the user authenticates
    # DIRECTLY with the auth server.
    try:
        logger.info(f"Step 1: Authenticating user '{username}' via auth server /auth/login")

        login_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/auth/login",
            json={'username': username, 'password': password},
            timeout=5,
        )

        if login_response.status_code != 200:
            error_msg = login_response.json().get('error', 'Authentication failed')
            flash(f'Login failed: {error_msg}', 'error')
            return redirect(url_for('login'))

        # Extract the user's token from the login response.
        # This token proves the user's identity to the auth server's
        # /oauth/authorize endpoint.
        login_data = login_response.json()
        user_token = login_data['access_token']

        logger.info(f"Step 1 complete: User '{username}' authenticated with auth server.")

    except requests.exceptions.RequestException as e:
        logger.error(f"Auth server unreachable: {e}")
        flash('Cannot reach the auth server. Is it running on port 5000?', 'error')
        return redirect(url_for('login'))

    # ── Step 2: Call /oauth/authorize (GET) to validate OAuth params ──────
    # In real OAuth, the browser would navigate to this URL directly.
    # The auth server checks:
    #   - Is the client_id valid?
    #   - Is the redirect_uri registered for this client?
    #   - Are the requested scopes allowed?
    #   - Is the user authenticated? (We send the user_token as Bearer)
    try:
        logger.info("Step 2: Calling GET /oauth/authorize to validate OAuth parameters")

        authorize_params = {
            'client_id': OAUTH_CONFIG['client_id'],
            'redirect_uri': OAUTH_CONFIG['redirect_uri'],
            'response_type': 'code',  # Authorization Code flow
            'scope': OAUTH_CONFIG['scopes'],
            'state': session['oauth_state'],
            'code_challenge': session['code_challenge'],
            'code_challenge_method': 'S256',
        }

        # Send the user's token as a Bearer token to prove their identity
        # to the authorization endpoint.
        authorize_response = requests.get(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/authorize",
            params=authorize_params,
            headers={'Authorization': f'Bearer {user_token}'},
            timeout=5,
            allow_redirects=False,  # Don't follow redirects — we handle them
        )

        logger.info(
            f"Step 2 complete: Authorization server responded with "
            f"status {authorize_response.status_code}"
        )

    except requests.exceptions.RequestException as e:
        logger.error(f"Authorization request failed: {e}")
        flash('Authorization request to auth server failed.', 'error')
        return redirect(url_for('login'))

    # ── Step 3: Call /oauth/authorize (POST) to approve authorization ─────
    # In real OAuth, the user would click an "Approve" button on the auth
    # server's consent page. We simulate this by POSTing authorize=true.
    #
    # WHY TWO STEPS (GET then POST)?
    #   GET:  "Show me what this client wants" — the auth server validates
    #         the request and shows a consent page.
    #   POST: "I approve" — the user confirms, and the auth server generates
    #         an authorization code.
    try:
        logger.info("Step 3: POSTing authorization approval to /oauth/authorize")

        approve_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/authorize",
            data={
                'authorize': 'true',
                'client_id': OAUTH_CONFIG['client_id'],
                'redirect_uri': OAUTH_CONFIG['redirect_uri'],
                'state': session['oauth_state'],
                'scopes': OAUTH_CONFIG['scopes'],
                'code_challenge': session['code_challenge'],
                'code_challenge_method': 'S256',
            },
            headers={'Authorization': f'Bearer {user_token}'},
            timeout=5,
            allow_redirects=False,  # Capture the redirect, don't follow it
        )

        # The auth server responds with a 302 redirect to our callback URL.
        # The redirect URL contains the authorization code and state parameter.
        # Example: http://localhost:5001/callback?code=abc123&state=xyz789
        if approve_response.status_code in (302, 303):
            redirect_url = approve_response.headers.get('Location')
            logger.info(
                f"Step 3 complete: Auth server redirecting to {redirect_url[:60]}..."
            )
            # Redirect the user's browser to our callback URL.
            # This is where we'll exchange the code for tokens.
            return redirect(redirect_url)
        else:
            logger.error(
                f"Authorization approval failed: {approve_response.status_code} "
                f"— {approve_response.text[:200]}"
            )
            flash('Authorization failed. The auth server did not approve the request.', 'error')
            return redirect(url_for('login'))

    except requests.exceptions.RequestException as e:
        logger.error(f"Authorization approval request failed: {e}")
        flash('Authorization approval failed.', 'error')
        return redirect(url_for('login'))


# ─────────────────────────────────────────────────────────────────────────────
# GET /callback — OAuth Callback (Authorization Code Exchange)
# ─────────────────────────────────────────────────────────────────────────────
# This is the most critical endpoint in the OAuth flow. The auth server
# redirects the user here after they approve (or deny) authorization.
#
# THE CALLBACK URL LOOKS LIKE:
#   http://localhost:5001/callback?code=abc123&state=xyz789
#
# WHAT HAPPENS HERE:
#   1. Check for errors (did the user deny? did something go wrong?).
#   2. Verify the state parameter (CSRF protection).
#   3. Extract the authorization code from the query parameters.
#   4. Exchange the code for tokens at the auth server's /oauth/token endpoint.
#   5. Store the tokens in the session.
#
# SECURITY NOTES:
#   - The authorization code is one-time-use and short-lived (typically 10 min).
#   - The code exchange happens server-to-server (back-channel), so the tokens
#     are never exposed to the user's browser.
#   - PKCE ensures that even if someone intercepted the code, they can't
#     exchange it without the code_verifier (which is in our session).
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/callback')
def callback():
    """Handle the OAuth 2.0 authorization callback."""

    # ── Step 1: Check for errors ─────────────────────────────────────────
    # If the user denied authorization or something went wrong, the auth
    # server includes an 'error' parameter in the callback URL.
    # Example: /callback?error=access_denied&error_description=User+denied
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        logger.warning(f"OAuth callback error: {error} — {error_description}")
        flash(f'Authorization failed: {error_description}', 'error')
        return redirect(url_for('index'))

    # ── Step 2: Verify the state parameter (CSRF protection) ─────────────
    # The state we sent in the authorization request must match the state
    # returned in the callback. If they don't match, this could be a CSRF
    # attack — someone is trying to inject an authorization code into our flow.
    returned_state = request.args.get('state')
    stored_state = session.get('oauth_state')

    if not returned_state or returned_state != stored_state:
        logger.error(
            f"State mismatch! Returned: {returned_state}, "
            f"Stored: {stored_state}. Possible CSRF attack."
        )
        flash('Security error: state parameter mismatch. Please try again.', 'error')
        return redirect(url_for('index'))

    logger.info("Step 1-2: Callback received, state verified.")

    # ── Step 3: Extract the authorization code ───────────────────────────
    # The authorization code is a short-lived, one-time-use credential that
    # the auth server generated when the user approved the authorization.
    # We exchange it for the actual tokens in the next step.
    code = request.args.get('code')
    if not code:
        flash('No authorization code received.', 'error')
        return redirect(url_for('index'))

    logger.info(f"Step 3: Authorization code received: {code[:8]}...")

    # ── Step 4: Exchange the authorization code for tokens ────────────────
    # This is the "token exchange" — the final step of the Authorization
    # Code flow. We POST to the auth server's /oauth/token endpoint with:
    #
    #   - grant_type:     "authorization_code" — tells the auth server
    #                     which flow we're completing.
    #   - code:           The authorization code from Step 3.
    #   - redirect_uri:   Must match what we sent in the authorization request.
    #                     The auth server checks this to prevent code injection.
    #   - client_id:      Identifies our application.
    #   - client_secret:  Proves we are who we claim to be (server-to-server).
    #   - code_verifier:  The PKCE code_verifier. The auth server hashes it
    #                     and compares to the code_challenge from Step 2.
    #
    # This request goes directly from our server to the auth server (back-channel).
    # The user's browser is NOT involved — the tokens never pass through it.
    try:
        logger.info("Step 4: Exchanging authorization code for tokens at /oauth/token")

        token_response = requests.post(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/token",
            json={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': OAUTH_CONFIG['redirect_uri'],
                'client_id': OAUTH_CONFIG['client_id'],
                'client_secret': OAUTH_CONFIG['client_secret'],
                'code_verifier': session.get('code_verifier'),
            },
            timeout=5,
        )

        if token_response.status_code != 200:
            error_data = token_response.json()
            error_msg = error_data.get('error_description', error_data.get('error', 'Token exchange failed'))
            logger.error(f"Token exchange failed: {error_msg}")
            flash(f'Token exchange failed: {error_msg}', 'error')
            return redirect(url_for('index'))

        token_data = token_response.json()
        logger.info(
            f"Step 4 complete: Received tokens — "
            f"access_token={'yes' if token_data.get('access_token') else 'no'}, "
            f"refresh_token={'yes' if token_data.get('refresh_token') else 'no'}, "
            f"id_token={'yes' if token_data.get('id_token') else 'no'}"
        )

    except requests.exceptions.RequestException as e:
        logger.error(f"Token exchange request failed: {e}")
        flash('Failed to exchange authorization code for tokens.', 'error')
        return redirect(url_for('index'))

    # ── Step 5: Store tokens in the session ──────────────────────────────
    # We store three tokens:
    #   - access_token:  Sent to the Resource API as a Bearer token.
    #   - refresh_token: Used to get new access tokens when they expire.
    #   - id_token:      OIDC identity token — tells us WHO the user is.
    #
    # IMPORTANT: Tokens in Flask sessions are stored in signed cookies.
    # This means:
    #   - They are tamper-proof (Flask signs them with SECRET_KEY).
    #   - They are NOT encrypted — anyone can base64-decode the cookie and
    #     read the tokens. In production, use server-side sessions (Redis,
    #     database) instead of cookie-based sessions.
    session['access_token'] = token_data.get('access_token')
    session['refresh_token'] = token_data.get('refresh_token')
    session['id_token'] = token_data.get('id_token')

    # Extract user info from the ID token and store it for UI display.
    session['user_info'] = get_user_info()

    # Clean up PKCE and state from the session — they're single-use.
    session.pop('code_verifier', None)
    session.pop('code_challenge', None)
    session.pop('oauth_state', None)

    logger.info(
        f"OAuth flow complete! User '{session['user_info'].get('username')}' "
        f"is now logged in."
    )

    flash('Login successful!', 'success')
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# GET /dashboard — Authenticated Dashboard
# ─────────────────────────────────────────────────────────────────────────────
# This is the main page after login. It demonstrates:
#   1. Calling the Resource API with a Bearer token (fetch tasks).
#   2. Calling the OIDC UserInfo endpoint (get user profile).
#   3. Decoding tokens for educational debug display.
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the authenticated dashboard with tasks and debug info."""

    access_token = session.get('access_token')

    # ── 1. Fetch tasks from the Resource API ─────────────────────────────
    # We call GET http://localhost:5002/tasks with the access token as a
    # Bearer token. The Resource API:
    #   a. Validates the JWT signature and expiration.
    #   b. Checks that the token has the 'read' scope.
    #   c. Returns only tasks belonging to the user identified by 'sub'.
    tasks = []
    try:
        tasks_response = requests.get(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks",
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        )

        if tasks_response.status_code == 200:
            tasks = tasks_response.json().get('tasks', [])
        elif tasks_response.status_code == 401:
            # Token might be expired — try refreshing and retry.
            if refresh_access_token():
                access_token = session['access_token']
                retry = requests.get(
                    f"{OAUTH_CONFIG['resource_api_url']}/tasks",
                    headers={'Authorization': f'Bearer {access_token}'},
                    timeout=5,
                )
                if retry.status_code == 200:
                    tasks = retry.json().get('tasks', [])
                else:
                    flash('Failed to fetch tasks after token refresh.', 'error')
            else:
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('logout_action'))
        else:
            flash(f'Failed to fetch tasks (HTTP {tasks_response.status_code}).', 'error')

    except requests.exceptions.RequestException as e:
        flash(f'Cannot reach the Task API. Is it running on port 5002? Error: {e}', 'error')

    # ── 2. Call the OIDC UserInfo endpoint ────────────────────────────────
    # GET /oauth/userinfo on the auth server with the access token.
    # This returns the user's current profile claims.
    userinfo = {}
    try:
        userinfo_response = requests.get(
            f"{OAUTH_CONFIG['auth_server_url']}/oauth/userinfo",
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        )
        if userinfo_response.status_code == 200:
            userinfo = userinfo_response.json()
    except requests.exceptions.RequestException:
        userinfo = {'error': 'Could not reach the auth server UserInfo endpoint.'}

    # ── 3. Decode tokens for debug display ────────────────────────────────
    # In production, clients treat access tokens as OPAQUE strings — they
    # just pass them along to APIs without looking inside. We decode them
    # here purely for educational purposes.
    access_token_claims = _safe_decode_token(access_token, 'Access Token')
    id_token_claims = _safe_decode_token(session.get('id_token'), 'ID Token')

    return render_template(
        'dashboard.html',
        tasks=tasks,
        access_token_claims=json.dumps(access_token_claims, indent=2, default=str),
        id_token_claims=json.dumps(id_token_claims, indent=2, default=str),
        userinfo_data=json.dumps(userinfo, indent=2, default=str),
    )


def _safe_decode_token(token, label):
    """
    Safely decode a JWT for debug display. Returns the claims dict or
    an error message if decoding fails.
    """
    if not token:
        return {'note': f'No {label} available.'}
    try:
        # Decode with full verification for display.
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        # Even if expired, we can still decode the payload for display.
        try:
            return jwt.decode(
                token, JWT_SECRET_KEY, algorithms=['HS256'],
                options={'verify_exp': False}
            )
        except Exception:
            return {'error': f'{label} could not be decoded.'}
    except jwt.InvalidTokenError as e:
        return {'error': f'{label} is invalid: {str(e)}'}


# ─────────────────────────────────────────────────────────────────────────────
# POST /tasks — Create a Task via the Resource API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/tasks', methods=['POST'])
@login_required
def create_task():
    """
    Create a task by calling the Resource API.

    This demonstrates the client acting as a PROXY:
      1. User submits the form on this app.
      2. This app calls POST /tasks on the Resource API with the Bearer token.
      3. The Resource API validates the token and creates the task.
      4. We redirect back to the dashboard.

    The access token's 'sub' claim tells the Resource API which user is
    creating the task. The 'write' scope authorizes the operation.
    """
    title = request.form.get('title', '').strip()
    if not title:
        flash('Task title is required.', 'error')
        return redirect(url_for('dashboard'))

    access_token = session.get('access_token')

    try:
        response = requests.post(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks",
            json={'title': title},
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        )

        if response.status_code == 201:
            flash('Task created!', 'success')
        elif response.status_code == 401:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        else:
            error = response.json().get('error_description', 'Unknown error')
            flash(f'Failed to create task: {error}', 'error')

    except requests.exceptions.RequestException as e:
        flash(f'Cannot reach the Task API: {e}', 'error')

    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# POST /tasks/<id>/complete — Mark a Task as Complete
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    """
    Mark a task as complete by calling PUT /tasks/<id> on the Resource API.

    The Resource API will:
      1. Validate the access token.
      2. Check for the 'write' scope.
      3. Verify that the task belongs to the authenticated user (IDOR prevention).
      4. Update the task's 'completed' field.
    """
    access_token = session.get('access_token')

    try:
        response = requests.put(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks/{task_id}",
            json={'completed': True},
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        )

        if response.status_code == 200:
            flash('Task marked as complete!', 'success')
        elif response.status_code == 401:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        elif response.status_code == 404:
            flash('Task not found.', 'error')
        else:
            flash('Failed to update task.', 'error')

    except requests.exceptions.RequestException as e:
        flash(f'Cannot reach the Task API: {e}', 'error')

    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# POST /tasks/<id>/delete — Delete a Task
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    """
    Delete a task by calling DELETE /tasks/<id> on the Resource API.

    Same flow as complete_task — the Resource API handles all validation,
    including ownership checks (IDOR prevention).
    """
    access_token = session.get('access_token')

    try:
        response = requests.delete(
            f"{OAUTH_CONFIG['resource_api_url']}/tasks/{task_id}",
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        )

        if response.status_code == 200:
            flash('Task deleted.', 'success')
        elif response.status_code == 401:
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))
        elif response.status_code == 404:
            flash('Task not found.', 'error')
        else:
            flash('Failed to delete task.', 'error')

    except requests.exceptions.RequestException as e:
        flash(f'Cannot reach the Task API: {e}', 'error')

    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# POST /logout — Proper OAuth Logout
# ─────────────────────────────────────────────────────────────────────────────
# Logging out in OAuth is more involved than just clearing the session cookie.
# A proper logout should:
#   1. Revoke the access token at the auth server.
#   2. Revoke the refresh token at the auth server.
#   3. Clear the local session.
#
# WHY REVOCATION IS IMPORTANT:
#   If we only clear the session cookie, the tokens are still valid on the
#   auth server. This means:
#     - If someone stole the access token, they can still use it until it expires.
#     - If someone stole the refresh token, they can get new access tokens forever.
#
#   By revoking tokens at the auth server, we ensure they are immediately
#   invalidated. The auth server adds them to a blocklist, and any future
#   use will be rejected.
#
#   This is especially important for refresh tokens, which are long-lived
#   (7 days in our setup). Without revocation, a stolen refresh token is
#   a 7-day skeleton key to the user's account.
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/logout', methods=['POST'])
def logout_action():
    """Revoke tokens at the auth server and clear the local session."""

    access_token = session.get('access_token')
    refresh_token = session.get('refresh_token')

    # ── Step 1: Revoke the access token ──────────────────────────────────
    # POST /oauth/revoke on the auth server with the access token.
    # The auth server will add it to the blocklist.
    if access_token:
        try:
            requests.post(
                f"{OAUTH_CONFIG['auth_server_url']}/oauth/revoke",
                json={'token': access_token, 'token_type_hint': 'access_token'},
                timeout=5,
            )
            logger.info("Access token revoked at auth server.")
        except requests.exceptions.RequestException:
            # If revocation fails (auth server down), we still clear the
            # local session. The token will expire naturally.
            logger.warning("Failed to revoke access token — auth server unreachable.")

    # ── Step 2: Revoke the refresh token ─────────────────────────────────
    # This is even more important than revoking the access token because
    # refresh tokens are long-lived. A stolen refresh token could be used
    # to generate new access tokens for days.
    if refresh_token:
        try:
            requests.post(
                f"{OAUTH_CONFIG['auth_server_url']}/oauth/revoke",
                json={'token': refresh_token, 'token_type_hint': 'refresh_token'},
                timeout=5,
            )
            logger.info("Refresh token revoked at auth server.")
        except requests.exceptions.RequestException:
            logger.warning("Failed to revoke refresh token — auth server unreachable.")

    # ── Step 3: Clear the local session ──────────────────────────────────
    # Remove all tokens and user info from the Flask session cookie.
    session.clear()

    logger.info("User logged out — tokens revoked, session cleared.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == '__main__':
    # Run on port 5001 (auth server = 5000, resource API = 5002).
    app.run(debug=True, host='0.0.0.0', port=5001)
