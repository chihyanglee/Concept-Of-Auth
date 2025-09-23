#!/usr/bin/env python3
"""
Auth Server Demo Script

This script demonstrates all the authentication and authorization concepts
implemented in the auth server. It shows how to use each endpoint and
explains the underlying security concepts.

Run this script after starting the auth server to see all features in action.
"""

import requests
import json
import time
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs

# Configuration
BASE_URL = "http://localhost:5000"
API_BASE = f"{BASE_URL}/auth"
OAUTH_BASE = f"{BASE_URL}/oauth"
ADMIN_BASE = f"{BASE_URL}/admin"

# Demo credentials
DEMO_USER = {
    "username": "testuser",
    "password": "testpass123"
}

DEMO_CLIENT = {
    "client_id": "demo-client",
    "client_secret": "demo-secret",
    "redirect_uri": "http://localhost:3000/callback"
}

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_response(response, description=""):
    """Print formatted API response"""
    print(f"\n{description}")
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    return code_verifier, code_challenge

def demo_core_authentication():
    """Demonstrate Phase 1: Core User Authentication"""
    print_section("PHASE 1: CORE USER AUTHENTICATION")
    
    print("\n1. User Registration")
    print("   Demonstrates secure password storage and user account creation")
    response = requests.post(f"{API_BASE}/register", json=DEMO_USER)
    print_response(response, "Register new user")
    
    print("\n2. User Login")
    print("   Demonstrates credential verification and JWT token generation")
    response = requests.post(f"{API_BASE}/login", json=DEMO_USER)
    print_response(response, "Login with credentials")
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']
        
        print("\n3. Access Protected Resource")
        print("   Demonstrates JWT token validation and user context extraction")
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{API_BASE}/me", headers=headers)
        print_response(response, "Get current user info")
        
        print("\n4. Token Refresh")
        print("   Demonstrates refresh token usage to get new access tokens")
        response = requests.post(f"{API_BASE}/refresh", json={"refresh_token": refresh_token})
        print_response(response, "Refresh access token")
        
        print("\n5. User Logout")
        print("   Demonstrates secure logout with token revocation")
        response = requests.post(f"{API_BASE}/logout", 
                               headers=headers,
                               json={"refresh_token": refresh_token})
        print_response(response, "Logout and revoke tokens")
        
        return access_token, refresh_token
    
    return None, None

def demo_oauth_flow():
    """Demonstrate Phase 2: OAuth 2.0 Authorization Code Flow with PKCE"""
    print_section("PHASE 2: OAUTH 2.0 AUTHORIZATION CODE FLOW WITH PKCE")
    
    # First, login to get a session
    print("\n1. User Login (for OAuth flow)")
    response = requests.post(f"{API_BASE}/login", json=DEMO_USER)
    if response.status_code != 200:
        print("Failed to login. Please register the user first.")
        return
    
    tokens = response.json()
    access_token = tokens['access_token']
    
    print("\n2. Generate PKCE Parameters")
    print("   Demonstrates PKCE (Proof Key for Code Exchange) for enhanced security")
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"   Code Verifier: {code_verifier}")
    print(f"   Code Challenge: {code_challenge}")
    
    print("\n3. Authorization Request")
    print("   Demonstrates OAuth 2.0 authorization request with PKCE")
    auth_params = {
        "response_type": "code",
        "client_id": DEMO_CLIENT["client_id"],
        "redirect_uri": DEMO_CLIENT["redirect_uri"],
        "scope": "read write openid profile",
        "state": secrets.token_urlsafe(16),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"{OAUTH_BASE}/authorize?{urlencode(auth_params)}"
    print(f"   Authorization URL: {auth_url}")
    
    # Simulate authorization by making a POST request with user consent
    print("\n4. User Authorization (Simulated)")
    print("   Demonstrates user consent and authorization code generation")
    auth_data = {
        "authorize": "true",
        "client_id": DEMO_CLIENT["client_id"],
        "redirect_uri": DEMO_CLIENT["redirect_uri"],
        "scopes": "read write openid profile",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(f"{OAUTH_BASE}/authorize", 
                           data=auth_data, 
                           headers=headers,
                           allow_redirects=False)
    
    if response.status_code == 302:
        # Extract authorization code from redirect URL
        redirect_url = response.headers['Location']
        parsed_url = parse_qs(redirect_url.split('?')[1])
        auth_code = parsed_url['code'][0]
        print(f"   Authorization Code: {auth_code}")
        
        print("\n5. Token Exchange")
        print("   Demonstrates authorization code exchange for access and refresh tokens")
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": DEMO_CLIENT["redirect_uri"],
            "client_id": DEMO_CLIENT["client_id"],
            "client_secret": DEMO_CLIENT["client_secret"],
            "code_verifier": code_verifier
        }
        
        response = requests.post(f"{OAUTH_BASE}/token", json=token_data)
        print_response(response, "Exchange authorization code for tokens")
        
        if response.status_code == 200:
            oauth_tokens = response.json()
            oauth_access_token = oauth_tokens['access_token']
            
            print("\n6. Access UserInfo Endpoint")
            print("   Demonstrates OpenID Connect UserInfo endpoint")
            headers = {"Authorization": f"Bearer {oauth_access_token}"}
            response = requests.get(f"{OAUTH_BASE}/userinfo", headers=headers)
            print_response(response, "Get user information via OAuth")
            
            print("\n7. Token Introspection")
            print("   Demonstrates token introspection for validation")
            response = requests.post(f"{OAUTH_BASE}/introspect", 
                                   json={"token": oauth_access_token})
            print_response(response, "Introspect OAuth access token")
            
            print("\n8. Token Revocation")
            print("   Demonstrates token revocation")
            response = requests.post(f"{OAUTH_BASE}/revoke", 
                                   json={"token": oauth_access_token})
            print_response(response, "Revoke OAuth access token")

def demo_client_credentials():
    """Demonstrate Phase 3: Client Credentials Flow"""
    print_section("PHASE 3: CLIENT CREDENTIALS FLOW")
    
    print("\n1. Client Credentials Token Request")
    print("   Demonstrates machine-to-machine authentication")
    token_data = {
        "grant_type": "client_credentials",
        "client_id": DEMO_CLIENT["client_id"],
        "client_secret": DEMO_CLIENT["client_secret"],
        "scope": "read write"
    }
    
    response = requests.post(f"{OAUTH_BASE}/token", json=token_data)
    print_response(response, "Get client credentials token")
    
    if response.status_code == 200:
        tokens = response.json()
        client_token = tokens['access_token']
        
        print("\n2. Use Client Token")
        print("   Demonstrates using client token for API access")
        headers = {"Authorization": f"Bearer {client_token}"}
        response = requests.get(f"{API_BASE}/me", headers=headers)
        print_response(response, "Access API with client token")

def demo_rbac():
    """Demonstrate Phase 4: Role-Based Access Control"""
    print_section("PHASE 4: ROLE-BASED ACCESS CONTROL (RBAC)")
    
    # Login as admin
    print("\n1. Admin Login")
    print("   Demonstrates admin role authentication")
    admin_credentials = {"username": "admin", "password": "admin123"}
    response = requests.post(f"{API_BASE}/login", json=admin_credentials)
    print_response(response, "Login as admin")
    
    if response.status_code == 200:
        admin_tokens = response.json()
        admin_token = admin_tokens['access_token']
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        print("\n2. List All Users (Admin Only)")
        print("   Demonstrates role-based access control")
        response = requests.get(f"{ADMIN_BASE}/users", headers=headers)
        print_response(response, "List all users (admin only)")
        
        print("\n3. Update User Role")
        print("   Demonstrates dynamic role management")
        # First, get the test user ID
        users_response = requests.get(f"{ADMIN_BASE}/users", headers=headers)
        if users_response.status_code == 200:
            users = users_response.json()['users']
            test_user = next((u for u in users if u['username'] == DEMO_USER['username']), None)
            if test_user:
                user_id = test_user['id']
                response = requests.put(f"{ADMIN_BASE}/users/{user_id}/role", 
                                      headers=headers,
                                      json={"role": "admin"})
                print_response(response, f"Update user {DEMO_USER['username']} role to admin")
        
        print("\n4. System Statistics")
        print("   Demonstrates admin-only system monitoring")
        response = requests.get(f"{ADMIN_BASE}/stats", headers=headers)
        print_response(response, "Get system statistics")

def demo_advanced_security():
    """Demonstrate Advanced Security Features"""
    print_section("ADVANCED SECURITY FEATURES")
    
    print("\n1. Session Management")
    print("   Demonstrates concurrent session tracking")
    
    # Login multiple times to create multiple sessions
    response1 = requests.post(f"{API_BASE}/login", json=DEMO_USER)
    response2 = requests.post(f"{API_BASE}/login", json=DEMO_USER)
    
    if response1.status_code == 200 and response2.status_code == 200:
        token1 = response1.json()['access_token']
        token2 = response2.json()['access_token']
        
        # Login as admin to view sessions
        admin_response = requests.post(f"{API_BASE}/login", 
                                     json={"username": "admin", "password": "admin123"})
        if admin_response.status_code == 200:
            admin_token = admin_response.json()['access_token']
            headers = {"Authorization": f"Bearer {admin_token}"}
            
            response = requests.get(f"{ADMIN_BASE}/sessions", headers=headers)
            print_response(response, "View active user sessions")
    
    print("\n2. Token Blocklist")
    print("   Demonstrates token revocation and blocklisting")
    
    # Login and then logout
    response = requests.post(f"{API_BASE}/login", json=DEMO_USER)
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access_token']
        
        # Logout to revoke tokens
        headers = {"Authorization": f"Bearer {access_token}"}
        requests.post(f"{API_BASE}/logout", headers=headers, 
                     json={"refresh_token": tokens['refresh_token']})
        
        # Try to use revoked token
        response = requests.get(f"{API_BASE}/me", headers=headers)
        print_response(response, "Try to use revoked token (should fail)")

def main():
    """Run all authentication demonstrations"""
    print("Auth Server Educational Demo")
    print("This script demonstrates all authentication and authorization concepts")
    print("Make sure the auth server is running on http://localhost:5000")
    
    try:
        # Test server connectivity
        response = requests.get(f"{BASE_URL}/api/docs")
        if response.status_code != 200:
            print("Error: Auth server is not running or not accessible")
            print("Please start the server with: uv run python app.py")
            return
        
        print("✓ Auth server is running and accessible")
        
        # Run all demonstrations
        demo_core_authentication()
        demo_oauth_flow()
        demo_client_credentials()
        demo_rbac()
        demo_advanced_security()
        
        print_section("DEMO COMPLETED")
        print("\nAll authentication and authorization concepts have been demonstrated!")
        print("\nKey Learning Points:")
        print("• Authentication vs Authorization")
        print("• JWT token structure and usage")
        print("• OAuth 2.0 flows and PKCE")
        print("• OpenID Connect identity layer")
        print("• Role-based access control")
        print("• Token revocation and security")
        print("• Session management")
        
        print(f"\nInteractive API documentation available at: {BASE_URL}/api/docs")
        
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to auth server")
        print("Please start the server with: uv run python app.py")
    except Exception as e:
        print(f"Error during demo: {e}")

if __name__ == "__main__":
    main()
