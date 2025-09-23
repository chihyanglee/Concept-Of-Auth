# PRD: Auth Service

## 1. Introduction
**Product:** Auth Service  
**Purpose:** This service will act as the central and sole authority for authentication and authorization within the microservices ecosystem. It is responsible for managing user and application identities, issuing secure tokens, and providing the necessary endpoints to implement OAuth 2.0 and OpenID Connect (OIDC) standards.  
**Tech Stack:** Python (Flask framework) and SQLite for data persistence.

---

## 2. Product Goals
- **Centralize Identity:** To be the single source of truth for user and application identity.  
- **Provide Secure Access:** To issue short-lived, signed JWT access tokens for secure API access.  
- **Ensure Great User Experience:** To enable persistent sessions through the use of refresh tokens.  
- **Implement Modern Standards:** To fully support standard OAuth 2.0 and OIDC flows for both first-party and third-party applications.  
- **Establish Granular Control:** To lay the foundation for role-based access control (RBAC) by embedding roles and permissions into tokens.

---

## 3. Features & Functional Requirements

### Phase 1: Core User Authentication
- **User Registration**  
  - **Endpoint:** `POST /register`  
  - **Description:** A new user can create an account by providing a username and password. The password must be securely hashed and stored.

- **User Login**  
  - **Endpoint:** `POST /login`  
  - **Description:** A registered user can log in with their credentials. Upon success, the service will return a JWT `access_token` and a `refresh_token`.

- **User Logout**  
  - **Endpoint:** `POST /logout`  
  - **Description:** A logged-in user can invalidate their session. The service will add the JWT's unique identifier (`jti`) to a blocklist to prevent its further use.

---

### Phase 2: Delegated Authorization (OAuth 2.0 & OIDC)
- **Authorization Flow Initiation**  
  - **Endpoint:** `GET /authorize`  
  - **Description:** Handles the first leg of the OAuth 2.0 Authorization Code flow. It will authenticate the user, ask for their consent to grant permissions (scopes) to a third-party application, and validate incoming PKCE challenges.

- **Token Exchange & Refresh**  
  - **Endpoint:** `POST /token`  
  - **Description:** Multi-purpose endpoint to:  
    - Exchange an `authorization_code` for an `access_token` and `refresh_token`, validating the PKCE `code_verifier`.  
    - Exchange a `refresh_token` for a new `access_token`.  
    - Issue an OIDC `id_token` if the `openid` scope was requested.  

- **User Identity Information**  
  - **Endpoint:** `GET /userinfo`  
  - **Description:** An OIDC-compliant endpoint that returns claims about the authenticated user when presented with a valid `access_token`.

---

### Phase 3: Application Authentication
- **Client Credentials Flow**  
  - **Endpoint:** `POST /token` (extended functionality)  
  - **Description:** Registered machine-to-machine applications can authenticate using their `client_id` and `client_secret` to receive an `access_token`.

---

### Phase 4: Authorization
- **Role Management**  
  - **Description:** The system must support assigning roles (e.g., admin, user) to both users and applications.

- **Token Claims**  
  - **Description:** Issued JWTs must contain claims for roles and scopes which downstream services can use to enforce permissions.

---

## 4. Technical Specifications

### a. Database Schema (SQLite)
**users Table**  
- `id` (INTEGER, PRIMARY KEY)  
- `username` (TEXT, UNIQUE, NOT NULL)  
- `password_hash` (TEXT, NOT NULL)  
- `role` (TEXT, NOT NULL, DEFAULT 'user')  

**clients Table**  
- `client_id` (TEXT, PRIMARY KEY)  
- `client_secret` (TEXT, NOT NULL)  
- `redirect_uris` (TEXT)  
- `scopes` (TEXT)  

**token_blocklist Table**  
- `jti` (TEXT, PRIMARY KEY)  
- `expires_at` (INTEGER, NOT NULL)  

---

### b. JWT Structure
- **Access Token:** Will contain standard claims (`iss`, `sub`, `exp`, `iat`, `jti`) plus custom claims for roles and scopes.  
- **ID Token:** OIDC compliant, containing claims like `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, etc.

---

### c. Key Dependencies
- **Flask:** Web framework.  
- **Flask-SQLAlchemy:** ORM for interacting with the SQLite database.  
- **PyJWT:** For creating and validating JWTs.  
- **Werkzeug:** For securely hashing and verifying passwords.  
- **Flasgger:** For generating Swagger UI from the Flask application.

---

### d. API Documentation
- **Specification:** The API will be documented using the OpenAPI 3.0 specification.  
- **Interactive UI:** An interactive Swagger UI will be exposed at the `/api/docs` endpoint, allowing for easy exploration and testing of all available API endpoints directly from the browser.
