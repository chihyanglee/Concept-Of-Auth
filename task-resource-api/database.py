"""
Database Configuration for the Task Resource API
=================================================

This module initializes the SQLAlchemy database instance for the Task Resource API.

IMPORTANT ARCHITECTURAL NOTE — Separate Databases per Service:
--------------------------------------------------------------
This is a SEPARATE database from the auth server's database. Each microservice
owns its own data store. This is a core microservices pattern called
"Database per Service":

  - Auth Server   -> auth_server.db  (users, clients, tokens, sessions)
  - Resource API  -> tasks.db        (tasks)

Why not share a database?
  1. Loose coupling: Services can evolve independently. If the auth server
     changes its schema, the task API is unaffected.
  2. Independent scaling: Each database can be scaled separately.
  3. Clear ownership: The auth server is the single source of truth for
     identity; the task API is the single source of truth for tasks.
  4. Security boundary: Even if the task API is compromised, the attacker
     doesn't get direct access to user credentials.

The ONLY thing connecting the two services is the JWT token. The auth server
issues it, the resource API validates it. They share a secret key (HS256) or
a public key (RS256) — nothing else.
"""

from flask_sqlalchemy import SQLAlchemy

# Create the database instance
# This will be initialized with the Flask app in app.py via db.init_app(app)
db = SQLAlchemy()
