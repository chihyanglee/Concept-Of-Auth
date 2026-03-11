"""
Task Model for the Resource API
================================

This module defines the Task model — the only data this service owns.

Key Concept — Separation of Concerns:
--------------------------------------
The auth server owns IDENTITY (who you are).
The resource server owns DATA (what you have).

They are connected by a single value: the 'sub' (subject) claim inside the JWT.
When the auth server issues a token, it puts the user's ID in the 'sub' claim.
When we create a task, we read that 'sub' claim and store it as user_id.

This means:
  - The resource API NEVER stores passwords or credentials.
  - The resource API NEVER authenticates users directly.
  - The resource API trusts the auth server's JWT as proof of identity.
  - User data isolation is enforced by filtering on user_id from the token.

Why user_id comes from the JWT, NEVER from user input:
------------------------------------------------------
If we let users pass their own user_id in the request body, a malicious user
could set user_id to someone else's ID and access/create tasks for that person.
By extracting user_id exclusively from the validated JWT 'sub' claim, we
guarantee the user can only interact with their own data. The JWT is
cryptographically signed — it cannot be forged without the secret key.
"""

from datetime import datetime
from database import db


class Task(db.Model):
    """
    Task Model — Represents a to-do item owned by a specific user.

    Fields:
      - id:         Auto-incrementing primary key.
      - user_id:    The owner's ID, extracted from the JWT 'sub' claim.
                    This is a string because JWT 'sub' claims are strings
                    (even though our auth server stores numeric user IDs,
                    the JWT spec says 'sub' should be a string).
      - title:      The task description provided by the user.
      - completed:  Whether the task is done. Defaults to False.
      - created_at: Timestamp for when the task was created.

    Note on user_id type:
      We store user_id as a String, not an Integer, because:
      1. The JWT 'sub' claim is always a string per the JWT spec (RFC 7519).
      2. If we ever switch auth providers (e.g., to an external IdP like Auth0),
         the 'sub' might be a UUID or an opaque string, not a number.
      3. Keeping it as a string makes the resource server more portable.
    """
    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False, index=True)
    title = db.Column(db.String(500), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """
        Serialize the task to a dictionary for JSON responses.

        Note: We include user_id in the output so the client can confirm
        ownership, but the client can NEVER set or change this value —
        it always comes from the JWT.
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'completed': self.completed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
