"""
Database Configuration

This module initializes the SQLAlchemy database instance that will be used
across the application. It avoids circular import issues by providing
a centralized database configuration.
"""

from flask_sqlalchemy import SQLAlchemy

# Create the database instance
db = SQLAlchemy()
