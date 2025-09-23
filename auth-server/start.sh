#!/bin/bash
# Auth Server Startup Script

echo "Starting Educational Auth Server..."
echo "=================================="

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed. Please install uv first."
    echo "Visit: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
uv sync

# Start the server
echo "Starting Flask development server..."
echo "Server will be available at: http://localhost:5000"
echo "API Documentation: http://localhost:5000/api/docs"
echo ""
echo "Default credentials:"
echo "  Admin: username=admin, password=admin123"
echo "  Demo Client: client_id=demo-client, client_secret=demo-secret"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

uv run python app.py
