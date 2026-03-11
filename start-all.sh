#!/bin/bash
# Start all three services for the OAuth demo
#
# Services:
#   Auth Server      (port 5000) — issues tokens, manages users
#   Task Client App  (port 5001) — web UI, OAuth client
#   Task Resource API (port 5002) — protected API, validates tokens
#
# Usage: ./start-all.sh
# Stop:  Ctrl+C (kills all three processes)

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
echo "  Auth Server:       http://localhost:5000  (Swagger: http://localhost:5000/api/docs)"
echo "  Task Client App:   http://localhost:5001  (Open this in your browser)"
echo "  Task Resource API: http://localhost:5002"
echo ""
echo "  Default login:     admin / admin123"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for all background processes
wait
