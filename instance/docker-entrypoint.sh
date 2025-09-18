#!/bin/bash

# Docker entrypoint script for TapIn Attendance App

echo "Starting TapIn Attendance Application..."

# Initialize databases
echo "Initializing databases..."
cd /app/app.py && python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Frontend database initialized')
"

cd /app/tapin_backend && python -c "
from app import app
from models import db
with app.app_context():
    db.create_all()
    print('Backend database initialized')
"

# Start backend API in background
echo "Starting backend API on port 8000..."
cd /app/tapin_backend
python app.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend application
echo "Starting frontend application on port 5000..."
cd /app/app.py
python app.py &
FRONTEND_PID=$!

# Function to handle shutdown
shutdown() {
    echo "Shutting down applications..."
    kill $BACKEND_PID $FRONTEND_PID
    wait $BACKEND_PID $FRONTEND_PID
    echo "Applications stopped"
    exit 0
}

# Trap signals
trap shutdown SIGTERM SIGINT

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID