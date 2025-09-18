# Multi-stage Dockerfile for TapIn Attendance App
FROM python:3.11-slim as base

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY app.py/requirements.txt ./frontend_requirements.txt
COPY tapin_backend/requirements.txt ./backend_requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r frontend_requirements.txt
RUN pip install --no-cache-dir -r backend_requirements.txt

# Copy application code
COPY . .

# Create instance directory for database
RUN mkdir -p instance

# Expose ports
EXPOSE 5000 8000

# Create startup script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Default command
CMD ["/docker-entrypoint.sh"]
