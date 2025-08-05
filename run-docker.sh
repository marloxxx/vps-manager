#!/bin/bash

echo "🚀 Starting VPS Manager Backend (API Only)..."

# Stop existing containers
echo "Stopping existing containers..."
docker-compose down

# Remove any existing volumes that might cause issues
echo "Cleaning up volumes..."
docker volume rm vps-manager_vps_config 2>/dev/null || true

# Create necessary directories and files
echo "Creating necessary files..."
mkdir -p ./app
touch ./app/config_db.json
touch ./app/users_db.json
chmod 644 ./app/config_db.json
chmod 644 ./app/users_db.json

# Build and start containers
echo "Building and starting containers..."
docker-compose up -d --build

# Check if containers are running
echo "Checking container status..."
sleep 5
docker-compose ps

echo ""
echo "✅ VPS Manager Backend is now running!"
echo "🌐 API URL: http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/docs"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down" 