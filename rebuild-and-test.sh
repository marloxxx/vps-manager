#!/bin/bash

echo "🔧 Rebuilding VPS Manager Backend..."
echo "======================================"

# Stop and remove existing container
echo "📦 Stopping existing container..."
docker compose down

# Remove the image to force rebuild
echo "🗑️  Removing old image..."
docker rmi vps-manager-backend:latest 2>/dev/null || true

# Build the new image
echo "🔨 Building new image..."
docker compose build --no-cache

# Start the container
echo "🚀 Starting container..."
docker compose up -d

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 10

# Check container status
echo "📊 Container status:"
docker compose ps

# Check logs
echo "📋 Recent logs:"
docker logs vps-manager-backend --tail 20

# Test login endpoint
echo "🧪 Testing login endpoint..."
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s

echo ""
echo "✅ Rebuild and test completed!"
echo "📝 Check the logs above for any errors." 