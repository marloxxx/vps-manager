#!/bin/bash

echo "🔧 Fixing JWT dependency issue..."

# Stop current container
echo "🛑 Stopping current container..."
docker compose down

# Remove old image to force rebuild
echo "🗑️ Removing old image..."
docker rmi vps-manager-backend_vps-manager-backend 2>/dev/null || true

# Build new image with updated requirements
echo "🔨 Building new image with JWT dependency..."
docker compose build --no-cache

# Start container
echo "🚀 Starting container..."
docker compose up -d

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 10

# Check if container is running
if docker ps | grep -q "vps-manager-backend"; then
    echo "✅ Container is running successfully!"
    echo ""
    echo "📋 Container Status:"
    docker ps | grep vps-manager-backend
    echo ""
    echo "📋 Recent Logs:"
    docker logs --tail 10 vps-manager-backend
    echo ""
    echo "🌐 API URL: http://localhost:8000"
    echo "📚 API Documentation: http://localhost:8000/docs"
    echo ""
    echo "🔑 Test Login:"
    echo "curl -X POST http://localhost:8000/api/auth/login \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{\"username\": \"admin\", \"password\": \"admin123\"}'"
else
    echo "❌ Container failed to start"
    echo "📋 Error logs:"
    docker logs vps-manager-backend
    exit 1
fi 