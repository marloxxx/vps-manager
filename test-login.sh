#!/bin/bash

echo "🔑 Testing VPS Manager Login..."

# Test login endpoint
echo "📡 Testing login endpoint..."
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "admin123"
  }' \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" \
  -s

echo ""
echo "📡 Testing health endpoint..."
curl -f http://localhost:8000/health \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" \
  -s

echo ""
echo "📡 Testing API docs endpoint..."
curl -f http://localhost:8000/docs \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" \
  -s

echo ""
echo "📋 Container Status:"
docker ps | grep vps-manager-backend

echo ""
echo "📋 Recent Logs:"
docker logs --tail 10 vps-manager-backend 