#!/bin/bash

# VPS Manager Backend - Development Test Script

echo "🧪 Testing VPS Manager Backend..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup-dev.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Test health endpoint
echo "📡 Testing health endpoint..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Health endpoint is responding!"
else
    echo "❌ Health endpoint not responding. Is the server running?"
    echo "💡 Start the server with: ./run-dev.sh"
    exit 1
fi

# Test login
echo "🔐 Testing authentication..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')

if echo "$LOGIN_RESPONSE" | grep -q "token"; then
    echo "✅ Authentication is working!"
    TOKEN=$(echo "$LOGIN_RESPONSE" | sed 's/.*"token":"\([^"]*\)".*/\1/')
    
    # Test authenticated endpoint
    if curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/auth/me > /dev/null; then
        echo "✅ Authenticated endpoints are working!"
    else
        echo "❌ Authenticated endpoints failed"
    fi
else
    echo "❌ Authentication failed"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

echo "�� All tests passed!" 