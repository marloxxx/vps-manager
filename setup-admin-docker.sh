#!/bin/bash

echo "🔧 Setting up Admin Account in Docker Container..."

# Set variables
CONTAINER_NAME="vps-manager-backend"
APP_DIR="/opt/vps-manager/app"
USERS_DB="$APP_DIR/users_db.json"

# Check if container is running
if ! docker ps | grep -q $CONTAINER_NAME; then
    echo "❌ Container $CONTAINER_NAME is not running"
    echo "Starting container first..."
    docker-compose up -d
    sleep 10
fi

# Create admin user JSON
echo "📝 Creating admin user configuration..."
ADMIN_USER_JSON='{
  "admin": {
    "username": "admin",
    "password": "admin123",
    "email": "admin@ptsi.co.id",
    "role": "admin",
    "is_active": true
  }
}'

# Create users_db.json in container
echo "📦 Creating users database in container..."
docker exec $CONTAINER_NAME mkdir -p $APP_DIR
echo "$ADMIN_USER_JSON" | docker exec -i $CONTAINER_NAME tee $USERS_DB > /dev/null

# Set proper permissions
echo "🔐 Setting proper permissions..."
docker exec $CONTAINER_NAME chmod 644 $USERS_DB
docker exec $CONTAINER_NAME chown root:root $USERS_DB

# Create config_db.json if it doesn't exist
echo "📋 Creating config database..."
if ! docker exec $CONTAINER_NAME test -f "$APP_DIR/config_db.json"; then
    echo "[]" | docker exec -i $CONTAINER_NAME tee "$APP_DIR/config_db.json" > /dev/null
    docker exec $CONTAINER_NAME chmod 644 "$APP_DIR/config_db.json"
    docker exec $CONTAINER_NAME chown root:root "$APP_DIR/config_db.json"
fi

# Restart container to apply changes
echo "🔄 Restarting container to apply changes..."
docker-compose restart

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 10

# Test login
echo "🔑 Testing admin login..."
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "admin123"
  }' \
  -w "\nHTTP Status: %{http_code}\n" \
  -s

echo ""
echo "✅ Admin account setup completed!"
echo ""
echo "📋 Admin Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo "  Email: admin@ptsi.co.id"
echo "  Role: admin"
echo ""
echo "🌐 API URL: http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/docs"
echo ""
echo "📋 Container Status:"
docker ps | grep $CONTAINER_NAME 