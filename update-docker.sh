#!/bin/bash

echo "🔄 Updating VPS Manager via Docker..."

# Set variables
CONTAINER_NAME="vps-manager-backend"
IMAGE_NAME="vps-manager-backend"
BACKUP_DIR="/opt/vps-manager/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Function to backup current data
backup_data() {
    echo "📦 Creating backup before update..."
    
    # Create backup directory
    sudo mkdir -p $BACKUP_DIR
    
    # Backup configs and users
    if docker exec $CONTAINER_NAME test -f /opt/vps-manager/app/config_db.json; then
        docker cp $CONTAINER_NAME:/opt/vps-manager/app/config_db.json $BACKUP_DIR/config_db_$DATE.json
        echo "✅ Config backup created: config_db_$DATE.json"
    fi
    
    if docker exec $CONTAINER_NAME test -f /opt/vps-manager/app/users_db.json; then
        docker cp $CONTAINER_NAME:/opt/vps-manager/app/users_db.json $BACKUP_DIR/users_db_$DATE.json
        echo "✅ Users backup created: users_db_$DATE.json"
    fi
    
    # Backup logs
    if docker exec $CONTAINER_NAME test -d /opt/vps-manager/logs; then
        docker cp $CONTAINER_NAME:/opt/vps-manager/logs $BACKUP_DIR/logs_$DATE
        echo "✅ Logs backup created: logs_$DATE"
    fi
}

# Function to restore data
restore_data() {
    echo "📥 Restoring data to new container..."
    
    # Restore configs
    if [ -f "$BACKUP_DIR/config_db_$DATE.json" ]; then
        docker cp $BACKUP_DIR/config_db_$DATE.json $CONTAINER_NAME:/opt/vps-manager/app/config_db.json
        echo "✅ Config restored"
    fi
    
    # Restore users
    if [ -f "$BACKUP_DIR/users_db_$DATE.json" ]; then
        docker cp $BACKUP_DIR/users_db_$DATE.json $CONTAINER_NAME:/opt/vps-manager/app/users_db.json
        echo "✅ Users restored"
    fi
    
    # Set proper permissions
    docker exec $CONTAINER_NAME chmod 644 /opt/vps-manager/app/config_db.json
    docker exec $CONTAINER_NAME chmod 644 /opt/vps-manager/app/users_db.json
}

# Check if container is running
if ! docker ps | grep -q $CONTAINER_NAME; then
    echo "❌ Container $CONTAINER_NAME is not running"
    echo "Starting container first..."
    docker-compose up -d
    sleep 10
fi

# Stop current container
echo "🛑 Stopping current container..."
docker-compose down

# Backup data
backup_data

# Pull latest code (if using git)
echo "📥 Pulling latest code..."
git pull origin main

# Build new image
echo "🔨 Building new Docker image..."
docker-compose build --no-cache

# Start new container
echo "🚀 Starting updated container..."
docker-compose up -d

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 15

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    echo "✅ Container is running"
    
    # Restore data
    restore_data
    
    # Restart container to apply restored data
    echo "🔄 Restarting container to apply restored data..."
    docker-compose restart
    
    # Final status check
    sleep 5
    if docker ps | grep -q $CONTAINER_NAME; then
        echo ""
        echo "🎉 Update completed successfully!"
        echo "🌐 API URL: http://localhost:8000"
        echo "📚 API Documentation: http://localhost:8000/docs"
        echo ""
        echo "📋 Container Status:"
        docker ps | grep $CONTAINER_NAME
        echo ""
        echo "📋 Recent Logs:"
        docker logs --tail 20 $CONTAINER_NAME
    else
        echo "❌ Container failed to start after update"
        echo "📋 Error logs:"
        docker logs $CONTAINER_NAME
        exit 1
    fi
else
    echo "❌ Container failed to start"
    echo "📋 Error logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi 