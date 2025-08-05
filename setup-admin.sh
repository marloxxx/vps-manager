#!/bin/bash

echo "🔧 Setting up VPS Manager Admin Account..."

# Set variables
APP_DIR="/opt/vps-manager/app"
USERS_DB="$APP_DIR/users_db.json"

# Create app directory if it doesn't exist
sudo mkdir -p $APP_DIR

# Create default admin user
echo "Creating default admin user..."
sudo tee $USERS_DB > /dev/null << 'EOF'
{
  "admin": {
    "username": "admin",
    "password": "admin123",
    "email": "admin@ptsi.co.id",
    "role": "admin",
    "is_active": true
  }
}
EOF

# Set proper permissions
sudo chmod 644 $USERS_DB
sudo chown root:root $USERS_DB

echo "✅ Admin account created successfully!"
echo ""
echo "📋 Default Admin Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo "  Email: admin@ptsi.co.id"
echo "  Role: admin"
echo ""
echo "⚠️  IMPORTANT: Change the password in production!"
echo ""
echo "To change password, edit: $USERS_DB"
echo "Or use the API to update user credentials." 