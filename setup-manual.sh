#!/bin/bash

# VPS Manager Backend - Manual Setup Script
# Setup dengan Virtual Environment dan Systemctl

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_header "VPS Manager Backend - Manual Setup"
print_status "Starting setup process..."

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
print_status "Installing required packages..."
apt install -y python3 python3-pip python3-venv nginx redis-server git curl wget jq
apt install -y build-essential python3-dev libffi-dev libssl-dev

# Create application directories
print_status "Creating application directories..."
mkdir -p /opt/vps-manager/app
mkdir -p /opt/vps-manager/logs
mkdir -p /opt/vps-manager/backups
mkdir -p /opt/vps-manager/templates

# Set permissions
chown -R root:root /opt/vps-manager
chmod -R 755 /opt/vps-manager

# Setup SSL certificates
print_status "Setting up SSL certificates..."
mkdir -p /etc/ssl/ptsi

# Create dummy certificates (replace with real ones in production)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/ptsi/wildcard.ptsi.co.id.key \
    -out /etc/ssl/ptsi/wildcard.ptsi.co.id.crt \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=PTSI/CN=*.ptsi.co.id"

# Set proper permissions
chmod 644 /etc/ssl/ptsi/wildcard.ptsi.co.id.crt
chmod 600 /etc/ssl/ptsi/wildcard.ptsi.co.id.key

# Setup admin user
print_status "Setting up admin user..."
cat > /opt/vps-manager/app/users_db.json << 'EOF'
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

chmod 644 /opt/vps-manager/app/users_db.json

# Copy application files
print_status "Copying application files..."
cp -r . /opt/vps-manager/vps-manager-backend/
chown -R root:root /opt/vps-manager/vps-manager-backend/
chmod +x /opt/vps-manager/vps-manager-backend/main.py

# Setup virtual environment
print_status "Setting up virtual environment..."
cd /opt/vps-manager/vps-manager-backend
python3 -m venv venv

# Install dependencies
print_status "Installing Python dependencies..."
/opt/vps-manager/vps-manager-backend/venv/bin/pip install --upgrade pip
/opt/vps-manager/vps-manager-backend/venv/bin/pip install -r requirements.txt

# Create systemd service file
print_status "Creating systemd service..."
cat > /etc/systemd/system/vps-manager.service << 'EOF'
[Unit]
Description=VPS Manager Backend API
After=network.target nginx.service redis.service
Wants=nginx.service redis.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vps-manager/vps-manager-backend
Environment=PATH=/opt/vps-manager/vps-manager-backend/venv/bin
ExecStart=/opt/vps-manager/vps-manager-backend/venv/bin/python main.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/vps-manager /etc/nginx/conf.d /etc/nginx/sites-available /etc/nginx/sites-enabled

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vps-manager

[Install]
WantedBy=multi-user.target
EOF

# Create Nginx configuration
print_status "Creating Nginx configuration..."
cat > /etc/nginx/sites-available/vps-manager-api << 'EOF'
server {
    listen 80;
    server_name api.vps-manager.com localhost;

    # API endpoints
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Health check
    location /health {
        proxy_pass http://localhost:8000/health;
        access_log off;
    }

    # API documentation
    location /docs {
        proxy_pass http://localhost:8000/docs;
    }

    # Logs
    access_log /var/log/nginx/vps-manager-api.access.log;
    error_log /var/log/nginx/vps-manager-api.error.log;
}
EOF

# Enable Nginx site
print_status "Enabling Nginx site..."
ln -sf /etc/nginx/sites-available/vps-manager-api /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
print_status "Testing Nginx configuration..."
nginx -t

# Reload systemd and enable service
print_status "Enabling and starting service..."
systemctl daemon-reload
systemctl enable vps-manager
systemctl start vps-manager

# Start Redis if not running
print_status "Starting Redis..."
systemctl enable redis-server
systemctl start redis-server

# Reload Nginx
print_status "Reloading Nginx..."
systemctl reload nginx

# Wait a moment for service to start
sleep 5

# Test the service
print_status "Testing service..."
if systemctl is-active --quiet vps-manager; then
    print_status "Service is running successfully!"
else
    print_error "Service failed to start. Check logs with: journalctl -u vps-manager -f"
    exit 1
fi

# Test API endpoints
print_status "Testing API endpoints..."
if curl -s http://localhost:8000/health > /dev/null; then
    print_status "Health endpoint is responding!"
else
    print_warning "Health endpoint not responding. Service may still be starting..."
fi

# Test login
print_status "Testing authentication..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')

if echo "$LOGIN_RESPONSE" | jq -e '.token' > /dev/null 2>&1; then
    print_status "Authentication is working!"
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
    
    # Test authenticated endpoint
    if curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/auth/me > /dev/null; then
        print_status "Authenticated endpoints are working!"
    else
        print_warning "Authenticated endpoints may have issues"
    fi
else
    print_error "Authentication failed. Check the service logs."
fi

# Setup firewall
print_status "Setting up firewall..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8000/tcp
ufw --force enable

# Create backup script
print_status "Creating backup script..."
cat > /opt/vps-manager/backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/vps-manager/backups"

# Create backup
tar -czf "$BACKUP_DIR/vps-manager_$DATE.tar.gz" \
    /opt/vps-manager/app \
    /opt/vps-manager/logs \
    /etc/nginx/sites-available/vps-manager-api

echo "Backup created: vps-manager_$DATE.tar.gz"
EOF

chmod +x /opt/vps-manager/backup.sh

print_header "Setup Complete!"

echo -e "${GREEN}✅ VPS Manager Backend has been successfully installed!${NC}"
echo ""
echo -e "${BLUE}📋 Login Information:${NC}"
echo -e "   Username: ${YELLOW}admin${NC}"
echo -e "   Password: ${YELLOW}admin123${NC}"
echo ""
echo -e "${BLUE}🌐 Access URLs:${NC}"
echo -e "   API: ${YELLOW}http://localhost:8000${NC}"
echo -e "   Documentation: ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "   Health Check: ${YELLOW}http://localhost:8000/health${NC}"
echo ""
echo -e "${BLUE}🔧 Service Management:${NC}"
echo -e "   Status: ${YELLOW}sudo systemctl status vps-manager${NC}"
echo -e "   Logs: ${YELLOW}sudo journalctl -u vps-manager -f${NC}"
echo -e "   Restart: ${YELLOW}sudo systemctl restart vps-manager${NC}"
echo ""
echo -e "${BLUE}📊 Monitoring:${NC}"
echo -e "   Application Logs: ${YELLOW}tail -f /opt/vps-manager/logs/vps-manager.log${NC}"
echo -e "   Nginx Logs: ${YELLOW}tail -f /var/log/nginx/vps-manager-api.access.log${NC}"
echo ""
echo -e "${BLUE}🔒 Security:${NC}"
echo -e "   Change default password: ${YELLOW}sudo nano /opt/vps-manager/app/users_db.json${NC}"
echo -e "   Setup SSL: ${YELLOW}sudo certbot --nginx -d your-domain.com${NC}"
echo ""
echo -e "${BLUE}💾 Backup:${NC}"
echo -e "   Manual backup: ${YELLOW}/opt/vps-manager/backup.sh${NC}"
echo -e "   Setup auto-backup: ${YELLOW}sudo crontab -e${NC}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Change the default password in production!${NC}"
echo ""
echo -e "${GREEN}🎉 Setup completed successfully!${NC}" 