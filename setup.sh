#!/bin/bash

# Enhanced VPS Manager Setup Script
set -e

echo "🚀 Setting up VPS Manager v2.0..."

# Create directory structure
sudo mkdir -p /opt/vps-manager/{logs,backups,templates}
sudo chown -R $USER:$USER /opt/vps-manager

# Install system dependencies
echo "📦 Installing system dependencies..."
sudo apt update
sudo apt install -y python3-venv nginx python3-pip htop curl wget git ufw

# Create virtualenv
echo "🐍 Setting up Python environment..."
python3 -m venv /opt/vps-manager/venv
source /opt/vps-manager/venv/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Create Nginx configuration directory structure
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled

# Create SSL directory for wildcard certificates
sudo mkdir -p /etc/ssl/ptsi

# Create systemd service
echo "⚙️ Creating systemd service..."
sudo bash -c 'cat > /etc/systemd/system/vps-manager.service' << 'EOL'
[Unit]
Description=VPS Manager API Service v2.0
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vps-manager
Environment="PATH=/opt/vps-manager/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/vps-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

# Create log rotation configuration
echo "📝 Setting up log rotation..."
sudo bash -c 'cat > /etc/logrotate.d/vps-manager' << 'EOL'
/opt/vps-manager/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload vps-manager
    endscript
}
EOL

# Create backup script
echo "💾 Creating backup script..."
sudo bash -c 'cat > /opt/vps-manager/backup.sh' << 'EOL'
#!/bin/bash
# VPS Manager Backup Script

BACKUP_DIR="/opt/vps-manager/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="vps-manager-backup-${DATE}.tar.gz"

# Create backup
tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" \
    -C /opt/vps-manager \
    config_db.json \
    users_db.json \
    templates/ \
    --exclude='*.pyc' \
    --exclude='__pycache__'

# Keep only last 10 backups
cd "${BACKUP_DIR}"
ls -t vps-manager-backup-*.tar.gz | tail -n +11 | xargs -r rm

echo "Backup created: ${BACKUP_FILE}"
EOL

sudo chmod +x /opt/vps-manager/backup.sh

# Create daily backup cron job
echo "⏰ Setting up daily backups..."
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/vps-manager/backup.sh") | crontab -

# Configure Nginx main config if needed
if [ ! -f /etc/nginx/nginx.conf.backup ]; then
    sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
fi

# Add rate limiting zones to nginx.conf if not present
if ! grep -q "limit_req_zone" /etc/nginx/nginx.conf; then
    echo "🔧 Configuring Nginx rate limiting..."
    sudo sed -i '/http {/a\\n    # Rate limiting zones\n    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n    limit_req_zone $binary_remote_addr zone=global:10m rate=100r/m;\n' /etc/nginx/nginx.conf
fi

# Configure UFW
echo "🔒 Configuring UFW firewall..."
sudo ufw allow 8000/tcp comment 'VPS Manager API'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw --force enable

# Copy application files
echo "📁 Copying application files..."
cp *.py /opt/vps-manager/
cp *.json /opt/vps-manager/

# Seed default users
echo "👤 Creating default users..."
cd /opt/vps-manager
python3 seeder.py seed

# Enable and start services
echo "🔄 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable vps-manager
sudo systemctl enable nginx

# Test Nginx configuration
sudo nginx -t

# Start services
sudo systemctl start nginx
sudo systemctl start vps-manager

# Set proper permissions
sudo chown -R root:root /opt/vps-manager
sudo chmod -R 755 /opt/vps-manager
sudo chmod 644 /opt/vps-manager/*.json

# Fetch dynamic IP
VPS_IP=$(curl -s ifconfig.me)

echo "✅ VPS Manager v2.0 setup completed!"
echo ""
echo "🌐 Access the API at: http://${VPS_IP}:8000"
echo "📚 API documentation at: http://${VPS_IP}:8000/docs"
echo "📊 Service status: systemctl status vps-manager"
echo "📋 View logs: journalctl -u vps-manager -f"
echo ""
echo "🔧 Next steps:"
echo "1. Configure your SSL certificates in /etc/ssl/ptsi/"
echo "2. Set up your frontend application"
echo "3. Create your first reverse proxy configuration"
echo ""
echo "🆘 Support: Check the documentation or create an issue on GitHub"