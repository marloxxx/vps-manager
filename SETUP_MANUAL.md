# VPS Manager Backend - Manual Setup Guide

**Setup Manual dengan Virtual Environment dan Systemctl**

## 📋 **Prerequisites**

### **System Requirements**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv nginx redis-server git curl wget

# Install additional dependencies
sudo apt install -y build-essential python3-dev libffi-dev libssl-dev
```

## 🐍 **Virtual Environment Setup**

### **1. Create Virtual Environment**
```bash
# Navigate to project directory
cd vps-manager-backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation
which python
# Should show: /path/to/vps-manager-backend/venv/bin/python
```

### **2. Install Dependencies**
```bash
# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Verify installation
pip list
```

## 🔧 **Configuration Setup**

### **1. Create Required Directories**
```bash
# Create application directories
sudo mkdir -p /opt/vps-manager/app
sudo mkdir -p /opt/vps-manager/logs
sudo mkdir -p /opt/vps-manager/backups
sudo mkdir -p /opt/vps-manager/templates

# Set permissions
sudo chown -R $USER:$USER /opt/vps-manager
sudo chmod -R 755 /opt/vps-manager
```

### **2. Setup SSL Certificates (PTSI)**
```bash
# Create SSL directory
sudo mkdir -p /etc/ssl/ptsi

# Create dummy certificates (replace with real ones in production)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/ptsi/wildcard.ptsi.co.id.key \
    -out /etc/ssl/ptsi/wildcard.ptsi.co.id.crt \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=PTSI/CN=*.ptsi.co.id"

# Set proper permissions
sudo chmod 644 /etc/ssl/ptsi/wildcard.ptsi.co.id.crt
sudo chmod 600 /etc/ssl/ptsi/wildcard.ptsi.co.id.key
```

### **3. Setup Admin User**
```bash
# Create admin user database
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

# Set permissions
chmod 644 /opt/vps-manager/app/users_db.json
```

## 🚀 **Systemctl Service Setup**

### **1. Create Service File**
```bash
# Create systemd service file
sudo tee /etc/systemd/system/vps-manager.service > /dev/null << 'EOF'
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
```

### **2. Copy Application Files**
```bash
# Copy application to system directory
sudo cp -r . /opt/vps-manager/vps-manager-backend/

# Set ownership
sudo chown -R root:root /opt/vps-manager/vps-manager-backend/

# Set permissions
sudo chmod +x /opt/vps-manager/vps-manager-backend/main.py
```

### **3. Setup Virtual Environment in System Directory**
```bash
# Create virtual environment in system directory
cd /opt/vps-manager/vps-manager-backend
sudo python3 -m venv venv

# Install dependencies
sudo /opt/vps-manager/vps-manager-backend/venv/bin/pip install --upgrade pip
sudo /opt/vps-manager/vps-manager-backend/venv/bin/pip install -r requirements.txt
```

### **4. Enable and Start Service**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable vps-manager

# Start service
sudo systemctl start vps-manager

# Check status
sudo systemctl status vps-manager
```

## 🔍 **Verification and Testing**

### **1. Check Service Status**
```bash
# Check if service is running
sudo systemctl status vps-manager

# Check logs
sudo journalctl -u vps-manager -f

# Check if port is listening
sudo netstat -tlnp | grep :8000
```

### **2. Test API Endpoints**
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Test with authentication
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.token')

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/auth/me
```

### **3. Test Nginx Integration**
```bash
# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Check Nginx status
sudo systemctl status nginx
```

## 🔧 **Nginx Configuration**

### **1. Create Nginx Configuration**
```bash
# Create Nginx configuration
sudo tee /etc/nginx/sites-available/vps-manager-api > /dev/null << 'EOF'
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
```

### **2. Enable Nginx Site**
```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/vps-manager-api /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

## 📊 **Monitoring and Logs**

### **1. View Service Logs**
```bash
# View real-time logs
sudo journalctl -u vps-manager -f

# View recent logs
sudo journalctl -u vps-manager --since "1 hour ago"

# View error logs
sudo journalctl -u vps-manager -p err
```

### **2. Application Logs**
```bash
# View application logs
tail -f /opt/vps-manager/logs/vps-manager.log

# View structured logs
tail -f /opt/vps-manager/logs/structured.log | jq

# View audit logs
tail -f /opt/vps-manager/logs/audit.log | jq
```

### **3. Nginx Logs**
```bash
# View Nginx access logs
tail -f /var/log/nginx/vps-manager-api.access.log

# View Nginx error logs
tail -f /var/log/nginx/vps-manager-api.error.log
```

## 🔧 **Service Management**

### **1. Service Commands**
```bash
# Start service
sudo systemctl start vps-manager

# Stop service
sudo systemctl stop vps-manager

# Restart service
sudo systemctl restart vps-manager

# Reload service (without restart)
sudo systemctl reload vps-manager

# Check status
sudo systemctl status vps-manager

# Enable auto-start
sudo systemctl enable vps-manager

# Disable auto-start
sudo systemctl disable vps-manager
```

### **2. Troubleshooting**
```bash
# Check if port is in use
sudo netstat -tlnp | grep :8000

# Check process
ps aux | grep vps-manager

# Check virtual environment
ls -la /opt/vps-manager/vps-manager-backend/venv/bin/python

# Test Python import
sudo /opt/vps-manager/vps-manager-backend/venv/bin/python -c "import main; print('Import successful')"
```

## 🔒 **Security Considerations**

### **1. Firewall Setup**
```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow API port (if exposed directly)
sudo ufw allow 8000/tcp

# Enable firewall
sudo ufw enable
```

### **2. SSL/TLS Setup**
```bash
# Install Certbot for Let's Encrypt
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d api.vps-manager.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### **3. Change Default Password**
```bash
# Edit user database
sudo nano /opt/vps-manager/app/users_db.json

# Restart service after changes
sudo systemctl restart vps-manager
```

## 🚀 **Production Deployment**

### **1. Environment Variables**
```bash
# Create environment file
sudo tee /opt/vps-manager/vps-manager-backend/.env > /dev/null << 'EOF'
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-super-secret-key-change-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Logging Configuration
LOG_LEVEL=INFO
LOG_DIR=/opt/vps-manager/logs
LOG_RETENTION_DAYS=30
EOF

# Set permissions
sudo chmod 600 /opt/vps-manager/vps-manager-backend/.env
```

### **2. Performance Optimization**
```bash
# Install additional dependencies for performance
sudo /opt/vps-manager/vps-manager-backend/venv/bin/pip install uvicorn[standard] gunicorn

# Update service file for production
sudo nano /etc/systemd/system/vps-manager.service
```

### **3. Backup Strategy**
```bash
# Create backup script
sudo tee /opt/vps-manager/backup.sh > /dev/null << 'EOF'
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

# Make executable
sudo chmod +x /opt/vps-manager/backup.sh

# Add to crontab for daily backups
sudo crontab -e
# Add: 0 2 * * * /opt/vps-manager/backup.sh
```

## 📚 **Useful Commands**

### **1. Development Commands**
```bash
# Activate virtual environment
source venv/bin/activate

# Run in development mode
python main.py

# Install new dependencies
pip install package-name
pip freeze > requirements.txt
```

### **2. Production Commands**
```bash
# View all logs
sudo journalctl -u vps-manager -f

# Check disk usage
df -h /opt/vps-manager

# Check memory usage
free -h

# Monitor processes
htop
```

### **3. Debugging Commands**
```bash
# Test API directly
curl -v http://localhost:8000/health

# Test with authentication
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/auth/me

# Check Redis
redis-cli ping

# Check Nginx configuration
sudo nginx -t
```

## ✅ **Verification Checklist**

- [ ] Virtual environment created and activated
- [ ] Dependencies installed successfully
- [ ] Service file created and enabled
- [ ] Application files copied to system directory
- [ ] Admin user created
- [ ] Service started and running
- [ ] API endpoints responding
- [ ] Nginx configuration working
- [ ] Logs being generated
- [ ] SSL certificates configured
- [ ] Firewall configured
- [ ] Backup strategy implemented

## 🆘 **Troubleshooting**

### **Common Issues**

1. **Service won't start**
   ```bash
   sudo journalctl -u vps-manager -n 50
   sudo systemctl status vps-manager
   ```

2. **Permission denied**
   ```bash
   sudo chown -R root:root /opt/vps-manager
   sudo chmod -R 755 /opt/vps-manager
   ```

3. **Port already in use**
   ```bash
   sudo netstat -tlnp | grep :8000
   sudo kill -9 PID
   ```

4. **Virtual environment not found**
   ```bash
   sudo /opt/vps-manager/vps-manager-backend/venv/bin/python --version
   ```

---

**VPS Manager Backend - Manual Setup Complete! 🎉**

Login credentials:
- **Username**: admin
- **Password**: admin123
- **API URL**: http://localhost:8000
- **Documentation**: http://localhost:8000/docs 