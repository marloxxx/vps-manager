# VPS Manager Backend API

**Surveyor Indonesia - VPS Manager v2.0.0**

A comprehensive VPS management system with advanced monitoring, logging, and scalability features.

## 🚀 **Features Overview**

### **Core Features**
- **Nginx Configuration Management** - Create, edit, and manage Nginx configurations
- **SSL Certificate Management** - PTSI wildcard certificate (*.ptsi.co.id) and Let's Encrypt integration
- **Load Balancing** - Advanced load balancer with health checks
- **Backup & Restore** - Automated backup system with retention policies
- **System Monitoring** - Real-time system metrics and health monitoring

### **Advanced Features**
- **Real-time Monitoring Dashboard** - WebSocket-based live metrics and alerts
- **Advanced Logging System** - Structured logging with audit trails and compliance
- **Scalability Improvements** - Redis caching, connection pooling, and horizontal scaling
- **Performance Analytics** - Detailed performance metrics and optimization tools

## 📋 **Table of Contents**

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [API Endpoints](#api-endpoints)
4. [Real-time Monitoring](#real-time-monitoring)
5. [Advanced Logging](#advanced-logging)
6. [Scalability Features](#scalability-features)
7. [Security](#security)
8. [Deployment](#deployment)
9. [Troubleshooting](#troubleshooting)

## 🛠️ **Installation**

### **Prerequisites**
```bash
# System requirements
- Python 3.8+
- Nginx
- Redis (optional, for caching)
- Docker (optional)

# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip nginx redis-server
```

### **Manual Setup (Recommended)**

#### **Development Environment**
```bash
# Clone repository
git clone <repository-url>
cd vps-manager-backend

# Setup development environment with virtual environment
chmod +x setup-dev.sh
./setup-dev.sh

# Start development server
./run-dev.sh
```

#### **Production Environment**
```bash
# Clone repository
git clone <repository-url>
cd vps-manager-backend

# Setup production environment with systemctl
sudo chmod +x setup-manual.sh
sudo ./setup-manual.sh

# Service will be automatically started and enabled
sudo systemctl status vps-manager
```

### **Legacy Setup (Not Recommended)**
```bash
# Clone repository
git clone <repository-url>
cd vps-manager-backend

# Install Python dependencies
pip install -r requirements.txt

# Run as root (required for Nginx management)
sudo python3 main.py
```

### **Docker Setup**
```bash
# Build and run with Docker (API only)
docker compose up -d

# Or build manually
docker build -t vps-manager-backend .
docker run -p 8000:8000 vps-manager-backend
```

## ⚙️ **Configuration**

### **Environment Variables**
```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis Configuration (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Logging Configuration
LOG_LEVEL=INFO
LOG_DIR=/var/log/vps-manager
LOG_RETENTION_DAYS=30

# SSL Configuration
SSL_CERT_DIR=/etc/ssl/ptsi
DEFAULT_SSL_CERT=/etc/ssl/ptsi/wildcard.ptsi.co.id.crt
DEFAULT_SSL_KEY=/etc/ssl/ptsi/wildcard.ptsi.co.id.key
LETSENCRYPT_EMAIL=admin@example.com
```

### **Nginx Configuration (External)**
```nginx
# Example Nginx configuration for the API
# Run this on your host system, not in Docker
server {
    listen 80;
    server_name api.vps-manager.com;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 📡 **API Endpoints**

### **Authentication**
```http
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
```

### **Configuration Management**
```http
GET    /api/configs                    # List all configurations
GET    /api/configs/{id}              # Get specific configuration
POST   /api/configs                   # Create new configuration
PUT    /api/configs/{id}              # Update configuration
DELETE /api/configs/{id}              # Delete configuration
POST   /api/configs/{id}/toggle       # Toggle configuration status
POST   /api/configs/{id}/test         # Test configuration
POST   /api/configs/validate          # Validate configuration
GET    /api/configs/{id}/form         # Get configuration for form editing
GET    /api/configs/{id}/metrics      # Get configuration metrics
```

### **SSL Certificate Management**
```http
GET    /api/ssl/certificates          # List SSL certificates
POST   /api/ssl/request-letsencrypt   # Request Let's Encrypt certificate
POST   /api/ssl/renew/{domain}        # Renew SSL certificate
POST   /api/ssl/upload                # Upload additional certificates
GET    /api/ssl/certificate/{domain}/content  # Get certificate content
GET    /api/ssl/domains               # List SSL domains
```

**Default SSL Configuration:**
- **SSL Directory**: `/etc/ssl/ptsi`
- **Default Certificate**: `/etc/ssl/ptsi/wildcard.ptsi.co.id.crt`
- **Default Key**: `/etc/ssl/ptsi/wildcard.ptsi.co.id.key`
- **Wildcard Domain**: `*.ptsi.co.id`

### **Load Balancer**
```http
GET    /api/load-balancer/pools       # List load balancer pools
POST   /api/load-balancer/pools       # Create load balancer pool
```

### **Backup & Restore**
```http
GET    /api/backup/list               # List backups
POST   /api/backup/create             # Create backup
GET    /api/backup/download/{filename} # Download backup
POST   /api/backup/restore/{filename} # Restore backup
DELETE /api/backup/delete/{filename}  # Delete backup
```

### **System Management**
```http
GET    /api/system/status             # Get system status
POST   /api/system/nginx/restart      # Restart Nginx
POST   /api/system/nginx/reload       # Reload Nginx
GET    /api/system/nginx/logs         # Get Nginx logs
```

### **Log Management**
```http
GET    /api/logs/nginx                # Get Nginx logs
GET    /api/logs/application          # Get application logs
GET    /api/logs/system               # Get system logs
GET    /api/logs/structured           # Get structured logs
GET    /api/logs/audit                # Get audit logs
GET    /api/logs/performance          # Get performance logs
GET    /api/logs/security             # Get security logs
GET    /api/logs/retention-policy     # Get retention policy
PUT    /api/logs/retention-policy     # Update retention policy
POST   /api/logs/cleanup              # Clean up old logs
```

## 📊 **Real-time Monitoring**

### **WebSocket Endpoints**
```http
WS /ws/monitoring                     # Real-time monitoring stream
```

### **Monitoring APIs**
```http
GET    /api/monitoring/metrics        # Get current metrics
GET    /api/monitoring/metrics/history # Get metrics history
POST   /api/monitoring/alerts/rules   # Create alert rule
GET    /api/monitoring/alerts/rules   # List alert rules
PUT    /api/monitoring/alerts/rules/{id} # Update alert rule
DELETE /api/monitoring/alerts/rules/{id} # Delete alert rule
GET    /api/monitoring/alerts         # Get alerts
POST   /api/monitoring/alerts/{id}/resolve # Resolve alert
```

### **Metrics Collected**
- **System Metrics**: CPU, Memory, Disk, Network usage
- **Nginx Metrics**: Connections, Requests per second
- **Application Metrics**: Response times, Error rates
- **Custom Metrics**: User-defined metrics and alerts

### **Alert System**
- **Threshold-based alerts** for system metrics
- **Email notifications** for critical alerts
- **Webhook integrations** for external systems
- **Alert resolution** and history tracking

## 📝 **Advanced Logging**

### **Log Types**
- **Structured Logs**: JSON-formatted application logs
- **Audit Logs**: User actions and compliance tracking
- **Performance Logs**: Request timing and performance metrics
- **Security Logs**: Security events and threat detection

### **Log Features**
- **Structured JSON logging** with consistent format
- **Log filtering** by level, source, time range
- **Log retention policies** with automatic cleanup
- **Compliance logging** for regulatory requirements
- **Performance tracking** with detailed metrics

### **Log Management**
```bash
# View logs
tail -f /var/log/vps-manager/structured.log
tail -f /var/log/vps-manager/audit.log
tail -f /var/log/vps-manager/performance.log

# Log rotation
logrotate /etc/logrotate.d/vps-manager
```

## 🔧 **Scalability Features**

### **Caching System**
- **Redis caching** for distributed environments
- **In-memory cache** fallback for single instances
- **Cache statistics** and monitoring
- **Cache invalidation** strategies

### **Connection Pooling**
- **Database connection pooling** for high concurrency
- **Connection monitoring** and statistics
- **Automatic connection management**
- **Connection health checks**

### **Horizontal Scaling**
- **Cluster management** for multi-node deployments
- **Load distribution** across nodes
- **Node health monitoring**
- **Task distribution** and queuing

### **Performance Monitoring**
```http
GET    /api/performance/cache/stats   # Cache statistics
POST   /api/performance/cache/clear   # Clear cache
GET    /api/performance/connections   # Connection pool stats
```

### **Health Checks**
```http
GET    /api/health/backend/{url}      # Check backend health
GET    /api/health/backends           # Get all backend status
```

### **Task Queue**
```http
POST   /api/tasks/queue               # Add background task
GET    /api/tasks/queue/status        # Get queue status
```

## 🔒 **Security**

### **Authentication**
- **JWT-based authentication** with secure tokens
- **Role-based access control** (Admin/User roles)
- **Session management** with automatic expiration
- **Secure password handling**

### **Default Admin Account**
```bash
Username: admin
Password: admin123
Email: admin@ptsi.co.id
Role: admin
```

**⚠️ Important:** Change the default password in production!

### **Authorization**
- **Endpoint-level permissions** for sensitive operations
- **Resource-based access control**
- **Audit logging** for all administrative actions
- **IP-based access restrictions**

### **Security Features**
- **Rate limiting** to prevent abuse
- **Input validation** and sanitization
- **SQL injection protection**
- **XSS protection** with proper headers
- **CORS configuration** for web applications

### **Compliance**
- **GDPR compliance** with data retention policies
- **Audit trails** for regulatory requirements
- **Security event logging** and monitoring
- **Data encryption** for sensitive information

## 🚀 **Deployment**

### **Production Deployment**
```bash
# Systemd service
sudo cp vps-manager.service /etc/systemd/system/
sudo systemctl enable vps-manager
sudo systemctl start vps-manager

# Nginx configuration
sudo cp nginx.conf /etc/nginx/sites-available/vps-manager
sudo ln -s /etc/nginx/sites-available/vps-manager /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### **Docker Deployment**
```yaml
# docker-compose.yml
version: '3.8'
services:
  vps-manager:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./logs:/var/log/vps-manager
      - ./configs:/etc/nginx/conf.d
    environment:
      - REDIS_HOST=redis
    depends_on:
      - redis
  
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

### **Kubernetes Deployment**
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vps-manager
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vps-manager
  template:
    metadata:
      labels:
        app: vps-manager
    spec:
      containers:
      - name: vps-manager
        image: vps-manager:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_HOST
          value: "redis-service"
```

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Permission Denied**
```bash
# Ensure running as root for Nginx management
sudo python3 main.py

# Check file permissions
sudo chown -R root:root /etc/nginx/conf.d/
sudo chmod 644 /etc/nginx/conf.d/*
```

#### **Nginx Configuration Errors**
```bash
# Test Nginx configuration
sudo nginx -t

# Check Nginx status
sudo systemctl status nginx

# View Nginx error logs
sudo tail -f /var/log/nginx/error.log
```

#### **Redis Connection Issues**
```bash
# Check Redis status
sudo systemctl status redis

# Test Redis connection
redis-cli ping

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

#### **WebSocket Connection Issues**
```bash
# Check WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     -H "Sec-WebSocket-Version: 13" \
     http://localhost:8000/ws/monitoring
```

#### **SSL Certificate Issues**
```bash
# Check PTSI SSL certificate
ls -la /etc/ssl/ptsi/
openssl x509 -in /etc/ssl/ptsi/wildcard.ptsi.co.id.crt -text -noout

# Verify certificate validity
openssl x509 -in /etc/ssl/ptsi/wildcard.ptsi.co.id.crt -checkend 86400 -noout

# Test SSL connection
curl -I https://your-domain.ptsi.co.id

# Check SSL certificate permissions
sudo chmod 644 /etc/ssl/ptsi/wildcard.ptsi.co.id.crt
sudo chmod 600 /etc/ssl/ptsi/wildcard.ptsi.co.id.key
```

### **Performance Issues**

#### **High Memory Usage**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Monitor cache usage
curl http://localhost:8000/api/performance/cache/stats
```

#### **Slow Response Times**
```bash
# Check system load
uptime
top

# Monitor performance logs
curl http://localhost:8000/api/logs/performance?limit=100
```

### **Log Analysis**

#### **Structured Logs**
```bash
# View recent logs
tail -f /var/log/vps-manager/structured.log | jq

# Filter by level
grep '"level":"ERROR"' /var/log/vps-manager/structured.log | jq
```

#### **Audit Logs**
```bash
# View user actions
tail -f /var/log/vps-manager/audit.log | jq

# Search for specific user
grep '"user_id":"admin"' /var/log/vps-manager/audit.log | jq
```

## 📚 **API Documentation**

### **Interactive Documentation**
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

### **Example Requests**

#### **Create Configuration**
```bash
curl -X POST "http://localhost:8000/api/configs" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "example-app",
  "server_name": "example.com",
    "listen_port": 80,
  "locations": [
    {
      "path": "/",
        "backend": "http://localhost:3000"
      }
    ]
  }'
```

#### **Monitor Real-time Metrics**
```javascript
// WebSocket connection
const ws = new WebSocket('ws://localhost:8000/ws/monitoring');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('System metrics:', data.system);
  console.log('Active alerts:', data.alerts);
};
```

## 🤝 **Contributing**

### **Development Setup**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 main.py
black main.py
```

### **Code Style**
- **PEP 8** compliance
- **Type hints** for all functions
- **Docstrings** for all classes and methods
- **Error handling** with proper logging

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 **Support**

- **Documentation**: [Wiki](https://github.com/surveyor-indonesia/vps-manager/wiki)
- **Issues**: [GitHub Issues](https://github.com/surveyor-indonesia/vps-manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/surveyor-indonesia/vps-manager/discussions)

---

**Surveyor Indonesia - VPS Manager v2.0.0**  
*Comprehensive VPS Management with Advanced Monitoring & Scalability*
