# VPS Manager Docker Deployment

Dokumentasi lengkap untuk deployment VPS Manager backend menggunakan Docker.

## 📋 Prerequisites

Sebelum menjalankan deployment, pastikan sistem memiliki:

- Docker (versi 20.10+)
- Docker Compose (versi 2.0+)
- Port 8000 dan 80 tersedia
- Minimal 2GB RAM
- Minimal 10GB disk space

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone <repository-url>
cd vps-manager/vps-manager-backend
```

### 2. Deploy dengan Script Otomatis
```bash
./docker-deploy.sh
```

### 3. Deploy Manual dengan Docker Compose
```bash
# Build image
docker-compose build

# Start service
docker-compose up -d

# Check status
docker-compose ps
```

## 📁 Struktur Volume

Docker deployment menggunakan volume untuk persistensi data:

```
docker-data/
├── config/          # Konfigurasi aplikasi
├── logs/            # Log files
├── backups/         # Backup files
├── templates/       # Template files
├── nginx/           # Nginx configuration
└── ssl/             # SSL certificates
```

## 🔧 Konfigurasi

### Environment Variables

Edit `docker-compose.yml` untuk mengubah environment variables:

```yaml
environment:
  - JWT_SECRET_KEY=your-super-secret-key-change-in-production
  - TZ=Asia/Jakarta
  - PYTHONPATH=/opt/vps-manager/app
```

### Port Configuration

Default ports:
- `8000`: API endpoint
- `80`: Nginx proxy

Untuk mengubah ports, edit `docker-compose.yml`:

```yaml
ports:
  - "8080:8000"  # Custom API port
  - "8081:80"    # Custom Nginx port
```

## 📊 Monitoring

### Health Check
```bash
# Check API health
curl http://localhost:8000/health

# Check container status
docker-compose ps
```

### Logs
```bash
# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f vps-manager-backend
```

## 🔐 Security

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`

### SSL Certificates
SSL certificates disimpan di volume `ssl_certs`. Untuk menggunakan custom certificates:

1. Place certificate files in `./docker-data/ssl/`
2. Update Nginx configuration
3. Restart container

## 🛠️ Management Commands

### Start Service
```bash
docker-compose up -d
```

### Stop Service
```bash
docker-compose down
```

### Restart Service
```bash
docker-compose restart
```

### Update Service
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d
```

### Backup Data
```bash
# Backup volumes
docker run --rm -v vps-manager_vps_config:/data -v $(pwd):/backup alpine tar czf /backup/config_backup.tar.gz -C /data .

# Backup all data
docker run --rm -v vps-manager_vps_config:/config -v vps-manager_vps_users:/users -v vps-manager_vps_backups:/backups -v $(pwd):/backup alpine tar czf /backup/full_backup.tar.gz -C /config . -C /users . -C /backups .
```

### Restore Data
```bash
# Restore from backup
docker run --rm -v vps-manager_vps_config:/data -v $(pwd):/backup alpine tar xzf /backup/config_backup.tar.gz -C /data
```

## 🔍 Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose logs

# Check port conflicts
lsof -i :8000
lsof -i :80

# Check disk space
df -h
```

### Permission Issues
```bash
# Fix permissions
sudo chown -R $USER:$USER ./docker-data
chmod -R 755 ./docker-data
```

### Network Issues
```bash
# Check network
docker network ls
docker network inspect vps-manager_vps-manager-network
```

### SSL Issues
```bash
# Check SSL certificates
docker exec vps-manager-backend ls -la /etc/ssl/ptsi/

# Test SSL
openssl s_client -connect localhost:443
```

## 📈 Performance

### Resource Limits
Edit `docker-compose.yml` untuk menambahkan resource limits:

```yaml
services:
  vps-manager-backend:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

### Scaling
Untuk production, gunakan multiple workers:

```yaml
environment:
  - WORKERS=4
```

## 🔄 Updates

### Update Application
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d
```

### Update Dependencies
```bash
# Update requirements.txt
# Rebuild container
docker-compose build --no-cache
docker-compose up -d
```

## 📝 Logs

### Application Logs
```bash
# View application logs
docker-compose logs -f vps-manager-backend

# View specific log file
docker exec vps-manager-backend cat /opt/vps-manager/logs/vps-manager.log
```

### Nginx Logs
```bash
# View Nginx access logs
docker exec vps-manager-backend tail -f /var/log/nginx/access.log

# View Nginx error logs
docker exec vps-manager-backend tail -f /var/log/nginx/error.log
```

## 🚨 Alerts & Monitoring

### Telegram Notifications
Sistem sudah terintegrasi dengan Telegram notifications. Pastikan environment variables berikut sudah diset:

```yaml
environment:
  - TELEGRAM_BOT_TOKEN=your-bot-token
  - TELEGRAM_CHANNEL_ID=your-channel-id
  - TELEGRAM_BOT_USERNAME=your-bot-username
  - TELEGRAM_USER_ID=@your-username
```

### Health Monitoring
```bash
# Check system metrics
curl http://localhost:8000/api/system/status

# Check monitoring metrics
curl http://localhost:8000/api/monitoring/metrics
```

## 🎯 Production Deployment

### Production Checklist
- [ ] Change default passwords
- [ ] Set strong JWT_SECRET_KEY
- [ ] Configure SSL certificates
- [ ] Set up monitoring
- [ ] Configure backups
- [ ] Set resource limits
- [ ] Configure log rotation
- [ ] Set up firewall rules

### Security Hardening
```bash
# Run security scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image vps-manager-backend:latest

# Check for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy fs .
```

## 📞 Support

Untuk bantuan lebih lanjut:

1. Check logs: `docker-compose logs`
2. Check documentation: `README.md`
3. Check API docs: `http://localhost:8000/docs`
4. Report issues di repository

---

**VPS Manager Docker Deployment** - Surveyor Indonesia 