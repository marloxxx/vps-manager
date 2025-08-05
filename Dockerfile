# Use Python 3.11 as base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Jakarta

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    wget \
    htop \
    procps \
    sudo \
    systemctl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directories
RUN mkdir -p /opt/vps-manager/{app,logs,backups,templates} \
    && mkdir -p /etc/nginx/sites-available \
    && mkdir -p /etc/nginx/sites-enabled \
    && mkdir -p /etc/ssl/ptsi

# Set working directory
WORKDIR /opt/vps-manager/app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir uvicorn gunicorn

# Copy application code
COPY main.py .
COPY README.md .

# Create necessary files and set permissions
RUN touch config_db.json \
    && chmod -R 755 /opt/vps-manager \
    && chmod 644 config_db.json

# Create default SSL certificate files if they don't exist
RUN touch /etc/ssl/ptsi/wildcard.ptsi.co.id.crt \
    && touch /etc/ssl/ptsi/wildcard.ptsi.co.id.key \
    && chmod 644 /etc/ssl/ptsi/wildcard.ptsi.co.id.crt \
    && chmod 600 /etc/ssl/ptsi/wildcard.ptsi.co.id.key

# Create a backup script
RUN echo '#!/bin/bash\n\
    BACKUP_DIR="/opt/vps-manager/backups"\n\
    DATE=$(date +%Y%m%d_%H%M%S)\n\
    BACKUP_FILE="vps-manager-backup-${DATE}.tar.gz"\n\
    \n\
    # Create backup\n\
    tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" \\\n\
    -C /opt/vps-manager \\\n\
    app/config_db.json \\\n\
    app/users_db.json \\\n\
    templates/ \\\n\
    --exclude="*.pyc" \\\n\
    --exclude="__pycache__"\n\
    \n\
    # Keep only last 10 backups\n\
    cd "${BACKUP_DIR}"\n\
    ls -t vps-manager-backup-*.tar.gz | tail -n +11 | xargs -r rm\n\
    \n\
    echo "Backup created: ${BACKUP_FILE}"\n' > /opt/vps-manager/backup.sh \
    && chmod +x /opt/vps-manager/backup.sh

# Configure Nginx
RUN echo 'server {\n\
    listen 80;\n\
    server_name _;\n\
    \n\
    location / {\n\
    proxy_pass http://127.0.0.1:8000;\n\
    proxy_set_header Host $host;\n\
    proxy_set_header X-Real-IP $remote_addr;\n\
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
    proxy_set_header X-Forwarded-Proto $scheme;\n\
    }\n\
    }\n' > /etc/nginx/sites-available/default \
    && ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Create systemd service file
RUN echo '[Unit]\n\
    Description=VPS Manager API Service\n\
    After=network.target nginx.service\n\
    Wants=nginx.service\n\
    \n\
    [Service]\n\
    Type=simple\n\
    User=root\n\
    Group=root\n\
    WorkingDirectory=/opt/vps-manager/app\n\
    Environment="PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n\
    ExecStart=/usr/local/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2\n\
    ExecReload=/bin/kill -HUP $MAINPID\n\
    Restart=always\n\
    RestartSec=5\n\
    StandardOutput=journal\n\
    StandardError=journal\n\
    \n\
    [Install]\n\
    WantedBy=multi-user.target\n' > /etc/systemd/system/vps-manager.service

# Create log rotation configuration
RUN echo '/opt/vps-manager/logs/*.log {\n\
    daily\n\
    missingok\n\
    rotate 30\n\
    compress\n\
    delaycompress\n\
    notifempty\n\
    create 644 root root\n\
    postrotate\n\
    systemctl reload vps-manager\n\
    endscript\n\
    }\n' > /etc/logrotate.d/vps-manager

# Expose API port
EXPOSE 8000 80

# Create entrypoint script
RUN echo '#!/bin/bash\n\
    set -e\n\
    \n\
    # Start Nginx\n\
    echo "Starting Nginx..."\n\
    nginx -g "daemon off;" &\n\
    \n\
    # Wait a moment for Nginx to start\n\
    sleep 2\n\
    \n\
    # Start FastAPI application\n\
    echo "Starting VPS Manager API..."\n\
    cd /opt/vps-manager/app\n\
    exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2\n' > /opt/vps-manager/entrypoint.sh \
    && chmod +x /opt/vps-manager/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/opt/vps-manager/entrypoint.sh"] 