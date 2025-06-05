# Use Python 3.10 as base image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    wget \
    htop \
    systemctl \
    procps \
    sudo \
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
COPY backend/app/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir uvicorn gunicorn

# Copy application code
COPY backend/app/ .
COPY backend/systemd/ /opt/vps-manager/systemd/
COPY backend/setup.sh /opt/vps-manager/setup.sh

# Create necessary files and set permissions
RUN touch /opt/vps-manager/app/config_db.json \
    && chmod +x /opt/vps-manager/setup.sh \
    && chmod -R 755 /opt/vps-manager \
    && chmod 644 /opt/vps-manager/app/config_db.json

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

# Expose API port
EXPOSE 8000

# Create entrypoint script
RUN echo '#!/bin/bash\n\
    # Start Nginx\n\
    nginx -g "daemon off;" &\n\
    \n\
    # Start FastAPI application\n\
    cd /opt/vps-manager/app\n\
    exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2\n' > /opt/vps-manager/entrypoint.sh \
    && chmod +x /opt/vps-manager/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/opt/vps-manager/entrypoint.sh"]
