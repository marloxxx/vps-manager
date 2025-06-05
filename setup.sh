#!/bin/bash

# Create directory structure
sudo mkdir -p /opt/vps-manager/{app,logs}
sudo chown -R $USER:$USER /opt/vps-manager

# Install system dependencies
sudo apt update
sudo apt install -y python3-venv nginx

# Create virtualenv
python3 -m venv /opt/vps-manager/venv
source /opt/vps-manager/venv/bin/activate

# Install Python packages
pip install fastapi uvicorn pydantic python-multipart

# Create initial config
cat > /opt/vps-manager/app/requirements.txt << 'EOL'
fastapi>=0.68.0
uvicorn>=0.15.0
pydantic>=1.8.0
python-multipart>=0.0.5
EOL

# Create systemd service
sudo bash -c 'cat > /etc/systemd/system/vps-manager.service' << 'EOL'
[Unit]
Description=VPS Manager API Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/vps-manager/app
Environment="PATH=/opt/vps-manager/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/vps-manager/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable vps-manager
sudo systemctl start vps-manager

echo "Setup completed. Service is running on port 8000"