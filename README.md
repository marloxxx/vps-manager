# VPS Manager Backend

Advanced reverse proxy management system backend built with FastAPI and Python.

## Features

- **Authentication & Authorization**: JWT-based authentication with role-based access control
- **User Management**: Complete user management with seeder support
- **Nginx Configuration**: Dynamic Nginx configuration generation and management
- **System Monitoring**: Real-time system statistics and health monitoring
- **API Documentation**: Automatic OpenAPI/Swagger documentation

## Installation

### Prerequisites

- Python 3.11+
- Nginx
- Root access (required for Nginx management)

### Setup

1. **Clone the repository:**
\`\`\`bash
git clone <repository-url>
cd vps-manager-backend
\`\`\`

2. **Create virtual environment:**
\`\`\`bash
python3 -m venv venv
source venv/bin/activate
\`\`\`

3. **Install dependencies:**
\`\`\`bash
pip install -r requirements.txt
\`\`\`

4. **Create necessary directories:**
\`\`\`bash
sudo mkdir -p /opt/vps-manager/{logs,backups,templates}
sudo chown -R $USER:$USER /opt/vps-manager
\`\`\`

5. **Seed default users:**
\`\`\`bash
# Seed default users (admin, user, operator, manager)
python3 seeder.py seed

# Or create custom user
python3 seeder.py create --username myuser --email user@example.com --password mypassword --role user
\`\`\`

## Usage

### Running the API

\`\`\`bash
# Development
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
python3 main.py
\`\`\`

### Using Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t vps-manager-backend .
docker run -d -p 8000:8000 --name vps-manager-backend vps-manager-backend
\`\`\`

### User Management

The seeder script provides comprehensive user management:

\`\`\`bash
# Seed default users
python3 seeder.py seed

# Force overwrite existing users
python3 seeder.py seed --force

# List all users
python3 seeder.py list

# Create custom user
python3 seeder.py create --username newuser --email user@example.com --password password123 --role admin

# Delete user
python3 seeder.py delete --username username

# Reset password
python3 seeder.py reset-password --username username --password newpassword
\`\`\`

### Default Users

The seeder creates these default users:

| Username | Email | Password | Role |
|----------|--------|----------|------|
| admin | admin@surveyorindonesia.com | admin123 | admin |
| user | user@surveyorindonesia.com | user123 | user |
| operator | operator@surveyorindonesia.com | operator123 | user |
| manager | manager@surveyorindonesia.com | manager123 | admin |

## API Endpoints

### Authentication

- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user info
- `POST /api/auth/logout` - User logout

### Configurations

- `GET /api/configs` - List all configurations
- `POST /api/configs` - Create new configuration
- `GET /api/configs/{id}` - Get specific configuration
- `PUT /api/configs/{id}` - Update configuration
- `DELETE /api/configs/{id}` - Delete configuration
- `POST /api/configs/{id}/toggle` - Toggle configuration status

### System Management

- `GET /api/system/status` - Get system statistics
- `POST /api/system/nginx/restart` - Restart Nginx (Admin only)
- `POST /api/system/nginx/reload` - Reload Nginx (Admin only)
- `GET /api/system/nginx/logs` - Get Nginx logs

### Health Check

- `GET /health` - API health check

## Configuration

### Environment Variables

- `JWT_SECRET_KEY` - Secret key for JWT tokens (change in production!)
- `BASE_DIR` - Base directory for VPS Manager (default: `/opt/vps-manager`)

### File Structure

\`\`\`
/opt/vps-manager/
├── config_db.json          # Configuration database
├── users_db.json           # User database
├── logs/                   # Application logs
├── backups/                # Configuration backups
└── templates/              # Configuration templates
\`\`\`

## Security

### Authentication

- JWT-based authentication with configurable expiration
- Role-based access control (admin/user)
- Secure password hashing using SHA-256

### Permissions

- **Admin users**: Full access to all features
- **Regular users**: Can only manage their own configurations
- **System operations**: Require admin privileges

### Rate Limiting

- Global rate limiting: 100 requests per hour per IP
- Per-endpoint rate limiting for sensitive operations

## Development

### Project Structure

\`\`\`
vps-manager-backend/
├── main.py                 # Main FastAPI application
├── auth.py                 # Authentication module
├── seeder.py              # User seeder script
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose configuration
└── README.md             # This file
\`\`\`

### Adding New Features

1. Create new endpoints in `main.py`
2. Add authentication decorators as needed
3. Update models and validation
4. Add tests for new functionality

### Database

The system uses JSON files for simplicity:
- `users_db.json` - User accounts and authentication
- `config_db.json` - Nginx configurations

For production, consider migrating to a proper database like PostgreSQL.

## Deployment

### Production Setup

1. **Install on server:**
\`\`\`bash
# Copy files to /opt/vps-manager-backend
sudo cp -r . /opt/vps-manager-backend

# Install system dependencies
sudo apt update
sudo apt install -y python3-venv nginx

# Setup virtual environment
cd /opt/vps-manager-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Seed users
python3 seeder.py seed
\`\`\`

2. **Create systemd service:**
\`\`\`ini
[Unit]
Description=VPS Manager Backend API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-manager-backend
Environment="PATH=/opt/vps-manager-backend/venv/bin"
ExecStart=/opt/vps-manager-backend/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
\`\`\`

3. **Enable and start service:**
\`\`\`bash
sudo systemctl enable vps-manager-backend
sudo systemctl start vps-manager-backend
\`\`\`

### Environment Configuration

Create `.env` file for production:
\`\`\`env
JWT_SECRET_KEY=your-very-secure-secret-key-here
BASE_DIR=/opt/vps-manager
LOG_LEVEL=INFO
\`\`\`

## Troubleshooting

### Common Issues

1. **Permission denied errors:**
   - Ensure the application runs as root for Nginx management
   - Check file permissions on `/opt/vps-manager`

2. **User database not found:**
   - Run the seeder: `python3 seeder.py seed`
   - Check if `/opt/vps-manager` directory exists

3. **Nginx commands fail:**
   - Ensure Nginx is installed and accessible
   - Check if the user has sudo privileges

### Logs

- Application logs: `/opt/vps-manager/logs/vps-manager.log`
- Systemd logs: `journalctl -u vps-manager-backend -f`

## License

MIT License - see LICENSE file for details.

## Support

For support and questions:
- Email: support@surveyorindonesia.com
- GitHub Issues: Create an issue on the repository
