# VPS Manager Backend

An advanced reverse proxy management system backend built with **FastAPI** and **Python**, designed to power the VPS Manager system with robust configuration management and system monitoring capabilities.

---

## 🚀 Features

- **🔐 Authentication & Authorization**: JWT-based authentication with role-based access control.
- **👤 User Management**: Comprehensive user management with seeder support.
- **⚙️ Nginx Configuration**: Dynamic generation and management of Nginx configurations.
- **📈 System Monitoring**: Real-time system statistics and health monitoring.
- **📚 API Documentation**: Automatic OpenAPI/Swagger documentation at `/docs`.

---

## 📋 Prerequisites

Before setting up the backend, ensure you have:
- **Python**: Version 3.11 or higher.
- **Nginx**: Installed and accessible.
- **Root Access**: Required for Nginx management.
- **UFW**: Configured to allow traffic on port 8000 (optional, but recommended).

---

## 🛠️ Installation

### Quick Setup
Run the provided setup script to automate installation:
```bash
chmod +x setup.sh
sudo ./setup.sh
```

The script configures the environment, installs dependencies, sets up services, and seeds default users.

---

## 📖 Usage

### Running the API
#### Development
Start the development server with hot-reload:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Production
Run the production server:
```bash
python3 main.py
```

### Using Docker
#### With Docker Compose
```bash
docker-compose up -d
```

#### Manual Docker Build
```bash
# Build Docker image
docker build -t vps-manager-backend .

# Run container
docker run -d -p 8000:8000 --name vps-manager-backend vps-manager-backend
```

### User Management
The `seeder.py` script provides comprehensive user management:
```bash
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
```

#### Default Users
The seeder creates the following default users:

| Username   | Email                            | Password      | Role  |
|------------|----------------------------------|---------------|-------|
| `admin`    | admin@surveyorindonesia.com     | `admin123`    | admin |
| `user`     | user@surveyorindonesia.com      | `user123`     | user  |
| `operator` | operator@surveyorindonesia.com  | `operator123` | user  |
| `manager`  | manager@surveyorindonesia.com   | `manager123`  | admin |

> **⚠️ Security Note**: Change default passwords in production environments!

---

## 🔍 API Endpoints

### Authentication
- `POST /api/auth/login`: User login.
- `GET /api/auth/me`: Get current user information.
- `POST /api/auth/logout`: User logout.

### Configurations
- `GET /api/configs`: List all configurations.
- `POST /api/configs`: Create a new configuration.
- `GET /api/configs/{id}`: Get a specific configuration.
- `PUT /api/configs/{id}`: Update a configuration.
- `DELETE /api/configs/{id}`: Delete a configuration.
- `POST /api/configs/{id}/toggle`: Enable or disable a configuration.

### System Management
- `GET /api/system/status`: Retrieve system statistics.
- `POST /api/system/nginx/restart`: Restart Nginx (Admin only).
- `POST /api/system/nginx/reload`: Reload Nginx configuration (Admin only).
- `GET /api/system/nginx/logs`: Retrieve Nginx logs.

### Health Check
- `GET /health`: Check API health status.

---

## 🔧 Configuration

### Environment Variables
| Variable            | Description                            | Default              | Required |
|---------------------|----------------------------------------|----------------------|----------|
| `JWT_SECRET_KEY`    | Secret key for JWT tokens              | None                 | Yes      |
| `BASE_DIR`          | Base directory for VPS Manager         | `/opt/vps-manager`   | No       |
| `LOG_LEVEL`         | Logging level (e.g., INFO, DEBUG)      | `INFO`               | No       |

Create a `.env` file in production:
```env
JWT_SECRET_KEY=your-very-secure-secret-key-here
BASE_DIR=/opt/vps-manager
LOG_LEVEL=INFO
```

### File Structure
```
/opt/vps-manager/
├── config_db.json    # Configuration database
├── users_db.json     # User database
├── logs/             # Application logs
├── backups/          # Configuration backups
├── templates/        # Configuration templates
```

---

## 🔒 Security

### Authentication
- JWT-based authentication with configurable token expiration.
- Role-based access control (admin and user roles).
- Secure password hashing using SHA-256.

### Permissions
- **Admin Users**: Full access to all features, including system operations.
- **Regular Users**: Limited to managing their own configurations.
- **System Operations**: Require admin privileges.

### Rate Limiting
- **Global**: 100 requests per hour per IP.
- **Per-Endpoint**: Configurable limits for sensitive operations.

---

## 🏗️ Development

### Project Structure
```
vps-manager-backend/
├── main.py               # Main FastAPI application
├── auth.py               # Authentication module
├── seeder.py             # User seeder script
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose configuration
├── setup.sh              # Installation script
└── README.md             # This file
```

### Adding New Features
1. Create new endpoints in `main.py`.
2. Add authentication decorators as needed.
3. Update models and validation schemas.
4. Add tests for new functionality.

### Database
The system uses JSON files for simplicity:
- `users_db.json`: Stores user accounts and authentication data.
- `config_db.json`: Stores Nginx configurations.

For production, consider migrating to a database like **PostgreSQL** for better scalability.

---

## 🚀 Deployment

### Production Setup
1. **Install on Server**:
```bash
# Copy files to /opt/vps-manager
sudo cp -r . /opt/vps-manager

# Install system dependencies
sudo apt update
sudo apt install -y python3-venv nginx

# Setup virtual environment
cd /opt/vps-manager
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Seed users
python3 seeder.py seed
```

2. **Create Systemd Service**:
```ini
[Unit]
Description=VPS Manager Backend API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-manager
Environment="PATH=/opt/vps-manager/venv/bin"
ExecStart=/opt/vps-manager/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Save to `/etc/systemd/system/vps-manager.service`.

3. **Enable and Start Service**:
```bash
sudo systemctl enable vps-manager
sudo systemctl start vps-manager
```

---

## 🐛 Troubleshooting

### Common Issues
1. **Permission Denied Errors**:
   - Ensure the application runs as root for Nginx management.
   - Verify file permissions on `/opt/vps-manager` (e.g., `sudo chmod -R 755 /opt/vps-manager`).

2. **User Database Not Found**:
   - Run the seeder: `python3 seeder.py seed`.
   - Check if `/opt/vps-manager/users_db.json` exists.

3. **Nginx Commands Fail**:
   - Ensure Nginx is installed and accessible (`nginx -t`).
   - Verify the user has sudo privileges for Nginx operations.

### Logs
- **Application Logs**: `/opt/vps-manager/logs/vps-manager.log`.
- **Systemd Logs**: `journalctl -u vps-manager -f`.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

For support and questions:
- **Email**: support@surveyorindonesia.com
- **GitHub Issues**: Create an issue on the repository for bugs or feature requests.

### Reporting Bugs
Include the following:
1. **Environment**: OS, Python version, Nginx version.
2. **Steps to Reproduce**: Detailed steps to recreate the issue.
3. **Expected Behavior**: What should happen.
4. **Actual Behavior**: What actually happens.
5. **Logs**: Relevant logs from `/opt/vps-manager/logs` or `journalctl`.

### Feature Requests
Provide the following:
1. **Use Case**: Why is this feature needed?
2. **Description**: Detailed description of the feature.
3. **Priority**: How important is this feature?

---

## 🙏 Acknowledgments

- **FastAPI Team**: For the high-performance API framework.
- **Nginx**: For the robust web server.
- **Surveyor Indonesia**: For project sponsorship and support.

---

**Made with ❤️ by Surveyor Indonesia**

For more information, visit our [website](https://ptsi.co.id).
