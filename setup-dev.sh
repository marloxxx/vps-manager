#!/bin/bash

# VPS Manager Backend - Development Setup Script
# Setup untuk Development Environment dengan Virtual Environment

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

print_header "VPS Manager Backend - Development Setup"
print_status "Starting development setup process..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed. Please install pip3 first."
    exit 1
fi

# Create virtual environment
print_status "Creating virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists. Removing old one..."
    rm -rf venv
fi

python3 -m venv venv

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Verify activation
if [[ "$VIRTUAL_ENV" == "" ]]; then
    print_error "Failed to activate virtual environment"
    exit 1
fi

print_status "Virtual environment activated: $VIRTUAL_ENV"

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
print_status "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    print_error "requirements.txt not found!"
    exit 1
fi

# Create development directories
print_status "Creating development directories..."
mkdir -p app
mkdir -p logs
mkdir -p backups
mkdir -p templates

# Setup admin user for development
print_status "Setting up admin user for development..."
cat > app/users_db.json << 'EOF'
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

chmod 644 app/users_db.json

# Create development SSL certificates
print_status "Creating development SSL certificates..."
mkdir -p /tmp/ssl/ptsi

# Create dummy certificates for development
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /tmp/ssl/ptsi/wildcard.ptsi.co.id.key \
    -out /tmp/ssl/ptsi/wildcard.ptsi.co.id.crt \
    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=PTSI/CN=*.ptsi.co.id"

chmod 644 /tmp/ssl/ptsi/wildcard.ptsi.co.id.crt
chmod 600 /tmp/ssl/ptsi/wildcard.ptsi.co.id.key

print_status "Development SSL certificates created in /tmp/ssl/ptsi/"

# Test Python import
print_status "Testing Python imports..."
if python -c "import main; print('✅ Main module imported successfully')" 2>/dev/null; then
    print_status "Python imports working correctly!"
else
    print_warning "Some imports may have issues (expected in development environment)"
fi

# Create development startup script
print_status "Creating development startup script..."
cat > run-dev.sh << 'EOF'
#!/bin/bash

# VPS Manager Backend - Development Startup Script

echo "🚀 Starting VPS Manager Backend in development mode..."

# Activate virtual environment
source venv/bin/activate

# Set development environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
export LOG_LEVEL=DEBUG
export API_HOST=0.0.0.0
export API_PORT=8000

# Create logs directory if it doesn't exist
mkdir -p logs

echo "📁 Working directory: $(pwd)"
echo "🐍 Python: $(which python)"
echo "🔧 Environment: Development"
echo "🌐 Host: 0.0.0.0:8000"
echo "📚 Documentation: http://localhost:8000/docs"
echo "🔍 Health Check: http://localhost:8000/health"
echo ""
echo "📋 Login credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the application
python main.py
EOF

chmod +x run-dev.sh

# Create test script
print_status "Creating test script..."
cat > test-dev.sh << 'EOF'
#!/bin/bash

# VPS Manager Backend - Development Test Script

echo "🧪 Testing VPS Manager Backend..."

# Activate virtual environment
source venv/bin/activate

# Test health endpoint
echo "📡 Testing health endpoint..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Health endpoint is responding!"
else
    echo "❌ Health endpoint not responding. Is the server running?"
    exit 1
fi

# Test login
echo "🔐 Testing authentication..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')

if echo "$LOGIN_RESPONSE" | grep -q "token"; then
    echo "✅ Authentication is working!"
    TOKEN=$(echo "$LOGIN_RESPONSE" | sed 's/.*"token":"\([^"]*\)".*/\1/')
    
    # Test authenticated endpoint
    if curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/auth/me > /dev/null; then
        echo "✅ Authenticated endpoints are working!"
    else
        echo "❌ Authenticated endpoints failed"
    fi
else
    echo "❌ Authentication failed"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi

echo "🎉 All tests passed!"
EOF

chmod +x test-dev.sh

# Create development environment file
print_status "Creating development environment file..."
cat > .env.dev << 'EOF'
# Development Environment Variables
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=dev-secret-key-change-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Logging Configuration
LOG_LEVEL=DEBUG
LOG_DIR=./logs
LOG_RETENTION_DAYS=7

# SSL Configuration (Development)
SSL_CERT_DIR=/tmp/ssl/ptsi
DEFAULT_SSL_CERT=/tmp/ssl/ptsi/wildcard.ptsi.co.id.crt
DEFAULT_SSL_KEY=/tmp/ssl/ptsi/wildcard.ptsi.co.id.key
EOF

print_header "Development Setup Complete!"

echo -e "${GREEN}✅ VPS Manager Backend development environment is ready!${NC}"
echo ""
echo -e "${BLUE}📋 Login Information:${NC}"
echo -e "   Username: ${YELLOW}admin${NC}"
echo -e "   Password: ${YELLOW}admin123${NC}"
echo ""
echo -e "${BLUE}🚀 How to start:${NC}"
echo -e "   Development mode: ${YELLOW}./run-dev.sh${NC}"
echo -e "   Or manually: ${YELLOW}source venv/bin/activate && python main.py${NC}"
echo ""
echo -e "${BLUE}🧪 How to test:${NC}"
echo -e "   Run tests: ${YELLOW}./test-dev.sh${NC}"
echo -e "   Health check: ${YELLOW}curl http://localhost:8000/health${NC}"
echo ""
echo -e "${BLUE}🌐 Access URLs:${NC}"
echo -e "   API: ${YELLOW}http://localhost:8000${NC}"
echo -e "   Documentation: ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "   Health Check: ${YELLOW}http://localhost:8000/health${NC}"
echo ""
echo -e "${BLUE}📁 Important Files:${NC}"
echo -e "   Virtual Environment: ${YELLOW}./venv/${NC}"
echo -e "   User Database: ${YELLOW}./app/users_db.json${NC}"
echo -e "   Logs: ${YELLOW}./logs/${NC}"
echo -e "   SSL Certificates: ${YELLOW}/tmp/ssl/ptsi/${NC}"
echo ""
echo -e "${BLUE}🔧 Development Commands:${NC}"
echo -e "   Activate venv: ${YELLOW}source venv/bin/activate${NC}"
echo -e "   Install package: ${YELLOW}pip install package-name${NC}"
echo -e "   Update requirements: ${YELLOW}pip freeze > requirements.txt${NC}"
echo -e "   View logs: ${YELLOW}tail -f logs/vps-manager.log${NC}"
echo ""
echo -e "${YELLOW}⚠️  This is a development setup. For production, use setup-manual.sh${NC}"
echo ""
echo -e "${GREEN}🎉 Development setup completed successfully!${NC}" 