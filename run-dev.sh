#!/bin/bash

# VPS Manager Backend - Development Startup Script

echo "🚀 Starting VPS Manager Backend in development mode..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup-dev.sh first."
    exit 1
fi

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