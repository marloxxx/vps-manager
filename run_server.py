#!/usr/bin/env python3

"""
VPS Manager Backend - Server Runner
Script untuk menjalankan server dengan logging dan error handling yang lebih baik
"""

import os
import sys
import logging
import uvicorn
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def setup_directories():
    """Create necessary directories."""
    directories = ['logs', 'app', 'backups', 'ssl']
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def check_dependencies():
    """Check if required dependencies are available."""
    try:
        import psutil
        print("✅ psutil available")
    except ImportError:
        print("⚠️  psutil not available - some features may not work")
    
    try:
        import uvicorn
        print("✅ uvicorn available")
    except ImportError:
        print("❌ uvicorn not available")
        return False
    
    return True

def main():
    """Main server startup function."""
    try:
        print("🚀 VPS Manager Backend - Server Startup")
        print("=" * 50)
        
        # Setup directories
        setup_directories()
        
        # Check dependencies
        if not check_dependencies():
            print("❌ Missing required dependencies")
            sys.exit(1)
        
        # Display server information
        print("\n📊 Server Information:")
        print(f"📁 Working Directory: {os.getcwd()}")
        print(f"🐍 Python Version: {sys.version}")
        print(f"🌐 Host: 0.0.0.0:8000")
        print(f"📚 API Documentation: http://0.0.0.0:8000/docs")
        print(f"🔍 Health Check: http://0.0.0.0:8000/health")
        print(f"🔌 WebSocket: ws://0.0.0.0:8000/ws/monitoring")
        print(f"📝 Logs: logs/server.log")
        print("=" * 50)
        
        # Start the server
        print("\n🚀 Starting server...")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info",
            access_log=True,
            log_config=None
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Server startup failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 