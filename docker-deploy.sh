#!/bin/bash

# VPS Manager Docker Deployment Script
# This script helps deploy the VPS Manager backend using Docker

set -e

echo "🚀 VPS Manager Docker Deployment"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Check if ports are available
check_ports() {
    print_status "Checking if ports 8000 and 80 are available..."
    
    if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port 8000 is already in use. Please stop the service using this port."
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port 80 is already in use. Please stop the service using this port."
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    print_success "Ports are available"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    # Create local directories for Docker volumes
    mkdir -p ./docker-data/{config,logs,backups,templates,nginx,ssl}
    
    # Set proper permissions
    chmod -R 755 ./docker-data
    
    print_success "Directories created"
}

# Build and start the container
deploy() {
    print_status "Building Docker image..."
    docker-compose build --no-cache
    
    print_status "Starting VPS Manager backend..."
    docker-compose up -d
    
    print_success "VPS Manager backend deployed successfully!"
}

# Check container status
check_status() {
    print_status "Checking container status..."
    
    if docker-compose ps | grep -q "Up"; then
        print_success "Container is running"
        
        # Show container logs
        print_status "Recent logs:"
        docker-compose logs --tail=20
        
        # Show health check
        print_status "Health check:"
        sleep 5
        if curl -f http://localhost:8000/health >/dev/null 2>&1; then
            print_success "Health check passed"
        else
            print_warning "Health check failed - container might still be starting"
        fi
    else
        print_error "Container is not running"
        docker-compose logs
        exit 1
    fi
}

# Show usage information
show_usage() {
    echo ""
    print_status "VPS Manager is now running!"
    echo ""
    echo "🌐 Access URLs:"
    echo "   API Documentation: http://localhost:8000/docs"
    echo "   API Health Check:  http://localhost:8000/health"
    echo "   Nginx Proxy:       http://localhost:80"
    echo ""
    echo "📁 Data Volumes:"
    echo "   Config:            ./docker-data/config/"
    echo "   Logs:              ./docker-data/logs/"
    echo "   Backups:           ./docker-data/backups/"
    echo "   Templates:         ./docker-data/templates/"
    echo "   SSL Certificates:  ./docker-data/ssl/"
    echo ""
    echo "🔧 Useful Commands:"
    echo "   View logs:         docker-compose logs -f"
    echo "   Stop service:      docker-compose down"
    echo "   Restart service:   docker-compose restart"
    echo "   Update service:    docker-compose pull && docker-compose up -d"
    echo ""
    echo "🔐 Default Login:"
    echo "   Username: admin"
    echo "   Password: admin123"
    echo ""
}

# Main deployment function
main() {
    echo ""
    print_status "Starting VPS Manager Docker deployment..."
    echo ""
    
    # Check prerequisites
    check_docker
    check_ports
    
    # Create directories
    create_directories
    
    # Deploy
    deploy
    
    # Check status
    check_status
    
    # Show usage
    show_usage
}

# Handle command line arguments
case "${1:-}" in
    "stop")
        print_status "Stopping VPS Manager..."
        docker-compose down
        print_success "VPS Manager stopped"
        ;;
    "restart")
        print_status "Restarting VPS Manager..."
        docker-compose restart
        print_success "VPS Manager restarted"
        ;;
    "logs")
        docker-compose logs -f
        ;;
    "status")
        docker-compose ps
        ;;
    "clean")
        print_warning "This will remove all containers and volumes. Are you sure? (y/N)"
        read -p "" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Cleaning up..."
            docker-compose down -v
            docker system prune -f
            rm -rf ./docker-data
            print_success "Cleanup completed"
        else
            print_status "Cleanup cancelled"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "VPS Manager Docker Deployment Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)  Deploy VPS Manager"
        echo "  stop       Stop the service"
        echo "  restart    Restart the service"
        echo "  logs       Show logs"
        echo "  status     Show status"
        echo "  clean      Remove all containers and volumes"
        echo "  help       Show this help"
        ;;
    *)
        main
        ;;
esac 