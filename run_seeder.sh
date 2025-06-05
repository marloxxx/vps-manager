#!/bin/bash

# VPS Manager User Seeder Script
# This script helps manage users for the VPS Manager system

set -e

echo "🚀 VPS Manager User Seeder"
echo "=" * 40

# Check if script is run as root (required for accessing /opt/vps-manager)
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root" 
   exit 1
fi

# Navigate to the script directory
cd "$(dirname "$0")"

# Check if Python virtual environment exists
if [ ! -d "/opt/vps-manager/venv" ]; then
    echo "❌ Python virtual environment not found at /opt/vps-manager/venv"
    echo "Please run the setup script first"
    exit 1
fi

# Activate virtual environment
source /opt/vps-manager/venv/bin/activate

# Run the seeder
echo "🌱 Running user seeder..."
python3 seeder.py "$@"

echo ""
echo "✅ Seeder operation completed!"
