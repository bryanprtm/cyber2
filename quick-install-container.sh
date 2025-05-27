#!/bin/bash
# Quick Install Script for Security Operation Center
# Repository: https://github.com/bryanprtm/cyber2.git

echo "⚡ Quick Install - Security Operation Center"
echo "==========================================="
echo "📂 Source: https://github.com/bryanprtm/cyber2.git"

# Update system
apt-get update -y
apt-get install -y curl git nodejs npm

# Clone repository
cd /opt
git clone https://github.com/bryanprtm/cyber2.git security-operations-center
cd security-operations-center

# Install dependencies
npm install

# Start application
echo "🚀 Starting Security Operation Center..."
npm run dev &

echo "✅ Installation complete!"
echo "🌐 Access: http://localhost:5000"
echo "📊 Health: http://localhost:5000/api/health"