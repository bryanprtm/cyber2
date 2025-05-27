#!/bin/bash

# Security Operation Center - Troubleshooting Script
# Untuk mengatasi masalah nginx welcome page dan port 5000

echo "🔧 Security Operation Center - Troubleshooting"
echo "============================================="

# Stop nginx jika berjalan
echo "🛑 Stopping nginx..."
sudo systemctl stop nginx 2>/dev/null || true
sudo systemctl disable nginx 2>/dev/null || true

# Kill semua proses di port 5000
echo "🔄 Clearing port 5000..."
sudo fuser -k 5000/tcp 2>/dev/null || true

# Masuk ke direktori aplikasi
cd /home/ubuntu/cyber2 2>/dev/null || cd ~/cyber2 2>/dev/null || {
    echo "❌ Directory cyber2 not found"
    exit 1
}

# Update aplikasi dari GitHub
echo "📥 Updating from GitHub..."
git pull origin main

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Start aplikasi langsung tanpa PM2 untuk testing
echo "🚀 Starting application directly..."
echo "Application will run on port 5000"
echo "Press Ctrl+C to stop"
echo ""

# Set environment dan jalankan
export NODE_ENV=production
export PORT=5000
npm run dev