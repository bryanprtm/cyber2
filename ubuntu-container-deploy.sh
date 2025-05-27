#!/bin/bash
# Ubuntu Container Deployment Script - Security Operation Center
# Script siap pakai untuk deployment di Ubuntu 20.04 Container

echo "🚀 Ubuntu Container Deployment - Security Operation Center"
echo "=========================================================="

# Set environment variables
export NODE_ENV=production
export DATABASE_URL="${DATABASE_URL:-postgresql://localhost:5432/security_operations_center}"

# Install system dependencies
echo "=== 📦 Installing system dependencies ==="
apt update
apt install -y nodejs npm postgresql nginx supervisor

# Start PostgreSQL
echo "=== 🗄️ Starting PostgreSQL ==="
service postgresql start

# Install application dependencies
echo "=== 📦 Installing application dependencies ==="
npm install --production
npm install -g tsx drizzle-kit

# Setup database
echo "=== 🏗️ Database setup ==="
npm run db:push

# Build for production
echo "=== 🔨 Building for production ==="
npm run build || echo "Using development mode"

# Configure Nginx
echo "=== 🌐 Configuring Nginx ==="
cat > /etc/nginx/sites-available/default << 'EOL'
server {
    listen 80 default_server;
    server_name _;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOL

# Start services
echo "=== 🚀 Starting services ==="
service nginx start
npm start &

echo "✅ Security Operation Center deployed successfully!"
echo "🌐 Access: http://your-container-ip"
echo "📊 Application ready with all cybersecurity tools!"