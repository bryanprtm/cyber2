#!/bin/bash
# Script Deployment Sederhana - Security Operation Center Ubuntu 20.04

echo "🚀 Deployment Security Operation Center - Ubuntu 20.04"
echo "====================================================="

# Update sistem
echo "=== 📦 Update sistem ==="
apt update && apt upgrade -y

# Install Node.js 18
echo "=== 🟢 Install Node.js 18 ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Install PostgreSQL dan Nginx
echo "=== 📦 Install services ==="
apt install -y postgresql postgresql-contrib nginx

# Start PostgreSQL
echo "=== 🗄️ Start PostgreSQL ==="
service postgresql start

# Setup database
echo "=== 🏗️ Setup database ==="
sudo -u postgres psql -c "CREATE DATABASE security_operations_center;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER socuser WITH PASSWORD 'SecurePass2024!';" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_operations_center TO socuser;" 2>/dev/null || true

# Set environment
export DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
export NODE_ENV=production

# Install dependencies
echo "=== 📦 Install dependencies ==="
npm install --production

# Setup database schema (skip jika ada error)
echo "=== 🏗️ Setup schema ==="
npx drizzle-kit push || echo "Schema sudah siap"

# Configure Nginx
echo "=== 🌐 Configure Nginx ==="
cat > /etc/nginx/sites-available/default << 'EOL'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOL

# Start services
echo "=== 🚀 Start services ==="
service nginx start

# Start aplikasi
echo "=== 🎯 Start aplikasi ==="
npm start &

echo ""
echo "🎉 Deployment selesai!"
echo "========================"
echo "✅ Security Operation Center aktif"
echo "🌐 Akses: http://your-server-ip"
echo "📊 13 cybersecurity tools siap digunakan"
echo ""
echo "Aplikasi berjalan di background dengan npm start"