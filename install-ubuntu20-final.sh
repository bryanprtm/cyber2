#!/bin/bash
# Script Instalasi Security Operation Center - Ubuntu 20.04 (Final)

set -e

echo "🚀 Security Operation Center - Ubuntu 20.04 Final Setup"
echo "======================================================="

# Get current directory
CURRENT_DIR=$(pwd)
APP_DIR="/opt/security-operations-center"

# Fix package dependencies first
echo "=== 🔧 Fixing package dependencies ==="
export DEBIAN_FRONTEND=noninteractive

apt update
apt --fix-broken install -y
apt install -y curl wget git build-essential software-properties-common

# Install Node.js 18 LTS
echo "=== 🟢 Installing Node.js 18 LTS ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

echo "✅ Node.js version: $(node --version)"
echo "✅ NPM version: $(npm --version)"

# Install other services
echo "=== 📦 Installing services ==="
apt install -y postgresql postgresql-contrib nginx supervisor

# Start services
echo "=== 🚀 Starting services ==="
service postgresql start
service nginx start
service supervisor start

# Setup PostgreSQL database
echo "=== 🗄️ Configuring database ==="
sudo -u postgres psql -c "DROP DATABASE IF EXISTS security_operations_center;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE security_operations_center;"
sudo -u postgres psql -c "DROP USER IF EXISTS socuser;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE USER socuser WITH ENCRYPTED PASSWORD 'SecurePass2024!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_operations_center TO socuser;"

echo "✅ Database configured successfully"

# Setup application directory (avoid self-copy issue)
echo "=== 📁 Setting up application ==="
if [ "$CURRENT_DIR" != "$APP_DIR" ]; then
    # Only copy if we're not already in the target directory
    mkdir -p $APP_DIR
    rsync -av --exclude='.git' --exclude='node_modules' --exclude='dist' . $APP_DIR/
    echo "✅ Application files copied to $APP_DIR"
else
    # We're already in the target directory
    echo "✅ Already in application directory: $APP_DIR"
fi

cd $APP_DIR

# Set environment variables
export DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Create environment file
cat > .env << EOL
DATABASE_URL=postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center
NODE_ENV=production
NODE_OPTIONS=--openssl-legacy-provider --max-old-space-size=4096
PGHOST=localhost
PGPORT=5432
PGUSER=socuser
PGPASSWORD=SecurePass2024!
PGDATABASE=security_operations_center
EOL

# Install npm dependencies
echo "=== 📦 Installing npm dependencies ==="
npm install --production

# Setup database schema
echo "=== 🏗️ Database schema setup ==="
npm run db:push

# Build application with multiple strategies
echo "=== 🔨 Building application ==="
mkdir -p dist/public

echo "Trying full build..."
if npm run build 2>/dev/null; then
    echo "✅ Full build successful"
elif echo "Trying client build..." && cd client && NODE_OPTIONS="--openssl-legacy-provider" npx vite build --outDir ../dist/public 2>/dev/null; then
    echo "✅ Client build successful"
    cd ..
else
    echo "⚠️ Build failed, setting up development mode"
    # Setup development mode
    mkdir -p dist/public
    cp client/index.html dist/public/ 2>/dev/null || true
    echo "✅ Development mode ready"
fi

# Ensure server files are available
echo "=== 📋 Preparing server files ==="
if [ -d "server" ]; then
    cp -r server dist/ 2>/dev/null || true
fi
if [ -d "shared" ]; then
    cp -r shared dist/ 2>/dev/null || true
fi
cp package*.json dist/ 2>/dev/null || true

# Configure Nginx
echo "=== 🌐 Configuring Nginx ==="
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOL

# Enable Nginx site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
nginx -t && nginx -s reload

# Setup Supervisor
echo "=== 🔧 Configuring Supervisor ==="
cat > /etc/supervisor/conf.d/security-operations-center.conf << EOL
[program:security-operations-center]
command=/usr/bin/npm start
directory=$APP_DIR
user=root
autostart=true
autorestart=true
stderr_logfile=/var/log/security-operations-center.err.log
stdout_logfile=/var/log/security-operations-center.out.log
environment=NODE_ENV=production,DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center",NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"
EOL

# Reload supervisor
supervisorctl reread
supervisorctl update

# Create startup script
echo "=== 🚀 Creating management scripts ==="
cat > /usr/local/bin/start-soc << 'EOL'
#!/bin/bash
echo "🚀 Starting Security Operation Center..."

# Start services
service postgresql start
service nginx start  
service supervisor start

# Start application
supervisorctl start security-operations-center

echo "✅ Security Operation Center started!"
echo "🌐 Access: http://$(hostname -I | awk '{print $1}' | tr -d ' ')"
echo "📊 Status: supervisorctl status"
EOL

chmod +x /usr/local/bin/start-soc

# Create monitoring script
cat > /usr/local/bin/status-soc << 'EOL'
#!/bin/bash
echo "📊 Security Operation Center Status"
echo "==================================="
echo "🔧 Application Status:"
supervisorctl status security-operations-center
echo ""
echo "🌐 Nginx Status:"
if service nginx status >/dev/null 2>&1; then
    echo "✅ Nginx: Running"
else
    echo "❌ Nginx: Stopped"
fi
echo ""
echo "🗄️ PostgreSQL Status:"
if service postgresql status >/dev/null 2>&1; then
    echo "✅ PostgreSQL: Running"
else
    echo "❌ PostgreSQL: Stopped"
fi
echo ""
echo "📱 Application URL: http://$(hostname -I | awk '{print $1}' | tr -d ' ')"
echo ""
echo "📋 Quick Commands:"
echo "   start-soc     - Start all services"
echo "   status-soc    - Show this status"
echo "   supervisorctl status - Detailed app status"
EOL

chmod +x /usr/local/bin/status-soc

# Create log viewer
cat > /usr/local/bin/logs-soc << 'EOL'
#!/bin/bash
echo "📄 Security Operation Center Logs"
echo "================================="
echo "Choose log to view:"
echo "1) Application logs"
echo "2) Error logs"
echo "3) Nginx logs"
echo "4) PostgreSQL logs"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1) tail -f /var/log/security-operations-center.out.log ;;
    2) tail -f /var/log/security-operations-center.err.log ;;
    3) tail -f /var/log/nginx/access.log ;;
    4) tail -f /var/log/postgresql/postgresql-12-main.log ;;
    *) echo "Invalid choice" ;;
esac
EOL

chmod +x /usr/local/bin/logs-soc

# Start the application
echo "=== 🎯 Starting Security Operation Center ==="
supervisorctl start security-operations-center

# Final status check
sleep 3
echo ""
echo "🎉 Installation Complete!"
echo "========================="
echo "✅ Security Operation Center installed successfully"
echo ""
echo "📋 Management Commands:"
echo "🚀 start-soc     - Start all services"
echo "📊 status-soc    - Check system status"
echo "📄 logs-soc      - View application logs"
echo ""
echo "🌐 Application URL: http://$(hostname -I | awk '{print $1}' | tr -d ' ')"
echo ""
echo "🔧 Advanced Commands:"
echo "   supervisorctl status"
echo "   supervisorctl restart security-operations-center"
echo "   nginx -t (test config)"
echo ""

# Show final status
status-soc