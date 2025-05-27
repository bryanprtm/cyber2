#!/bin/bash
# Script Instalasi Security Operation Center - Ubuntu 20.04 (Fixed Dependencies)

set -e

echo "🚀 Security Operation Center - Ubuntu 20.04 Setup (Fixed)"
echo "========================================================="

# Fix package dependencies first
echo "=== 🔧 Fixing package dependencies ==="
export DEBIAN_FRONTEND=noninteractive

# Update package lists
apt update

# Fix broken packages
apt --fix-broken install -y

# Install core dependencies without conflicts
apt install -y curl wget git build-essential software-properties-common

# Install Node.js 18 LTS first
echo "=== 🟢 Installing Node.js 18 LTS ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

echo "✅ Node.js version: $(node --version)"
echo "✅ NPM version: $(npm --version)"

# Install PostgreSQL
echo "=== 🗄️ Installing PostgreSQL ==="
apt install -y postgresql postgresql-contrib

# Install Nginx
echo "=== 🌐 Installing Nginx ==="
apt install -y nginx

# Install supervisor (without systemctl conflict)
echo "=== 🔧 Installing Supervisor ==="
apt install -y supervisor

# Start services manually (avoid systemctl conflicts)
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

# Setup application directory
echo "=== 📁 Setting up application ==="
APP_DIR="/opt/security-operations-center"
mkdir -p $APP_DIR

# Copy application files
cp -r . $APP_DIR/
cd $APP_DIR

# Set environment variables
export DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Create environment file
cat > $APP_DIR/.env << EOL
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
echo "=== 📦 Installing dependencies ==="
npm install --production

# Setup database schema
echo "=== 🏗️ Database schema setup ==="
npm run db:push

# Build application with fallback
echo "=== 🔨 Building application ==="
mkdir -p dist/public

# Try different build strategies
if npm run build; then
    echo "✅ Full build successful"
elif cd client && NODE_OPTIONS="--openssl-legacy-provider" npx vite build --outDir ../dist/public; then
    echo "✅ Client build successful"
    cd ..
else
    echo "⚠️ Using development mode"
    # Copy client files as fallback
    cp client/index.html dist/public/ 2>/dev/null || true
    mkdir -p dist/public/assets
    cp -r client/src/* dist/public/assets/ 2>/dev/null || true
fi

# Copy server files
cp -r server dist/ 2>/dev/null || true
cp -r shared dist/ 2>/dev/null || true
cp package*.json dist/ 2>/dev/null || true

# Configure Nginx
echo "=== 🌐 Configuring Nginx ==="
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80 default_server;
    server_name _;

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
    }
}
EOL

# Enable site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
nginx -s reload

# Setup Supervisor configuration
echo "=== 🔧 Configuring Supervisor ==="
cat > /etc/supervisor/conf.d/security-operations-center.conf << EOL
[program:security-operations-center]
command=/usr/bin/npm start
directory=$APP_DIR
autostart=true
autorestart=true
stderr_logfile=/var/log/security-operations-center.err.log
stdout_logfile=/var/log/security-operations-center.out.log
environment=NODE_ENV=production,DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
EOL

# Reload supervisor
supervisorctl reread
supervisorctl update
supervisorctl start security-operations-center

# Create startup script
echo "=== 🚀 Creating startup script ==="
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
echo "🌐 Access: http://$(hostname -I | awk '{print $1}')"
EOL

chmod +x /usr/local/bin/start-soc

# Create monitoring script
cat > /usr/local/bin/monitor-soc << 'EOL'
#!/bin/bash
echo "📊 Security Operation Center Status"
echo "==================================="
echo "🔧 Application:"
supervisorctl status security-operations-center
echo ""
echo "🌐 Nginx:"
service nginx status | head -2
echo ""
echo "🗄️ PostgreSQL:"
service postgresql status | head -2
echo ""
echo "📱 URL: http://$(hostname -I | awk '{print $1}')"
EOL

chmod +x /usr/local/bin/monitor-soc

echo ""
echo "🎉 Installation Complete!"
echo "========================="
echo "✅ Security Operation Center installed successfully"
echo ""
echo "📋 Commands:"
echo "🚀 Start: start-soc"
echo "📊 Monitor: monitor-soc"
echo "🌐 Access: http://your-server-ip"
echo ""
echo "🔧 Manual controls:"
echo "supervisorctl status"
echo "supervisorctl restart security-operations-center"
echo ""
echo "Starting application now..."
start-soc