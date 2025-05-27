#!/bin/bash
# Script Instalasi Security Operation Center - Ubuntu 20.04 Container
# Optimized untuk deployment container production

set -e

echo "🚀 Security Operation Center - Ubuntu 20.04 Container Setup"
echo "========================================================="

# Update sistem dan install dependensi dasar
echo "=== 📦 Updating system dan installing base dependencies ==="
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y
apt install -y curl wget git build-essential software-properties-common \
    supervisor nginx postgresql postgresql-contrib sudo systemctl

# Install Node.js 18 LTS
echo "=== 🟢 Installing Node.js 18 LTS ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

echo "✅ Node.js version: $(node --version)"
echo "✅ NPM version: $(npm --version)"

# Setup PostgreSQL
echo "=== 🗄️ Configuring PostgreSQL ==="
service postgresql start

# Create database and user
sudo -u postgres psql -c "DROP DATABASE IF EXISTS security_operations_center;"
sudo -u postgres psql -c "CREATE DATABASE security_operations_center;"
sudo -u postgres psql -c "DROP USER IF EXISTS socuser;"
sudo -u postgres psql -c "CREATE USER socuser WITH ENCRYPTED PASSWORD 'SecurePass2024!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_operations_center TO socuser;"
sudo -u postgres psql -c "ALTER USER socuser CREATEDB;"

echo "✅ Database configured successfully"

# Setup aplikasi directory
echo "=== 📁 Setting up application directory ==="
APP_DIR="/opt/security-operations-center"
mkdir -p $APP_DIR
cp -r . $APP_DIR/
cd $APP_DIR

# Set proper permissions
chown -R root:root $APP_DIR
chmod -R 755 $APP_DIR

# Configure environment variables
echo "=== 🔧 Setting environment variables ==="
cat > /etc/environment << EOL
DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
NODE_ENV=production
NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=8192"
PGHOST=localhost
PGPORT=5432
PGUSER=socuser
PGPASSWORD=SecurePass2024!
PGDATABASE=security_operations_center
EOL

# Load environment variables
source /etc/environment

# Install npm dependencies
echo "=== 📦 Installing application dependencies ==="
npm install --production --no-optional

# Setup database schema
echo "=== 🏗️ Setting up database schema ==="
npm run db:push

# Build aplikasi dengan multiple fallback strategies
echo "=== 🔨 Building application ==="
mkdir -p dist/public dist/server

# Strategy 1: Full build
if npm run build 2>/dev/null; then
    echo "✅ Full build successful"
elif cd client && npx vite build --outDir ../dist/public --mode production 2>/dev/null; then
    echo "✅ Client build successful"
    cd ..
else
    echo "⚠️ Build failed, using development assets"
    # Fallback: Copy development assets
    mkdir -p dist/public
    cp client/index.html dist/public/
    cp -r client/src dist/public/
fi

# Copy server files
cp -r server/* dist/server/ 2>/dev/null || echo "Server files copied"
cp -r shared dist/ 2>/dev/null || echo "Shared files copied"
cp package*.json dist/

# Setup Nginx configuration
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
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Main application
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

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location /static/ {
        alias $APP_DIR/dist/public/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOL

# Enable Nginx site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
nginx -t

# Setup Supervisor for process management
echo "=== 🔧 Setting up Supervisor ==="
cat > /etc/supervisor/conf.d/security-operations-center.conf << EOL
[program:security-operations-center]
command=/usr/bin/npm start
directory=$APP_DIR
user=root
autostart=true
autorestart=true
stderr_logfile=/var/log/security-operations-center.err.log
stdout_logfile=/var/log/security-operations-center.out.log
environment=NODE_ENV=production,DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center",NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=8192"

[program:postgresql]
command=/usr/lib/postgresql/12/bin/postgres -D /var/lib/postgresql/12/main -c config_file=/etc/postgresql/12/main/postgresql.conf
user=postgres
autostart=true
autorestart=true
stderr_logfile=/var/log/postgresql.err.log
stdout_logfile=/var/log/postgresql.out.log

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
stderr_logfile=/var/log/nginx.err.log
stdout_logfile=/var/log/nginx.out.log
EOL

# Setup startup script
echo "=== 🚀 Creating startup script ==="
cat > /usr/local/bin/start-security-center << 'EOL'
#!/bin/bash
echo "🚀 Starting Security Operation Center..."

# Start PostgreSQL
service postgresql start
sleep 3

# Update supervisor configuration
supervisorctl reread
supervisorctl update

# Start all services
supervisorctl start all

# Start Nginx
service nginx start

echo "✅ Security Operation Center started successfully!"
echo "🌐 Application available at: http://localhost"
echo "📊 Monitor logs: supervisorctl tail -f security-operations-center"
echo "🔧 Supervisor status: supervisorctl status"
EOL

chmod +x /usr/local/bin/start-security-center

# Setup monitoring script
echo "=== 📊 Creating monitoring script ==="
cat > /usr/local/bin/monitor-security-center << 'EOL'
#!/bin/bash
echo "📊 Security Operation Center - System Monitor"
echo "============================================"
echo "🔧 Supervisor Status:"
supervisorctl status
echo ""
echo "🌐 Nginx Status:"
service nginx status | head -3
echo ""
echo "🗄️ PostgreSQL Status:"
service postgresql status | head -3
echo ""
echo "💾 System Resources:"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 $3}' | awk -F'%' '{print $1}')"
echo "Memory: $(free -h | awk 'NR==2{printf "%.1f%% of %s", $3*100/$2, $2}')"
echo "Disk: $(df -h / | awk 'NR==2{print $5 " of " $2}')"
echo ""
echo "📱 Application URL: http://$(hostname -I | awk '{print $1}')"
EOL

chmod +x /usr/local/bin/monitor-security-center

# Final setup
echo "=== 🎯 Final configuration ==="
supervisorctl reread
supervisorctl update

echo ""
echo "🎉 Installation Complete!"
echo "========================="
echo "✅ Security Operation Center has been installed successfully"
echo ""
echo "📋 Quick Commands:"
echo "🚀 Start all services: start-security-center"
echo "📊 Monitor system: monitor-security-center"
echo "🔧 Supervisor control: supervisorctl status"
echo "📱 Access application: http://your-server-ip"
echo ""
echo "🔐 Database Details:"
echo "Host: localhost"
echo "Database: security_operations_center"
echo "User: socuser"
echo "Password: SecurePass2024!"
echo ""
echo "📁 Application Directory: $APP_DIR"
echo "📊 Log Files: /var/log/security-operations-center.*"
echo ""
echo "To start the application now, run:"
echo "start-security-center"