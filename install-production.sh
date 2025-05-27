#!/bin/bash
# Script Instalasi Production - Security Operation Center Ubuntu 20.04

echo "🚀 Security Operation Center - Production Installation"
echo "===================================================="

# Update sistem
echo "=== 📦 System Update ==="
apt update && apt upgrade -y

# Install Node.js 18 LTS
echo "=== 🟢 Installing Node.js 18 ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

echo "✅ Node.js $(node --version) installed"
echo "✅ NPM $(npm --version) installed"

# Install Nginx
echo "=== 🌐 Installing Nginx ==="
apt install -y nginx

# Setup aplikasi directory
echo "=== 📁 Setting up application ==="
APP_DIR="/opt/security-operations-center"
mkdir -p $APP_DIR

# Copy files
cp index.js $APP_DIR/
cp package-simple.json $APP_DIR/package.json

cd $APP_DIR

# Install minimal dependencies
echo "=== 📦 Installing dependencies ==="
npm install express

# Create systemd service
echo "=== 🔧 Creating systemd service ==="
cat > /etc/systemd/system/security-operations-center.service << EOL
[Unit]
Description=Security Operations Center
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=NODE_ENV=production
Environment=PORT=5000
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

# Configure Nginx
echo "=== 🌐 Configuring Nginx ==="
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Security headers
    add_header X-Frame-Options "DENY" always;
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
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }
}
EOL

# Enable Nginx site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
nginx -t

# Enable and start services
echo "=== 🚀 Starting services ==="
systemctl daemon-reload
systemctl enable security-operations-center
systemctl start security-operations-center
systemctl enable nginx
systemctl start nginx

# Wait for service to start
sleep 3

# Test the service
echo "=== 🧪 Testing service ==="
if curl -s http://localhost/health > /dev/null; then
    echo "✅ Service responding correctly"
else
    echo "⚠️ Service may need time to start"
fi

# Create management scripts
echo "=== 🛠️ Creating management tools ==="

# Status script
cat > /usr/local/bin/soc-status << 'EOL'
#!/bin/bash
echo "📊 Security Operation Center Status"
echo "==================================="
echo "🔧 Application:"
systemctl status security-operations-center --no-pager -l
echo ""
echo "🌐 Nginx:"
systemctl status nginx --no-pager -l
echo ""
echo "📱 Health Check:"
curl -s http://localhost/health | python3 -m json.tool 2>/dev/null || echo "Service starting..."
echo ""
echo "🌍 Access URL: http://$(hostname -I | awk '{print $1}')"
EOL

# Restart script
cat > /usr/local/bin/soc-restart << 'EOL'
#!/bin/bash
echo "🔄 Restarting Security Operation Center..."
systemctl restart security-operations-center
systemctl restart nginx
echo "✅ Services restarted"
EOL

# Logs script
cat > /usr/local/bin/soc-logs << 'EOL'
#!/bin/bash
echo "📄 Security Operation Center Logs"
echo "Press Ctrl+C to exit"
journalctl -u security-operations-center -f
EOL

# Make scripts executable
chmod +x /usr/local/bin/soc-*

echo ""
echo "🎉 Installation Complete!"
echo "========================="
echo "✅ Security Operation Center installed successfully"
echo ""
echo "📋 Management Commands:"
echo "🔍 soc-status   - Check service status"
echo "🔄 soc-restart  - Restart services"
echo "📄 soc-logs     - View live logs"
echo ""
echo "🌐 Application URL: http://$(hostname -I | awk '{print $1}')"
echo "🔗 Health Check: http://$(hostname -I | awk '{print $1}')/health"
echo "🛠️ API Tools: http://$(hostname -I | awk '{print $1}')/api/tools"
echo ""
echo "📊 Service Status:"
soc-status