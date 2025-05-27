#!/bin/bash

# Security Operation Center - Simple Ubuntu Deployment
# Repository: https://github.com/bryanprtm/cyber2.git
# Deployment tanpa nginx, langsung akses port 5000

set -e

echo "🚀 Security Operation Center - Simple Ubuntu Deployment"
echo "=================================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Node.js 20.x
echo "📦 Installing Node.js 20.x..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify Node.js installation
echo "✅ Node.js version: $(node --version)"
echo "✅ NPM version: $(npm --version)"

# Install Git
echo "📦 Installing Git..."
sudo apt-get install -y git

# Clone Security Operation Center repository
echo "🔄 Cloning Security Operation Center from GitHub..."
if [ -d "cyber2" ]; then
    echo "Directory exists, updating..."
    cd cyber2
    git pull origin main
else
    git clone https://github.com/bryanprtm/cyber2.git
    cd cyber2
fi

# Install dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Install PM2 for process management
echo "📦 Installing PM2..."
sudo npm install -g pm2

# Create PM2 ecosystem file (CommonJS format)
echo "📝 Creating PM2 configuration..."
cat > ecosystem.config.cjs << 'EOF'
module.exports = {
  apps: [{
    name: 'security-operation-center',
    script: 'npm',
    args: 'run dev',
    cwd: '/home/ubuntu/cyber2',
    env: {
      NODE_ENV: 'production',
      PORT: 5000
    },
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    log_file: '/var/log/soc-combined.log',
    out_file: '/var/log/soc-out.log',
    error_file: '/var/log/soc-error.log'
  }]
};
EOF

# Create log directory
sudo mkdir -p /var/log
sudo chown ubuntu:ubuntu /var/log/soc-*.log 2>/dev/null || true

# Start application with PM2
echo "🚀 Starting Security Operation Center with PM2..."
pm2 delete security-operation-center 2>/dev/null || true
pm2 start ecosystem.config.cjs

# Configure PM2 to start on boot
pm2 save
pm2 startup

# Install UFW firewall
echo "🔒 Configuring firewall..."
sudo ufw enable
sudo ufw allow 22
sudo ufw allow 5000

# Create management scripts
echo "📝 Creating management scripts..."

# Status script
sudo tee /usr/local/bin/soc-status > /dev/null << 'EOF'
#!/bin/bash
echo "=== Security Operation Center Status ==="
echo "PM2 Status:"
pm2 status
echo ""
echo "Application Logs:"
pm2 logs security-operation-center --lines 10
echo ""
echo "System Resources:"
free -h
df -h / | tail -1
echo ""
echo "Network Status:"
netstat -tlnp | grep :5000 || echo "Port 5000 not listening"
EOF

# Restart script
sudo tee /usr/local/bin/soc-restart > /dev/null << 'EOF'
#!/bin/bash
echo "🔄 Restarting Security Operation Center..."
cd /home/ubuntu/cyber2
git pull origin main
npm install
pm2 restart security-operation-center
echo "✅ Restart completed!"
EOF

# Logs script
sudo tee /usr/local/bin/soc-logs > /dev/null << 'EOF'
#!/bin/bash
echo "📋 Security Operation Center Logs:"
pm2 logs security-operation-center --lines 50
EOF

# Update script
sudo tee /usr/local/bin/soc-update > /dev/null << 'EOF'
#!/bin/bash
echo "📥 Updating Security Operation Center..."
cd /home/ubuntu/cyber2
git pull origin main
npm install
pm2 restart security-operation-center
echo "✅ Update completed!"
EOF

# Make scripts executable
sudo chmod +x /usr/local/bin/soc-*

# Wait for application to start
echo "⏳ Waiting for application to start..."
sleep 10

# Test application
echo "🧪 Testing application..."
if curl -f http://localhost:5000/api/health > /dev/null 2>&1; then
    echo "✅ Security Operation Center is running successfully!"
else
    echo "❌ Application health check failed, checking logs..."
    pm2 logs security-operation-center --lines 20
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')

echo ""
echo "🎉 Security Operation Center Deployment Complete!"
echo "=================================================="
echo "✅ Application Status: $(pm2 list | grep security-operation-center | awk '{print $10}')"
echo "🌐 Access URL: http://$SERVER_IP:5000"
echo "🔍 Health Check: http://$SERVER_IP:5000/api/health"
echo "📊 Dashboard: http://$SERVER_IP:5000/api/dashboard/stats"
echo ""
echo "Management Commands:"
echo "• soc-status  - Check application status"
echo "• soc-restart - Restart application"
echo "• soc-logs    - View application logs"
echo "• soc-update  - Update from GitHub"
echo ""
echo "🔒 Make sure to configure your firewall:"
echo "• Port 5000 is open for the application"
echo "• Port 22 is open for SSH access"
echo ""
echo "📝 Log files location:"
echo "• Combined: /var/log/soc-combined.log"
echo "• Output: /var/log/soc-out.log"
echo "• Error: /var/log/soc-error.log"
echo ""
echo "🚀 Security Operation Center is ready for cybersecurity testing!"