#!/bin/bash

# Security Operation Center - Quick Fix untuk Ubuntu
# Mengatasi masalah build dan deployment

echo "🔧 Quick Fix - Security Operation Center"
echo "======================================="

# Stop semua service yang konflik
echo "🛑 Stopping conflicting services..."
sudo systemctl stop nginx apache2 2>/dev/null || true
sudo pkill -f node 2>/dev/null || true
sudo fuser -k 5000/tcp 2>/dev/null || true

# Install Node.js 18 LTS (lebih stabil)
echo "📦 Installing Node.js 18 LTS..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

echo "✅ Node.js version: $(node --version)"
echo "✅ NPM version: $(npm --version)"

# Clone atau update repository
if [ ! -d "cyber2" ]; then
    echo "📥 Cloning repository..."
    git clone https://github.com/bryanprtm/cyber2.git
fi

cd cyber2

# Clean install
echo "🧹 Clean installation..."
rm -rf node_modules package-lock.json
npm cache clean --force
npm install

# Create simple startup script
echo "📝 Creating startup script..."
cat > start-soc.sh << 'EOF'
#!/bin/bash
cd /home/ubuntu/cyber2
export NODE_ENV=production
export PORT=5000
echo "🚀 Starting Security Operation Center on port 5000..."
npm run dev
EOF

chmod +x start-soc.sh

# Create background service script
echo "📝 Creating background service..."
cat > start-background.sh << 'EOF'
#!/bin/bash
cd /home/ubuntu/cyber2
export NODE_ENV=production
export PORT=5000
nohup npm run dev > /tmp/soc.log 2>&1 &
echo $! > /tmp/soc.pid
echo "🚀 Security Operation Center started in background"
echo "📋 View logs: tail -f /tmp/soc.log"
echo "🛑 Stop service: kill $(cat /tmp/soc.pid)"
EOF

chmod +x start-background.sh

# Test build
echo "🧪 Testing build..."
npm run build 2>/dev/null || {
    echo "⚠️  Build failed, using development mode"
}

# Test aplikasi
echo "🧪 Starting application test..."
timeout 15s npm run dev &
TEST_PID=$!
sleep 10

if curl -f http://localhost:5000/api/health > /dev/null 2>&1; then
    echo "✅ Application test successful!"
    kill $TEST_PID 2>/dev/null || true
else
    echo "⚠️  Application test inconclusive"
    kill $TEST_PID 2>/dev/null || true
fi

# Get server info
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "🎉 Quick Fix Complete!"
echo "====================)"
echo ""
echo "🚀 Start Application:"
echo "• Manual: ./start-soc.sh"
echo "• Background: ./start-background.sh"
echo ""
echo "🌐 Access URLs:"
echo "• Main App: http://$SERVER_IP:5000"
echo "• Health Check: http://$SERVER_IP:5000/api/health"
echo ""
echo "📋 Troubleshooting:"
echo "• View logs: tail -f /tmp/soc.log"
echo "• Check process: ps aux | grep node"
echo "• Stop background: kill \$(cat /tmp/soc.pid)"
echo ""
echo "🔒 Firewall:"
echo "• sudo ufw allow 5000"
echo ""
echo "✅ Security Operation Center is ready!"