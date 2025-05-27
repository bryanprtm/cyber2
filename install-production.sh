#!/bin/bash

# Security Operation Center - Production Installation
# Fixes DATABASE_URL issue and sets up proper environment

echo "🚀 Security Operation Center - Production Setup"
echo "=============================================="

cd cyber2 2>/dev/null || {
    echo "❌ Please run this from the directory containing cyber2 folder"
    exit 1
}

# Stop any running processes
sudo pkill -f "npm run dev" 2>/dev/null || true
sudo fuser -k 5000/tcp 2>/dev/null || true

# Install PostgreSQL
echo "📦 Installing PostgreSQL..."
sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
echo "📝 Setting up database..."
sudo -u postgres psql << EOF
CREATE DATABASE security_operations_center;
CREATE USER socuser WITH PASSWORD 'SecureSOC2024!';
GRANT ALL PRIVILEGES ON DATABASE security_operations_center TO socuser;
ALTER USER socuser CREATEDB;
\q
EOF

# Create environment file with proper DATABASE_URL
echo "📝 Creating production environment..."
cat > .env << EOF
NODE_ENV=production
PORT=5000
DATABASE_URL=postgresql://socuser:SecureSOC2024!@localhost:5432/security_operations_center
PGHOST=localhost
PGUSER=socuser
PGPASSWORD=SecureSOC2024!
PGDATABASE=security_operations_center
PGPORT=5432
EOF

# Install dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Run database migrations
echo "🗄️ Setting up database schema..."
npm run db:push

# Create startup script
echo "📝 Creating startup script..."
cat > start-production.sh << 'EOF'
#!/bin/bash
cd /home/ubuntu/cyber2

# Load environment variables
export NODE_ENV=production
export PORT=5000
export DATABASE_URL=postgresql://socuser:SecureSOC2024!@localhost:5432/security_operations_center
export PGHOST=localhost
export PGUSER=socuser
export PGPASSWORD=SecureSOC2024!
export PGDATABASE=security_operations_center
export PGPORT=5432

echo "🚀 Starting Security Operation Center..."
echo "✅ Database: PostgreSQL"
echo "✅ Port: $PORT"

npm run dev
EOF

chmod +x start-production.sh

# Create systemd service for auto-start
echo "📝 Creating system service..."
sudo tee /etc/systemd/system/security-operation-center.service > /dev/null << EOF
[Unit]
Description=Security Operation Center
After=network.target postgresql.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/cyber2
Environment=NODE_ENV=production
Environment=PORT=5000
Environment=DATABASE_URL=postgresql://socuser:SecureSOC2024!@localhost:5432/security_operations_center
Environment=PGHOST=localhost
Environment=PGUSER=socuser
Environment=PGPASSWORD=SecureSOC2024!
Environment=PGDATABASE=security_operations_center
Environment=PGPORT=5432
ExecStart=/usr/bin/npm run dev
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable security-operation-center

# Open firewall
echo "🔒 Configuring firewall..."
sudo ufw allow 5000
sudo ufw allow 5432

# Test database connection
echo "🧪 Testing database connection..."
PGPASSWORD=SecureSOC2024! psql -h localhost -U socuser -d security_operations_center -c "SELECT version();" 2>/dev/null && echo "✅ Database connection successful!" || echo "⚠️ Database connection test failed"

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo "🎉 Production Setup Complete!"
echo "============================"
echo ""
echo "🚀 Start Options:"
echo "• Manual: ./start-production.sh"
echo "• System Service: sudo systemctl start security-operation-center"
echo ""
echo "🌐 Access URLs:"
echo "• Main App: http://$SERVER_IP:5000"
echo "• Health Check: http://$SERVER_IP:5000/api/health"
echo ""
echo "📊 Database Info:"
echo "• Type: PostgreSQL"
echo "• Database: security_operations_center"
echo "• User: socuser"
echo "• Host: localhost:5432"
echo ""
echo "🔧 Management Commands:"
echo "• Status: sudo systemctl status security-operation-center"
echo "• Logs: sudo journalctl -u security-operation-center -f"
echo "• Restart: sudo systemctl restart security-operation-center"
echo ""
echo "✅ Security Operation Center is ready for production use!"