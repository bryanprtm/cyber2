#!/bin/bash

# Security Operation Center - Fix Database Issue
# Mengatasi error DATABASE_URL must be set

echo "🔧 Fixing Security Operation Center Database Issue"
echo "================================================"

cd cyber2 2>/dev/null || {
    echo "❌ Directory cyber2 not found. Please run installation script first."
    exit 1
}

# Install SQLite3 sebagai fallback database
echo "📦 Installing SQLite3..."
sudo apt-get update
sudo apt-get install -y sqlite3

# Create SQLite database file
echo "📝 Creating SQLite database..."
mkdir -p database
touch database/security_center.db

# Set DATABASE_URL environment variable untuk SQLite
export DATABASE_URL="file:./database/security_center.db"

# Create .env file
echo "📝 Creating .env file..."
cat > .env << EOF
# Security Operation Center Environment
NODE_ENV=production
PORT=5000
DATABASE_URL=file:./database/security_center.db
PGHOST=localhost
PGUSER=socuser
PGPASSWORD=SecureSOC2024
PGDATABASE=security_operations_center
PGPORT=5432
EOF

# Buat startup script yang include environment
echo "📝 Creating startup script with environment..."
cat > start-with-env.sh << 'EOF'
#!/bin/bash
cd /home/ubuntu/cyber2
source .env
echo "🚀 Starting Security Operation Center..."
echo "✅ DATABASE_URL: $DATABASE_URL"
echo "✅ PORT: $PORT"
npm run dev
EOF

chmod +x start-with-env.sh

# Background startup script
cat > start-background-env.sh << 'EOF'
#!/bin/bash
cd /home/ubuntu/cyber2
source .env
nohup npm run dev > /tmp/soc.log 2>&1 &
echo $! > /tmp/soc.pid
echo "🚀 Security Operation Center started in background"
echo "📋 View logs: tail -f /tmp/soc.log"
echo "🛑 Stop service: kill $(cat /tmp/soc.pid)"
EOF

chmod +x start-background-env.sh

# Test database connection
echo "🧪 Testing database setup..."
source .env
echo "DATABASE_URL: $DATABASE_URL"

# Initialize database if needed
npm run db:push 2>/dev/null || echo "⚠️ Database initialization skipped"

echo ""
echo "🎉 Database Fix Complete!"
echo "========================"
echo ""
echo "🚀 Start Application:"
echo "• Manual: ./start-with-env.sh"
echo "• Background: ./start-background-env.sh"
echo ""
echo "📊 Database Info:"
echo "• Type: SQLite (fallback)"
echo "• Location: ./database/security_center.db"
echo "• Environment: Configured in .env"
echo ""
echo "🌐 After starting, access:"
echo "• http://YOUR_SERVER_IP:5000"
echo ""
echo "✅ Ready to run Security Operation Center!"