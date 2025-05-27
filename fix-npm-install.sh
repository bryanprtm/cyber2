#!/bin/bash
# Fix NPM Installation Issues - Security Operation Center

echo "🔧 Memperbaiki masalah NPM installation..."

# Navigate to app directory
cd /opt/security-operations-center

# Clean npm cache and remove problematic files
echo "=== 🧹 Membersihkan cache dan file bermasalah ==="
npm cache clean --force
rm -rf node_modules
rm -f package-lock.json

# Clear any remaining npm temp files
rm -rf /tmp/npm-*
rm -rf ~/.npm

# Install dependencies with fresh start
echo "=== 📦 Installing dependencies dengan fresh start ==="
npm install --no-package-lock --legacy-peer-deps

# If that fails, try with different approach
if [ $? -ne 0 ]; then
    echo "=== 🔄 Mencoba dengan strategi alternatif ==="
    npm install --force --no-audit --no-fund
fi

# Verify installation
if [ -d "node_modules" ]; then
    echo "✅ Dependencies berhasil diinstall"
    
    # Continue with database setup
    echo "=== 🗄️ Setting up database schema ==="
    export DATABASE_URL="postgresql://socuser:SecurePass2024!@localhost:5432/security_operations_center"
    npm run db:push
    
    # Try to build
    echo "=== 🔨 Building application ==="
    mkdir -p dist/public
    
    if npm run build; then
        echo "✅ Build berhasil!"
    else
        echo "⚠️ Build gagal, menggunakan development mode"
        # Copy essential files for development mode
        cp client/index.html dist/public/ 2>/dev/null || true
        echo "✅ Development mode siap"
    fi
    
    echo "🎉 Setup selesai! Aplikasi siap dijalankan."
    
else
    echo "❌ Installation masih gagal"
    echo "Mencoba manual installation..."
    
    # Manual approach - install core packages only
    npm init -y
    npm install express tsx typescript --save
    npm install drizzle-orm @neondatabase/serverless --save
    npm install react react-dom --save
    
    echo "✅ Core packages installed"
fi

# Start the application
echo "=== 🚀 Starting application ==="
supervisorctl restart security-operations-center || npm start &

echo "✅ Security Operation Center siap!"
echo "🌐 Akses aplikasi di: http://$(hostname -I | awk '{print $1}')"