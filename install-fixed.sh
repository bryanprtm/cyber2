#!/bin/bash
# Script Instalasi Security Operation Center - Ubuntu 20.04 (Fixed)

set -e

echo "🚀 Memulai instalasi Security Operation Center..."
echo "📋 Script ini akan menginstal semua dependensi yang diperlukan"

# Update sistem
echo "=== 🔄 Update sistem ==="
apt update && apt upgrade -y

# Install dependensi dasar
echo "=== 📦 Menginstal dependensi dasar ==="
apt install -y curl wget git build-essential software-properties-common

# Install Node.js 18
echo "=== 📦 Menginstal Node.js 18 ==="
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt install -y nodejs

# Install PostgreSQL
echo "=== 🗄️ Menginstal PostgreSQL ==="
apt install -y postgresql postgresql-contrib

# Setup database
echo "=== 🔧 Mengkonfigurasi database ==="
systemctl start postgresql
systemctl enable postgresql

# Buat database dan user
sudo -u postgres psql -c "CREATE DATABASE security_operations_center;"
sudo -u postgres psql -c "CREATE USER socuser WITH ENCRYPTED PASSWORD 'securepass123';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_operations_center TO socuser;"

# Set environment variables
echo "=== 🔧 Setting environment variables ==="
export DATABASE_URL="postgresql://socuser:securepass123@localhost:5432/security_operations_center"
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Copy aplikasi ke direktori yang tepat
echo "=== 📁 Menyiapkan direktori aplikasi ==="
INSTALL_DIR="/opt/security-operations-center"
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR/
cd $INSTALL_DIR

# Install dependensi npm
echo "=== 📦 Menginstal dependensi aplikasi ==="
npm install --production

# Build aplikasi (dengan fallback)
echo "=== 🚀 Build aplikasi ==="
if npm run build; then
    echo "✅ Build berhasil"
else
    echo "⚠️ Build gagal, menggunakan mode development"
    mkdir -p dist/public
    cp -r client/* dist/public/
fi

# Install Nginx
echo "=== 🌐 Menginstal Nginx ==="
apt install -y nginx

# Konfigurasi Nginx
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://localhost:5000;
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

# Aktifkan konfigurasi Nginx
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Buat service systemd
echo "=== 🔧 Membuat service systemd ==="
cat > /etc/systemd/system/security-operations-center.service << EOL
[Unit]
Description=Security Operations Center
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=NODE_ENV=production
Environment=DATABASE_URL=postgresql://socuser:securepass123@localhost:5432/security_operations_center
Environment=NODE_OPTIONS=--openssl-legacy-provider --max-old-space-size=4096
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

# Reload dan start service
systemctl daemon-reload
systemctl enable security-operations-center
systemctl start security-operations-center

# Setup firewall
echo "=== 🔥 Mengkonfigurasi firewall ==="
ufw allow 22
ufw allow 80
ufw allow 443
ufw --force enable

echo "🎉 Instalasi selesai!"
echo "📱 Aplikasi dapat diakses di: http://your-server-ip"
echo "🔧 Status service: systemctl status security-operations-center"
echo "📊 Log aplikasi: journalctl -u security-operations-center -f"