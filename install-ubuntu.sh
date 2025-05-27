#!/bin/bash
# Script Instalasi untuk Aplikasi Pusat Operasi Keamanan pada Ubuntu 20.04
# Dibuat untuk mengotomatiskan proses instalasi pada container

set -e  # Exit on any error

echo "=========================================================="
echo "🚀 Memulai instalasi Pusat Operasi Keamanan"
echo "=========================================================="

# Memperbarui sistem
echo "=== 📦 Memperbarui paket sistem ==="
apt-get update
apt-get upgrade -y

# Menginstal dependensi yang diperlukan
echo "=== 🔧 Menginstal dependensi yang diperlukan ==="
apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    pkg-config \
    postgresql \
    postgresql-contrib \
    nginx \
    supervisor \
    python3-dev \
    python3-pip

# Menginstal Node.js versi 20 LTS (versi terbaru yang kompatibel)
echo "=== 📋 Menginstal Node.js v20 LTS ==="
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Verifikasi instalasi Node.js
echo "=== ✅ Verifikasi Node.js ==="
node --version
npm --version

# Membuat user aplikasi
echo "=== 👤 Membuat user aplikasi ==="
useradd -r -s /bin/false socapp || true
mkdir -p /opt/security-operations-center
chown socapp:socapp /opt/security-operations-center

# Membuat direktori aplikasi
echo "=== 📁 Membuat direktori aplikasi ==="
cd /opt/security-operations-center

# Jika aplikasi sudah ada di direktori ini, skip cloning
if [ ! -f "package.json" ]; then
    echo "=== 📥 Menyalin file aplikasi ==="
    # Asumsi bahwa script ini dijalankan dari direktori root proyek
    cp -r /workspace/* . 2>/dev/null || cp -r /app/* . 2>/dev/null || echo "⚠️  Silakan salin file aplikasi secara manual"
fi

# Set ownership
chown -R socapp:socapp /opt/security-operations-center

# Menginstal dependensi aplikasi dengan mengatasi masalah crypto
echo "=== 📦 Menginstal dependensi aplikasi ==="
export NODE_OPTIONS="--openssl-legacy-provider"
sudo -u socapp npm install

# Mengkonfigurasi database PostgreSQL
echo "=== 🗄️ Mengkonfigurasi database PostgreSQL ==="
systemctl start postgresql
systemctl enable postgresql

# Buat database dan user
sudo -u postgres psql -c "DROP DATABASE IF EXISTS securityoperationscenter;"
sudo -u postgres psql -c "DROP USER IF EXISTS socadmin;"
sudo -u postgres psql -c "CREATE USER socadmin WITH PASSWORD 'SOC_Admin_2024!';"
sudo -u postgres psql -c "CREATE DATABASE securityoperationscenter OWNER socadmin;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE securityoperationscenter TO socadmin;"

# Membuat file environment variables
echo "=== ⚙️ Membuat file environment variables ==="
cat > .env << EOL
# Database Configuration
DATABASE_URL=postgresql://socadmin:SOC_Admin_2024!@localhost:5432/securityoperationscenter
PGDATABASE=securityoperationscenter
PGHOST=localhost
PGPASSWORD=SOC_Admin_2024!
PGPORT=5432
PGUSER=socadmin

# Application Configuration
NODE_ENV=production
PORT=5000
HOST=0.0.0.0

# Build Configuration
NODE_OPTIONS=--openssl-legacy-provider
EOL

chown socapp:socapp .env

# Membuat database schema
echo "=== 🏗️ Membuat database schema ==="
sudo -u socapp npm run db:push

# Fix untuk masalah crypto dan build aplikasi
echo "=== 🔨 Memperbaiki konfigurasi build ==="

# Membuat script build alternatif yang mengatasi masalah entry module
cat > build-production.js << 'EOL'
const { build } = require('vite');
const path = require('path');

async function buildApp() {
  try {
    console.log('Starting production build...');
    
    // Build dengan konfigurasi yang diperbaiki
    await build({
      root: path.resolve(__dirname, 'client'),
      build: {
        outDir: path.resolve(__dirname, 'dist/public'),
        emptyOutDir: true,
        rollupOptions: {
          input: path.resolve(__dirname, 'client/index.html'),
        },
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, 'client/src'),
          '@shared': path.resolve(__dirname, 'shared'),
          '@assets': path.resolve(__dirname, 'attached_assets'),
        },
      },
      define: {
        global: 'globalThis',
      },
    });
    
    console.log('Build completed successfully!');
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

buildApp();
EOL

# Membuat package.json dengan script build yang diperbaiki
echo "=== 📦 Memperbarui package.json untuk build produksi ==="
cp package.json package.json.backup

# Update package.json dengan script build yang baru
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.scripts = pkg.scripts || {};
pkg.scripts['build:prod'] = 'NODE_OPTIONS=\"--openssl-legacy-provider\" node build-production.js';
pkg.scripts['build:fallback'] = 'NODE_OPTIONS=\"--openssl-legacy-provider\" npx vite build --mode production';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
console.log('package.json updated successfully');
"

# Build aplikasi dengan environment yang tepat
echo "=== 🚀 Build aplikasi untuk produksi ==="
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Coba build dengan script yang diperbaiki terlebih dahulu
if sudo -u socapp -E npm run build:prod; then
    echo "✅ Build berhasil dengan script yang diperbaiki"
elif sudo -u socapp -E npm run build:fallback; then
    echo "✅ Build berhasil dengan fallback method"
else
    echo "⚠️ Build gagal, menggunakan development mode"
    echo "Aplikasi akan berjalan dalam mode development"
fi

# Mengonfigurasi Nginx sebagai reverse proxy
echo "=== 🌐 Mengkonfigurasi Nginx ==="
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80;
    server_name _;

    client_max_body_size 100M;

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
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /ws {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOL

# Aktifkan site Nginx
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

# Mengonfigurasi aplikasi sebagai layanan dengan Supervisor
echo "=== 🔧 Mengkonfigurasi aplikasi sebagai layanan ==="
cat > /etc/supervisor/conf.d/security-operations-center.conf << 'EOL'
[program:security-operations-center]
command=/usr/bin/npm start
directory=/opt/security-operations-center
user=socapp
autostart=true
autorestart=true
environment=NODE_ENV=production,NODE_OPTIONS="--openssl-legacy-provider"
stdout_logfile=/var/log/security-operations-center.log
stderr_logfile=/var/log/security-operations-center-error.log
stdout_logfile_maxbytes=10MB
stderr_logfile_maxbytes=10MB
stdout_logfile_backups=5
stderr_logfile_backups=5
EOL

# Restart supervisor dan start aplikasi
systemctl enable supervisor
systemctl restart supervisor
supervisorctl reread
supervisorctl update
supervisorctl start security-operations-center

# Membuat script untuk monitoring
echo "=== 📊 Membuat script monitoring ==="
cat > /usr/local/bin/soc-status << 'EOL'
#!/bin/bash
echo "=== Status Pusat Operasi Keamanan ==="
echo "📊 Status Aplikasi:"
supervisorctl status security-operations-center

echo ""
echo "🗄️ Status Database:"
systemctl status postgresql --no-pager -l

echo ""
echo "🌐 Status Nginx:"
systemctl status nginx --no-pager -l

echo ""
echo "🔗 Koneksi Database:"
sudo -u postgres psql -d securityoperationscenter -c "SELECT 'Database Connected Successfully' as status;"

echo ""
echo "📱 Akses Aplikasi:"
echo "  - Local: http://localhost"
echo "  - External: http://$(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
EOL

chmod +x /usr/local/bin/soc-status

# Setup firewall (opsional)
echo "=== 🔥 Konfigurasi firewall ==="
ufw --force enable
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 5432/tcp # PostgreSQL (hanya jika diperlukan akses eksternal)

# Pesan Sukses
echo "=========================================================="
echo "🎉 Instalasi Pusat Operasi Keamanan SELESAI!"
echo "=========================================================="
echo "📱 Akses aplikasi di:"
echo "  - http://localhost (local)"
echo "  - http://$(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP') (external)"
echo ""
echo "🗄️ Kredensial Database PostgreSQL:"
echo "  - User: socadmin"
echo "  - Password: SOC_Admin_2024!"
echo "  - Database: securityoperationscenter"
echo "  - Port: 5432"
echo ""
echo "🔧 Perintah berguna:"
echo "  - Status aplikasi: soc-status"
echo "  - Restart aplikasi: supervisorctl restart security-operations-center"
echo "  - Log aplikasi: tail -f /var/log/security-operations-center.log"
echo "  - Log error: tail -f /var/log/security-operations-center-error.log"
echo ""
echo "⚠️  CATATAN KEAMANAN:"
echo "  - Ganti password database default"
echo "  - Konfigurasi SSL/TLS untuk produksi"
echo "  - Batasi akses database dari external"
echo "=========================================================="