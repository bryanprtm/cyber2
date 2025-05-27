#!/bin/bash
# Script Instalasi Security Operation Center - PHP + MySQL Edition
# Ubuntu 20.04 Container Ready

echo "🚀 Security Operation Center - PHP + MySQL Installation"
echo "======================================================"

# Update sistem
echo "=== 📦 System Update ==="
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y

# Install PHP 8.0 dan ekstensi yang diperlukan
echo "=== 🐘 Installing PHP 8.0 ==="
apt install -y software-properties-common
add-apt-repository ppa:ondrej/php -y
apt update

apt install -y php8.0 php8.0-fpm php8.0-mysql php8.0-curl php8.0-json php8.0-mbstring \
    php8.0-xml php8.0-zip php8.0-gd php8.0-cli php8.0-common php8.0-opcache

echo "✅ PHP $(php -v | head -n1 | cut -d' ' -f2) installed"

# Install MySQL Server
echo "=== 🗄️ Installing MySQL Server ==="
apt install -y mysql-server mysql-client

# Start MySQL service
service mysql start

# Secure MySQL installation (automated)
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'rootpass123';"
mysql -e "DELETE FROM mysql.user WHERE User='';"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "FLUSH PRIVILEGES;"

echo "✅ MySQL installed and secured"

# Install Nginx
echo "=== 🌐 Installing Nginx ==="
apt install -y nginx

# Setup aplikasi directory
echo "=== 📁 Setting up application ==="
APP_DIR="/var/www/security-operations-center"
mkdir -p $APP_DIR

# Copy application files
cp -r . $APP_DIR/
cd $APP_DIR

# Set proper permissions
chown -R www-data:www-data $APP_DIR
chmod -R 755 $APP_DIR

# Setup database
echo "=== 🏗️ Setting up database ==="
mysql -u root -prootpass123 < database/schema.sql

echo "✅ Database and tables created"

# Configure Nginx for PHP
echo "=== 🌐 Configuring Nginx ==="
cat > /etc/nginx/sites-available/security-operations-center << 'EOL'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/security-operations-center;
    index index.php index.html;
    
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Main location
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    # PHP processing
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Security: deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ /(database|classes)/.*\.php$ {
        deny all;
    }
    
    # API routes
    location /api/ {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    # Health check
    location /health {
        try_files $uri /index.php?$query_string;
    }
}
EOL

# Enable site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/security-operations-center /etc/nginx/sites-enabled/
nginx -t

# Configure PHP-FPM
echo "=== 🔧 Configuring PHP-FPM ==="
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /etc/php/8.0/fpm/php.ini
sed -i 's/max_execution_time = 30/max_execution_time = 300/' /etc/php/8.0/fpm/php.ini
sed -i 's/memory_limit = 128M/memory_limit = 512M/' /etc/php/8.0/fpm/php.ini

# Start services
echo "=== 🚀 Starting services ==="
service php8.0-fpm start
service nginx start
service mysql start

# Enable services to start on boot
systemctl enable php8.0-fpm
systemctl enable nginx
systemctl enable mysql

# Test the application
echo "=== 🧪 Testing application ==="
sleep 3

if curl -s http://localhost/health > /dev/null; then
    echo "✅ Application responding correctly"
else
    echo "⚠️ Application may need time to start"
fi

# Create management scripts
echo "=== 🛠️ Creating management tools ==="

# Status script
cat > /usr/local/bin/soc-php-status << 'EOL'
#!/bin/bash
echo "📊 Security Operation Center - PHP Edition Status"
echo "================================================"
echo "🐘 PHP-FPM:"
systemctl status php8.0-fpm --no-pager -l | head -3
echo ""
echo "🌐 Nginx:"
systemctl status nginx --no-pager -l | head -3
echo ""
echo "🗄️ MySQL:"
systemctl status mysql --no-pager -l | head -3
echo ""
echo "📱 Application URL: http://$(hostname -I | awk '{print $1}')"
echo "🔗 Health Check: http://$(hostname -I | awk '{print $1}')/health"
echo "🛠️ API Tools: http://$(hostname -I | awk '{print $1}')/api/tools"
EOL

# Restart script
cat > /usr/local/bin/soc-php-restart << 'EOL'
#!/bin/bash
echo "🔄 Restarting Security Operation Center services..."
systemctl restart php8.0-fpm
systemctl restart nginx
systemctl restart mysql
echo "✅ All services restarted"
EOL

# Database backup script
cat > /usr/local/bin/soc-php-backup << 'EOL'
#!/bin/bash
BACKUP_DIR="/var/backups/security-operations-center"
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)

echo "💾 Creating database backup..."
mysqldump -u root -prootpass123 security_operations_center > $BACKUP_DIR/backup_$DATE.sql
echo "✅ Backup saved: $BACKUP_DIR/backup_$DATE.sql"
EOL

# Logs script
cat > /usr/local/bin/soc-php-logs << 'EOL'
#!/bin/bash
echo "📄 Security Operation Center Logs"
echo "================================="
echo "Choose log to view:"
echo "1) Nginx access logs"
echo "2) Nginx error logs" 
echo "3) PHP-FPM logs"
echo "4) MySQL logs"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1) tail -f /var/log/nginx/access.log ;;
    2) tail -f /var/log/nginx/error.log ;;
    3) tail -f /var/log/php8.0-fpm.log ;;
    4) tail -f /var/log/mysql/error.log ;;
    *) echo "Invalid choice" ;;
esac
EOL

# Make scripts executable
chmod +x /usr/local/bin/soc-php-*

# Create application config file
cat > $APP_DIR/config.php << 'EOL'
<?php
/**
 * Security Operation Center Configuration
 */

define('APP_NAME', 'Security Operation Center');
define('APP_VERSION', '2.0.0');
define('APP_ENV', 'production');

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'security_operations_center');
define('DB_USER', 'socuser');
define('DB_PASS', 'SecurePass2024!');
define('DB_CHARSET', 'utf8mb4');

// Security Configuration
define('SCAN_TIMEOUT', 300);
define('MAX_SCAN_RESULTS', 1000);
define('ENABLE_LOGGING', true);

// Paths
define('APP_ROOT', __DIR__);
define('CLASSES_PATH', APP_ROOT . '/classes');
define('VIEWS_PATH', APP_ROOT . '/views');
EOL

echo ""
echo "🎉 Installation Complete!"
echo "========================="
echo "✅ Security Operation Center (PHP + MySQL) installed successfully"
echo ""
echo "📋 Management Commands:"
echo "🔍 soc-php-status   - Check system status"
echo "🔄 soc-php-restart  - Restart all services"
echo "💾 soc-php-backup   - Backup database"
echo "📄 soc-php-logs     - View application logs"
echo ""
echo "🌐 Application URL: http://$(hostname -I | awk '{print $1}')"
echo "🔗 Health Check: http://$(hostname -I | awk '{print $1}')/health"
echo "🛠️ API Endpoint: http://$(hostname -I | awk '{print $1}')/api/tools"
echo ""
echo "📊 System Information:"
echo "   PHP Version: $(php -v | head -n1 | cut -d' ' -f2)"
echo "   MySQL Version: $(mysql --version | cut -d' ' -f6)"
echo "   Nginx Version: $(nginx -v 2>&1 | cut -d' ' -f3)"
echo ""
echo "🔐 Database Details:"
echo "   Host: localhost"
echo "   Database: security_operations_center"
echo "   User: socuser"
echo "   13 cybersecurity tools ready to use"
echo ""

# Show final status
soc-php-status