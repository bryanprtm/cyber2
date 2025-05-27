#!/bin/bash
# Quick deployment script untuk testing di Ubuntu container
# Simplified version untuk rapid deployment

echo "🚀 Quick Deploy - Security Operation Center"
echo "=========================================="

# Setup basic directory
mkdir -p /opt/soc/{database,logs}
cd /opt/soc

# Install minimal PHP jika belum ada
if ! command -v php &> /dev/null; then
    echo "Installing PHP..."
    apt update && apt install -y php php-sqlite3 php-curl
fi

# Create simple PHP application
cat > index.php << 'EOFPHP'
<?php
// Simple Security Operation Center
header('Content-Type: text/html; charset=UTF-8');

// Create SQLite database
$db = new SQLite3('/opt/soc/security.db');
$db->exec("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, tool TEXT, target TEXT, result TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

$request = $_SERVER['REQUEST_URI'] ?? '/';

if (strpos($request, '/api/health') !== false) {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'OK', 'version' => '2.0.0-container', 'php' => PHP_VERSION]);
    exit;
}

if (strpos($request, '/api/tools') !== false) {
    header('Content-Type: application/json');
    $tools = [
        ['id' => 'port-scanner', 'name' => 'Port Scanner', 'category' => 'Network'],
        ['id' => 'whois-lookup', 'name' => 'WHOIS Lookup', 'category' => 'Intel'],
        ['id' => 'ping-sweep', 'name' => 'Ping Sweep', 'category' => 'Network'],
        ['id' => 'header-check', 'name' => 'Header Analyzer', 'category' => 'Web'],
        ['id' => 'ssl-scan', 'name' => 'SSL Scanner', 'category' => 'Security']
    ];
    echo json_encode($tools);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Security Operation Center - Container</title>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { font-size: 2.5rem; text-shadow: 0 0 10px #0f0; }
        .status { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .card { background: rgba(0,255,0,0.1); border: 1px solid #0f0; padding: 15px; border-radius: 5px; }
        .tools { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
        .tool { background: rgba(255,255,255,0.05); border: 1px solid #333; padding: 15px; border-radius: 5px; }
        .tool:hover { border-color: #0f0; }
        .btn { background: #0f0; color: #000; border: none; padding: 8px 15px; cursor: pointer; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SECURITY OPERATION CENTER</h1>
        <p>Ubuntu Container Edition | PHP <?= PHP_VERSION ?></p>
    </div>
    
    <div class="status">
        <div class="card">
            <h3>Status</h3>
            <div>🟢 ONLINE</div>
        </div>
        <div class="card">
            <h3>Tools</h3>
            <div>5 READY</div>
        </div>
        <div class="card">
            <h3>Database</h3>
            <div>📊 SQLite</div>
        </div>
        <div class="card">
            <h3>Container</h3>
            <div>🐧 Ubuntu</div>
        </div>
    </div>
    
    <div class="tools" id="tools">
        <!-- Tools loaded via JavaScript -->
    </div>
    
    <script>
        fetch('/api/tools')
            .then(r => r.json())
            .then(tools => {
                const container = document.getElementById('tools');
                tools.forEach(tool => {
                    container.innerHTML += `
                        <div class="tool">
                            <h3>${tool.name}</h3>
                            <p>Category: ${tool.category}</p>
                            <button class="btn" onclick="alert('Tool ${tool.id} ready!')">Execute</button>
                        </div>
                    `;
                });
            });
    </script>
</body>
</html>
EOFPHP

echo "✅ Security Operation Center deployed!"
echo "🌐 Starting PHP server on port 8080..."
php -S 0.0.0.0:8080 index.php