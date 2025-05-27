<?php
try {
    $pdo = new PDO('sqlite:security_center.db');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tools table
    $pdo->exec("CREATE TABLE IF NOT EXISTS tools (
        id TEXT PRIMARY KEY,
        nama TEXT NOT NULL,
        deskripsi TEXT,
        kategori TEXT NOT NULL,
        icon TEXT,
        aktif INTEGER DEFAULT 1,
        usage_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Create scan_results table
    $pdo->exec("CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_id TEXT,
        target TEXT NOT NULL,
        result_data TEXT,
        status TEXT DEFAULT 'completed',
        scan_duration REAL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Insert tools data
    $tools = [
        ['port-scanner', 'Pemindai Port', 'Memindai port terbuka pada target untuk analisis keamanan', 'Jaringan', 'network'],
        ['whois-lookup', 'WHOIS Lookup', 'Mencari informasi registrasi domain dan kepemilikan', 'Intelijen', 'search'],
        ['ping-sweep', 'Ping Sweep', 'Memindai host aktif dalam range jaringan tertentu', 'Jaringan', 'radar'],
        ['header-analyzer', 'Analisis Header HTTP', 'Menganalisis header keamanan pada website', 'Web', 'file-text'],
        ['ssl-scanner', 'Pemindai SSL/TLS', 'Memeriksa konfigurasi dan keamanan SSL/TLS', 'Keamanan', 'shield'],
        ['tech-detector', 'Deteksi Teknologi', 'Mendeteksi teknologi yang digunakan website', 'Web', 'cpu'],
        ['url-scanner', 'Pemindai URL', 'Memindai keamanan dan reputasi URL', 'Web', 'link'],
        ['cors-tester', 'Tester CORS', 'Menguji konfigurasi Cross-Origin Resource Sharing', 'Web', 'globe'],
        ['sql-injector', 'SQL Injection Tester', 'Menguji kerentanan SQL injection pada aplikasi web', 'Keamanan', 'database'],
        ['xss-scanner', 'XSS Scanner', 'Memindai kerentanan Cross-Site Scripting', 'Keamanan', 'code'],
        ['file-scanner', 'Pemindai File', 'Menganalisis file untuk deteksi malware dan ancaman', 'Keamanan', 'file'],
        ['email-hunter', 'Pemburu Email', 'Mencari dan mengumpulkan alamat email dari website', 'Intelijen', 'mail'],
        ['phone-doxing', 'Phone Doxing', 'Mencari informasi terkait nomor telepon', 'Intelijen', 'phone']
    ];
    
    $stmt = $pdo->prepare("INSERT OR IGNORE INTO tools (id, nama, deskripsi, kategori, icon) VALUES (?, ?, ?, ?, ?)");
    foreach ($tools as $tool) {
        $stmt->execute($tool);
    }
    
    echo "✅ Database setup completed\n";
    echo "📊 " . count($tools) . " cybersecurity tools loaded\n";
    
} catch (PDOException $e) {
    echo "❌ Database error: " . $e->getMessage() . "\n";
}
?>
