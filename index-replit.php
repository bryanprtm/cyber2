<?php
/**
 * Security Operation Center - Replit Edition
 * PHP version optimized for Replit environment
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Security headers
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// Database connection
try {
    $pdo = new PDO('sqlite:security_center.db');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Simple routing
$request = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

// API Routes
if (strpos($request, '/api/tools') === 0) {
    $stmt = $pdo->query("SELECT * FROM tools WHERE aktif = 1 ORDER BY kategori, nama");
    $tools = $stmt->fetchAll(PDO::FETCH_ASSOC);
    header('Content-Type: application/json');
    echo json_encode($tools);
    exit;
}

if (strpos($request, '/api/dashboard/stats') === 0) {
    $stmt = $pdo->query("SELECT COUNT(*) as total_scans FROM scan_results");
    $stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $response = [
        'totalScans' => (int)$stats['total_scans'],
        'scansToday' => rand(5, 20),
        'securityScore' => rand(70, 95),
        'activeThreats' => rand(5, 15),
        'lastUpdate' => date('c')
    ];
    
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

if (strpos($request, '/api/scan/port') === 0 && $method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $target = $input['target'] ?? '';
    $ports = explode(',', $input['ports'] ?? '80,443');
    
    // Simulate port scan results
    $result = [
        'target' => $target,
        'scanTime' => rand(500, 2000),
        'openPorts' => [],
        'closedPorts' => [],
        'totalPorts' => count($ports),
        'status' => 'completed'
    ];
    
    foreach ($ports as $port) {
        $port = (int)trim($port);
        if (rand(0, 3) === 0) { // 25% chance port is open
            $result['openPorts'][] = [
                'port' => $port,
                'service' => getServiceName($port),
                'responseTime' => rand(10, 100) . 'ms'
            ];
        } else {
            $result['closedPorts'][] = $port;
        }
    }
    
    // Save to database
    $stmt = $pdo->prepare("INSERT INTO scan_results (tool_id, target, result_data) VALUES (?, ?, ?)");
    $stmt->execute(['port-scanner', $target, json_encode($result)]);
    
    header('Content-Type: application/json');
    echo json_encode($result);
    exit;
}

if (strpos($request, '/health') === 0) {
    $health = [
        'status' => 'OK',
        'timestamp' => date('c'),
        'version' => '2.0.0-replit',
        'php_version' => PHP_VERSION,
        'database' => 'sqlite'
    ];
    header('Content-Type: application/json');
    echo json_encode($health);
    exit;
}

// Serve frontend
if (file_exists('views/index.html')) {
    include 'views/index.html';
} else {
    echo "<h1>Security Operation Center</h1>";
    echo "<p>PHP + SQLite Edition running on Replit</p>";
    echo "<p><a href='/api/tools'>View Available Tools</a></p>";
    echo "<p><a href='/health'>Health Check</a></p>";
}

function getServiceName($port) {
    $services = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
        53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP',
        443 => 'HTTPS', 993 => 'IMAPS', 995 => 'POP3S',
        3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL',
        8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt'
    ];
    return $services[$port] ?? 'Unknown';
}
?>
