<?php
/**
 * Security Operation Center - PHP Version
 * Pusat Operasi Keamanan dengan arsitektur PHP/MySQL
 */

// Error reporting untuk development
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Header keamanan
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

// CORS headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// Autoload classes
spl_autoload_register(function ($class_name) {
    $file = __DIR__ . '/classes/' . $class_name . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'security_operations_center');
define('DB_USER', 'socuser');
define('DB_PASS', 'SecurePass2024!');
define('DB_CHARSET', 'utf8mb4');

// Initialize application
try {
    $app = new SecurityApp();
    $app->run();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => 'Internal Server Error',
        'message' => $e->getMessage()
    ]);
}

/**
 * Main Application Class
 */
class SecurityApp {
    private $pdo;
    private $router;
    
    public function __construct() {
        $this->initDatabase();
        $this->initRouter();
    }
    
    private function initDatabase() {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            throw new Exception("Database connection failed: " . $e->getMessage());
        }
    }
    
    private function initRouter() {
        $this->router = new Router();
        
        // API Routes
        $this->router->get('/api/tools', [$this, 'getTools']);
        $this->router->get('/api/dashboard/stats', [$this, 'getDashboardStats']);
        $this->router->post('/api/scan/port', [$this, 'portScan']);
        $this->router->post('/api/scan/whois', [$this, 'whoisLookup']);
        $this->router->post('/api/scan/ping-sweep', [$this, 'pingSweep']);
        $this->router->get('/health', [$this, 'healthCheck']);
        
        // Frontend routes
        $this->router->get('/', [$this, 'index']);
        $this->router->get('/dashboard', [$this, 'dashboard']);
        $this->router->get('/tools', [$this, 'tools']);
    }
    
    public function run() {
        $requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $requestMethod = $_SERVER['REQUEST_METHOD'];
        
        $this->router->dispatch($requestMethod, $requestUri);
    }
    
    // API Endpoints
    public function getTools() {
        $stmt = $this->pdo->query("SELECT * FROM tools WHERE aktif = 1 ORDER BY kategori, nama");
        $tools = $stmt->fetchAll();
        
        header('Content-Type: application/json');
        echo json_encode($tools);
    }
    
    public function getDashboardStats() {
        $stmt = $this->pdo->query("
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as scans_today,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans
            FROM scan_results
        ");
        $stats = $stmt->fetch();
        
        $response = [
            'totalScans' => (int)$stats['total_scans'],
            'scansToday' => (int)$stats['scans_today'],
            'completedScans' => (int)$stats['completed_scans'],
            'securityScore' => rand(70, 95),
            'activeThreats' => rand(5, 25),
            'lastUpdate' => date('c')
        ];
        
        header('Content-Type: application/json');
        echo json_encode($response);
    }
    
    public function portScan() {
        $input = json_decode(file_get_contents('php://input'), true);
        $target = filter_var($input['target'] ?? '', FILTER_SANITIZE_STRING);
        $ports = $input['ports'] ?? '22,80,443,8080';
        
        if (empty($target)) {
            http_response_code(400);
            echo json_encode(['error' => 'Target diperlukan']);
            return;
        }
        
        $scanner = new PortScanner();
        $result = $scanner->scan($target, explode(',', $ports));
        
        // Save to database
        $this->saveScanResult('port-scanner', $target, $result);
        
        header('Content-Type: application/json');
        echo json_encode($result);
    }
    
    public function whoisLookup() {
        $input = json_decode(file_get_contents('php://input'), true);
        $domain = filter_var($input['domain'] ?? '', FILTER_SANITIZE_STRING);
        
        if (empty($domain)) {
            http_response_code(400);
            echo json_encode(['error' => 'Domain diperlukan']);
            return;
        }
        
        $whois = new WhoisLookup();
        $result = $whois->lookup($domain);
        
        $this->saveScanResult('whois-lookup', $domain, $result);
        
        header('Content-Type: application/json');
        echo json_encode($result);
    }
    
    public function pingSweep() {
        $input = json_decode(file_get_contents('php://input'), true);
        $network = filter_var($input['network'] ?? '', FILTER_SANITIZE_STRING);
        
        if (empty($network)) {
            http_response_code(400);
            echo json_encode(['error' => 'Network range diperlukan']);
            return;
        }
        
        $ping = new PingSweep();
        $result = $ping->sweep($network);
        
        $this->saveScanResult('ping-sweep', $network, $result);
        
        header('Content-Type: application/json');
        echo json_encode($result);
    }
    
    public function healthCheck() {
        $health = [
            'status' => 'OK',
            'timestamp' => date('c'),
            'version' => '1.0.0',
            'php_version' => PHP_VERSION,
            'database' => 'connected'
        ];
        
        header('Content-Type: application/json');
        echo json_encode($health);
    }
    
    // Frontend pages
    public function index() {
        require_once 'views/index.html';
    }
    
    public function dashboard() {
        require_once 'views/dashboard.html';
    }
    
    public function tools() {
        require_once 'views/tools.html';
    }
    
    private function saveScanResult($toolId, $target, $result) {
        $stmt = $this->pdo->prepare("
            INSERT INTO scan_results (tool_id, target, result_data, status, created_at) 
            VALUES (?, ?, ?, 'completed', NOW())
        ");
        $stmt->execute([$toolId, $target, json_encode($result)]);
    }
}

/**
 * Simple Router Class
 */
class Router {
    private $routes = [];
    
    public function get($path, $callback) {
        $this->routes['GET'][$path] = $callback;
    }
    
    public function post($path, $callback) {
        $this->routes['POST'][$path] = $callback;
    }
    
    public function dispatch($method, $path) {
        if (isset($this->routes[$method][$path])) {
            call_user_func($this->routes[$method][$path]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Route tidak ditemukan']);
        }
    }
}
?>