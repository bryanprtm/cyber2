<?php
/**
 * Header Analyzer - Security Operation Center
 * Analisis header keamanan HTTP
 */

class HeaderAnalyzer {
    
    public function analyze($url) {
        $startTime = microtime(true);
        $results = [
            'url' => $url,
            'scanTime' => 0,
            'status' => 'completed',
            'headers' => [],
            'securityHeaders' => [],
            'vulnerabilities' => [],
            'securityScore' => 0
        ];
        
        // Validasi URL
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $results['status'] = 'error';
            $results['error'] = 'URL tidak valid';
            return $results;
        }
        
        // Ambil headers
        $headers = $this->getHeaders($url);
        
        if (!$headers) {
            $results['status'] = 'error';
            $results['error'] = 'Tidak dapat mengambil headers';
            return $results;
        }
        
        $results['headers'] = $headers;
        $results['securityHeaders'] = $this->analyzeSecurityHeaders($headers);
        $results['vulnerabilities'] = $this->checkVulnerabilities($headers);
        $results['securityScore'] = $this->calculateSecurityScore($results['securityHeaders']);
        
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function getHeaders($url) {
        $context = stream_context_create([
            'http' => [
                'method' => 'HEAD',
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (compatible; SecurityAnalyzer/1.0)'
            ]
        ]);
        
        $headers = @get_headers($url, 1, $context);
        
        if (!$headers) {
            return false;
        }
        
        return $headers;
    }
    
    private function analyzeSecurityHeaders($headers) {
        $securityHeaders = [
            'X-Frame-Options' => [
                'present' => isset($headers['X-Frame-Options']),
                'value' => $headers['X-Frame-Options'] ?? null,
                'secure' => false,
                'description' => 'Melindungi dari clickjacking attacks'
            ],
            'X-XSS-Protection' => [
                'present' => isset($headers['X-XSS-Protection']),
                'value' => $headers['X-XSS-Protection'] ?? null,
                'secure' => false,
                'description' => 'Mengaktifkan filter XSS browser'
            ],
            'X-Content-Type-Options' => [
                'present' => isset($headers['X-Content-Type-Options']),
                'value' => $headers['X-Content-Type-Options'] ?? null,
                'secure' => false,
                'description' => 'Mencegah MIME type sniffing'
            ],
            'Strict-Transport-Security' => [
                'present' => isset($headers['Strict-Transport-Security']),
                'value' => $headers['Strict-Transport-Security'] ?? null,
                'secure' => false,
                'description' => 'Memaksa koneksi HTTPS'
            ],
            'Content-Security-Policy' => [
                'present' => isset($headers['Content-Security-Policy']),
                'value' => $headers['Content-Security-Policy'] ?? null,
                'secure' => false,
                'description' => 'Melindungi dari XSS dan injeksi kode'
            ],
            'Referrer-Policy' => [
                'present' => isset($headers['Referrer-Policy']),
                'value' => $headers['Referrer-Policy'] ?? null,
                'secure' => false,
                'description' => 'Mengontrol informasi referrer'
            ]
        ];
        
        // Evaluate security of each header
        foreach ($securityHeaders as $header => &$info) {
            if ($info['present']) {
                $info['secure'] = $this->isSecureHeaderValue($header, $info['value']);
            }
        }
        
        return $securityHeaders;
    }
    
    private function isSecureHeaderValue($header, $value) {
        switch ($header) {
            case 'X-Frame-Options':
                return in_array(strtoupper($value), ['DENY', 'SAMEORIGIN']);
            case 'X-XSS-Protection':
                return strpos($value, '1') === 0;
            case 'X-Content-Type-Options':
                return strtolower($value) === 'nosniff';
            case 'Strict-Transport-Security':
                return strpos($value, 'max-age=') !== false;
            case 'Content-Security-Policy':
                return !empty($value) && strpos($value, 'unsafe-inline') === false;
            case 'Referrer-Policy':
                return in_array(strtolower($value), ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']);
            default:
                return true;
        }
    }
    
    private function checkVulnerabilities($headers) {
        $vulnerabilities = [];
        
        // Check for information disclosure
        if (isset($headers['Server'])) {
            $vulnerabilities[] = [
                'type' => 'Information Disclosure',
                'severity' => 'Low',
                'description' => 'Server header mengungkap informasi server',
                'recommendation' => 'Sembunyikan atau ubah header Server'
            ];
        }
        
        if (isset($headers['X-Powered-By'])) {
            $vulnerabilities[] = [
                'type' => 'Information Disclosure',
                'severity' => 'Low',
                'description' => 'X-Powered-By header mengungkap teknologi backend',
                'recommendation' => 'Hapus header X-Powered-By'
            ];
        }
        
        // Check for missing security headers
        $requiredHeaders = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options'];
        
        foreach ($requiredHeaders as $requiredHeader) {
            if (!isset($headers[$requiredHeader])) {
                $vulnerabilities[] = [
                    'type' => 'Missing Security Header',
                    'severity' => 'Medium',
                    'description' => "Header keamanan $requiredHeader tidak ditemukan",
                    'recommendation' => "Tambahkan header $requiredHeader"
                ];
            }
        }
        
        return $vulnerabilities;
    }
    
    private function calculateSecurityScore($securityHeaders) {
        $totalHeaders = count($securityHeaders);
        $secureHeaders = 0;
        
        foreach ($securityHeaders as $header) {
            if ($header['present'] && $header['secure']) {
                $secureHeaders++;
            }
        }
        
        return round(($secureHeaders / $totalHeaders) * 100);
    }
}
?>