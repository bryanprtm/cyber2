<?php
/**
 * Port Scanner - Security Operation Center
 * Pemindai port untuk analisis keamanan jaringan
 */

class PortScanner {
    private $timeout = 5;
    
    public function scan($target, $ports) {
        $startTime = microtime(true);
        $results = [
            'target' => $target,
            'scanTime' => 0,
            'openPorts' => [],
            'closedPorts' => [],
            'filteredPorts' => [],
            'totalPorts' => count($ports),
            'status' => 'completed'
        ];
        
        // Validasi target
        if (!$this->isValidTarget($target)) {
            $results['status'] = 'error';
            $results['error'] = 'Target tidak valid';
            return $results;
        }
        
        foreach ($ports as $port) {
            $port = (int)trim($port);
            if ($port <= 0 || $port > 65535) continue;
            
            $portResult = $this->scanPort($target, $port);
            
            switch ($portResult['status']) {
                case 'open':
                    $results['openPorts'][] = [
                        'port' => $port,
                        'service' => $this->getServiceName($port),
                        'banner' => $portResult['banner'] ?? '',
                        'responseTime' => $portResult['responseTime']
                    ];
                    break;
                case 'closed':
                    $results['closedPorts'][] = $port;
                    break;
                case 'filtered':
                    $results['filteredPorts'][] = $port;
                    break;
            }
        }
        
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function scanPort($target, $port) {
        $startTime = microtime(true);
        
        $connection = @fsockopen($target, $port, $errno, $errstr, $this->timeout);
        
        if ($connection) {
            $responseTime = round((microtime(true) - $startTime) * 1000, 2);
            
            // Coba ambil banner
            $banner = '';
            if ($port == 80 || $port == 8080) {
                fwrite($connection, "HEAD / HTTP/1.0\r\n\r\n");
                $banner = fread($connection, 1024);
            } elseif ($port == 22) {
                $banner = fread($connection, 256);
            } elseif ($port == 21) {
                $banner = fread($connection, 256);
            }
            
            fclose($connection);
            
            return [
                'status' => 'open',
                'responseTime' => $responseTime,
                'banner' => trim($banner)
            ];
        } else {
            if ($errno == 110 || $errno == 111) {
                return ['status' => 'closed'];
            } else {
                return ['status' => 'filtered'];
            }
        }
    }
    
    private function isValidTarget($target) {
        // Validasi IP address atau hostname
        return filter_var($target, FILTER_VALIDATE_IP) || 
               filter_var($target, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
    }
    
    private function getServiceName($port) {
        $services = [
            21 => 'FTP',
            22 => 'SSH',
            23 => 'Telnet',
            25 => 'SMTP',
            53 => 'DNS',
            80 => 'HTTP',
            110 => 'POP3',
            143 => 'IMAP',
            443 => 'HTTPS',
            993 => 'IMAPS',
            995 => 'POP3S',
            3306 => 'MySQL',
            3389 => 'RDP',
            5432 => 'PostgreSQL',
            8080 => 'HTTP-Alt',
            8443 => 'HTTPS-Alt'
        ];
        
        return $services[$port] ?? 'Unknown';
    }
}
?>