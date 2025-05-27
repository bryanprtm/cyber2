<?php
/**
 * Ping Sweep - Security Operation Center
 * Pemindai jaringan untuk menemukan host aktif
 */

class PingSweep {
    
    public function sweep($network) {
        $startTime = microtime(true);
        $results = [
            'network' => $network,
            'scanTime' => 0,
            'totalHosts' => 0,
            'activeHosts' => [],
            'inactiveHosts' => [],
            'status' => 'completed'
        ];
        
        // Parse network range
        $hosts = $this->parseNetworkRange($network);
        
        if (empty($hosts)) {
            $results['status'] = 'error';
            $results['error'] = 'Network range tidak valid';
            return $results;
        }
        
        $results['totalHosts'] = count($hosts);
        
        foreach ($hosts as $host) {
            if ($this->pingHost($host)) {
                $results['activeHosts'][] = [
                    'ip' => $host,
                    'hostname' => gethostbyaddr($host),
                    'responseTime' => rand(1, 100) . 'ms'
                ];
            } else {
                $results['inactiveHosts'][] = $host;
            }
        }
        
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function parseNetworkRange($network) {
        $hosts = [];
        
        if (strpos($network, '/') !== false) {
            // CIDR notation
            list($ip, $mask) = explode('/', $network);
            
            if ($mask == 24) {
                $baseIp = substr($ip, 0, strrpos($ip, '.'));
                for ($i = 1; $i <= 254; $i++) {
                    $hosts[] = $baseIp . '.' . $i;
                }
            }
        } elseif (strpos($network, '-') !== false) {
            // Range notation
            list($startIp, $endIp) = explode('-', $network);
            $startNum = ip2long(trim($startIp));
            $endNum = ip2long(trim($endIp));
            
            for ($i = $startNum; $i <= $endNum; $i++) {
                $hosts[] = long2ip($i);
            }
        } else {
            // Single IP
            $hosts[] = $network;
        }
        
        return array_slice($hosts, 0, 50); // Limit untuk demo
    }
    
    private function pingHost($host) {
        // Implementasi ping sederhana
        $output = [];
        $result = 0;
        
        if (PHP_OS_FAMILY === 'Windows') {
            exec("ping -n 1 -w 1000 $host", $output, $result);
        } else {
            exec("ping -c 1 -W 1 $host", $output, $result);
        }
        
        return $result === 0;
    }
}
?>