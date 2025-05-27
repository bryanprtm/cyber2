<?php
/**
 * XSS Scanner - Security Operation Center
 * Memindai kerentanan Cross-Site Scripting
 */

class XssScanner {
    
    private $payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>'
    ];
    
    public function scan($url, $parameters = []) {
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
            
            $testResult = $this->testXssPayload($url, $payload, $parameters);
            
            if ($testResult['vulnerable']) {
                $results['vulnerabilities'][] = [
                    'payload' => $payload,
                    'method' => $testResult['method'],
                    'parameter' => $testResult['parameter'],
                    'type' => $testResult['type'],
                    'evidence' => $testResult['evidence']
                ];
            }
        }
        
        $results['riskLevel'] = $this->calculateRiskLevel($results['vulnerabilities']);
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function testXssPayload($url, $payload, $parameters) {
        $result = [
            'vulnerable' => false,
            'method' => 'GET',
            'parameter' => '',
            'type' => 'Reflected XSS',
            'evidence' => ''
        ];
        
        // Test GET parameters
        if (!empty($parameters)) {
            foreach ($parameters as $param => $value) {
                $testUrl = $url . '?' . $param . '=' . urlencode($payload);
                $response = $this->makeRequest($testUrl);
                
                if ($this->detectXssInResponse($response, $payload)) {
                    $result['vulnerable'] = true;
                    $result['parameter'] = $param;
                    $result['evidence'] = 'Payload reflected in response without proper encoding';
                    return $result;
                }
            }
        }
        
        // Test POST parameters
        if (!empty($parameters)) {
            $postData = [];
            foreach ($parameters as $param => $value) {
                $postData[$param] = $payload;
                
                $response = $this->makePostRequest($url, $postData);
                
                if ($this->detectXssInResponse($response, $payload)) {
                    $result['vulnerable'] = true;
                    $result['method'] = 'POST';
                    $result['parameter'] = $param;
                    $result['evidence'] = 'Payload reflected in POST response without proper encoding';
                    return $result;
                }
                
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
                'user_agent' => 'Mozilla/5.0 (compatible; XSSScanner/1.0)',
                'header' => 'Accept: text/html,application/xhtml+xml,application/xml'
            ]
        ]);
        
        return @file_get_contents($url, false, $context) ?: '';
    }
    
    private function makePostRequest($url, $data) {
        $postData = http_build_query($data);
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Content-Type: application/x-www-form-urlencoded',
                    'Accept: text/html,application/xhtml+xml,application/xml'
                ],
                'content' => $postData,
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (compatible; XSSScanner/1.0)'
            ]
        ]);
        
        return @file_get_contents($url, false, $context) ?: '';
    }
    
    private function detectXssInResponse($response, $payload) {
        // Check if payload is reflected in response
        if (strpos($response, $payload) !== false) {
            return true;
        }
        
        // Check for decoded versions
        $decodedPayload = html_entity_decode($payload);
        if (strpos($response, $decodedPayload) !== false) {
            return true;
        }
        
        // Check for partial reflection
        if (strpos($payload, '<script>') !== false && 
            strpos($response, '<script>') !== false) {
            return true;
        }
        
        return false;
    }
    
    private function calculateRiskLevel($vulnerabilities) {
        $count = count($vulnerabilities);
        
        if ($count === 0) {
            return 'Low';
        } elseif ($count <= 2) {
            return 'Medium';
        } elseif ($count <= 4) {
            return 'High';
        } else {
            return 'Critical';
        }
    }
}
?>