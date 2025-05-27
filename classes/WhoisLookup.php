<?php
/**
 * WHOIS Lookup - Security Operation Center
 * Pencarian informasi domain dan IP address
 */

class WhoisLookup {
    
    public function lookup($domain) {
        $startTime = microtime(true);
        $results = [
            'domain' => $domain,
            'scanTime' => 0,
            'status' => 'completed',
            'domainInfo' => [],
            'registrarInfo' => [],
            'dnsInfo' => [],
            'ipInfo' => []
        ];
        
        // Validasi domain
        if (!$this->isValidDomain($domain)) {
            $results['status'] = 'error';
            $results['error'] = 'Domain tidak valid';
            return $results;
        }
        
        // Dapatkan informasi domain
        $results['domainInfo'] = $this->getDomainInfo($domain);
        $results['dnsInfo'] = $this->getDnsInfo($domain);
        $results['ipInfo'] = $this->getIpInfo($domain);
        
        $results['scanTime'] = round((microtime(true) - $startTime) * 1000, 2);
        
        return $results;
    }
    
    private function getDomainInfo($domain) {
        $info = [
            'domain' => $domain,
            'registrar' => 'Unknown',
            'creationDate' => 'Unknown',
            'expirationDate' => 'Unknown',
            'status' => 'Active',
            'nameservers' => []
        ];
        
        // Simulasi data WHOIS (dalam implementasi nyata, gunakan API WHOIS)
        $info['registrar'] = 'Example Registrar Inc.';
        $info['creationDate'] = date('Y-m-d', strtotime('-2 years'));
        $info['expirationDate'] = date('Y-m-d', strtotime('+1 year'));
        
        return $info;
    }
    
    private function getDnsInfo($domain) {
        $dnsInfo = [
            'aRecords' => [],
            'mxRecords' => [],
            'nsRecords' => [],
            'txtRecords' => []
        ];
        
        // Dapatkan A records
        $aRecords = dns_get_record($domain, DNS_A);
        if ($aRecords) {
            foreach ($aRecords as $record) {
                $dnsInfo['aRecords'][] = $record['ip'];
            }
        }
        
        // Dapatkan MX records
        $mxRecords = dns_get_record($domain, DNS_MX);
        if ($mxRecords) {
            foreach ($mxRecords as $record) {
                $dnsInfo['mxRecords'][] = [
                    'target' => $record['target'],
                    'priority' => $record['pri']
                ];
            }
        }
        
        // Dapatkan NS records
        $nsRecords = dns_get_record($domain, DNS_NS);
        if ($nsRecords) {
            foreach ($nsRecords as $record) {
                $dnsInfo['nsRecords'][] = $record['target'];
            }
        }
        
        return $dnsInfo;
    }
    
    private function getIpInfo($domain) {
        $ip = gethostbyname($domain);
        
        if ($ip === $domain) {
            return ['error' => 'Cannot resolve IP address'];
        }
        
        return [
            'ipAddress' => $ip,
            'reverseDns' => gethostbyaddr($ip),
            'location' => $this->getIpLocation($ip),
            'asn' => $this->getAsnInfo($ip)
        ];
    }
    
    private function getIpLocation($ip) {
        // Simulasi data geolokasi IP
        $locations = [
            'country' => 'Indonesia',
            'city' => 'Jakarta',
            'region' => 'DKI Jakarta',
            'latitude' => -6.2088,
            'longitude' => 106.8456,
            'timezone' => 'Asia/Jakarta'
        ];
        
        return $locations;
    }
    
    private function getAsnInfo($ip) {
        // Simulasi data ASN
        return [
            'asn' => 'AS7713',
            'organization' => 'PT Telekomunikasi Indonesia',
            'description' => 'Telkom Indonesia'
        ];
    }
    
    private function isValidDomain($domain) {
        return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
    }
}
?>