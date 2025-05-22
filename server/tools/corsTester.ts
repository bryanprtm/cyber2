import axios from 'axios';

export interface CorsTesterOptions {
  url: string;
  methods?: string[];
  headers?: Record<string, string>;
  withCredentials?: boolean;
  timeout?: number;
  userAgent?: string;
}

export interface CorsTestResult {
  url: string;
  scanTime: number;
  accessControlAllowOrigin?: string;
  accessControlAllowMethods?: string[];
  accessControlAllowHeaders?: string[];
  accessControlAllowCredentials?: boolean;
  accessControlExposeHeaders?: string[];
  accessControlMaxAge?: number;
  corsEnabled: boolean;
  methodsSupported: Record<string, boolean>;
  preflight: {
    status: number;
    success: boolean;
    headers?: Record<string, string>;
  };
  simpleRequest: {
    status: number;
    success: boolean;
    headers?: Record<string, string>;
  };
  crossSiteRequest: {
    status: number;
    success: boolean;
    headers?: Record<string, string>;
  };
  credentialedRequest?: {
    status: number;
    success: boolean;
    headers?: Record<string, string>;
  };
  vulnerabilities: Array<{
    type: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    description: string;
    impact?: string;
    recommendation?: string;
  }>;
  securityRating: {
    overall: 'Safe' | 'Somewhat Safe' | 'Potentially Unsafe' | 'Unsafe';
    score: number; // 0-100
  };
  corsConfig?: {
    policy: string;
    wildcard: boolean;
    permissive: boolean;
    restrictive: boolean;
  };
}

/**
 * Test CORS configuration of a URL
 * @param options CORS tester options
 * @returns CORS test results
 */
export async function testCors(options: CorsTesterOptions): Promise<CorsTestResult> {
  const { 
    url, 
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'], 
    headers = { 'X-Test-Header': 'test-value', 'Content-Type': 'application/json' },
    withCredentials = true,
    timeout = 10000,
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Normalize URL (ensure it has protocol)
  const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
  
  // Default result skeleton with most properties filled later
  const result: CorsTestResult = {
    url: normalizedUrl,
    scanTime: 0, // Updated at the end
    corsEnabled: false,
    methodsSupported: {},
    preflight: {
      status: 0,
      success: false
    },
    simpleRequest: {
      status: 0,
      success: false
    },
    crossSiteRequest: {
      status: 0,
      success: false
    },
    vulnerabilities: [],
    securityRating: {
      overall: 'Unsafe',
      score: 0
    }
  };
  
  // Initialize methods supported object for each method
  for (const method of methods) {
    result.methodsSupported[method] = false;
  }
  
  try {
    // 1. Simple Request (GET request with basic headers)
    const simpleResponse = await makeRequest(normalizedUrl, 'GET', {}, false, timeout, userAgent);
    
    result.simpleRequest = {
      status: simpleResponse.status,
      success: simpleResponse.status >= 200 && simpleResponse.status < 400,
      headers: simpleResponse.headers
    };
    
    // Extract CORS headers
    const corsHeaders = extractCorsHeaders(simpleResponse.headers);
    Object.assign(result, corsHeaders);
    
    // Determine if CORS is enabled based on presence of Access-Control-Allow-Origin header
    result.corsEnabled = !!result.accessControlAllowOrigin;
    
    // 2. Test preflight request (OPTIONS)
    try {
      const preflightResponse = await makeRequest(
        normalizedUrl, 
        'OPTIONS',
        {
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': Object.keys(headers).join(','),
          'Origin': 'https://example.com'
        },
        false,
        timeout,
        userAgent
      );
      
      result.preflight = {
        status: preflightResponse.status,
        success: preflightResponse.status >= 200 && preflightResponse.status < 400,
        headers: preflightResponse.headers
      };
      
      // Update CORS headers from preflight if not already set
      const preflightCorsHeaders = extractCorsHeaders(preflightResponse.headers);
      Object.keys(preflightCorsHeaders).forEach(key => {
        if (!result[key as keyof CorsTestResult]) {
          (result as any)[key] = preflightCorsHeaders[key as keyof typeof preflightCorsHeaders];
        }
      });
      
    } catch (error: any) {
      result.preflight = {
        status: error.response?.status || 0,
        success: false,
        headers: error.response?.headers
      };
      
      // Add vulnerability if preflight fails but site might support CORS
      if (result.corsEnabled) {
        result.vulnerabilities.push({
          type: 'Preflight Failure',
          severity: 'Medium',
          description: 'Preflight request failed but CORS headers were detected in simple request.',
          impact: 'May prevent complex requests from working across origins.',
          recommendation: 'Ensure OPTIONS requests are properly handled with correct CORS headers.'
        });
      }
    }
    
    // 3. Test cross-site request with a different origin
    try {
      const crossSiteResponse = await makeRequest(
        normalizedUrl,
        'GET',
        {
          'Origin': 'https://evil-site.example.com'
        },
        false,
        timeout,
        userAgent
      );
      
      result.crossSiteRequest = {
        status: crossSiteResponse.status,
        success: crossSiteResponse.status >= 200 && crossSiteResponse.status < 400,
        headers: crossSiteResponse.headers
      };
      
    } catch (error: any) {
      result.crossSiteRequest = {
        status: error.response?.status || 0,
        success: false,
        headers: error.response?.headers
      };
    }
    
    // 4. Test with credentials if requested
    if (withCredentials) {
      try {
        const credentialedResponse = await makeRequest(
          normalizedUrl,
          'GET',
          {
            'Origin': 'https://example.com'
          },
          true,
          timeout,
          userAgent
        );
        
        result.credentialedRequest = {
          status: credentialedResponse.status,
          success: credentialedResponse.status >= 200 && credentialedResponse.status < 400,
          headers: credentialedResponse.headers
        };
        
      } catch (error: any) {
        result.credentialedRequest = {
          status: error.response?.status || 0,
          success: false,
          headers: error.response?.headers
        };
      }
    }
    
    // 5. Test supported methods (for each method we are checking)
    for (const method of methods) {
      try {
        const methodResponse = await makeRequest(
          normalizedUrl,
          method,
          {
            'Origin': 'https://example.com'
          },
          false,
          timeout / 2, // Shorter timeout for method tests
          userAgent
        );
        
        // Method is supported if it doesn't return 405 Method Not Allowed
        result.methodsSupported[method] = methodResponse.status !== 405;
        
      } catch (error: any) {
        // Method might be supported if we get certain errors (like unauthorized)
        result.methodsSupported[method] = error.response?.status !== 405;
      }
    }
    
    // 6. Analyze CORS configuration for security issues
    analyzeCorsConfig(result);
    
    // Update security rating
    calculateSecurityRating(result);
    
  } catch (error: any) {
    console.error('CORS testing error:', error);
    
    // Add a general error vulnerability
    result.vulnerabilities.push({
      type: 'Testing Error',
      severity: 'Medium',
      description: `Error during CORS testing: ${error.message}`,
      recommendation: 'Check if the URL is accessible.'
    });
    
    // Update security rating for error case
    result.securityRating = {
      overall: 'Unsafe',
      score: 0
    };
  }
  
  // Update final scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Make a request with specific options
 */
async function makeRequest(
  url: string, 
  method: string,
  additionalHeaders: Record<string, string> = {},
  withCredentials: boolean,
  timeout: number,
  userAgent: string
): Promise<{ status: number, headers: any, data?: any }> {
  try {
    const response = await axios({
      url,
      method,
      headers: {
        'User-Agent': userAgent,
        ...additionalHeaders
      },
      withCredentials,
      timeout,
      validateStatus: () => true // Don't throw on non-2xx status
    });
    
    return {
      status: response.status,
      headers: response.headers,
      data: response.data
    };
  } catch (error: any) {
    if (error.response) {
      return {
        status: error.response.status,
        headers: error.response.headers
      };
    }
    throw error;
  }
}

/**
 * Extract CORS headers from response headers
 */
function extractCorsHeaders(headers: Record<string, string>): Partial<CorsTestResult> {
  const result: Partial<CorsTestResult> = {};
  
  // Convert all header names to lowercase for case-insensitive matching
  const normalizedHeaders: Record<string, string> = {};
  Object.entries(headers).forEach(([key, value]) => {
    normalizedHeaders[key.toLowerCase()] = value;
  });
  
  // Access-Control-Allow-Origin
  if (normalizedHeaders['access-control-allow-origin']) {
    result.accessControlAllowOrigin = normalizedHeaders['access-control-allow-origin'];
  }
  
  // Access-Control-Allow-Methods
  if (normalizedHeaders['access-control-allow-methods']) {
    result.accessControlAllowMethods = normalizedHeaders['access-control-allow-methods']
      .split(',')
      .map(method => method.trim());
  }
  
  // Access-Control-Allow-Headers
  if (normalizedHeaders['access-control-allow-headers']) {
    result.accessControlAllowHeaders = normalizedHeaders['access-control-allow-headers']
      .split(',')
      .map(header => header.trim());
  }
  
  // Access-Control-Allow-Credentials
  if (normalizedHeaders['access-control-allow-credentials']) {
    result.accessControlAllowCredentials = 
      normalizedHeaders['access-control-allow-credentials'].toLowerCase() === 'true';
  }
  
  // Access-Control-Expose-Headers
  if (normalizedHeaders['access-control-expose-headers']) {
    result.accessControlExposeHeaders = normalizedHeaders['access-control-expose-headers']
      .split(',')
      .map(header => header.trim());
  }
  
  // Access-Control-Max-Age
  if (normalizedHeaders['access-control-max-age']) {
    result.accessControlMaxAge = parseInt(normalizedHeaders['access-control-max-age'], 10);
  }
  
  return result;
}

/**
 * Analyze CORS configuration and add vulnerabilities
 */
function analyzeCorsConfig(result: CorsTestResult): void {
  // 1. Check for wildcard origin
  const hasWildcardOrigin = result.accessControlAllowOrigin === '*';
  
  // 2. Check if credentials allowed with wildcard (this is not allowed by browsers but check anyway)
  const credentialsWithWildcard = hasWildcardOrigin && result.accessControlAllowCredentials === true;
  
  // 3. Check for missing preflight support but CORS enabled
  const missingPreflightSupport = result.corsEnabled && 
    (!result.preflight.success || !result.accessControlAllowMethods);
  
  // 4. Determine policy type
  let policyType = 'Unknown';
  let isWildcard = false;
  let isPermissive = false;
  let isRestrictive = false;
  
  if (result.accessControlAllowOrigin) {
    if (result.accessControlAllowOrigin === '*') {
      policyType = 'Wildcard (*) - Allows any origin';
      isWildcard = true;
      isPermissive = true;
    } else if (result.accessControlAllowOrigin.includes('*')) {
      policyType = 'Wildcard pattern - Allows multiple origins with pattern';
      isWildcard = true;
      isPermissive = true;
    } else if (result.accessControlAllowOrigin.includes(',')) {
      policyType = 'Multiple origins - Explicitly allows multiple origins';
      isPermissive = true;
    } else {
      policyType = 'Single origin - Restricted to one origin';
      isRestrictive = true;
    }
  } else {
    policyType = 'No CORS - CORS is not explicitly enabled';
    isRestrictive = true;
  }
  
  // Set CORS configuration details
  result.corsConfig = {
    policy: policyType,
    wildcard: isWildcard,
    permissive: isPermissive,
    restrictive: isRestrictive
  };
  
  // Add vulnerabilities based on findings
  
  // Wildcard origin vulnerability
  if (hasWildcardOrigin) {
    result.vulnerabilities.push({
      type: 'Wildcard Origin',
      severity: 'Medium',
      description: 'CORS policy uses wildcard (*) for allowed origins.',
      impact: 'Allows any website to make cross-origin requests to this resource.',
      recommendation: 'Restrict CORS to specific trusted origins rather than using a wildcard.'
    });
  }
  
  // Credentials with wildcard vulnerability (should be impossible due to browser restrictions)
  if (credentialsWithWildcard) {
    result.vulnerabilities.push({
      type: 'Invalid Credentials Configuration',
      severity: 'High',
      description: 'CORS policy allows credentials with wildcard origin, which browsers will reject.',
      impact: 'Credentialed requests will fail despite the server allowing them.',
      recommendation: 'Specify exact origins when allowing credentials, as browsers do not allow wildcard with credentials.'
    });
  }
  
  // Missing preflight support
  if (missingPreflightSupport) {
    result.vulnerabilities.push({
      type: 'Incomplete CORS Implementation',
      severity: 'Medium',
      description: 'CORS is enabled, but preflight requests are not properly supported.',
      impact: 'Non-simple cross-origin requests will fail.',
      recommendation: 'Ensure the server responds properly to OPTIONS requests with all necessary CORS headers.'
    });
  }
  
  // Missing credentials support but credentials attempted
  if (result.credentialedRequest && !result.accessControlAllowCredentials && result.corsEnabled) {
    result.vulnerabilities.push({
      type: 'Missing Credentials Support',
      severity: 'Low',
      description: 'CORS is enabled, but the server does not support credentials for cross-origin requests.',
      impact: 'Authenticated cross-origin requests will fail.',
      recommendation: 'Add Access-Control-Allow-Credentials: true if you need to support authenticated cross-origin requests.'
    });
  }
  
  // Overly restrictive configuration
  if (result.corsEnabled && isRestrictive && !result.crossSiteRequest.success) {
    result.vulnerabilities.push({
      type: 'Restrictive CORS Configuration',
      severity: 'Low',
      description: 'CORS is configured, but the policy is very restrictive.',
      impact: 'May prevent legitimate cross-origin access.',
      recommendation: 'If cross-origin access is needed, ensure the necessary origins are allowed.'
    });
  }
}

/**
 * Calculate the overall security rating based on vulnerabilities
 */
function calculateSecurityRating(result: CorsTestResult): void {
  // Start with a perfect score
  let score = 100;
  
  // Count vulnerabilities by severity
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  
  result.vulnerabilities.forEach(vuln => {
    switch (vuln.severity) {
      case 'Critical':
        criticalCount++;
        score -= 25;
        break;
      case 'High':
        highCount++;
        score -= 15;
        break;
      case 'Medium':
        mediumCount++;
        score -= 10;
        break;
      case 'Low':
        lowCount++;
        score -= 5;
        break;
    }
  });
  
  // Consider CORS configuration type in the rating
  if (result.corsConfig) {
    if (result.corsConfig.wildcard) {
      score -= 20; // Wildcard policies are generally less secure
    }
    
    if (result.corsConfig.restrictive) {
      score += 10; // Restrictive policies are generally more secure
    }
  }
  
  // Special case: if CORS is not enabled at all (and that's intentional)
  if (!result.corsEnabled && result.vulnerabilities.length === 0) {
    score = 95; // Not 100 because CORS might be needed for legitimate use cases
  }
  
  // Determine overall rating based on score
  let overall: CorsTestResult['securityRating']['overall'];
  
  if (score >= 90) {
    overall = 'Safe';
  } else if (score >= 70) {
    overall = 'Somewhat Safe';
  } else if (score >= 40) {
    overall = 'Potentially Unsafe';
  } else {
    overall = 'Unsafe';
  }
  
  // Ensure score is between 0 and 100
  score = Math.max(0, Math.min(100, score));
  
  // Update the security rating
  result.securityRating = {
    overall,
    score
  };
}