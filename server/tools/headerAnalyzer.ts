import axios from 'axios';

export interface HeaderAnalyzerOptions {
  url: string;
  timeout?: number;
  followRedirects?: boolean;
  userAgent?: string;
}

export interface SecurityHeader {
  name: string;
  value: string | null;
  description: string;
  status: 'good' | 'warning' | 'bad' | 'info';
  recommendation?: string;
}

export interface HeaderAnalysisResult {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  securityHeaders: SecurityHeader[];
  missingSecurityHeaders: SecurityHeader[];
  serverInfo: {
    server?: string;
    poweredBy?: string;
    technology?: string;
  };
  redirectChain?: Array<{
    url: string;
    statusCode: number;
    headers: Record<string, string>;
  }>;
  totalTime: number;
  securityScore: number;
  contentType?: string;
  cookies?: Array<{
    name: string;
    value: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: string;
  }>;
  requestSummary: {
    method: string;
    url: string;
    redirects: number;
    headersCount: number;
  };
}

// Security headers metadata for analysis
const SECURITY_HEADERS = {
  'Strict-Transport-Security': {
    description: 'Enforces HTTPS usage to prevent downgrade attacks',
    recommendation: 'Add header with value: max-age=31536000; includeSubDomains'
  },
  'Content-Security-Policy': {
    description: 'Prevents XSS attacks by restricting resource loading',
    recommendation: 'Add a content security policy that restricts resources to trusted sources'
  },
  'X-Content-Type-Options': {
    description: 'Prevents MIME-sniffing attacks',
    recommendation: 'Add header with value: nosniff'
  },
  'X-Frame-Options': {
    description: 'Prevents clickjacking attacks by restricting iframe usage',
    recommendation: 'Add header with value: DENY or SAMEORIGIN'
  },
  'X-XSS-Protection': {
    description: 'Additional protection against XSS attacks',
    recommendation: 'Add header with value: 1; mode=block'
  },
  'Referrer-Policy': {
    description: 'Controls how much referrer information is included with requests',
    recommendation: 'Add header with value: strict-origin-when-cross-origin'
  },
  'Permissions-Policy': {
    description: 'Controls which browser features can be used (formerly Feature-Policy)',
    recommendation: 'Configure permissions to only allow needed features'
  },
  'Cache-Control': {
    description: 'Controls how responses are cached',
    recommendation: 'Set appropriate caching directives for sensitive content'
  },
  'Access-Control-Allow-Origin': {
    description: 'Controls which domains can access the resource via CORS',
    recommendation: 'Restrict to specific trusted domains instead of using wildcard (*)'
  }
};

/**
 * Analyze HTTP headers of a given URL for security assessment
 * @param options Header analyzer options
 * @returns Analysis results including security assessment
 */
export async function analyzeHeaders(options: HeaderAnalyzerOptions): Promise<HeaderAnalysisResult> {
  const startTime = Date.now();
  
  try {
    // Configure axios request options
    const axiosOptions: any = {
      timeout: options.timeout || 10000,
      maxRedirects: options.followRedirects ? 5 : 0,
      validateStatus: (status: number) => status >= 100 && status < 600,
      headers: {}
    };
    
    // Set custom user agent if provided
    if (options.userAgent) {
      axiosOptions.headers['User-Agent'] = options.userAgent;
    }
    
    // Make the HTTP request
    const response = await axios.get(options.url, axiosOptions);
    const endTime = Date.now();
    
    // Normalize header names (convert to lowercase for easier processing)
    const normalizedHeaders: Record<string, string> = {};
    const originalHeaders: Record<string, string> = {};
    
    Object.entries(response.headers).forEach(([key, value]) => {
      normalizedHeaders[key.toLowerCase()] = typeof value === 'string' ? value : String(value);
      originalHeaders[key] = typeof value === 'string' ? value : String(value);
    });
    
    // Extract server information
    const serverInfo = {
      server: normalizedHeaders['server'] || undefined,
      poweredBy: normalizedHeaders['x-powered-by'] || undefined,
      technology: undefined
    };
    
    // Try to determine technology from headers
    if (normalizedHeaders['x-generator']) {
      serverInfo.technology = normalizedHeaders['x-generator'];
    }
    
    // Analyze security headers
    const securityHeaders: SecurityHeader[] = [];
    const missingSecurityHeaders: SecurityHeader[] = [];
    
    // Check for expected security headers
    Object.entries(SECURITY_HEADERS).forEach(([headerName, metadata]) => {
      const normalizedName = headerName.toLowerCase();
      const headerValue = normalizedHeaders[normalizedName];
      
      if (headerValue) {
        let status: 'good' | 'warning' | 'bad' | 'info' = 'good';
        
        // Additional validation for specific headers
        if (normalizedName === 'strict-transport-security') {
          if (!headerValue.includes('max-age=') || parseInt(headerValue.split('max-age=')[1]) < 31536000) {
            status = 'warning';
          }
        } else if (normalizedName === 'content-security-policy') {
          if (headerValue.includes('unsafe-inline') || headerValue.includes('unsafe-eval')) {
            status = 'warning';
          }
        } else if (normalizedName === 'x-frame-options') {
          if (!['DENY', 'SAMEORIGIN'].includes(headerValue.toUpperCase())) {
            status = 'warning';
          }
        } else if (normalizedName === 'access-control-allow-origin') {
          if (headerValue === '*') {
            status = 'warning';
          }
        }
        
        securityHeaders.push({
          name: headerName,
          value: headerValue,
          description: metadata.description,
          status
        });
      } else {
        missingSecurityHeaders.push({
          name: headerName,
          value: null,
          description: metadata.description,
          status: 'bad',
          recommendation: metadata.recommendation
        });
      }
    });
    
    // Check for potentially insecure headers that expose information
    if (normalizedHeaders['server']) {
      securityHeaders.push({
        name: 'Server',
        value: normalizedHeaders['server'],
        description: 'Reveals server software information',
        status: 'warning',
        recommendation: 'Consider removing or obfuscating this header'
      });
    }
    
    if (normalizedHeaders['x-powered-by']) {
      securityHeaders.push({
        name: 'X-Powered-By',
        value: normalizedHeaders['x-powered-by'],
        description: 'Reveals technology stack information',
        status: 'warning',
        recommendation: 'Remove this header to prevent technology fingerprinting'
      });
    }
    
    // Calculate security score (simple heuristic)
    const maxScore = Object.keys(SECURITY_HEADERS).length;
    const presentSecurityHeaders = securityHeaders.filter(h => 
      Object.keys(SECURITY_HEADERS).includes(h.name) && h.status === 'good'
    ).length;
    
    const securityScore = Math.round((presentSecurityHeaders / maxScore) * 100);
    
    // Extract content type
    const contentType = normalizedHeaders['content-type'];
    
    // Extract cookies (if any)
    const cookies: any[] = [];
    if (normalizedHeaders['set-cookie']) {
      const cookieStrings = Array.isArray(normalizedHeaders['set-cookie']) 
        ? normalizedHeaders['set-cookie'] 
        : [normalizedHeaders['set-cookie']];
      
      cookieStrings.forEach(cookieStr => {
        try {
          const parts = cookieStr.split(';');
          const [name, value] = parts[0].split('=').map(s => s.trim());
          
          const cookie: any = {
            name,
            value,
            secure: cookieStr.toLowerCase().includes('secure'),
            httpOnly: cookieStr.toLowerCase().includes('httponly')
          };
          
          // Extract SameSite if present
          const sameSitePart = parts.find(p => p.trim().toLowerCase().startsWith('samesite='));
          if (sameSitePart) {
            cookie.sameSite = sameSitePart.split('=')[1].trim();
          }
          
          cookies.push(cookie);
        } catch (e) {
          // Skip malformed cookies
        }
      });
    }
    
    // Build the final result
    return {
      url: options.url,
      statusCode: response.status,
      headers: originalHeaders,
      securityHeaders,
      missingSecurityHeaders,
      serverInfo,
      totalTime: endTime - startTime,
      securityScore,
      contentType,
      cookies,
      requestSummary: {
        method: 'GET',
        url: options.url,
        redirects: response.request?._redirectable?._redirectCount || 0,
        headersCount: Object.keys(originalHeaders).length
      }
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(`Header analysis failed: ${error.message} ${error.response?.status || ''}`);
    } else {
      throw new Error(`Header analysis failed: ${(error as Error).message}`);
    }
  }
}