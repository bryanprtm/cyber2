import axios from 'axios';
import { AxiosResponse } from 'axios';

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
    technology?: string | undefined;
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

// Security headers metadata for analysis with detailed recommendations and grading
const SECURITY_HEADERS: Record<string, { 
  description: string; 
  recommendation: string;
  importance: 'critical' | 'high' | 'medium' | 'low';
  validator?: (value: string) => { valid: boolean; reason?: string; };
}> = {
  'Strict-Transport-Security': {
    description: 'Enforces HTTPS usage to prevent protocol downgrade attacks and cookie hijacking',
    recommendation: 'Add header with value: max-age=31536000; includeSubDomains; preload',
    importance: 'critical',
    validator: (value: string) => {
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      if (!maxAgeMatch) return { valid: false, reason: 'Missing max-age directive' };
      
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) { // 1 year in seconds
        return { valid: false, reason: 'max-age should be at least 31536000 (1 year)' };
      }
      
      if (!value.includes('includeSubDomains')) {
        return { valid: false, reason: 'Missing includeSubDomains directive' };
      }
      
      return { valid: true };
    }
  },
  'Content-Security-Policy': {
    description: 'Prevents XSS attacks by specifying which dynamic resources are allowed to load',
    recommendation: 'Implement a strict CSP that disallows unsafe-inline and unsafe-eval',
    importance: 'critical',
    validator: (value: string) => {
      if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
        return { valid: false, reason: 'Contains unsafe-inline or unsafe-eval directives' };
      }
      if (value.includes('*')) {
        return { valid: false, reason: 'Contains wildcard (*) sources which weaken security' };
      }
      return { valid: true };
    }
  },
  'X-Content-Type-Options': {
    description: 'Prevents browsers from MIME-sniffing a response away from the declared content-type',
    recommendation: 'Add header with value: nosniff',
    importance: 'high',
    validator: (value: string) => {
      return { valid: value.toLowerCase() === 'nosniff' };
    }
  },
  'X-Frame-Options': {
    description: 'Prevents clickjacking attacks by restricting who can put this site in a frame',
    recommendation: 'Add header with value: DENY or SAMEORIGIN',
    importance: 'high',
    validator: (value: string) => {
      const upperValue = value.toUpperCase();
      return { valid: ['DENY', 'SAMEORIGIN'].includes(upperValue) };
    }
  },
  'X-XSS-Protection': {
    description: 'Legacy cross-site scripting filter for older browsers (mostly obsolete with proper CSP)',
    recommendation: 'Add header with value: 1; mode=block',
    importance: 'medium',
    validator: (value: string) => {
      return { valid: value === '1; mode=block' };
    }
  },
  'Referrer-Policy': {
    description: 'Controls how much referrer information is included with requests',
    recommendation: 'Add header with value: strict-origin-when-cross-origin',
    importance: 'medium',
    validator: (value: string) => {
      const safePolicies = [
        'no-referrer',
        'no-referrer-when-downgrade',
        'strict-origin',
        'strict-origin-when-cross-origin'
      ];
      return { valid: safePolicies.includes(value.toLowerCase()) };
    }
  },
  'Permissions-Policy': {
    description: 'Allows a site to control which features and APIs can be used (formerly Feature-Policy)',
    recommendation: 'Configure to restrict sensitive browser features',
    importance: 'medium'
  },
  'Cross-Origin-Opener-Policy': {
    description: 'Controls if a window opener retains references to newly opened windows',
    recommendation: 'Add header with value: same-origin',
    importance: 'medium',
    validator: (value: string) => {
      return { valid: ['same-origin', 'same-origin-allow-popups'].includes(value.toLowerCase()) };
    }
  },
  'Cross-Origin-Embedder-Policy': {
    description: 'Prevents a document from loading any cross-origin resources that don\'t explicitly grant the document permission',
    recommendation: 'Add header with value: require-corp',
    importance: 'medium'
  },
  'Cross-Origin-Resource-Policy': {
    description: 'Prevents other origins from reading the response of the resources to which this header is applied',
    recommendation: 'Add header with value: same-origin',
    importance: 'medium'
  },
  'Cache-Control': {
    description: 'Controls how responses are cached by browsers and proxies',
    recommendation: 'For sensitive content: no-store, max-age=0',
    importance: 'medium',
    validator: (value: string) => {
      if (value.includes('public') && !value.includes('no-store')) {
        return { valid: false, reason: 'Public cache without no-store may expose sensitive data' };
      }
      return { valid: true };
    }
  },
  'Clear-Site-Data': {
    description: 'Clears browsing data (cookies, storage, cache) associated with the requesting website',
    recommendation: 'For logout pages, use: "cache", "cookies", "storage"',
    importance: 'low'
  },
  'Access-Control-Allow-Origin': {
    description: 'Controls which domains can access resources via CORS',
    recommendation: 'Only allow specific trusted domains instead of using wildcard (*)',
    importance: 'high',
    validator: (value: string) => {
      return { valid: value !== '*', reason: value === '*' ? 'Wildcard (*) allows any domain to access the resource' : undefined };
    }
  },
  'Access-Control-Allow-Credentials': {
    description: 'Controls if CORS requests can include credentials (cookies, auth headers)',
    recommendation: 'Only set to true if absolutely necessary and with strict CORS origin policy',
    importance: 'high',
    validator: (value: string) => {
      return { valid: value !== 'true' || true, reason: value === 'true' ? 'Allowing credentials should be done with caution' : undefined };
    }
  },
  'Expect-CT': {
    description: 'Certificate Transparency policy enforcement (being deprecated in favor of HSTS preloading)',
    recommendation: 'enforce, max-age=30',
    importance: 'low'
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