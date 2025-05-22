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
    const axiosOptions = {
      timeout: options.timeout || 10000,
      maxRedirects: options.followRedirects ? 5 : 0,
      validateStatus: (status: number) => status >= 100 && status < 600,
      headers: {} as Record<string, string>
    };
    
    // Set custom user agent if provided
    if (options.userAgent) {
      axiosOptions.headers['User-Agent'] = options.userAgent;
    } else {
      // Set a realistic user agent if none provided
      axiosOptions.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
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

    // Extract additional technology indicators
    const technologyIndicators = detectTechnologyFromHeaders(normalizedHeaders);
    if (technologyIndicators && !serverInfo.technology) {
      serverInfo.technology = technologyIndicators;
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
        let recommendation: string | undefined = undefined;
        
        // Use validators if available
        if (metadata.validator) {
          const validationResult = metadata.validator(headerValue);
          if (!validationResult.valid) {
            status = metadata.importance === 'critical' ? 'bad' : 'warning';
            recommendation = validationResult.reason ? 
              `Current value is problematic: ${validationResult.reason}. ${metadata.recommendation}` : 
              metadata.recommendation;
          }
        }
        
        securityHeaders.push({
          name: headerName,
          value: headerValue,
          description: metadata.description,
          status,
          recommendation
        });
      } else {
        // Determine status based on importance
        let status: 'good' | 'warning' | 'bad' | 'info' = 'bad';
        
        if (metadata.importance === 'low') {
          status = 'info';
        } else if (metadata.importance === 'medium') {
          status = 'warning';
        } else {
          status = 'bad';
        }
        
        missingSecurityHeaders.push({
          name: headerName,
          value: null,
          description: metadata.description,
          status,
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
    
    if (normalizedHeaders['x-aspnet-version']) {
      securityHeaders.push({
        name: 'X-AspNet-Version',
        value: normalizedHeaders['x-aspnet-version'],
        description: 'Reveals ASP.NET version information',
        status: 'bad',
        recommendation: 'Remove this header to prevent technology fingerprinting'
      });
    }

    if (normalizedHeaders['x-runtime']) {
      securityHeaders.push({
        name: 'X-Runtime',
        value: normalizedHeaders['x-runtime'],
        description: 'Reveals Ruby on Rails runtime information',
        status: 'warning',
        recommendation: 'Remove this header to prevent technology fingerprinting'
      });
    }
    
    // Calculate security score with weighted approach
    const scoreData = calculateSecurityScore(securityHeaders, missingSecurityHeaders);
    
    // Extract content type
    const contentType = normalizedHeaders['content-type'];
    
    // Extract cookies (if any)
    const cookies: Array<{
      name: string;
      value: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite?: string;
    }> = [];

    if (normalizedHeaders['set-cookie']) {
      const cookieStrings = Array.isArray(normalizedHeaders['set-cookie']) 
        ? normalizedHeaders['set-cookie'] 
        : [normalizedHeaders['set-cookie']];
      
      cookieStrings.forEach(cookieStr => {
        try {
          const parts = cookieStr.split(';');
          const nameValuePair = parts[0].split('=');
          
          if (nameValuePair.length >= 2) {
            const name = nameValuePair[0].trim();
            const value = nameValuePair.slice(1).join('=').trim(); // Handle values with = in them
            
            const cookie = {
              name,
              value,
              secure: cookieStr.toLowerCase().includes('secure'),
              httpOnly: cookieStr.toLowerCase().includes('httponly')
            };
            
            // Extract SameSite if present
            const sameSitePart = parts.find(p => p.trim().toLowerCase().startsWith('samesite='));
            if (sameSitePart) {
              const sameSiteValue = sameSitePart.split('=')[1]?.trim();
              if (sameSiteValue) {
                cookie.sameSite = sameSiteValue;
              }
            }
            
            cookies.push(cookie);
          }
        } catch (e) {
          // Skip malformed cookies
          console.error("Error parsing cookie:", e);
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
      securityScore: scoreData.score,
      contentType,
      cookies,
      requestSummary: {
        method: 'GET',
        url: options.url,
        redirects: (response as any).request?._redirectable?._redirectCount || 0,
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

/**
 * Calculates a weighted security score based on present and missing headers
 * Gives more weight to critical security headers
 */
function calculateSecurityScore(
  presentHeaders: SecurityHeader[], 
  missingHeaders: SecurityHeader[]
): { score: number; details: string } {
  // Define weights based on importance
  const weights = {
    'critical': 5,
    'high': 3,
    'medium': 2,
    'low': 1
  };
  
  let totalPoints = 0;
  let earnedPoints = 0;
  let details = "";
  
  // Calculate points for present headers
  for (const header of presentHeaders) {
    const headerName = header.name;
    const metadata = SECURITY_HEADERS[headerName];
    
    if (!metadata) continue;
    
    const headerWeight = weights[metadata.importance] || 1;
    totalPoints += headerWeight;
    
    // If status is good, add full points
    if (header.status === 'good') {
      earnedPoints += headerWeight;
    } 
    // If warning, add half points
    else if (header.status === 'warning') {
      earnedPoints += headerWeight / 2;
    }
    // No points for 'bad' status
  }
  
  // Subtract points for missing critical/high headers
  for (const header of missingHeaders) {
    const headerName = header.name;
    const metadata = SECURITY_HEADERS[headerName];
    
    if (!metadata) continue;
    
    const headerWeight = weights[metadata.importance] || 1;
    totalPoints += headerWeight;
    
    // Missing headers earn no points, already accounted for above
  }
  
  // Calculate percentage
  const score = totalPoints > 0 ? Math.round((earnedPoints / totalPoints) * 100) : 0;
  
  // Create score details
  details = `Earned ${earnedPoints} out of ${totalPoints} possible points`;
  
  return { score, details };
}

/**
 * Attempts to detect technology stack from HTTP headers
 */
function detectTechnologyFromHeaders(headers: Record<string, string>): string | undefined {
  const techPatterns: Array<{pattern: RegExp; name: string}> = [
    // Web servers
    { pattern: /Apache/i, name: 'Apache' },
    { pattern: /nginx/i, name: 'Nginx' },
    { pattern: /IIS/i, name: 'Microsoft IIS' },
    { pattern: /LiteSpeed/i, name: 'LiteSpeed' },
    
    // Programming languages/frameworks
    { pattern: /PHP/i, name: 'PHP' },
    { pattern: /ASP\.NET/i, name: 'ASP.NET' },
    { pattern: /Express/i, name: 'Express.js' },
    { pattern: /Rails/i, name: 'Ruby on Rails' },
    { pattern: /Django/i, name: 'Django' },
    { pattern: /Laravel/i, name: 'Laravel' },
    { pattern: /Spring/i, name: 'Spring' },
    
    // CMS and platforms
    { pattern: /WordPress/i, name: 'WordPress' },
    { pattern: /Drupal/i, name: 'Drupal' },
    { pattern: /Joomla/i, name: 'Joomla' },
    { pattern: /Shopify/i, name: 'Shopify' },
    { pattern: /Magento/i, name: 'Magento' },
    { pattern: /Ghost/i, name: 'Ghost' },
  ];
  
  // Check server header
  if (headers['server']) {
    for (const tech of techPatterns) {
      if (tech.pattern.test(headers['server'])) {
        return tech.name;
      }
    }
  }
  
  // Check powered by header
  if (headers['x-powered-by']) {
    for (const tech of techPatterns) {
      if (tech.pattern.test(headers['x-powered-by'])) {
        return tech.name;
      }
    }
  }
  
  // Check all headers for technology clues
  for (const [headerName, headerValue] of Object.entries(headers)) {
    for (const tech of techPatterns) {
      if (tech.pattern.test(headerValue)) {
        return tech.name;
      }
    }
  }
  
  return undefined;
}