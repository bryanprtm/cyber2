import axios from 'axios';

export interface UrlScannerOptions {
  url: string;
  checkPhishing?: boolean;
  checkMalware?: boolean;
  checkReputation?: boolean;
  timeout?: number;
  userAgent?: string;
}

export interface UrlScanResult {
  url: string;
  normalizedUrl: string;
  scanTime: number;
  status: {
    code: number;
    text: string;
  };
  ipAddress?: string;
  isSecure: boolean;
  protocol: string;
  redirects: Array<{
    url: string;
    statusCode: number;
  }>;
  securityRating: {
    overall: 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown';
    score: number; // 0-100
    reasons: string[];
  };
  phishingDetection?: {
    isPhishing: boolean;
    confidence: number; // 0-100
    indicators: string[];
    targetBrand?: string;
  };
  malwareDetection?: {
    hasMalware: boolean;
    confidence: number; // 0-100
    detectionType?: string[];
    virusNames?: string[];
  };
  reputationInfo?: {
    score: number; // 0-100
    categories: string[];
    firstSeen?: string;
    lastUpdated?: string;
    source: string;
  };
  contentAnalysis: {
    title?: string;
    description?: string;
    hasLogin: boolean;
    hasDownloads: boolean;
    hasExternalScripts: boolean;
    externalDomains: string[];
    technologies: string[];
    screenshots?: string[];
  };
  riskFactors: Array<{
    type: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    description: string;
  }>;
}

/**
 * Scan a URL for phishing, malware, reputation issues
 * @param options URL scanner options
 * @returns URL scan results
 */
export async function scanUrl(options: UrlScannerOptions): Promise<UrlScanResult> {
  const { 
    url, 
    checkPhishing = true, 
    checkMalware = true, 
    checkReputation = true,
    timeout = 30000,
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Normalize URL (ensure it has protocol)
  const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
  
  // Simulating actual scan since we don't have access to real URL scanning services
  // In a real implementation, this would use proper security APIs and services
  try {
    // Make HTTP request to the URL with error handling
    let response;
    try {
      response = await axios.get(normalizedUrl, {
        timeout,
        maxRedirects: 5,
        validateStatus: () => true, // Allow any status code
        headers: {
          'User-Agent': userAgent
        }
      });
    } catch (err) {
      // If failed to get the URL, create simulated response
      console.log(`Error fetching URL: ${normalizedUrl}`, err.message);
      response = {
        status: err.response?.status || 0,
        statusText: err.message || 'Failed to fetch URL',
        headers: {},
        data: '',
        request: { _redirectable: { _redirects: [] } }
      };
    }
    
    // Extract base information
    const protocol = new URL(normalizedUrl).protocol;
    const isSecure = protocol === 'https:';
    const statusCode = response.status;
    const statusText = response.statusText;
    
    // Collect redirect chain
    const redirects = response.request._redirectable 
      ? response.request._redirectable._redirects.map((r: any) => ({
          url: r.url,
          statusCode: r.statusCode
        }))
      : [];
    
    // Extract IP address from response (simulated)
    const ipAddress = '192.0.2.' + Math.floor(Math.random() * 255);
    
    // Base result object
    const result: UrlScanResult = {
      url,
      normalizedUrl,
      scanTime: 0, // Will update at the end
      status: {
        code: statusCode,
        text: statusText
      },
      ipAddress,
      isSecure,
      protocol,
      redirects,
      securityRating: {
        overall: 'Unknown',
        score: 0,
        reasons: []
      },
      contentAnalysis: {
        title: extractTitle(response.data),
        description: extractMetaDescription(response.data),
        hasLogin: checkForLoginForm(response.data),
        hasDownloads: checkForDownloads(response.data),
        hasExternalScripts: checkForExternalScripts(response.data),
        externalDomains: extractExternalDomains(response.data, normalizedUrl),
        technologies: detectTechnologies(response.data, response.headers)
      },
      riskFactors: []
    };
    
    // Security rating calculation (simplified example)
    const securityIssues: string[] = [];
    let securityScore = 100; // Start with perfect score
    
    // Basic security checks
    if (!isSecure) {
      securityIssues.push('Uses insecure HTTP protocol');
      securityScore -= 30;
      result.riskFactors.push({
        type: 'Insecure Protocol',
        severity: 'High',
        description: 'The website uses unencrypted HTTP instead of HTTPS'
      });
    }
    
    // Redirect checks
    if (redirects.length > 3) {
      securityIssues.push('Multiple redirects detected');
      securityScore -= 10;
      result.riskFactors.push({
        type: 'Excessive Redirects',
        severity: 'Low',
        description: `${redirects.length} redirects before reaching final destination`
      });
    }
    
    // Login form without HTTPS
    if (result.contentAnalysis.hasLogin && !isSecure) {
      securityIssues.push('Login form on non-HTTPS page');
      securityScore -= 35;
      result.riskFactors.push({
        type: 'Insecure Login',
        severity: 'Critical',
        description: 'Login form detected on a page without HTTPS encryption'
      });
    }
    
    // External script risks
    if (result.contentAnalysis.hasExternalScripts) {
      securityIssues.push('Uses external scripts');
      securityScore -= 5;
      result.riskFactors.push({
        type: 'External Scripts',
        severity: 'Low',
        description: 'Website loads scripts from external domains which could pose a security risk'
      });
    }
    
    // Check for phishing indicators if requested
    if (checkPhishing) {
      try {
        const phishingResult = simulatePhishingCheck(response.data, normalizedUrl);
        result.phishingDetection = phishingResult;
        
        if (phishingResult && phishingResult.isPhishing) {
          securityIssues.push('Phishing indicators detected');
          securityScore -= 60;
          result.riskFactors.push({
            type: 'Potential Phishing',
            severity: 'Critical',
            description: `Site contains indicators of phishing targeting ${phishingResult.targetBrand || 'users'}`
          });
        }
      } catch (error) {
        console.error("Error in phishing check:", error);
        result.phishingDetection = {
          isPhishing: false,
          confidence: 0,
          indicators: ["Error performing phishing check"]
        };
      }
    }
    
    // Check for malware indicators if requested
    if (checkMalware) {
      try {
        const malwareResult = simulateMalwareCheck(response.data);
        result.malwareDetection = malwareResult;
        
        if (malwareResult && malwareResult.hasMalware) {
          securityIssues.push('Malware indicators detected');
          securityScore -= 80;
          result.riskFactors.push({
            type: 'Potential Malware',
            severity: 'Critical',
            description: 'Site contains patterns associated with malware distribution'
          });
        }
      } catch (error) {
        console.error("Error in malware check:", error);
        result.malwareDetection = {
          hasMalware: false,
          confidence: 0,
          detectionType: ["Error performing malware check"]
        };
      }
    }
    
    // Check reputation if requested
    if (checkReputation) {
      try {
        const reputationResult = simulateReputationCheck(normalizedUrl);
        result.reputationInfo = reputationResult;
        
        if (reputationResult && reputationResult.score < 40) {
          securityIssues.push('Poor site reputation');
          securityScore -= 30;
          result.riskFactors.push({
            type: 'Poor Reputation',
            severity: 'High',
            description: 'Site has a concerning reputation score based on historical data'
          });
        }
      } catch (error) {
        console.error("Error in reputation check:", error);
        result.reputationInfo = {
          score: 50,
          categories: ["Unknown"],
          source: "Error checking reputation"
        };
      }
    }
    
    // Finalize security rating
    result.securityRating.score = Math.max(0, securityScore);
    result.securityRating.reasons = securityIssues;
    
    // Determine overall rating based on score
    if (securityScore >= 80) {
      result.securityRating.overall = 'Safe';
    } else if (securityScore >= 50) {
      result.securityRating.overall = 'Suspicious';
    } else {
      result.securityRating.overall = 'Malicious';
    }
    
    // Update scan time
    result.scanTime = Date.now() - startTime;
    
    return result;
  } catch (error: any) {
    // Create error result
    const errorResult: UrlScanResult = {
      url,
      normalizedUrl,
      scanTime: Date.now() - startTime,
      status: {
        code: error.response?.status || 0,
        text: error.message || 'Unknown error'
      },
      isSecure: normalizedUrl.startsWith('https:'),
      protocol: new URL(normalizedUrl).protocol,
      redirects: [],
      securityRating: {
        overall: 'Unknown',
        score: 0,
        reasons: ['Unable to scan URL: ' + error.message]
      },
      contentAnalysis: {
        hasLogin: false,
        hasDownloads: false,
        hasExternalScripts: false,
        externalDomains: [],
        technologies: []
      },
      riskFactors: [{
        type: 'Scan Error',
        severity: 'Medium',
        description: `Error scanning URL: ${error.message}`
      }]
    };
    
    return errorResult;
  }
}

// Helper functions 

/**
 * Extract page title from HTML content
 */
function extractTitle(html: string): string | undefined {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return titleMatch ? titleMatch[1].trim() : undefined;
}

/**
 * Extract meta description from HTML content
 */
function extractMetaDescription(html: string): string | undefined {
  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["'][^>]*>/i) ||
                   html.match(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["'][^>]*>/i);
  return descMatch ? descMatch[1].trim() : undefined;
}

/**
 * Check if page contains login forms
 */
function checkForLoginForm(html: string): boolean {
  return /type=["']password["']|input[^>]+password/i.test(html) ||
         /<form[^>]*>(?:[^<]|<(?!\/form>))*password(?:[^<]|<(?!\/form>))*<\/form>/i.test(html) ||
         /login|sign in|signin|log in|authenticate/i.test(html);
}

/**
 * Check if page contains download links
 */
function checkForDownloads(html: string): boolean {
  return /href=["'][^"']*\.(?:exe|zip|rar|dll|msi|dmg|apk|app)/i.test(html) ||
         /download|get[\s-]file|get[\s-]app/i.test(html);
}

/**
 * Check if page loads scripts from external domains
 */
function checkForExternalScripts(html: string): boolean {
  return /<script[^>]*src=["']https?:\/\/(?!www\.google|cdn)/i.test(html);
}

/**
 * Extract external domains referenced in HTML content
 */
function extractExternalDomains(html: string, currentUrl: string): string[] {
  const currentDomain = new URL(currentUrl).hostname;
  const domainRegex = /https?:\/\/([^\/\s"']+)/g;
  const domains = new Set<string>();
  
  let match;
  while ((match = domainRegex.exec(html)) !== null) {
    const domain = match[1];
    if (domain !== currentDomain && !domain.includes('cdn') && !domain.includes('google')) {
      domains.add(domain);
    }
  }
  
  return Array.from(domains).slice(0, 10); // Limit to first 10 domains
}

/**
 * Detect technologies used on the website
 */
function detectTechnologies(html: string, headers: any): string[] {
  const technologies: string[] = [];
  
  // Check for common frameworks and technologies
  if (html.includes('jQuery')) technologies.push('jQuery');
  if (html.includes('bootstrap')) technologies.push('Bootstrap');
  if (html.includes('react')) technologies.push('React');
  if (html.includes('angular')) technologies.push('Angular');
  if (html.includes('vue')) technologies.push('Vue.js');
  if (headers['x-powered-by']?.includes('PHP')) technologies.push('PHP');
  if (headers['x-powered-by']?.includes('ASP.NET')) technologies.push('ASP.NET');
  if (headers['server']?.includes('nginx')) technologies.push('Nginx');
  if (headers['server']?.includes('Apache')) technologies.push('Apache');
  if (html.includes('wp-content')) technologies.push('WordPress');
  if (html.includes('Shopify')) technologies.push('Shopify');
  if (html.includes('Drupal')) technologies.push('Drupal');
  
  return technologies;
}

/**
 * Simulate phishing detection 
 * Note: This is a simplified simulation for demonstration purposes only
 */
function simulatePhishingCheck(html: string, url: string): UrlScanResult['phishingDetection'] {
  const phishingIndicators: string[] = [];
  let phishingScore = 0;
  let targetBrand: string | undefined;
  
  // Check for common phishing indicators
  if (/<form[^>]*>(?:[^<]|<(?!\/form>))*password(?:[^<]|<(?!\/form>))*<\/form>/i.test(html)) {
    phishingIndicators.push('Contains login form');
    phishingScore += 10;
  }
  
  // Check for mismatched domain and content
  const lowerHtml = html.toLowerCase();
  const domain = new URL(url).hostname.toLowerCase();
  
  const brandChecks = [
    { brand: 'paypal', keywords: ['paypal', 'payment', 'account', 'secure'] },
    { brand: 'apple', keywords: ['apple', 'icloud', 'itunes', 'apple id'] },
    { brand: 'microsoft', keywords: ['microsoft', 'office365', 'outlook', 'onedrive'] },
    { brand: 'amazon', keywords: ['amazon', 'aws', 'prime'] },
    { brand: 'facebook', keywords: ['facebook', 'fb', 'messenger'] },
    { brand: 'google', keywords: ['google', 'gmail', 'drive'] },
    { brand: 'bank', keywords: ['bank', 'credit union', 'checking', 'savings', 'account'] }
  ];
  
  for (const { brand, keywords } of brandChecks) {
    const keywordMatches = keywords.filter(k => lowerHtml.includes(k)).length;
    if (keywordMatches >= 2 && !domain.includes(brand)) {
      phishingIndicators.push(`Content mentions ${brand} but domain doesn't match`);
      phishingScore += 40;
      targetBrand = brand;
      break;
    }
  }
  
  // Check for suspicious URL characteristics
  if (url.includes('login') && url.includes('redirect')) {
    phishingIndicators.push('Suspicious URL pattern with login and redirect');
    phishingScore += 20;
  }
  
  if (url.includes('@') || url.includes('%')) {
    phishingIndicators.push('URL contains suspicious characters (@, %)');
    phishingScore += 30;
  }
  
  // Check for data collection forms on non-HTTPS
  if (url.startsWith('http:') && /<form[^>]*>/i.test(html)) {
    phishingIndicators.push('Data collection form on non-HTTPS site');
    phishingScore += 25;
  }
  
  // Check for domain typosquatting (simplified)
  const typoTargets = ['paypal', 'microsoft', 'apple', 'google', 'facebook', 'amazon', 'gmail'];
  for (const target of typoTargets) {
    if (domain.includes(target) && domain !== target + '.com') {
      phishingIndicators.push(`Possible typosquatting of ${target}.com`);
      phishingScore += 35;
      targetBrand = target;
    }
  }
  
  // Final determination
  return {
    isPhishing: phishingScore >= 50,
    confidence: phishingScore,
    indicators: phishingIndicators,
    targetBrand
  };
}

/**
 * Simulate malware detection
 * Note: This is a simplified simulation for demonstration purposes only
 */
function simulateMalwareCheck(html: string): UrlScanResult['malwareDetection'] {
  const malwareIndicators: string[] = [];
  let malwareScore = 0;
  
  // Check for suspicious script patterns
  if (/eval\(atob\(|eval\(decode|String\.fromCharCode/i.test(html)) {
    malwareIndicators.push('Obfuscated JavaScript code');
    malwareScore += 50;
  }
  
  if (/document\.cookie|localStorage|sessionStorage/.test(html) && 
      /new Image\(\)\.src=|fetch\(/.test(html)) {
    malwareIndicators.push('Potential data exfiltration code');
    malwareScore += 40;
  }
  
  if (/iframe[^>]*opacity:\s*0|iframe[^>]*display:\s*none|iframe[^>]*height:\s*0|iframe[^>]*width:\s*0/i.test(html)) {
    malwareIndicators.push('Hidden iframe detected');
    malwareScore += 60;
  }
  
  // Check for drive-by download scripts
  if (/ActiveXObject|ShockwaveFlash|\.jar|\.class/i.test(html)) {
    malwareIndicators.push('Potentially vulnerable plugin content');
    malwareScore += 30;
  }
  
  // Check for redirector scripts
  if (/window\.location\s*=|location\.href\s*=|document\.location\s*=/.test(html)) {
    malwareIndicators.push('Page redirect script');
    malwareScore += 20;
  }
  
  // Check for malvertising patterns
  if (/pop\s*under|popunder|pop\s*up|popupunder|click\s*under/i.test(html)) {
    malwareIndicators.push('Potential malvertising scripts');
    malwareScore += 35;
  }
  
  return {
    hasMalware: malwareScore >= 60,
    confidence: malwareScore,
    detectionType: malwareIndicators.length > 0 ? ['Suspicious script patterns'] : undefined,
    virusNames: malwareScore >= 60 ? ['Simulated.JS.Malicious'] : undefined
  };
}

/**
 * Simulate website reputation check
 * Note: This is a simplified simulation for demonstration purposes only
 */
function simulateReputationCheck(url: string): UrlScanResult['reputationInfo'] {
  const domain = new URL(url).hostname;
  let reputationScore = 80; // Default good score
  const categories: string[] = [];
  
  // Simulate reputation checks
  if (domain.length > 30) {
    reputationScore -= 20;
    categories.push('Unusually long domain');
  }
  
  if (domain.includes('free') || domain.includes('download')) {
    reputationScore -= 15;
    categories.push('Download site');
  }
  
  if (domain.includes('news') || domain.includes('blog')) {
    categories.push('News/Blog');
  }
  
  if (domain.includes('shop') || domain.includes('store')) {
    categories.push('E-commerce');
  }
  
  // Random reputation adjustment (for demo variety)
  const randomAdjust = Math.floor(Math.random() * 40) - 20; // -20 to +20
  reputationScore = Math.max(0, Math.min(100, reputationScore + randomAdjust));
  
  // Random age of site
  const daysAgo = Math.floor(Math.random() * 1000);
  const firstSeen = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
  const lastUpdated = new Date(Date.now() - Math.floor(Math.random() * 30) * 24 * 60 * 60 * 1000).toISOString();
  
  return {
    score: reputationScore,
    categories,
    firstSeen,
    lastUpdated,
    source: 'Security Operation Center Simulation'
  };
}