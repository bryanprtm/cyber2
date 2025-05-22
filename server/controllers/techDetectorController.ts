import { Request, Response } from 'express';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle technology detection requests via the API
 */
// Technology patterns to detect
const techPatterns = {
  frameworks: [
    { name: 'React', pattern: /react|reactjs/i, categories: ['JavaScript Framework'], website: 'https://reactjs.org' },
    { name: 'Angular', pattern: /angular|ng-/i, categories: ['JavaScript Framework'], website: 'https://angular.io' },
    { name: 'Vue.js', pattern: /vue|vuejs/i, categories: ['JavaScript Framework'], website: 'https://vuejs.org' },
    { name: 'jQuery', pattern: /jquery/i, categories: ['JavaScript Library'], website: 'https://jquery.com' },
    { name: 'Bootstrap', pattern: /bootstrap/i, categories: ['CSS Framework'], website: 'https://getbootstrap.com' },
    { name: 'Tailwind CSS', pattern: /tailwind/i, categories: ['CSS Framework'], website: 'https://tailwindcss.com' },
    { name: 'Express.js', pattern: /express/i, categories: ['Web Framework'], website: 'https://expressjs.com' },
    { name: 'Next.js', pattern: /next-js|nextjs|__next/i, categories: ['JavaScript Framework'], website: 'https://nextjs.org' },
  ],
  cms: [
    { name: 'WordPress', pattern: /wordpress|wp-content|wp-includes/i, categories: ['CMS'], website: 'https://wordpress.org' },
    { name: 'Drupal', pattern: /drupal/i, categories: ['CMS'], website: 'https://www.drupal.org' },
    { name: 'Joomla', pattern: /joomla/i, categories: ['CMS'], website: 'https://www.joomla.org' },
    { name: 'Shopify', pattern: /shopify/i, categories: ['CMS', 'E-commerce'], website: 'https://www.shopify.com' },
  ],
  analytics: [
    { name: 'Google Analytics', pattern: /google-analytics|googletagmanager|gtag|ga\(/i, categories: ['Analytics'], website: 'https://analytics.google.com' },
    { name: 'Google Tag Manager', pattern: /googletagmanager|gtm/i, categories: ['Tag Manager'], website: 'https://tagmanager.google.com' },
    { name: 'Facebook Pixel', pattern: /facebook-pixel|fbevents|fbq\(/i, categories: ['Analytics'], website: 'https://www.facebook.com/business/tools/meta-pixel' },
  ],
  jsLibraries: [
    { name: 'Lodash', pattern: /lodash|_\./i, categories: ['JavaScript Library'], website: 'https://lodash.com' },
    { name: 'Moment.js', pattern: /moment\.js|moment\(/i, categories: ['JavaScript Library'], website: 'https://momentjs.com' },
    { name: 'Axios', pattern: /axios/i, categories: ['HTTP Client'], website: 'https://axios-http.com' },
    { name: 'Redux', pattern: /redux/i, categories: ['State Management'], website: 'https://redux.js.org' },
  ]
};

/**
 * Detect technologies by category
 */
function detectTechnologiesByCategory(
  category: keyof typeof techPatterns,
  html: string,
  $: cheerio.CheerioAPI,
  headers: Record<string, string>
): any[] {
  const results: any[] = [];
  const patterns = techPatterns[category];
  
  // Check for patterns in HTML
  for (const tech of patterns) {
    let confidence = 0;
    
    // Check HTML content
    if (tech.pattern.test(html)) {
      confidence += 60;
    }
    
    // Check script sources
    if ($(`script[src*="${tech.name.toLowerCase()}"]`).length > 0) {
      confidence += 80;
    }
    
    // Check inline script content
    let inlineScriptMatches = 0;
    $('script').each(function(_, element) {
      const content = $(element).html();
      if (content && tech.pattern.test(content)) {
        inlineScriptMatches++;
      }
    });
    
    if (inlineScriptMatches > 0) {
      confidence += Math.min(inlineScriptMatches * 10, 70);
    }
    
    // Check CSS links
    if ($(`link[href*="${tech.name.toLowerCase()}"]`).length > 0) {
      confidence += 70;
    }
    
    // Add to results if confidence is high enough
    if (confidence > 40) {
      results.push({
        name: tech.name,
        categories: tech.categories,
        confidence: Math.min(confidence, 100),
        website: tech.website
      });
    }
  }
  
  return results;
}

/**
 * Detect server-side language
 */
function detectServerLanguage(headers: Record<string, string>, html: string): string | undefined {
  // Check headers for language clues
  if (headers['x-powered-by']) {
    if (/php/i.test(headers['x-powered-by'])) return 'PHP';
    if (/asp\.net/i.test(headers['x-powered-by'])) return 'ASP.NET';
    if (/express/i.test(headers['x-powered-by'])) return 'Node.js (Express)';
  }
  
  // Check for HTML clues
  if (/wp-content|wp-includes/i.test(html)) return 'PHP (WordPress)';
  if (/drupal/i.test(html)) return 'PHP (Drupal)';
  
  return undefined;
}

export async function handleTechDetection(req: Request, res: Response) {
  try {
    const { url, timeout, userAgent } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting tech detection for: ${url}`);
    
    const startTime = Date.now();
    
    // Configure axios request options
    const axiosOptions: any = {
      timeout: timeout || 15000,
      maxRedirects: 3,
      headers: {
        'User-Agent': userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      },
      validateStatus: (status: number) => status >= 200 && status < 400
    };
    
    // Make the HTTP request
    const response = await axios.get(url, axiosOptions);
    const html = response.data;
    
    // Parse HTML with Cheerio
    const $ = cheerio.load(html);
    
    // Extract headers
    const headers: Record<string, string> = {};
    Object.entries(response.headers).forEach(([key, value]) => {
      headers[key] = typeof value === 'string' ? value : String(value);
    });
    
    // Extract cookies
    const cookies: any[] = [];
    if (response.headers['set-cookie']) {
      const cookieArray = Array.isArray(response.headers['set-cookie']) 
        ? response.headers['set-cookie'] 
        : [response.headers['set-cookie']];
      
      cookieArray.forEach(cookieStr => {
        const parts = cookieStr.split(';');
        const mainPart = parts[0].split('=');
        const cookie: any = {
          name: mainPart[0],
          value: mainPart[1],
          secure: cookieStr.includes('secure'),
          httpOnly: cookieStr.includes('HttpOnly')
        };
        cookies.push(cookie);
      });
    }
    
    // Extract meta tags
    const metaTags: Record<string, string> = {};
    $('meta').each(function(_, element) {
      const name = $(element).attr('name') || $(element).attr('property');
      const content = $(element).attr('content');
      
      if (name && content) {
        metaTags[name] = content;
      }
    });
    
    // Detect all technologies
    const jsLibraries = detectTechnologiesByCategory('jsLibraries', html, $, headers);
    const frameworks = detectTechnologiesByCategory('frameworks', html, $, headers);
    const cms = detectTechnologiesByCategory('cms', html, $, headers);
    const analytics = detectTechnologiesByCategory('analytics', html, $, headers);
    
    // Get server info
    const serverInfo = {
      server: headers['server'],
      poweredBy: headers['x-powered-by'],
      language: detectServerLanguage(headers, html)
    };
    
    // Create a list of all technologies
    const technologies = [
      ...jsLibraries,
      ...frameworks,
      ...cms,
      ...analytics
    ].filter((tech, index, self) => 
      index === self.findIndex(t => t.name === tech.name)
    );
    
    const result = {
      url: url,
      technologies,
      frameworks,
      cms,
      serverInfo,
      jsLibraries,
      analytics,
      headers,
      cookies,
      metaTags,
      scanTime: Date.now() - startTime
    };
    
    // Store scan result in the database if user is logged in
    const userId = 1; // Default for demo purposes
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'tech-detector',
        target: url,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] Tech detection scan saved with ID: ${savedScan.id}`);
      
      // Add scanId to result
      result['scanId'] = savedScan.id;
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('Tech detection error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Tech detection failed'
    });
  }
}