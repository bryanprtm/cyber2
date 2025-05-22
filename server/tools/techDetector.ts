import axios from 'axios';
import cheerio from 'cheerio';
import { analyze } from 'wappalyzer-core';

export interface TechDetectorOptions {
  url: string;
  timeout?: number;
  userAgent?: string;
  checkScripts?: boolean;
  deepScan?: boolean;
}

export interface TechnologyResult {
  name: string;
  categories: string[];
  confidence: number;
  website?: string;
  icon?: string;
  version?: string;
}

export interface TechDetectorResult {
  url: string;
  technologies: TechnologyResult[];
  frameworks: TechnologyResult[];
  cms: TechnologyResult[];
  serverInfo: {
    server?: string;
    poweredBy?: string;
    language?: string;
  };
  jsLibraries: TechnologyResult[];
  analytics: TechnologyResult[];
  headers: Record<string, string>;
  cookies: any[];
  metaTags: Record<string, string>;
  scanTime: number;
}

// Technology categories
const CATEGORY_MAPPING: Record<string, string> = {
  '1': 'CMS',
  '2': 'Message Boards',
  '3': 'Database Managers',
  '4': 'Documentation Tools',
  '5': 'Widgets',
  '6': 'Web Shops',
  '7': 'Photo Galleries',
  '8': 'Analytics',
  '9': 'Hosting Panels',
  '10': 'Aggregators',
  '11': 'JavaScript Frameworks',
  '12': 'Video Players',
  '13': 'Comment Systems',
  '14': 'Security',
  '15': 'Font Scripts',
  '16': 'Web Frameworks',
  '17': 'Miscellaneous',
  '18': 'Editors',
  '19': 'LMS',
  '20': 'Web Servers',
  '21': 'Cache Tools',
  '22': 'Rich Text Editors',
  '23': 'JavaScript Graphics',
  '24': 'Mobile Frameworks',
  '25': 'Programming Languages',
  '26': 'Operating Systems',
  '27': 'Search Engines',
  '28': 'Web Mail',
  '29': 'CDN',
  '30': 'Marketing Automation',
  '31': 'Web Server Extensions',
  '32': 'Databases',
  '33': 'Maps',
  '34': 'Advertising',
  '35': 'Network Devices',
  '36': 'Media Servers',
  '37': 'Webcams',
  '38': 'Printers',
  '39': 'Payment Processors',
  '40': 'Tag Managers',
  '41': 'Paywalls',
  '42': 'Build CI Systems',
  '43': 'Control Systems',
  '44': 'Remote Access',
  '45': 'Development',
  '46': 'Network Storage',
  '47': 'Feed Readers',
  '48': 'Document Management Systems',
  '49': 'Landing Page Builders',
  '50': 'Live Chat',
  '51': 'CRM',
  '52': 'SEO',
  '53': 'Accounting',
  '54': 'Cryptominers',
  '55': 'Static Site Generator',
  '56': 'User Onboarding',
  '57': 'JavaScript Libraries',
  '58': 'Containers',
  '59': 'SaaS',
  '60': 'PaaS',
  '61': 'IaaS',
  '62': 'Reverse Proxies',
  '63': 'Load Balancers',
  '64': 'UI Frameworks',
  '65': 'Cookie Compliance',
  '66': 'Accessibility',
  '67': 'Authentication',
  '68': 'SVG',
  '69': 'Reservations & Booking',
  '70': 'Surveys',
  '71': 'Ecommerce',
  '72': 'Social Media',
  '73': 'Email Services',
  '74': 'A/B Testing',
};

/**
 * Detect technologies used on a website
 * @param options Technology detector options
 * @returns Detected technologies and other website information
 */
export async function detectTechnologies(options: TechDetectorOptions): Promise<TechDetectorResult> {
  const startTime = Date.now();
  
  try {
    // Configure axios request options
    const axiosOptions: any = {
      timeout: options.timeout || 15000,
      maxRedirects: 3,
      headers: {
        'User-Agent': options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      },
      validateStatus: (status: number) => status >= 200 && status < 400
    };
    
    // Make the HTTP request
    const response = await axios.get(options.url, axiosOptions);
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
        const [name, value] = parts[0].split('=').map(s => s.trim());
        cookies.push({ name, value });
      });
    }
    
    // Extract meta tags
    const metaTags: Record<string, string> = {};
    $('meta').each((_, element) => {
      const name = $(element).attr('name') || $(element).attr('property');
      const content = $(element).attr('content');
      
      if (name && content) {
        metaTags[name] = content;
      }
    });
    
    // Extract scripts for deeper analysis if requested
    let scripts: string[] = [];
    if (options.checkScripts) {
      $('script').each((_, element) => {
        const src = $(element).attr('src');
        if (src) {
          scripts.push(src);
        }
      });
    }
    
    // Get server information
    const serverInfo = {
      server: headers['server'],
      poweredBy: headers['x-powered-by'],
      language: detectServerLanguage(headers, metaTags)
    };
    
    // Prepare data for Wappalyzer analysis
    const url = new URL(options.url);
    const wappalyzerData = {
      url: options.url,
      html,
      headers,
      scriptSrc: scripts,
      cookies: cookies.reduce((acc, cookie) => {
        acc[cookie.name] = cookie.value;
        return acc;
      }, {} as Record<string, string>),
      meta: metaTags
    };
    
    // Use Wappalyzer to analyze the site
    const wappalyzerResults = analyze(wappalyzerData);
    
    // Process and categorize the results
    const allTechnologies: TechnologyResult[] = Object.entries(wappalyzerResults).map(([name, data]) => {
      const categories = data.categories.map(catId => CATEGORY_MAPPING[String(catId)] || `Category ${catId}`);
      
      return {
        name,
        categories,
        confidence: data.confidence,
        version: data.version,
        website: data.website,
        icon: data.icon
      };
    });
    
    // Sort technologies by confidence
    allTechnologies.sort((a, b) => b.confidence - a.confidence);
    
    // Filter technologies into specific categories
    const frameworks = allTechnologies.filter(tech => 
      tech.categories.some(cat => 
        cat === 'Web Frameworks' || 
        cat === 'JavaScript Frameworks' || 
        cat === 'Mobile Frameworks' ||
        cat === 'UI Frameworks'
      )
    );
    
    const cms = allTechnologies.filter(tech => 
      tech.categories.some(cat => cat === 'CMS')
    );
    
    const jsLibraries = allTechnologies.filter(tech => 
      tech.categories.some(cat => cat === 'JavaScript Libraries')
    );
    
    const analytics = allTechnologies.filter(tech => 
      tech.categories.some(cat => cat === 'Analytics')
    );
    
    const endTime = Date.now();
    
    // Return the structured result
    return {
      url: options.url,
      technologies: allTechnologies,
      frameworks,
      cms,
      serverInfo,
      jsLibraries,
      analytics,
      headers,
      cookies,
      metaTags,
      scanTime: endTime - startTime
    };
  } catch (error) {
    console.error('Technology detection error:', error);
    throw new Error(`Technology detection failed: ${(error as Error).message}`);
  }
}

/**
 * Try to detect server programming language from headers and meta tags
 */
function detectServerLanguage(headers: Record<string, string>, metaTags: Record<string, string>): string | undefined {
  // Check common server headers
  if (headers['x-powered-by']) {
    const poweredBy = headers['x-powered-by'].toLowerCase();
    
    if (poweredBy.includes('php')) return 'PHP';
    if (poweredBy.includes('asp.net')) return 'ASP.NET';
    if (poweredBy.includes('nodejs')) return 'Node.js';
    if (poweredBy.includes('ruby')) return 'Ruby';
    if (poweredBy.includes('python')) return 'Python';
    if (poweredBy.includes('java')) return 'Java';
  }
  
  // Check for framework-specific headers
  if (headers['x-rails-version']) return 'Ruby (Rails)';
  if (headers['x-django-version']) return 'Python (Django)';
  if (headers['x-aspnet-version']) return 'ASP.NET';
  if (headers['x-drupal-cache']) return 'PHP (Drupal)';
  if (headers['x-generator'] && headers['x-generator'].toLowerCase().includes('wordpress')) return 'PHP (WordPress)';
  
  // Check meta generator tag
  if (metaTags['generator']) {
    const generator = metaTags['generator'].toLowerCase();
    
    if (generator.includes('wordpress')) return 'PHP (WordPress)';
    if (generator.includes('drupal')) return 'PHP (Drupal)';
    if (generator.includes('joomla')) return 'PHP (Joomla)';
    if (generator.includes('ghost')) return 'Node.js (Ghost)';
    if (generator.includes('django')) return 'Python (Django)';
    if (generator.includes('ruby on rails')) return 'Ruby (Rails)';
  }
  
  return undefined;
}