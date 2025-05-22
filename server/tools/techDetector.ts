import axios from 'axios';
import * as cheerio from 'cheerio';

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
    { name: 'Laravel', pattern: /laravel/i, categories: ['Web Framework'], website: 'https://laravel.com' },
    { name: 'Ruby on Rails', pattern: /rails/i, categories: ['Web Framework'], website: 'https://rubyonrails.org' },
    { name: 'Django', pattern: /django/i, categories: ['Web Framework'], website: 'https://www.djangoproject.com' },
    { name: 'Flask', pattern: /flask/i, categories: ['Web Framework'], website: 'https://flask.palletsprojects.com' },
    { name: 'Next.js', pattern: /next-js|nextjs|__next/i, categories: ['JavaScript Framework'], website: 'https://nextjs.org' },
    { name: 'Gatsby', pattern: /gatsby/i, categories: ['Static Site Generator'], website: 'https://www.gatsbyjs.com' },
    { name: 'Svelte', pattern: /svelte/i, categories: ['JavaScript Framework'], website: 'https://svelte.dev' },
    { name: 'Nuxt.js', pattern: /nuxt|__nuxt/i, categories: ['JavaScript Framework'], website: 'https://nuxtjs.org' },
  ],
  cms: [
    { name: 'WordPress', pattern: /wordpress|wp-content|wp-includes/i, categories: ['CMS'], website: 'https://wordpress.org' },
    { name: 'Drupal', pattern: /drupal/i, categories: ['CMS'], website: 'https://www.drupal.org' },
    { name: 'Joomla', pattern: /joomla/i, categories: ['CMS'], website: 'https://www.joomla.org' },
    { name: 'Magento', pattern: /magento/i, categories: ['CMS', 'E-commerce'], website: 'https://magento.com' },
    { name: 'Shopify', pattern: /shopify/i, categories: ['CMS', 'E-commerce'], website: 'https://www.shopify.com' },
    { name: 'Squarespace', pattern: /squarespace/i, categories: ['CMS'], website: 'https://www.squarespace.com' },
    { name: 'Wix', pattern: /wix/i, categories: ['CMS'], website: 'https://www.wix.com' },
    { name: 'Ghost', pattern: /ghost/i, categories: ['CMS'], website: 'https://ghost.org' },
    { name: 'Contentful', pattern: /contentful/i, categories: ['Headless CMS'], website: 'https://www.contentful.com' },
    { name: 'Strapi', pattern: /strapi/i, categories: ['Headless CMS'], website: 'https://strapi.io' },
  ],
  analytics: [
    { name: 'Google Analytics', pattern: /google-analytics|googletagmanager|gtag|ga\(/i, categories: ['Analytics'], website: 'https://analytics.google.com' },
    { name: 'Google Tag Manager', pattern: /googletagmanager|gtm/i, categories: ['Tag Manager'], website: 'https://tagmanager.google.com' },
    { name: 'Hotjar', pattern: /hotjar/i, categories: ['Analytics'], website: 'https://www.hotjar.com' },
    { name: 'Matomo', pattern: /matomo|piwik/i, categories: ['Analytics'], website: 'https://matomo.org' },
    { name: 'Mixpanel', pattern: /mixpanel/i, categories: ['Analytics'], website: 'https://mixpanel.com' },
    { name: 'Segment', pattern: /segment/i, categories: ['Analytics'], website: 'https://segment.com' },
    { name: 'Facebook Pixel', pattern: /facebook-pixel|fbevents|fbq\(/i, categories: ['Analytics'], website: 'https://www.facebook.com/business/tools/meta-pixel' },
  ],
  jsLibraries: [
    { name: 'Lodash', pattern: /lodash|_\./i, categories: ['JavaScript Library'], website: 'https://lodash.com' },
    { name: 'Moment.js', pattern: /moment\.js|moment\(/i, categories: ['JavaScript Library'], website: 'https://momentjs.com' },
    { name: 'D3.js', pattern: /d3\.js|d3-/i, categories: ['Visualization'], website: 'https://d3js.org' },
    { name: 'Chart.js', pattern: /chart\.js/i, categories: ['Visualization'], website: 'https://www.chartjs.org' },
    { name: 'THREE.js', pattern: /three\.js/i, categories: ['3D'], website: 'https://threejs.org' },
    { name: 'Axios', pattern: /axios/i, categories: ['HTTP Client'], website: 'https://axios-http.com' },
    { name: 'Socket.io', pattern: /socket\.io/i, categories: ['WebSockets'], website: 'https://socket.io' },
    { name: 'Redux', pattern: /redux/i, categories: ['State Management'], website: 'https://redux.js.org' },
    { name: 'Underscore', pattern: /_\./i, categories: ['JavaScript Library'], website: 'https://underscorejs.org' },
    { name: 'Alpine.js', pattern: /alpine\.js|x-data/i, categories: ['JavaScript Framework'], website: 'https://alpinejs.dev' },
  ],
  servers: [
    { name: 'Apache', pattern: /apache/i, categories: ['Web Server'], website: 'https://httpd.apache.org' },
    { name: 'Nginx', pattern: /nginx/i, categories: ['Web Server'], website: 'https://nginx.org' },
    { name: 'Microsoft IIS', pattern: /iis|microsoft-iis/i, categories: ['Web Server'], website: 'https://www.iis.net' },
    { name: 'Cloudflare', pattern: /cloudflare/i, categories: ['CDN'], website: 'https://www.cloudflare.com' },
    { name: 'Node.js', pattern: /node\.js|express/i, categories: ['Application Server'], website: 'https://nodejs.org' },
    { name: 'Vercel', pattern: /vercel/i, categories: ['Hosting Platform'], website: 'https://vercel.com' },
    { name: 'Netlify', pattern: /netlify/i, categories: ['Hosting Platform'], website: 'https://www.netlify.com' },
    { name: 'LiteSpeed', pattern: /litespeed/i, categories: ['Web Server'], website: 'https://www.litespeedtech.com' },
  ],
  languages: [
    { name: 'PHP', pattern: /php/i, categories: ['Programming Language'], website: 'https://www.php.net' },
    { name: 'ASP.NET', pattern: /asp\.net/i, categories: ['Framework'], website: 'https://dotnet.microsoft.com/apps/aspnet' },
    { name: 'Ruby', pattern: /ruby|rails/i, categories: ['Programming Language'], website: 'https://www.ruby-lang.org' },
    { name: 'Python', pattern: /python|django|flask/i, categories: ['Programming Language'], website: 'https://www.python.org' },
    { name: 'Java', pattern: /java|jsp|servlet/i, categories: ['Programming Language'], website: 'https://www.java.com' },
  ]
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
    
    const result: TechDetectorResult = {
      url: options.url,
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
    
    return result;
  } catch (error) {
    console.error('Technology detection error:', error);
    throw new Error(`Technology detection failed: ${(error as Error).message}`);
  }
}

/**
 * Detect technologies by category
 */
function detectTechnologiesByCategory(
  category: keyof typeof techPatterns,
  html: string,
  $: cheerio.CheerioAPI,
  headers: Record<string, string>
): TechnologyResult[] {
  const results: TechnologyResult[] = [];
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
    
    // Check meta tags
    if ($(`meta[name*="${tech.name.toLowerCase()}"], meta[content*="${tech.name.toLowerCase()}"]`).length > 0) {
      confidence += 90;
    }
    
    // Check headers
    for (const [headerName, headerValue] of Object.entries(headers)) {
      if (tech.pattern.test(headerValue)) {
        confidence += 90;
      }
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
    if (/node/i.test(headers['x-powered-by'])) return 'Node.js';
    if (/rails/i.test(headers['x-powered-by'])) return 'Ruby on Rails';
  }
  
  // Check for HTML clues
  if (/wp-content|wp-includes/i.test(html)) return 'PHP (WordPress)';
  if (/drupal/i.test(html)) return 'PHP (Drupal)';
  if (/joomla/i.test(html)) return 'PHP (Joomla)';
  if (/django/i.test(html)) return 'Python (Django)';
  if (/laravel/i.test(html)) return 'PHP (Laravel)';
  if (/ruby on rails|rails/i.test(html)) return 'Ruby (Rails)';
  if (/\.jsp|javax|java/i.test(html)) return 'Java';
  
  return undefined;
}