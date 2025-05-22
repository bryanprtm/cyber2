import axios from 'axios';
import cheerio from 'cheerio';

export interface EmailHunterOptions {
  url: string;
  maxDepth?: number;
  timeout?: number;
  followLinks?: boolean;
}

export interface EmailHunterResult {
  url: string;
  emailAddresses: string[];
  potentialEmails: string[];
  patternsFound: string[];
  scanTime: number;
  scannedPages: number;
  sources: {
    [url: string]: string[];
  };
}

/**
 * Find email addresses on a website by scanning content
 * @param options Email hunter options
 * @returns Email addresses found on the website
 */
export async function findEmails(options: EmailHunterOptions): Promise<EmailHunterResult> {
  const startTime = Date.now();
  
  const maxDepth = options.maxDepth || 1;
  const timeout = options.timeout || 10000;
  const followLinks = options.followLinks !== false;
  
  // Normalize URL format
  let baseUrl = options.url;
  if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
    baseUrl = `https://${baseUrl}`;
  }
  
  // Extract domain for forming relative URLs
  const urlObj = new URL(baseUrl);
  const domain = urlObj.hostname;
  const baseOrigin = urlObj.origin;
  
  // Track visited URLs to avoid duplicates
  const visitedUrls = new Set<string>();
  const foundEmails = new Set<string>();
  const potentialEmails = new Set<string>();
  const patternsFound = new Set<string>();
  const emailSources: Record<string, string[]> = {};
  
  // Queue for BFS traversal
  const urlQueue: Array<{ url: string; depth: number }> = [
    { url: baseUrl, depth: 0 }
  ];
  
  // Regular expressions for email detection
  const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi;
  const potentialEmailRegex = /([a-zA-Z0-9._-]+\s*[\[\(]at[\]\)]\s*[a-zA-Z0-9._-]+\s*[\[\(]dot[\]\)]\s*[a-zA-Z0-9._-]+)/gi;
  const obfuscatedEmailRegex = /([a-zA-Z0-9._-]+\s*\[\s*at\s*\]\s*[a-zA-Z0-9._-]+\s*\[\s*dot\s*\]\s*[a-zA-Z0-9._-]+)/gi;
  
  // Counter for the number of pages scanned
  let scannedPages = 0;
  
  // BFS traversal of the website
  while (urlQueue.length > 0 && scannedPages < 20) { // Limit to 20 pages max for safety
    const { url, depth } = urlQueue.shift()!;
    
    // Skip if already visited or if depth exceeds maximum
    if (visitedUrls.has(url) || depth > maxDepth) {
      continue;
    }
    
    visitedUrls.add(url);
    scannedPages++;
    
    try {
      const response = await axios.get(url, {
        timeout,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      });
      
      const contentType = response.headers['content-type'] || '';
      
      // Only process HTML content
      if (!contentType.includes('text/html')) {
        continue;
      }
      
      const html = response.data;
      
      // Parse HTML with Cheerio
      const $ = cheerio.load(html);
      
      // Remove script and style elements to avoid false positives
      $('script, style').remove();
      
      // Get text content
      const text = $('body').text();
      
      // Find emails in text content
      const emailMatches = text.match(emailRegex) || [];
      const potentialMatches = text.match(potentialEmailRegex) || [];
      const obfuscatedMatches = text.match(obfuscatedEmailRegex) || [];
      
      // Process the email matches
      emailMatches.forEach(email => {
        email = email.toLowerCase().trim();
        foundEmails.add(email);
        
        if (!emailSources[email]) {
          emailSources[email] = [];
        }
        
        if (!emailSources[email].includes(url)) {
          emailSources[email].push(url);
        }
      });
      
      // Process potential email matches
      [...potentialMatches, ...obfuscatedMatches].forEach(potentialEmail => {
        potentialEmail = potentialEmail.toLowerCase().trim();
        potentialEmails.add(potentialEmail);
        
        // Extract patterns for obfuscation
        if (potentialEmail.includes('at') || potentialEmail.includes('dot')) {
          patternsFound.add('Email obfuscation: replacing @ with "at" and . with "dot"');
        }
      });
      
      // Find emails in mailto: links
      $('a[href^="mailto:"]').each((_, element) => {
        const href = $(element).attr('href') || '';
        const email = href.replace('mailto:', '').split('?')[0].toLowerCase().trim();
        
        if (email && email.includes('@')) {
          foundEmails.add(email);
          
          if (!emailSources[email]) {
            emailSources[email] = [];
          }
          
          if (!emailSources[email].includes(url)) {
            emailSources[email].push(url);
          }
        }
      });
      
      // Find emails in contact and about pages specifically
      if (url.includes('/contact') || url.includes('/about')) {
        const contactEmails = extractEmailsFromContactPage($, url);
        contactEmails.forEach(email => {
          foundEmails.add(email);
          
          if (!emailSources[email]) {
            emailSources[email] = [];
          }
          
          if (!emailSources[email].includes(url)) {
            emailSources[email].push(url);
          }
        });
      }
      
      // Check for JSON-LD structured data
      $('script[type="application/ld+json"]').each((_, element) => {
        try {
          const jsonLdText = $(element).html() || '';
          const jsonLd = JSON.parse(jsonLdText);
          
          // Check for emails in organization data
          if (jsonLd && jsonLd.email) {
            let email = jsonLd.email.toLowerCase().trim();
            foundEmails.add(email);
            
            if (!emailSources[email]) {
              emailSources[email] = [];
            }
            
            if (!emailSources[email].includes(url)) {
              emailSources[email].push(url);
            }
          }
        } catch (e) {
          // Ignore JSON parse errors
        }
      });
      
      // Follow links if enabled and depth allows
      if (followLinks && depth < maxDepth) {
        // Find all links on the page
        $('a[href]').each((_, element) => {
          let href = $(element).attr('href') || '';
          
          // Skip non-http links, anchors, and javascript
          if (href.startsWith('#') || 
              href.startsWith('javascript:') || 
              href.startsWith('tel:') || 
              href.startsWith('mailto:')) {
            return;
          }
          
          // Convert relative URLs to absolute
          if (href.startsWith('/')) {
            href = `${baseOrigin}${href}`;
          } else if (!href.startsWith('http://') && !href.startsWith('https://')) {
            href = `${baseOrigin}/${href}`;
          }
          
          // Only follow links to the same domain
          if (new URL(href).hostname !== domain) {
            return;
          }
          
          // Add to queue if not visited
          if (!visitedUrls.has(href)) {
            urlQueue.push({ url: href, depth: depth + 1 });
          }
        });
      }
    } catch (error) {
      console.error(`Error scanning ${url}:`, error);
      // Continue with next URL
    }
  }
  
  const endTime = Date.now();
  
  // Prepare structured result
  return {
    url: baseUrl,
    emailAddresses: Array.from(foundEmails),
    potentialEmails: Array.from(potentialEmails),
    patternsFound: Array.from(patternsFound),
    scanTime: endTime - startTime,
    scannedPages,
    sources: emailSources
  };
}

/**
 * Extract emails from contact page with special handling for contact forms
 */
function extractEmailsFromContactPage($: cheerio.CheerioAPI, url: string): string[] {
  const foundEmails = new Set<string>();
  
  // Check for contact form fields that might hint at emails
  $('input[type="email"], input[name*="email"], input[id*="email"]').each((_, element) => {
    // Check if there's a placeholder or value
    const placeholder = $(element).attr('placeholder') || '';
    const value = $(element).attr('value') || '';
    
    if (placeholder.includes('@') && placeholder.includes('.')) {
      foundEmails.add(placeholder.toLowerCase().trim());
    }
    
    if (value.includes('@') && value.includes('.')) {
      foundEmails.add(value.toLowerCase().trim());
    }
  });
  
  // Look for email-like patterns near contact labels
  $('label').each((_, element) => {
    const labelText = $(element).text().toLowerCase();
    if (labelText.includes('email') || labelText.includes('e-mail')) {
      // Get the closest input
      const inputId = $(element).attr('for');
      let input;
      
      if (inputId) {
        input = $(`#${inputId}`);
      } else {
        input = $(element).next('input');
      }
      
      if (input.length) {
        const placeholder = input.attr('placeholder') || '';
        const value = input.attr('value') || '';
        
        if (placeholder.includes('@') && placeholder.includes('.')) {
          foundEmails.add(placeholder.toLowerCase().trim());
        }
        
        if (value.includes('@') && value.includes('.')) {
          foundEmails.add(value.toLowerCase().trim());
        }
      }
    }
  });
  
  return Array.from(foundEmails);
}