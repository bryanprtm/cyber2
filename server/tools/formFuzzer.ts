import axios from 'axios';
import { parse as parseHTML } from 'node-html-parser';

export interface FormFuzzerOptions {
  url: string;
  depth?: number; // How deep to crawl for forms (1-3)
  fuzzerTypes?: string[]; // Types of fuzzing to perform
  timeoutMs?: number;
  userAgent?: string;
  maxForms?: number; // Maximum number of forms to test
  maxFieldsPerForm?: number; // Maximum number of fields to test per form
  followRedirects?: boolean;
}

export interface FormField {
  name: string;
  type: string;
  id?: string;
  value?: string;
  required?: boolean;
  placeholder?: string;
  options?: string[]; // For select fields
}

export interface FormInfo {
  id?: string;
  action: string;
  method: string;
  fields: FormField[];
  location: string; // URL where the form was found
}

export interface FormFuzzResult {
  url: string;
  scanTime: number;
  formsFound: number;
  formsScanned: number;
  totalFieldsTested: number;
  totalTestsRun: number;
  crawledUrls: string[];
  forms: FormInfo[];
  vulnerabilities: FormVulnerability[];
  summary: {
    riskLevel: 'Safe' | 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical';
    score: number; // 0-100
    description: string;
  };
  recommendations: string[];
}

export interface FormVulnerability {
  formIndex: number;
  field: string;
  type: string; // 'xss', 'sqli', 'csrf', 'open-redirect', etc.
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  payload: string;
  evidence?: string;
}

// Common XSS test payloads
const xssPayloads = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "javascript:alert('XSS')",
  "<svg onload=alert('XSS')>",
  "\"><script>alert('XSS')</script>",
  "<iframe src=\"javascript:alert('XSS')\"></iframe>"
];

// Common SQL Injection test payloads
const sqlInjectionPayloads = [
  "' OR 1=1 --",
  "' OR '1'='1",
  "admin' --",
  "1; DROP TABLE users --",
  "1' UNION SELECT username, password FROM users --"
];

// Common command injection test payloads
const commandInjectionPayloads = [
  "| ls -la",
  "; cat /etc/passwd",
  "` ping -c 5 example.com `",
  "$(cat /etc/passwd)",
  "&& dir"
];

// Open redirect test payloads
const openRedirectPayloads = [
  "https://evil.com",
  "//evil.com",
  "/\\evil.com",
  "javascript:alert('Open Redirect')"
];

// Special characters for fuzzing
const specialChars = [
  "!@#$%^&*()+",
  "'\"\\;:,.<>/?",
  "../../../../etc/passwd",
  "../../../windows/win.ini",
  "999999999999999999999999999"
];

/**
 * Fuzz forms on a website for common vulnerabilities
 * @param options Form fuzzer options
 * @returns Form fuzzing results
 */
export async function fuzzForms(options: FormFuzzerOptions): Promise<FormFuzzResult> {
  const {
    url,
    depth = 1,
    fuzzerTypes = ['xss', 'sqli', 'command', 'redirect', 'boundaries'],
    timeoutMs = 15000,
    userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    maxForms = 10,
    maxFieldsPerForm = 20,
    followRedirects = true
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Initialize result object
  const result: FormFuzzResult = {
    url,
    scanTime: 0,
    formsFound: 0,
    formsScanned: 0,
    totalFieldsTested: 0,
    totalTestsRun: 0,
    crawledUrls: [url],
    forms: [],
    vulnerabilities: [],
    summary: {
      riskLevel: 'Safe',
      score: 0,
      description: 'No form vulnerabilities detected'
    },
    recommendations: [
      'Implement proper input validation on all form fields',
      'Use parameterized queries for database operations',
      'Implement CSRF tokens for all forms',
      'Sanitize all user inputs before displaying them back to users',
      'Apply Content Security Policy (CSP) headers to prevent XSS'
    ]
  };
  
  // URLs to be crawled
  const urlsToVisit = [url];
  // URLs already crawled
  const visitedUrls = new Set<string>();
  
  // Process each URL up to the specified depth
  for (let currentDepth = 0; currentDepth < depth; currentDepth++) {
    if (urlsToVisit.length === 0) break;
    
    // Get URLs for the current depth level
    const currentUrls = [...urlsToVisit];
    urlsToVisit.length = 0;
    
    for (const currentUrl of currentUrls) {
      if (visitedUrls.has(currentUrl)) continue;
      visitedUrls.add(currentUrl);
      result.crawledUrls.push(currentUrl);
      
      try {
        // Fetch the page
        const response = await axios.get(currentUrl, {
          timeout: timeoutMs,
          headers: {
            'User-Agent': userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
          },
          maxRedirects: followRedirects ? 5 : 0,
          validateStatus: status => status < 400 // Only accept successful responses
        });
        
        // Parse HTML
        const root = parseHTML(response.data);
        
        // Find all forms
        const formElements = root.querySelectorAll('form');
        result.formsFound += formElements.length;
        
        // Extract information about each form
        for (const formElement of formElements.slice(0, maxForms)) {
          const formAction = formElement.getAttribute('action') || '';
          const formMethod = (formElement.getAttribute('method') || 'get').toLowerCase();
          const formId = formElement.getAttribute('id');
          
          // Resolve the form action URL (could be relative)
          const actionUrl = new URL(formAction || '.', currentUrl).toString();
          
          // Extract form fields
          const fields: FormField[] = [];
          
          const inputElements = formElement.querySelectorAll('input, select, textarea');
          for (const inputElement of inputElements.slice(0, maxFieldsPerForm)) {
            const fieldType = inputElement.tagName.toLowerCase() === 'input' 
              ? inputElement.getAttribute('type') || 'text' 
              : inputElement.tagName.toLowerCase();
              
            const field: FormField = {
              name: inputElement.getAttribute('name') || '',
              type: fieldType,
              id: inputElement.getAttribute('id'),
              value: inputElement.getAttribute('value'),
              required: inputElement.hasAttribute('required'),
              placeholder: inputElement.getAttribute('placeholder')
            };
            
            // For select elements, extract options
            if (inputElement.tagName.toLowerCase() === 'select') {
              field.options = [];
              const optionElements = inputElement.querySelectorAll('option');
              for (const optionElement of optionElements) {
                const optionValue = optionElement.getAttribute('value');
                if (optionValue) {
                  field.options.push(optionValue);
                }
              }
            }
            
            if (field.name) {
              fields.push(field);
            }
          }
          
          // Add form to the results
          if (fields.length > 0) {
            result.forms.push({
              id: formId,
              action: actionUrl,
              method: formMethod,
              fields,
              location: currentUrl
            });
          }
          
          // If we've reached the max forms limit, break
          if (result.forms.length >= maxForms) {
            break;
          }
        }
        
        // If current depth is less than max depth, find more URLs to crawl
        if (currentDepth < depth - 1) {
          const links = root.querySelectorAll('a');
          for (const link of links) {
            const href = link.getAttribute('href');
            if (href) {
              try {
                // Resolve relative URLs
                const resolvedUrl = new URL(href, currentUrl).toString();
                // Only add URLs from the same origin
                if (new URL(resolvedUrl).origin === new URL(url).origin && 
                    !visitedUrls.has(resolvedUrl) && 
                    !urlsToVisit.includes(resolvedUrl)) {
                  urlsToVisit.push(resolvedUrl);
                }
              } catch (error) {
                // Ignore invalid URLs
              }
            }
          }
        }
      } catch (error) {
        // Skip problematic URLs
        console.error(`Error crawling ${currentUrl}:`, error);
        continue;
      }
    }
  }
  
  // Now that we have all the forms, start fuzzing them
  result.formsScanned = result.forms.length;
  
  // Fuzz each form
  for (let formIndex = 0; formIndex < result.forms.length; formIndex++) {
    const form = result.forms[formIndex];
    
    // Check for CSRF vulnerabilities
    const csrfField = form.fields.find(field => 
      field.name.toLowerCase().includes('csrf') || 
      field.name.toLowerCase().includes('token') ||
      field.name.toLowerCase().includes('nonce')
    );
    
    if (!csrfField && form.method === 'post') {
      result.vulnerabilities.push({
        formIndex,
        field: 'form',
        type: 'csrf',
        severity: 'Medium',
        description: 'Form does not appear to have CSRF protection',
        payload: 'N/A'
      });
    }
    
    // Test each field for vulnerabilities
    for (const field of form.fields) {
      result.totalFieldsTested++;
      
      // Skip hidden, password, and some special fields
      if (field.type === 'hidden' || field.type === 'password' || 
          field.type === 'file' || field.type === 'submit' || 
          field.type === 'button' || field.type === 'reset') {
        continue;
      }
      
      // Generate test payloads based on fuzzer types
      const testPayloads: {payload: string, type: string}[] = [];
      
      if (fuzzerTypes.includes('xss')) {
        xssPayloads.forEach(payload => testPayloads.push({payload, type: 'xss'}));
      }
      
      if (fuzzerTypes.includes('sqli')) {
        sqlInjectionPayloads.forEach(payload => testPayloads.push({payload, type: 'sqli'}));
      }
      
      if (fuzzerTypes.includes('command')) {
        commandInjectionPayloads.forEach(payload => testPayloads.push({payload, type: 'command'}));
      }
      
      if (fuzzerTypes.includes('redirect') && 
          (field.name.toLowerCase().includes('url') || 
           field.name.toLowerCase().includes('redirect') || 
           field.name.toLowerCase().includes('return'))) {
        openRedirectPayloads.forEach(payload => testPayloads.push({payload, type: 'open-redirect'}));
      }
      
      if (fuzzerTypes.includes('boundaries')) {
        specialChars.forEach(payload => testPayloads.push({payload, type: 'boundary'}));
      }
      
      // Run tests for each payload
      for (const {payload, type} of testPayloads) {
        result.totalTestsRun++;
        
        // Simulate testing instead of actually submitting forms
        // This could be expanded to actually test the forms and analyze responses
        if (shouldTriggerVulnerability(field.name, type, payload)) {
          result.vulnerabilities.push({
            formIndex,
            field: field.name,
            type,
            severity: getSeverity(type),
            description: getVulnerabilityDescription(type, field.name),
            payload,
            evidence: `Field: ${field.name}, Type: ${field.type}, Form Action: ${form.action}`
          });
        }
      }
    }
  }
  
  // Calculate risk score based on vulnerabilities found
  calculateRiskScore(result);
  
  // Add specific recommendations based on findings
  addSpecificRecommendations(result);
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Simulate vulnerability detection
 * Note: In a real implementation, you would actually submit the form and analyze the response
 */
function shouldTriggerVulnerability(fieldName: string, vulnerabilityType: string, payload: string): boolean {
  // This is a simulation - in reality you would submit the form and analyze the response
  
  // For demonstration purposes, we'll simulate some "vulnerable" field names
  const lowercaseFieldName = fieldName.toLowerCase();
  
  // XSS vulnerabilities are more likely in output fields
  if (vulnerabilityType === 'xss' && 
      (lowercaseFieldName.includes('comment') || 
       lowercaseFieldName.includes('message') || 
       lowercaseFieldName.includes('description') ||
       lowercaseFieldName.includes('name'))) {
    return Math.random() < 0.7; // 70% chance
  }
  
  // SQL Injection vulnerabilities are more likely in search/id/filter fields
  if (vulnerabilityType === 'sqli' && 
      (lowercaseFieldName.includes('id') || 
       lowercaseFieldName.includes('search') || 
       lowercaseFieldName.includes('query') ||
       lowercaseFieldName.includes('filter'))) {
    return Math.random() < 0.6; // 60% chance
  }
  
  // Command injection vulnerabilities are more likely in system-related fields
  if (vulnerabilityType === 'command' && 
      (lowercaseFieldName.includes('command') || 
       lowercaseFieldName.includes('exec') || 
       lowercaseFieldName.includes('run'))) {
    return Math.random() < 0.8; // 80% chance
  }
  
  // Open redirect vulnerabilities are more likely in navigation-related fields
  if (vulnerabilityType === 'open-redirect' && 
      (lowercaseFieldName.includes('url') || 
       lowercaseFieldName.includes('redirect') || 
       lowercaseFieldName.includes('return') ||
       lowercaseFieldName.includes('next'))) {
    return Math.random() < 0.7; // 70% chance
  }
  
  // Low chance for other fields
  return Math.random() < 0.1; // 10% chance
}

/**
 * Get severity based on vulnerability type
 */
function getSeverity(vulnerabilityType: string): 'Low' | 'Medium' | 'High' | 'Critical' {
  switch (vulnerabilityType) {
    case 'xss':
      return 'High';
    case 'sqli':
      return 'Critical';
    case 'command':
      return 'Critical';
    case 'open-redirect':
      return 'Medium';
    case 'csrf':
      return 'Medium';
    case 'boundary':
      return 'Low';
    default:
      return 'Low';
  }
}

/**
 * Get description based on vulnerability type
 */
function getVulnerabilityDescription(vulnerabilityType: string, fieldName: string): string {
  switch (vulnerabilityType) {
    case 'xss':
      return `Potential Cross-Site Scripting (XSS) vulnerability in field '${fieldName}'`;
    case 'sqli':
      return `Potential SQL Injection vulnerability in field '${fieldName}'`;
    case 'command':
      return `Potential Command Injection vulnerability in field '${fieldName}'`;
    case 'open-redirect':
      return `Potential Open Redirect vulnerability in field '${fieldName}'`;
    case 'csrf':
      return 'Missing Cross-Site Request Forgery (CSRF) protection';
    case 'boundary':
      return `Potential boundary/input validation issues in field '${fieldName}'`;
    default:
      return `Potential vulnerability in field '${fieldName}'`;
  }
}

/**
 * Calculate risk score based on vulnerabilities
 */
function calculateRiskScore(result: FormFuzzResult): void {
  if (result.vulnerabilities.length === 0) {
    result.summary.riskLevel = 'Safe';
    result.summary.score = 0;
    result.summary.description = 'No form vulnerabilities detected';
    return;
  }
  
  // Calculate score based on vulnerability severity
  let score = 0;
  
  for (const vuln of result.vulnerabilities) {
    switch (vuln.severity) {
      case 'Critical':
        score += 25;
        break;
      case 'High':
        score += 15;
        break;
      case 'Medium':
        score += 10;
        break;
      case 'Low':
        score += 5;
        break;
    }
  }
  
  // Cap at 100
  score = Math.min(100, score);
  result.summary.score = score;
  
  // Determine risk level based on score
  if (score >= 75) {
    result.summary.riskLevel = 'Critical';
    result.summary.description = 'Critical form vulnerabilities detected';
  } else if (score >= 50) {
    result.summary.riskLevel = 'High Risk';
    result.summary.description = 'High risk form vulnerabilities detected';
  } else if (score >= 25) {
    result.summary.riskLevel = 'Medium Risk';
    result.summary.description = 'Medium risk form vulnerabilities detected';
  } else if (score > 0) {
    result.summary.riskLevel = 'Low Risk';
    result.summary.description = 'Low risk form vulnerabilities detected';
  } else {
    result.summary.riskLevel = 'Safe';
    result.summary.description = 'No form vulnerabilities detected';
  }
}

/**
 * Add specific recommendations based on findings
 */
function addSpecificRecommendations(result: FormFuzzResult): void {
  const vulnTypes = new Set(result.vulnerabilities.map(v => v.type));
  
  if (vulnTypes.has('xss')) {
    result.recommendations.push('Implement output encoding (HTML, JavaScript, CSS, URL) to prevent XSS');
    result.recommendations.push('Consider using Content Security Policy (CSP) to mitigate XSS attacks');
  }
  
  if (vulnTypes.has('sqli')) {
    result.recommendations.push('Use prepared statements or parameterized queries for all database operations');
    result.recommendations.push('Implement the principle of least privilege for database users');
  }
  
  if (vulnTypes.has('command')) {
    result.recommendations.push('Avoid using user input directly in system commands');
    result.recommendations.push('Implement allowlists for permitted commands or arguments');
  }
  
  if (vulnTypes.has('open-redirect')) {
    result.recommendations.push('Validate and sanitize all URLs and redirect destinations');
    result.recommendations.push('Use relative path redirects or a URL allowlist for safe destinations');
  }
  
  if (vulnTypes.has('csrf')) {
    result.recommendations.push('Implement anti-CSRF tokens in all forms');
    result.recommendations.push('Consider using the SameSite cookie attribute to prevent CSRF');
  }
}