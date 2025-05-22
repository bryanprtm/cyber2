import axios from 'axios';
import whois from 'whois';
import { parsers } from 'whoisjs';
import { promisify } from 'util';

// Convert callback-based whois.lookup to Promise-based
const lookupPromise = promisify(whois.lookup);

export interface WhoisOptions {
  domain: string;
  followIcannReferral?: boolean;
  timeout?: number;
}

export interface WhoisResult {
  domainName?: string;
  registrar?: string;
  registrarWhoisServer?: string;
  registrarUrl?: string;
  updatedDate?: string;
  creationDate?: string;
  registryExpiryDate?: string;
  registrant?: {
    organization?: string;
    name?: string;
    email?: string;
    country?: string;
  };
  admin?: {
    name?: string;
    email?: string;
  };
  tech?: {
    name?: string;
    email?: string;
  };
  nameServers?: string[];
  status?: string[];
  raw: string;
}

/**
 * Perform a WHOIS lookup for a domain
 * @param options WhoisOptions containing domain and other parameters
 * @returns WhoisResult with formatted domain information
 */
export async function lookupDomain(options: WhoisOptions): Promise<WhoisResult> {
  const { domain, followIcannReferral = true, timeout = 10000 } = options;
  
  if (!domain) {
    throw new Error('Domain is required');
  }
  
  // Normalize the domain (remove protocol, www, etc.)
  const normalizedDomain = normalizeDomain(domain);
  
  try {
    // Perform the WHOIS lookup
    const lookupOptions = {
      follow: followIcannReferral ? 3 : 0, // Follow referral servers up to 3 times if enabled
      timeout: timeout / 1000, // Convert to seconds
    };
    
    const rawData = await lookupPromise(normalizedDomain, lookupOptions);
    
    if (!rawData) {
      throw new Error('No WHOIS data returned');
    }
    
    // Parse the raw WHOIS data
    const parsedData = parseWhoisData(normalizedDomain, rawData);
    
    return {
      ...parsedData,
      raw: rawData
    };
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    throw new Error(`WHOIS lookup failed: ${(error as Error).message}`);
  }
}

/**
 * Normalize a domain name by removing protocols, www, and trailing slashes
 */
function normalizeDomain(domain: string): string {
  let normalizedDomain = domain;
  
  // Remove protocol (http://, https://)
  normalizedDomain = normalizedDomain.replace(/^https?:\/\//i, '');
  
  // Remove www.
  normalizedDomain = normalizedDomain.replace(/^www\./i, '');
  
  // Remove everything after the first slash
  normalizedDomain = normalizedDomain.split('/')[0];
  
  // Remove port numbers if present
  normalizedDomain = normalizedDomain.split(':')[0];
  
  return normalizedDomain.trim().toLowerCase();
}

/**
 * Parse raw WHOIS data into a structured format
 */
function parseWhoisData(domain: string, rawData: string): Partial<WhoisResult> {
  try {
    // Attempt to use the whoisjs parser for structured data
    const parser = parsers.getParser(domain);
    
    if (parser) {
      const parsedData = parser.parse(rawData);
      
      // Map the parsed data to our WhoisResult structure
      return {
        domainName: findValue(parsedData, ['domainName', 'domain', 'domain_name']),
        registrar: findValue(parsedData, ['registrar', 'registrar_name']),
        registrarWhoisServer: findValue(parsedData, ['registrarWhoisServer', 'whois_server']),
        registrarUrl: findValue(parsedData, ['registrarUrl', 'registrar_url']),
        updatedDate: findValue(parsedData, ['updatedDate', 'updated_date']),
        creationDate: findValue(parsedData, ['creationDate', 'creation_date', 'created_date']),
        registryExpiryDate: findValue(parsedData, ['registryExpiryDate', 'expiration_date', 'expires']),
        registrant: {
          organization: findValue(parsedData, ['registrantOrganization', 'registrant_organization']),
          name: findValue(parsedData, ['registrantName', 'registrant_name']),
          email: findValue(parsedData, ['registrantEmail', 'registrant_email']),
          country: findValue(parsedData, ['registrantCountry', 'registrant_country']),
        },
        admin: {
          name: findValue(parsedData, ['adminName', 'admin_name']),
          email: findValue(parsedData, ['adminEmail', 'admin_email']),
        },
        tech: {
          name: findValue(parsedData, ['techName', 'tech_name']),
          email: findValue(parsedData, ['techEmail', 'tech_email']),
        },
        nameServers: extractNameServers(parsedData, rawData),
        status: extractDomainStatus(parsedData, rawData),
      };
    }
    
    // Fall back to regex-based extraction if parser fails
    return extractWithRegex(rawData);
  } catch (error) {
    console.error('Error parsing WHOIS data:', error);
    return fallbackExtraction(rawData);
  }
}

/**
 * Find a value in the parsed data using multiple possible keys
 */
function findValue(data: any, keys: string[]): string | undefined {
  if (!data) return undefined;
  
  for (const key of keys) {
    if (data[key]) {
      return data[key];
    }
  }
  
  return undefined;
}

/**
 * Extract name servers from parsed data or raw data
 */
function extractNameServers(parsedData: any, rawData: string): string[] {
  // Try to get from parsed data first
  if (parsedData && parsedData.nameServers && Array.isArray(parsedData.nameServers)) {
    return parsedData.nameServers;
  }
  
  if (parsedData && parsedData.name_servers && Array.isArray(parsedData.name_servers)) {
    return parsedData.name_servers;
  }
  
  // Fall back to regex extraction
  const nsRegex = /(?:name server|nameserver|nserver)s?:?\s+([^\s]+)/gi;
  const matches = [...rawData.matchAll(nsRegex)];
  const nameServers = matches.map(match => match[1].toLowerCase()).filter(Boolean);
  
  // Remove duplicates
  return [...new Set(nameServers)];
}

/**
 * Extract domain status from parsed data or raw data
 */
function extractDomainStatus(parsedData: any, rawData: string): string[] {
  // Try to get from parsed data first
  if (parsedData && parsedData.status && Array.isArray(parsedData.status)) {
    return parsedData.status;
  }
  
  if (parsedData && parsedData.domain_status && Array.isArray(parsedData.domain_status)) {
    return parsedData.domain_status;
  }
  
  // Fall back to regex extraction
  const statusRegex = /(?:domain )?status:?\s+([^\r\n]+)/gi;
  const matches = [...rawData.matchAll(statusRegex)];
  const statuses = matches.map(match => match[1].trim()).filter(Boolean);
  
  // Remove duplicates
  return [...new Set(statuses)];
}

/**
 * Extract WHOIS data using regex patterns when parser fails
 */
function extractWithRegex(rawData: string): Partial<WhoisResult> {
  const result: Partial<WhoisResult> = {};
  
  // Domain name
  const domainMatch = rawData.match(/(?:domain name|domain):\s*([^\r\n]+)/i);
  if (domainMatch) result.domainName = domainMatch[1].trim();
  
  // Registrar
  const registrarMatch = rawData.match(/registrar:\s*([^\r\n]+)/i);
  if (registrarMatch) result.registrar = registrarMatch[1].trim();
  
  // Registrar URL
  const registrarUrlMatch = rawData.match(/registrar url:\s*([^\r\n]+)/i);
  if (registrarUrlMatch) result.registrarUrl = registrarUrlMatch[1].trim();
  
  // Registrar WHOIS Server
  const whoisServerMatch = rawData.match(/whois server:\s*([^\r\n]+)/i);
  if (whoisServerMatch) result.registrarWhoisServer = whoisServerMatch[1].trim();
  
  // Dates
  const updatedDateMatch = rawData.match(/updated date:\s*([^\r\n]+)/i);
  if (updatedDateMatch) result.updatedDate = updatedDateMatch[1].trim();
  
  const creationDateMatch = rawData.match(/(?:creation date|created on|registration date):\s*([^\r\n]+)/i);
  if (creationDateMatch) result.creationDate = creationDateMatch[1].trim();
  
  const expiryDateMatch = rawData.match(/(?:registry expiry date|expiration date|expires on):\s*([^\r\n]+)/i);
  if (expiryDateMatch) result.registryExpiryDate = expiryDateMatch[1].trim();
  
  // Registrant info
  result.registrant = {};
  
  const registrantOrgMatch = rawData.match(/(?:registrant organization|registrant):\s*([^\r\n]+)/i);
  if (registrantOrgMatch) result.registrant.organization = registrantOrgMatch[1].trim();
  
  const registrantNameMatch = rawData.match(/registrant name:\s*([^\r\n]+)/i);
  if (registrantNameMatch) result.registrant.name = registrantNameMatch[1].trim();
  
  const registrantEmailMatch = rawData.match(/registrant email:\s*([^\r\n]+)/i);
  if (registrantEmailMatch) result.registrant.email = registrantEmailMatch[1].trim();
  
  const registrantCountryMatch = rawData.match(/registrant country:\s*([^\r\n]+)/i);
  if (registrantCountryMatch) result.registrant.country = registrantCountryMatch[1].trim();
  
  // Admin info
  result.admin = {};
  
  const adminNameMatch = rawData.match(/admin name:\s*([^\r\n]+)/i);
  if (adminNameMatch) result.admin.name = adminNameMatch[1].trim();
  
  const adminEmailMatch = rawData.match(/admin email:\s*([^\r\n]+)/i);
  if (adminEmailMatch) result.admin.email = adminEmailMatch[1].trim();
  
  // Tech info
  result.tech = {};
  
  const techNameMatch = rawData.match(/tech name:\s*([^\r\n]+)/i);
  if (techNameMatch) result.tech.name = techNameMatch[1].trim();
  
  const techEmailMatch = rawData.match(/tech email:\s*([^\r\n]+)/i);
  if (techEmailMatch) result.tech.email = techEmailMatch[1].trim();
  
  // Name servers
  result.nameServers = extractNameServers({}, rawData);
  
  // Status
  result.status = extractDomainStatus({}, rawData);
  
  return result;
}

/**
 * Last resort extraction method for when all else fails
 */
function fallbackExtraction(rawData: string): Partial<WhoisResult> {
  return {
    // At minimum, we parse the name servers and status
    nameServers: extractNameServers({}, rawData),
    status: extractDomainStatus({}, rawData),
  };
}