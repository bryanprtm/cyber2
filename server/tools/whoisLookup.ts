import axios from 'axios';
import { exec } from 'child_process';
import { promisify } from 'util';

// Convert exec to Promise-based
const execPromise = promisify(exec);

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
  const { domain, timeout = 10000 } = options;
  
  if (!domain) {
    throw new Error('Domain is required');
  }
  
  // Normalize the domain (remove protocol, www, etc.)
  const normalizedDomain = normalizeDomain(domain);
  
  try {
    // Execute the whois command
    const { stdout } = await execPromise(`whois ${normalizedDomain}`, {
      timeout: timeout
    });
    
    if (!stdout) {
      throw new Error('No WHOIS data returned');
    }
    
    // Parse the raw data into structured format
    const result = parseWhoisData(stdout, normalizedDomain);
    
    return {
      ...result,
      raw: stdout
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
function parseWhoisData(rawData: string, domain: string): Partial<WhoisResult> {
  const result: Partial<WhoisResult> = {
    domainName: domain,
    nameServers: [],
    status: []
  };
  
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
  const nsRegex = /(?:name server|nameserver|nserver)s?:?\s+([^\s\r\n]+)/gi;
  let match;
  const nameServers = [];
  
  while ((match = nsRegex.exec(rawData)) !== null) {
    nameServers.push(match[1].toLowerCase());
  }
  
  // Remove duplicates
  result.nameServers = [...new Set(nameServers)];
  
  // Status
  const statusRegex = /(?:domain )?status:?\s+([^\r\n]+)/gi;
  const statuses = [];
  
  while ((match = statusRegex.exec(rawData)) !== null) {
    statuses.push(match[1].trim());
  }
  
  // Remove duplicates
  result.status = [...new Set(statuses)];
  
  return result;
}