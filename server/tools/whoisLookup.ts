import { promisify } from 'util';
import whois from 'whois';
import { parsers } from 'whoisjs';

// Promisify the whois lookup function
const whoisLookup = promisify(whois.lookup);

export interface WhoisOptions {
  domain: string;
  followIcannReferral?: boolean;
  server?: string;
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
    street?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
    phone?: string;
    email?: string;
  };
  admin?: {
    organization?: string;
    name?: string;
    email?: string;
  };
  tech?: {
    organization?: string;
    name?: string;
    email?: string;
  };
  nameServers?: string[];
  dnssec?: string;
  status?: string[];
  raw: string;
  parsedData: any;
}

/**
 * Perform a WHOIS lookup on a domain name
 * @param options WHOIS lookup options
 * @returns WhoisResult object containing parsed domain information
 */
export async function lookupDomain(options: WhoisOptions): Promise<WhoisResult> {
  try {
    // Set up whois lookup options
    const whoisOptions: any = {};
    if (options.server) whoisOptions.server = options.server;
    if (options.followIcannReferral !== undefined) whoisOptions.follow = options.followIcannReferral;
    if (options.timeout) whoisOptions.timeout = options.timeout;
    
    // Normalize domain name (remove protocol and path)
    let domain = options.domain.trim().toLowerCase();
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.replace(/^www\./, '');
    domain = domain.split('/')[0];
    
    // Perform the whois lookup
    const rawData = await whoisLookup(domain, whoisOptions);
    
    // Try to parse the raw data
    const parser = parsers.getParser(domain);
    let parsedData = null;
    
    try {
      if (parser) {
        parsedData = parser.parse(rawData);
      }
    } catch (parseError) {
      console.error('Error parsing WHOIS data:', parseError);
      // Continue with rawData even if parsing failed
    }
    
    // Construct standardized result object
    const result: WhoisResult = {
      raw: rawData,
      parsedData: parsedData
    };
    
    // Extract common fields if parsing was successful
    if (parsedData) {
      // Domain info
      result.domainName = parsedData.domainName || 
                       parsedData.domain_name || 
                       parsedData.domain || 
                       domain;
      
      result.registrar = parsedData.registrar || 
                      parsedData.sponsoring_registrar;
      
      result.registrarWhoisServer = parsedData.registrar_whois_server ||
                                 parsedData.whois_server;
      
      result.registrarUrl = parsedData.registrar_url;
      
      // Dates
      result.creationDate = parsedData.creation_date || 
                         parsedData.created || 
                         parsedData.created_date;
      
      result.updatedDate = parsedData.updated_date ||
                        parsedData.last_updated;
      
      result.registryExpiryDate = parsedData.registry_expiry_date ||
                               parsedData.expiration_date || 
                               parsedData.expires;
      
      // Name servers
      if (parsedData.name_servers || parsedData.nameservers) {
        result.nameServers = parsedData.name_servers || parsedData.nameservers;
        // Normalize name servers to array
        if (typeof result.nameServers === 'string') {
          result.nameServers = [result.nameServers];
        }
      }
      
      // Status
      if (parsedData.status) {
        if (Array.isArray(parsedData.status)) {
          result.status = parsedData.status;
        } else if (typeof parsedData.status === 'string') {
          result.status = parsedData.status.split(',').map((s: string) => s.trim());
        }
      }
      
      // Registrant info
      if (parsedData.registrant || parsedData.owner) {
        const registrantData = parsedData.registrant || parsedData.owner;
        result.registrant = {
          organization: registrantData.organization || registrantData.org,
          name: registrantData.name,
          street: registrantData.street || registrantData.address,
          city: registrantData.city,
          state: registrantData.state || registrantData.province,
          postalCode: registrantData.postal_code || registrantData.postalcode,
          country: registrantData.country,
          phone: registrantData.phone || registrantData.telephone,
          email: registrantData.email
        };
      }
      
      // Admin info
      if (parsedData.admin || parsedData.administrative_contact) {
        const adminData = parsedData.admin || parsedData.administrative_contact;
        result.admin = {
          organization: adminData.organization || adminData.org,
          name: adminData.name,
          email: adminData.email
        };
      }
      
      // Tech info
      if (parsedData.tech || parsedData.technical_contact) {
        const techData = parsedData.tech || parsedData.technical_contact;
        result.tech = {
          organization: techData.organization || techData.org,
          name: techData.name,
          email: techData.email
        };
      }
      
      // DNSSEC
      result.dnssec = parsedData.dnssec;
    }
    
    return result;
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    throw new Error(`WHOIS lookup failed: ${(error as Error).message}`);
  }
}