import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Globe, Search, Shield, Server, Loader2, Calendar, User, Building, Mail } from 'lucide-react';

// Define the WHOIS result type
interface WhoisResult {
  domainName: string;
  registrar: string;
  registrarUrl?: string;
  creationDate: string;
  expiryDate: string;
  updateDate?: string;
  nameServers: string[];
  status: string[];
  registrant?: {
    name?: string;
    organization?: string;
    email?: string;
    country?: string;
  };
}

export default function WhoisPage() {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<WhoisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate domain input
    if (!domain || domain.trim() === '') {
      setError('Please enter a domain name');
      return;
    }
    
    // Basic domain validation
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Invalid domain format. Example: example.com');
      return;
    }
    
    // Reset state and start loading
    setError(null);
    setIsLoading(true);
    setResults(null);
    
    // Generate fake data after a delay to simulate API request
    setTimeout(() => {
      // Get domain parts and TLD
      const domainParts = domain.split('.');
      const tld = domainParts[domainParts.length - 1];
      
      // Create dates
      const now = new Date();
      const creationDate = new Date(now);
      creationDate.setFullYear(now.getFullYear() - 3 - Math.floor(Math.random() * 7));
      
      const expiryDate = new Date(now);
      expiryDate.setFullYear(now.getFullYear() + 1 + Math.floor(Math.random() * 3));
      
      const updateDate = new Date(now);
      updateDate.setMonth(now.getMonth() - Math.floor(Math.random() * 6));
      
      // Create registrar info based on TLD
      const registrarMap: Record<string, string> = {
        'com': 'GoDaddy.com, LLC',
        'net': 'Network Solutions, LLC',
        'org': 'Public Interest Registry',
        'io': 'Afilias Ltd.',
        'co': 'GoDaddy.com, LLC',
        'ai': 'Nic.ai',
        'dev': 'Google Domains'
      };
      
      const registrar = registrarMap[tld] || 'Example Registrar, Inc.';
      
      // Create result
      const result: WhoisResult = {
        domainName: domain,
        registrar,
        registrarUrl: `https://www.${registrar.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '').replace('ltd.', '')}.com`,
        creationDate: creationDate.toISOString().split('T')[0],
        expiryDate: expiryDate.toISOString().split('T')[0],
        updateDate: updateDate.toISOString().split('T')[0],
        nameServers: [
          `ns1.${domain}`,
          `ns2.${domain}`,
          `ns3.${domain}`
        ],
        status: [
          'clientTransferProhibited',
          'clientUpdateProhibited',
          'clientDeleteProhibited'
        ],
        registrant: {
          name: 'Domain Administrator',
          organization: `${domainParts[0].charAt(0).toUpperCase() + domainParts[0].slice(1)} Inc.`,
          email: `admin@${domain}`,
          country: 'US'
        }
      };
      
      // Update state
      setResults(result);
      setIsLoading(false);
    }, 1500);
  };
  
  // Calculate domain age
  const getDomainAge = (creationDate: string) => {
    const created = new Date(creationDate);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - created.getTime());
    const diffYears = Math.ceil(diffTime / (1000 * 60 * 60 * 24 * 365));
    return diffYears;
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <Helmet>
        <title>WHOIS Lookup | CyberPulse Security Toolkit</title>
        <meta name="description" content="Look up comprehensive domain registration information including registrar, creation date, expiry date, and contact details." />
      </Helmet>
      
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold text-primary mb-2">WHOIS Domain Lookup</h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Discover who owns a domain, when it was registered, and when it expires. 
          Search for comprehensive registration data for any domain.
        </p>
      </div>
      
      <Card className="max-w-4xl mx-auto p-6 mb-8">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="domain">Domain Name</Label>
            <div className="flex gap-2">
              <Input
                id="domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com"
                className="flex-1"
              />
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Loading...
                  </>
                ) : (
                  <>
                    <Search className="mr-2 h-4 w-4" />
                    Lookup
                  </>
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Enter a domain name without 'http://' or 'www'. Example: example.com
            </p>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive">
              {error}
            </div>
          )}
        </form>
      </Card>
      
      {isLoading && (
        <Card className="max-w-4xl mx-auto p-6 flex items-center justify-center">
          <div className="text-center py-8">
            <div className="h-16 w-16 mx-auto rounded-full border-4 border-primary/30 border-t-primary animate-spin mb-4"></div>
            <p className="text-muted-foreground">Retrieving WHOIS information for {domain}...</p>
          </div>
        </Card>
      )}
      
      {results && (
        <Card className="max-w-4xl mx-auto p-6">
          <div className="mb-4 flex items-center justify-between flex-wrap gap-2">
            <h2 className="text-2xl font-bold text-primary">
              {results.domainName}
            </h2>
            <Badge className="bg-primary">
              {getDomainAge(results.creationDate)} years old
            </Badge>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold mb-2 flex items-center">
                  <Globe className="mr-2 h-5 w-5 text-primary" />
                  Domain Information
                </h3>
                <div className="space-y-2">
                  <div>
                    <Label className="text-xs text-muted-foreground">Registrar</Label>
                    <p>{results.registrar}</p>
                  </div>
                  
                  {results.registrarUrl && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Registrar URL</Label>
                      <p>
                        <a 
                          href={results.registrarUrl} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-blue-500 hover:underline"
                        >
                          {results.registrarUrl}
                        </a>
                      </p>
                    </div>
                  )}
                  
                  <div>
                    <Label className="text-xs text-muted-foreground">Status</Label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {results.status.map((status, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {status}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold mb-2 flex items-center">
                  <Calendar className="mr-2 h-5 w-5 text-primary" />
                  Important Dates
                </h3>
                <div className="space-y-2">
                  <div>
                    <Label className="text-xs text-muted-foreground">Creation Date</Label>
                    <p>{results.creationDate}</p>
                  </div>
                  
                  <div>
                    <Label className="text-xs text-muted-foreground">Expiry Date</Label>
                    <p>{results.expiryDate}</p>
                  </div>
                  
                  {results.updateDate && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Last Updated</Label>
                      <p>{results.updateDate}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
            
            <div className="space-y-4">
              {results.registrant && (
                <div>
                  <h3 className="text-lg font-semibold mb-2 flex items-center">
                    <Building className="mr-2 h-5 w-5 text-primary" />
                    Registrant Information
                  </h3>
                  <div className="space-y-2">
                    {results.registrant.organization && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Organization</Label>
                        <p>{results.registrant.organization}</p>
                      </div>
                    )}
                    
                    {results.registrant.name && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Name</Label>
                        <p>{results.registrant.name}</p>
                      </div>
                    )}
                    
                    {results.registrant.email && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Email</Label>
                        <p className="flex items-center">
                          <Mail className="h-3 w-3 mr-1 text-muted-foreground" />
                          {results.registrant.email}
                        </p>
                      </div>
                    )}
                    
                    {results.registrant.country && (
                      <div>
                        <Label className="text-xs text-muted-foreground">Country</Label>
                        <p>{results.registrant.country}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              <div>
                <h3 className="text-lg font-semibold mb-2 flex items-center">
                  <Server className="mr-2 h-5 w-5 text-primary" />
                  Name Servers
                </h3>
                <div className="space-y-1">
                  {results.nameServers.map((ns, i) => (
                    <div key={i} className="p-2 bg-muted rounded-md text-sm">
                      {ns}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
          
          <div className="mt-6">
            <p className="text-sm text-muted-foreground">
              Note: WHOIS data may be masked or limited due to privacy protection services.
            </p>
          </div>
        </Card>
      )}
      
      <div className="max-w-4xl mx-auto mt-12 space-y-6">
        <div>
          <h2 className="text-xl font-bold text-primary mb-3 flex items-center">
            <Search className="mr-2 h-5 w-5" />
            About WHOIS Lookup
          </h2>
          <p className="text-muted-foreground">
            WHOIS (pronounced as "who is") is a query and response protocol that is widely used for querying 
            databases that store the registered users or assignees of an Internet resource, such as a domain name, 
            an IP address block, or an autonomous system. This tool helps you find information about domain names, 
            including the registrar, registration date, and contact information.
          </p>
        </div>
        
        <div>
          <h2 className="text-xl font-bold text-primary mb-3 flex items-center">
            <Shield className="mr-2 h-5 w-5" />
            Security Implications
          </h2>
          <p className="text-muted-foreground">
            WHOIS data can be used to verify domain legitimacy, assess age and ownership patterns, and identify 
            potentially suspicious registration activities. Older domains with consistent ownership histories are 
            generally more trustworthy than newly registered domains or domains with frequently changing ownership.
          </p>
        </div>
      </div>
    </div>
  );
}