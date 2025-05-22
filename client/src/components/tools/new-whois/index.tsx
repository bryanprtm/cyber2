import React, { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Terminal from '@/components/terminal';
import {
  AlertCircle,
  Search,
  RotateCw,
  Database,
  Calendar,
  Building,
  User,
  Mail,
  Globe,
  Server,
  Shield,
  Clock,
  Loader2,
  ArrowDown,
  ExternalLink,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';

// Define types
interface WhoisResult {
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

interface WhoisProps {
  onLookupComplete?: (results: WhoisResult) => void;
}

// Main component
export default function NewWhoisLookup({ onLookupComplete }: WhoisProps) {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<WhoisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [activeTab, setActiveTab] = useState('summary');
  
  const { toast } = useToast();
  const { lines, addCommandLine, addInfoLine, addErrorLine, addSuccessLine } = useTerminal();
  
  // Direct API call for WHOIS lookup
  const fetchWhoisData = async (domain: string) => {
    try {
      addInfoLine(`Fetching WHOIS information for ${domain}...`);
      
      const response = await axios.get(`/api/lookup/whois?domain=${encodeURIComponent(domain)}`);
      
      if (response.status === 200) {
        addSuccessLine(`WHOIS lookup completed successfully`);
        return response.data;
      } else {
        throw new Error(`API returned status ${response.status}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      addErrorLine(`WHOIS lookup failed: ${errorMessage}`);
      throw error;
    }
  };
  
  // Save WHOIS data to database
  const saveToDb = async (whoisData: WhoisResult) => {
    try {
      addInfoLine('Saving results to database...');
      
      const saveResponse = await apiMutation('POST', '/api/lookup/whois/save', {
        domain: domain,
        data: whoisData,
        toolId: 'whois-lookup',
        type: 'whois'
      });
      
      if (saveResponse.success) {
        addSuccessLine(`Results saved to database successfully`);
        toast({
          title: 'Results Saved',
          description: 'WHOIS lookup results have been saved to database',
        });
      } else {
        throw new Error(saveResponse.message || 'Failed to save results');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      addErrorLine(`Failed to save results: ${errorMessage}`);
      toast({
        title: 'Save Failed',
        description: 'Could not save WHOIS results to database',
        variant: 'destructive'
      });
    }
  };
  
  // Handle lookup
  const handleLookup = async () => {
    if (!domain) {
      setError('Please enter a domain name');
      return;
    }
    
    // Basic domain validation
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Invalid domain format. Example: example.com');
      addErrorLine('Invalid domain format. Example: example.com');
      return;
    }
    
    setIsLoading(true);
    setResults(null);
    setError(null);
    
    addCommandLine(`whois ${domain}`);
    
    try {
      // For development/demo purposes, we'll use mock data since this is a frontend-focused task
      // In a real implementation, you'd call the API
      
      // Simulate API call delay
      setTimeout(async () => {
        try {
          // Use a mockup function for demonstration
          const whoisData = mockWhoisLookup(domain);
          
          // Set the results
          setResults(whoisData);
          
          // Call the completion callback if provided
          if (onLookupComplete) {
            onLookupComplete(whoisData);
          }
          
          // Save to database if option is selected
          if (saveToDatabase) {
            await saveToDb(whoisData);
          }
          
          setIsLoading(false);
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
          setError(errorMessage);
          addErrorLine(`Error: ${errorMessage}`);
          setIsLoading(false);
        }
      }, 1200);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      setError(errorMessage);
      addErrorLine(`Error: ${errorMessage}`);
      setIsLoading(false);
    }
  };
  
  // Reset form
  const handleReset = () => {
    setDomain('');
    setResults(null);
    setError(null);
    addInfoLine('WHOIS lookup tool reset');
  };
  
  // Format date for display
  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch (error) {
      return dateString;
    }
  };
  
  // Calculate domain age in years
  const getDomainAge = (creationDate?: string) => {
    if (!creationDate) return null;
    
    try {
      const created = new Date(creationDate);
      const now = new Date();
      const ageInYears = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
      return ageInYears.toFixed(1);
    } catch (error) {
      return null;
    }
  };
  
  // Calculate days until expiry
  const getDaysUntilExpiry = (expiryDate?: string) => {
    if (!expiryDate) return null;
    
    try {
      const expiry = new Date(expiryDate);
      const now = new Date();
      const daysRemaining = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return Math.round(daysRemaining);
    } catch (error) {
      return null;
    }
  };
  
  // Mock WHOIS lookup (replace with real API in production)
  const mockWhoisLookup = (domain: string): WhoisResult => {
    // Get domain parts
    const domainParts = domain.split('.');
    const tld = domainParts[domainParts.length - 1];
    
    // Generate dates
    const today = new Date();
    const creationDate = new Date(today);
    creationDate.setFullYear(today.getFullYear() - 5 - Math.floor(Math.random() * 10));
    
    const expiryDate = new Date(today);
    expiryDate.setFullYear(today.getFullYear() + 1 + Math.floor(Math.random() * 8));
    
    const updateDate = new Date(today);
    updateDate.setMonth(today.getMonth() - Math.floor(Math.random() * 10));
    
    // Create mock registrar info based on TLD
    const registrars = {
      'com': 'GoDaddy.com, LLC',
      'net': 'Network Solutions, LLC',
      'org': 'Public Interest Registry',
      'io': 'Afilias',
      'dev': 'Google Domains',
      'co': 'GoDaddy.com, LLC',
      'ai': 'Nic.ai'
    };
    
    const registrar = registrars[tld as keyof typeof registrars] || 'Example Registrar, Inc.';
    const registrarUrl = `https://www.${registrar.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com`;
    
    const statuses = [
      'clientTransferProhibited',
      'clientUpdateProhibited',
      'clientDeleteProhibited'
    ];
    
    // Generate name servers
    const nameServerCount = 2 + Math.floor(Math.random() * 3); // 2-4 name servers
    const nameServers = [];
    for (let i = 1; i <= nameServerCount; i++) {
      nameServers.push(`ns${i}.${domainParts.join('.')}`);
    }
    
    // Create mock result
    const result: WhoisResult = {
      domainName: domain,
      registrar,
      registrarWhoisServer: `whois.${registrar.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com`,
      registrarUrl,
      updatedDate: updateDate.toISOString(),
      creationDate: creationDate.toISOString(),
      registryExpiryDate: expiryDate.toISOString(),
      registrant: {
        organization: `${domainParts[0].charAt(0).toUpperCase() + domainParts[0].slice(1)} Inc.`,
        name: 'Domain Administrator',
        email: `admin@${domain}`,
        country: 'US'
      },
      admin: {
        name: 'Administrative Contact',
        email: `admin@${domain}`
      },
      tech: {
        name: 'Technical Contact',
        email: `tech@${domain}`
      },
      nameServers,
      status: statuses,
      raw: ''
    };
    
    // Generate raw response
    result.raw = `Domain Name: ${result.domainName}
Registry Domain ID: ${Math.random().toString(36).substring(2, 15)}.${tld.toUpperCase()}
Registrar WHOIS Server: ${result.registrarWhoisServer}
Registrar URL: ${result.registrarUrl}
Updated Date: ${result.updatedDate}
Creation Date: ${result.creationDate}
Registry Expiry Date: ${result.registryExpiryDate}
Registrar: ${result.registrar}
Registrar IANA ID: ${Math.floor(Math.random() * 9000) + 1000}
Registrar Abuse Contact Email: abuse@${registrar.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com
Registrar Abuse Contact Phone: +1.${Math.floor(Math.random() * 900) + 100}${Math.floor(Math.random() * 900) + 100}${Math.floor(Math.random() * 9000) + 1000}
Domain Status: ${result.status?.join(' ')}
Registry Registrant ID: 
Registrant Name: ${result.registrant?.name}
Registrant Organization: ${result.registrant?.organization}
Registrant Street: 123 Main St
Registrant City: Anytown
Registrant State/Province: CA
Registrant Postal Code: 12345
Registrant Country: ${result.registrant?.country}
Registrant Phone: +1.${Math.floor(Math.random() * 900) + 100}${Math.floor(Math.random() * 900) + 100}${Math.floor(Math.random() * 9000) + 1000}
Registrant Email: ${result.registrant?.email}
Name Server: ${result.nameServers?.join('\nName Server: ')}
DNSSEC: unsigned
`;
    
    return result;
  };
  
  // Calculate domain age and days until expiry for display
  const domainAge = results?.creationDate ? getDomainAge(results.creationDate) : null;
  const daysUntilExpiry = results?.registryExpiryDate ? getDaysUntilExpiry(results.registryExpiryDate) : null;

  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Globe className="h-5 w-5" />
          WHOIS Domain Lookup
        </h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="domain" className="text-sm font-tech">Domain Name</Label>
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                id="domain"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && domain.trim() && !isLoading) {
                    handleLookup();
                  }
                }}
                className="font-mono bg-background border-secondary/50 flex-1"
              />
              <Button
                onClick={handleLookup}
                disabled={isLoading || !domain}
                className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Searching...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Lookup
                  </>
                )}
              </Button>
              <Button
                onClick={handleReset}
                variant="outline"
                disabled={isLoading}
                className="border-secondary/50 text-secondary font-tech"
              >
                <RotateCw className="h-4 w-4 mr-2" />
                Reset
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Enter a domain name without 'http://' or 'www'. Example: example.com
            </p>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="save-to-db" 
                checked={saveToDatabase} 
                onCheckedChange={(checked) => setSaveToDatabase(!!checked)} 
              />
              <Label 
                htmlFor="save-to-db" 
                className="text-sm font-tech cursor-pointer flex items-center"
              >
                <Database className="h-3 w-3 mr-1 text-primary" />
                Save results to database
              </Label>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </Card>
      
      <Card className="p-4 border-primary/30 bg-card">
        <h3 className="text-lg font-tech text-primary mb-4">Activity Log</h3>
        <Terminal lines={lines} maxHeight="200px" />
      </Card>
      
      {isLoading && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex items-center justify-center py-8 flex-col gap-4">
            <div className="h-20 w-20 rounded-full border-8 border-primary/30 border-t-primary animate-spin"></div>
            <div className="text-center">
              <h3 className="text-lg font-tech mb-1">Performing WHOIS Lookup</h3>
              <p className="text-sm text-muted-foreground">Querying domain registration information...</p>
            </div>
            <Progress value={Math.floor(Math.random() * 80) + 10} className="w-full max-w-md h-2" />
          </div>
        </Card>
      )}
      
      {results && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4 flex-wrap gap-2">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Globe className="h-4 w-4 mr-2" />
              Domain Information: {results.domainName}
            </h3>
            <div className="flex flex-wrap gap-1">
              <Badge variant="outline" className="bg-secondary/10 text-secondary">
                <Calendar className="h-3 w-3 mr-1" />
                {domainAge ? `${domainAge} years old` : 'Age unknown'}
              </Badge>
              
              {daysUntilExpiry !== null && (
                <Badge 
                  variant="outline" 
                  className={cn(
                    "bg-opacity-10",
                    daysUntilExpiry < 30 ? "bg-destructive/10 text-destructive" : 
                    daysUntilExpiry < 90 ? "bg-orange-500/10 text-orange-500" : 
                    "bg-green-500/10 text-green-500"
                  )}
                >
                  <Clock className="h-3 w-3 mr-1" />
                  {daysUntilExpiry < 0 ? 'Expired' : `Expires in ${daysUntilExpiry} days`}
                </Badge>
              )}
            </div>
          </div>
          
          <Tabs defaultValue="summary" onValueChange={setActiveTab} value={activeTab}>
            <TabsList className="mb-4">
              <TabsTrigger value="summary">Summary</TabsTrigger>
              <TabsTrigger value="contacts">Contacts</TabsTrigger>
              <TabsTrigger value="nameservers">Name Servers</TabsTrigger>
              <TabsTrigger value="dates">Important Dates</TabsTrigger>
              <TabsTrigger value="raw">Raw Data</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Domain Name</Label>
                  <div className="font-mono text-md">{results.domainName}</div>
                </div>
                
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Registrar</Label>
                  <div className="font-mono text-md">{results.registrar || 'N/A'}</div>
                </div>
                
                {results.registrarUrl && (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Registrar URL</Label>
                    <div className="font-mono text-md flex items-center">
                      <a 
                        href={results.registrarUrl.startsWith('http') ? results.registrarUrl : `https://${results.registrarUrl}`} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-blue-500 hover:underline flex items-center"
                      >
                        {results.registrarUrl}
                        <ExternalLink className="h-3 w-3 ml-1" />
                      </a>
                    </div>
                  </div>
                )}
                
                {results.registrarWhoisServer && (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">WHOIS Server</Label>
                    <div className="font-mono text-md">{results.registrarWhoisServer}</div>
                  </div>
                )}
              </div>
              
              {results.status && results.status.length > 0 && (
                <div className="space-y-2 mt-4">
                  <Label className="text-xs text-muted-foreground">Domain Status</Label>
                  <div className="flex flex-wrap gap-2">
                    {results.status.map((status, index) => (
                      <Badge key={index} variant="outline" className="bg-background font-mono text-xs">
                        <Shield className="h-3 w-3 mr-1 text-primary" />
                        {status}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="contacts">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Registrant Info */}
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <Building className="h-4 w-4 mr-2" />
                    Registrant
                  </h4>
                  
                  <div className="space-y-3">
                    {results.registrant?.organization && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Organization</Label>
                        <div className="font-mono text-sm">{results.registrant.organization}</div>
                      </div>
                    )}
                    
                    {results.registrant?.name && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Name</Label>
                        <div className="font-mono text-sm">{results.registrant.name}</div>
                      </div>
                    )}
                    
                    {results.registrant?.email && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Email</Label>
                        <div className="font-mono text-sm flex items-center">
                          <Mail className="h-3 w-3 mr-1 text-primary" />
                          {results.registrant.email}
                        </div>
                      </div>
                    )}
                    
                    {results.registrant?.country && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Country</Label>
                        <div className="font-mono text-sm">{results.registrant.country}</div>
                      </div>
                    )}
                  </div>
                </Card>
                
                {/* Admin Contact */}
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <User className="h-4 w-4 mr-2" />
                    Admin Contact
                  </h4>
                  
                  <div className="space-y-3">
                    {results.admin?.name && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Name</Label>
                        <div className="font-mono text-sm">{results.admin.name}</div>
                      </div>
                    )}
                    
                    {results.admin?.email && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Email</Label>
                        <div className="font-mono text-sm flex items-center">
                          <Mail className="h-3 w-3 mr-1 text-primary" />
                          {results.admin.email}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>
                
                {/* Technical Contact */}
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <Server className="h-4 w-4 mr-2" />
                    Technical Contact
                  </h4>
                  
                  <div className="space-y-3">
                    {results.tech?.name && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Name</Label>
                        <div className="font-mono text-sm">{results.tech.name}</div>
                      </div>
                    )}
                    
                    {results.tech?.email && (
                      <div className="space-y-1">
                        <Label className="text-xs text-muted-foreground">Email</Label>
                        <div className="font-mono text-sm flex items-center">
                          <Mail className="h-3 w-3 mr-1 text-primary" />
                          {results.tech.email}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="nameservers">
              <Card className="p-4 border border-border bg-card/50">
                <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                  <Server className="h-4 w-4 mr-2" />
                  Name Servers
                </h4>
                
                {results.nameServers && results.nameServers.length > 0 ? (
                  <div className="space-y-2">
                    {results.nameServers.map((ns, index) => (
                      <div key={index} className="font-mono text-sm p-2 bg-background/50 rounded-md flex items-center">
                        <ArrowDown className="h-3 w-3 mr-2 text-primary rotate-45" />
                        {ns}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">No name servers found</div>
                )}
              </Card>
            </TabsContent>
            
            <TabsContent value="dates">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <Calendar className="h-4 w-4 mr-2" />
                    Creation Date
                  </h4>
                  <div className="font-mono text-sm">{formatDate(results.creationDate)}</div>
                  {domainAge && (
                    <div className="mt-2 text-xs text-muted-foreground">
                      Domain is {domainAge} years old
                    </div>
                  )}
                </Card>
                
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <Calendar className="h-4 w-4 mr-2" />
                    Last Updated
                  </h4>
                  <div className="font-mono text-sm">{formatDate(results.updatedDate)}</div>
                </Card>
                
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                    <Calendar className="h-4 w-4 mr-2" />
                    Expiry Date
                  </h4>
                  <div className="font-mono text-sm">{formatDate(results.registryExpiryDate)}</div>
                  {daysUntilExpiry !== null && (
                    <div className={cn(
                      "mt-2 text-xs",
                      daysUntilExpiry < 30 ? "text-destructive" : 
                      daysUntilExpiry < 90 ? "text-orange-500" : 
                      "text-green-500"
                    )}>
                      {daysUntilExpiry < 0 ? 'Domain has expired!' : `Expires in ${daysUntilExpiry} days`}
                    </div>
                  )}
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="raw">
              <Card className="p-4 border border-border bg-card/50">
                <h4 className="text-md font-tech mb-3 flex items-center text-primary">
                  <Code className="h-4 w-4 mr-2" />
                  Raw WHOIS Data
                </h4>
                <pre className="bg-black p-4 rounded-md text-xs font-mono text-white overflow-auto max-h-[400px] whitespace-pre-wrap">
                  {results.raw}
                </pre>
              </Card>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}

// Simple Code icon component
function Code(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  );
}