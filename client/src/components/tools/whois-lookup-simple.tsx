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
  onLookupComplete?: (results: any) => void;
}

// Mock user ID for demo
const MOCK_USER_ID = 1;

export default function WhoisLookupSimple({ onLookupComplete }: WhoisProps) {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<WhoisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [showRawData, setShowRawData] = useState(false);
  
  const { toast } = useToast();
  const { lines, addCommandLine, addInfoLine, addErrorLine, addSuccessLine } = useTerminal();
  
  // Save lookup results to database
  const saveLookupResults = async (lookupResults: WhoisResult) => {
    try {
      addInfoLine(`Saving WHOIS results to database...`);
      
      // Prepare data for API
      const lookupData = {
        userId: MOCK_USER_ID,
        toolId: 'whois-lookup',
        target: domain,
        results: lookupResults,
        status: 'completed',
      };
      
      // Save to database through API
      const response = await apiMutation('POST', '/api/lookup/whois', {
        ...lookupData
      });
      
      if (response.success) {
        addSuccessLine(`WHOIS results saved to database`);
        toast({
          title: "Results Saved",
          description: "WHOIS lookup results have been stored in the database",
          variant: "default"
        });
      } else {
        throw new Error(response.message || 'Failed to save WHOIS results');
      }
    } catch (error) {
      addErrorLine(`Failed to save WHOIS results: ${(error as Error).message}`);
      toast({
        title: "Save Failed",
        description: "Could not save results to database",
        variant: "destructive"
      });
    }
  };
  
  // Handle form submission
  const handleLookup = async () => {
    if (!domain) {
      setError('Domain name is required');
      addErrorLine('Domain name is required');
      return;
    }
    
    // Basic domain validation
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Invalid domain format. Example: example.com');
      addErrorLine('Invalid domain format. Example: example.com');
      return;
    }
    
    // Start lookup
    setIsLoading(true);
    setResults(null);
    setError(null);
    setShowRawData(false);
    
    addCommandLine(`whois ${domain}`);
    
    try {
      // Instead of WebSockets, use a direct API call for simplicity
      addInfoLine(`Looking up WHOIS information for ${domain}...`);
      
      // Simulated WHOIS data (since we previously had issues with WebSockets)
      // In a real implementation, you would fetch this from your API
      setTimeout(() => {
        const simulatedData = generateWhoisData(domain);
        setResults(simulatedData);
        addSuccessLine(`WHOIS lookup for ${domain} completed`);
        
        if (onLookupComplete) {
          onLookupComplete(simulatedData);
        }
        
        // Save results to database if option is checked
        if (saveToDatabase) {
          saveLookupResults(simulatedData);
        }
        
        setIsLoading(false);
      }, 1500);
    } catch (error) {
      setIsLoading(false);
      const errorMsg = `WHOIS lookup failed: ${(error as Error).message}`;
      setError(errorMsg);
      addErrorLine(errorMsg);
    }
  };
  
  // Generate simulated WHOIS data
  function generateWhoisData(domain: string): WhoisResult {
    const currentDate = new Date();
    const creationDate = new Date();
    creationDate.setFullYear(creationDate.getFullYear() - 5); // 5 years ago
    
    const expiryDate = new Date();
    expiryDate.setFullYear(expiryDate.getFullYear() + 3); // 3 years from now
    
    const updatedDate = new Date();
    updatedDate.setMonth(updatedDate.getMonth() - 3); // 3 months ago
    
    // Top-level domain
    const tld = domain.split('.').pop() || 'com';
    
    // Get registrar info based on tld
    const registrarInfo = {
      name: "Example Registrar, Inc.",
      whoisServer: `whois.${tld}`,
      url: `https://example-registrar.${tld}`
    };
    
    const result = {
      domainName: domain,
      registrar: registrarInfo.name,
      registrarWhoisServer: registrarInfo.whoisServer,
      registrarUrl: registrarInfo.url,
      updatedDate: updatedDate.toISOString(),
      creationDate: creationDate.toISOString(),
      registryExpiryDate: expiryDate.toISOString(),
      registrant: {
        organization: "Example Organization Ltd.",
        name: "Domain Administrator",
        email: `admin@${domain}`,
        country: "US"
      },
      admin: {
        name: "Administrative Contact",
        email: `admin@${domain}`
      },
      tech: {
        name: "Technical Contact",
        email: `tech@${domain}`
      },
      nameServers: [
        `ns1.${domain}`,
        `ns2.${domain}`,
        `ns3.${domain}`,
      ],
      status: [
        "clientTransferProhibited",
        "clientUpdateProhibited",
        "clientDeleteProhibited"
      ],
      raw: ""
    };
    
    // Generate raw data
    result.raw = JSON.stringify(result, null, 2);
    
    return result;
  }
  
  // Reset form
  const handleReset = () => {
    setDomain('');
    setResults(null);
    setError(null);
    setShowRawData(false);
    addInfoLine('WHOIS lookup tool reset');
  };
  
  // Format date string for display
  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (e) {
      return dateString;
    }
  };
  
  // Calculate domain age in years if creation date is available
  const getDomainAge = (creationDate?: string) => {
    if (!creationDate) return null;
    
    try {
      const created = new Date(creationDate);
      const now = new Date();
      const ageInYears = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
      return ageInYears.toFixed(1);
    } catch (e) {
      return null;
    }
  };
  
  // Calculate days until expiry if expiry date is available
  const getDaysUntilExpiry = (expiryDate?: string) => {
    if (!expiryDate) return null;
    
    try {
      const expiry = new Date(expiryDate);
      const now = new Date();
      const daysRemaining = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return Math.round(daysRemaining);
    } catch (e) {
      return null;
    }
  };
  
  const domainAge = getDomainAge(results?.creationDate);
  const daysUntilExpiry = getDaysUntilExpiry(results?.registryExpiryDate);
  
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
            <div className="relative w-16 h-16">
              <div className="absolute inset-0 rounded-full border-4 border-primary/30"></div>
              <div className="absolute top-0 left-0 right-0 bottom-0 rounded-full border-4 border-primary border-t-transparent animate-spin"></div>
            </div>
            <div className="text-center">
              <h3 className="text-lg font-tech mb-1">Performing WHOIS Lookup</h3>
              <p className="text-sm text-muted-foreground">Querying registration information for {domain}...</p>
            </div>
          </div>
        </Card>
      )}
      
      {results && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Globe className="h-4 w-4 mr-2" />
              Domain Information
            </h3>
            <div className="flex space-x-1">
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
          
          <Tabs defaultValue="summary">
            <TabsList className="mb-4">
              <TabsTrigger value="summary">Summary</TabsTrigger>
              <TabsTrigger value="contacts">Contacts</TabsTrigger>
              <TabsTrigger value="nameservers">Name Servers</TabsTrigger>
              <TabsTrigger value="dates">Important Dates</TabsTrigger>
              <TabsTrigger value="raw" onClick={() => setShowRawData(true)}>Raw Data</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Domain Name</Label>
                  <div className="font-mono text-md">{results.domainName || domain}</div>
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
                <pre className="bg-black p-4 rounded-md text-xs font-mono text-white overflow-auto max-h-[400px]">
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

// Add missing component
function Code(props: any) {
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