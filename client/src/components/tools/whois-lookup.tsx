import React, { useState } from 'react';
import { useWebSocket } from '@/hooks/use-websocket';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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

export default function WhoisLookup({ onLookupComplete }: WhoisProps) {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<WhoisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [followIcannReferral, setFollowIcannReferral] = useState(true);
  const [showRawData, setShowRawData] = useState(false);
  
  const { isConnected, sendMessage, lastMessage } = useWebSocket();
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine } = useTerminal();
  const { toast } = useToast();
  
  // Handle WebSocket messages
  React.useEffect(() => {
    if (!lastMessage) return;
    
    const msg = lastMessage as any;
    
    switch (msg.type) {
      case 'whois_results':
        setIsLoading(false);
        setResults(msg.data);
        
        if (onLookupComplete) {
          onLookupComplete(msg.data);
        }
        
        addInfoLine(`WHOIS lookup for ${domain} completed`);
        
        // Save results to database if option is checked
        if (saveToDatabase) {
          saveLookupResults(msg.data);
        }
        break;
        
      case 'error':
        setIsLoading(false);
        setError(msg.data.message);
        addErrorLine(msg.data.message);
        break;
    }
  }, [lastMessage, domain, addInfoLine, addErrorLine, addSystemLine, saveToDatabase, onLookupComplete]);
  
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
        addInfoLine(`WHOIS results saved to database`);
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
  const handleLookup = () => {
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
    
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }
    
    // Start lookup
    setIsLoading(true);
    setResults(null);
    setError(null);
    setShowRawData(false);
    
    addCommandLine(`whois ${domain}`);
    
    // Send lookup request via WebSocket
    const success = sendMessage('whois_lookup', {
      domain,
      followIcannReferral,
      timeout: 10000
    });
    
    if (!success) {
      setIsLoading(false);
      setError('Failed to send WHOIS lookup request. Please try again.');
      addErrorLine('Failed to send WHOIS lookup request. Please try again.');
    }
  };
  
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
                id="follow-referral" 
                checked={followIcannReferral} 
                onCheckedChange={(checked) => setFollowIcannReferral(!!checked)} 
              />
              <Label 
                htmlFor="follow-referral" 
                className="text-sm font-tech cursor-pointer"
              >
                Follow ICANN referral
              </Label>
            </div>
            
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
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Organization</Label>
                      <div className="font-mono text-sm">{results.registrant?.organization || 'N/A'}</div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Name</Label>
                      <div className="font-mono text-sm">{results.registrant?.name || 'N/A'}</div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Email</Label>
                      <div className="font-mono text-sm">
                        {results.registrant?.email ? (
                          <a href={`mailto:${results.registrant.email}`} className="text-blue-500 hover:underline">
                            {results.registrant.email}
                          </a>
                        ) : 'N/A'}
                      </div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Country</Label>
                      <div className="font-mono text-sm">{results.registrant?.country || 'N/A'}</div>
                    </div>
                  </div>
                </Card>
                
                {/* Admin Contact */}
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-secondary">
                    <User className="h-4 w-4 mr-2" />
                    Admin Contact
                  </h4>
                  
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Name</Label>
                      <div className="font-mono text-sm">{results.admin?.name || 'N/A'}</div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Email</Label>
                      <div className="font-mono text-sm">
                        {results.admin?.email ? (
                          <a href={`mailto:${results.admin.email}`} className="text-blue-500 hover:underline">
                            {results.admin.email}
                          </a>
                        ) : 'N/A'}
                      </div>
                    </div>
                  </div>
                </Card>
                
                {/* Technical Contact */}
                <Card className="p-4 border border-border bg-card/50">
                  <h4 className="text-md font-tech mb-3 flex items-center text-accent">
                    <Server className="h-4 w-4 mr-2" />
                    Technical Contact
                  </h4>
                  
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Name</Label>
                      <div className="font-mono text-sm">{results.tech?.name || 'N/A'}</div>
                    </div>
                    
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Email</Label>
                      <div className="font-mono text-sm">
                        {results.tech?.email ? (
                          <a href={`mailto:${results.tech.email}`} className="text-blue-500 hover:underline">
                            {results.tech.email}
                          </a>
                        ) : 'N/A'}
                      </div>
                    </div>
                  </div>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="nameservers">
              <div className="space-y-4">
                <h4 className="text-md font-tech flex items-center">
                  <Server className="h-4 w-4 mr-2 text-primary" />
                  Name Servers
                </h4>
                
                {results.nameServers && results.nameServers.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {results.nameServers.map((ns, index) => (
                      <Card key={index} className="p-3 border border-border bg-card/50">
                        <div className="font-mono text-sm flex items-center">
                          <Globe className="h-3.5 w-3.5 mr-2 text-secondary" />
                          {ns}
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <div className="text-muted-foreground text-sm">No name servers found</div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="dates">
              <div className="space-y-5">
                <h4 className="text-md font-tech flex items-center">
                  <Calendar className="h-4 w-4 mr-2 text-primary" />
                  Important Dates
                </h4>
                
                <div className="space-y-6">
                  {/* Created Date */}
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground flex items-center">
                      <Calendar className="h-3.5 w-3.5 mr-1.5 text-primary" />
                      Creation Date
                    </Label>
                    <div className="font-mono text-md">
                      {formatDate(results.creationDate)}
                      {domainAge && <span className="text-sm text-muted-foreground ml-2">({domainAge} years ago)</span>}
                    </div>
                  </div>
                  
                  {/* Updated Date */}
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground flex items-center">
                      <ArrowDown className="h-3.5 w-3.5 mr-1.5 text-secondary" />
                      Last Updated
                    </Label>
                    <div className="font-mono text-md">{formatDate(results.updatedDate)}</div>
                  </div>
                  
                  {/* Expiry Date */}
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground flex items-center">
                      <Clock className="h-3.5 w-3.5 mr-1.5 text-accent" />
                      Expiration Date
                    </Label>
                    <div className="font-mono text-md">
                      {formatDate(results.registryExpiryDate)}
                      {daysUntilExpiry !== null && (
                        <span className={cn(
                          "text-sm ml-2",
                          daysUntilExpiry < 30 ? "text-destructive" : 
                          daysUntilExpiry < 90 ? "text-orange-500" : 
                          "text-green-500"
                        )}>
                          ({daysUntilExpiry < 0 ? 'Expired' : `${daysUntilExpiry} days remaining`})
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="raw">
              {showRawData && results.raw && (
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <Label className="text-xs text-muted-foreground">Raw WHOIS Data</Label>
                    <Button
                      onClick={() => {
                        navigator.clipboard.writeText(results.raw);
                        toast({
                          title: "Copied",
                          description: "Raw WHOIS data copied to clipboard",
                          variant: "default"
                        });
                      }}
                      variant="outline"
                      size="sm"
                      className="text-xs"
                    >
                      Copy to Clipboard
                    </Button>
                  </div>
                  <Card className="p-2 border border-border bg-card/50">
                    <pre className="whitespace-pre-wrap font-mono text-xs overflow-auto max-h-96 p-2">
                      {results.raw}
                    </pre>
                  </Card>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}