import React, { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, Search, RotateCw, Globe, Loader2 } from 'lucide-react';
import Terminal from '@/components/terminal';
import { useTerminal } from '@/hooks/use-terminal';

interface WhoisResult {
  domainName: string;
  registrar: string;
  creationDate: string;
  expiryDate: string;
  nameServers: string[];
  status: string;
}

export default function BasicWhoisLookup() {
  const [domain, setDomain] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [results, setResults] = useState<WhoisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const { lines, addCommandLine, addInfoLine, addErrorLine, addSuccessLine } = useTerminal();
  
  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDomain(e.target.value);
  };
  
  const handleLookup = () => {
    // Validate domain
    if (!domain || domain.trim() === '') {
      setError('Please enter a domain name');
      return;
    }
    
    // Simple domain validation
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      setError('Invalid domain format. Example: example.com');
      addErrorLine('Invalid domain format. Example: example.com');
      return;
    }
    
    // Reset previous results
    setError(null);
    setResults(null);
    setIsLoading(true);
    
    // Add command to terminal
    addCommandLine(`whois ${domain}`);
    addInfoLine(`Looking up WHOIS information for ${domain}...`);
    
    // Simulate network request
    setTimeout(() => {
      // Generate fake WHOIS data
      const today = new Date();
      
      // Create fake creation date (1-10 years ago)
      const creationDate = new Date();
      creationDate.setFullYear(today.getFullYear() - Math.floor(Math.random() * 10) - 1);
      
      // Create fake expiry date (1-5 years in future)
      const expiryDate = new Date();
      expiryDate.setFullYear(today.getFullYear() + Math.floor(Math.random() * 5) + 1);
      
      // Create result
      const result: WhoisResult = {
        domainName: domain,
        registrar: domain.endsWith('.com') ? 'GoDaddy.com, LLC' : 
                   domain.endsWith('.org') ? 'Public Interest Registry' : 
                   domain.endsWith('.net') ? 'Network Solutions, LLC' : 
                   'Example Registrar, Inc.',
        creationDate: creationDate.toISOString().split('T')[0],
        expiryDate: expiryDate.toISOString().split('T')[0],
        nameServers: [
          `ns1.${domain}`, 
          `ns2.${domain}`
        ],
        status: 'Active'
      };
      
      // Update state
      setResults(result);
      setIsLoading(false);
      addSuccessLine(`WHOIS lookup completed for ${domain}`);
    }, 1500);
  };
  
  const handleReset = () => {
    setDomain('');
    setResults(null);
    setError(null);
    addInfoLine('WHOIS lookup tool reset');
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-bold text-primary mb-4 flex items-center gap-2">
          <Globe className="h-5 w-5" />
          WHOIS Domain Lookup
        </h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="domain" className="text-sm">Domain Name</Label>
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                id="domain"
                placeholder="example.com"
                value={domain}
                onChange={handleDomainChange}
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
                className="bg-primary text-primary-foreground hover:bg-primary/90"
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
                className="border-secondary/50 text-secondary"
              >
                <RotateCw className="h-4 w-4 mr-2" />
                Reset
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Enter a domain name without 'http://' or 'www'. Example: example.com
            </p>
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
        <h3 className="text-lg font-bold text-primary mb-4">Activity Log</h3>
        <Terminal lines={lines} maxHeight="200px" />
      </Card>
      
      {isLoading && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex items-center justify-center py-6 flex-col gap-3">
            <div className="h-16 w-16 rounded-full border-4 border-primary/30 border-t-primary animate-spin"></div>
            <p className="text-center text-muted-foreground">Looking up information for {domain}...</p>
          </div>
        </Card>
      )}
      
      {results && (
        <Card className="p-4 border-primary/30 bg-card">
          <h3 className="text-lg font-bold text-primary mb-4">WHOIS Results</h3>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label className="text-xs text-muted-foreground">Domain Name</Label>
                <p className="font-mono">{results.domainName}</p>
              </div>
              
              <div>
                <Label className="text-xs text-muted-foreground">Registrar</Label>
                <p className="font-mono">{results.registrar}</p>
              </div>
              
              <div>
                <Label className="text-xs text-muted-foreground">Creation Date</Label>
                <p className="font-mono">{results.creationDate}</p>
              </div>
              
              <div>
                <Label className="text-xs text-muted-foreground">Expiry Date</Label>
                <p className="font-mono">{results.expiryDate}</p>
              </div>
            </div>
            
            <div>
              <Label className="text-xs text-muted-foreground">Name Servers</Label>
              <div className="flex flex-wrap gap-2 mt-1">
                {results.nameServers.map((ns, i) => (
                  <Badge key={i} variant="outline" className="font-mono">
                    {ns}
                  </Badge>
                ))}
              </div>
            </div>
            
            <div>
              <Label className="text-xs text-muted-foreground">Domain Status</Label>
              <p className="font-mono">{results.status}</p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}