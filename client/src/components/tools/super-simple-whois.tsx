import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Loader2, Search } from 'lucide-react';

export default function SuperSimpleWhois() {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  
  const handleSubmit = () => {
    if (!domain) return;
    
    setIsLoading(true);
    setResult(null);
    
    // Mock data generation with timeout to simulate API call
    setTimeout(() => {
      setResult({
        domain: domain,
        registrar: "Example Registrar, Inc.",
        created: "2010-05-17",
        expires: "2025-05-17",
        status: "Active"
      });
      setIsLoading(false);
    }, 1000);
  };
  
  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Input 
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1"
        />
        <Button onClick={handleSubmit} disabled={isLoading || !domain}>
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
      
      {result && (
        <Card className="p-4">
          <h3 className="text-lg font-bold mb-2">WHOIS Results</h3>
          <div className="space-y-2">
            <div>
              <Label>Domain</Label>
              <p>{result.domain}</p>
            </div>
            <div>
              <Label>Registrar</Label>
              <p>{result.registrar}</p>
            </div>
            <div>
              <Label>Created</Label>
              <p>{result.created}</p>
            </div>
            <div>
              <Label>Expires</Label>
              <p>{result.expires}</p>
            </div>
            <div>
              <Label>Status</Label>
              <p>{result.status}</p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}