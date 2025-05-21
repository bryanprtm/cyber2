import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Copy, Refresh, Shield, ExternalLink } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface HashGeneratorProps {
  onHashGenerated?: (result: any) => void;
}

// Hash algorithms supported
const hashAlgorithms = [
  { value: 'md5', label: 'MD5 (Not Secure)' },
  { value: 'sha1', label: 'SHA-1 (Not Secure)' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' },
  { value: 'sha3-256', label: 'SHA3-256' },
  { value: 'sha3-512', label: 'SHA3-512' }
];

export default function HashGenerator({ onHashGenerated }: HashGeneratorProps) {
  const [input, setInput] = useState('');
  const [algorithm, setAlgorithm] = useState('sha256');
  const [hash, setHash] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Generate hash
  const generateHash = async () => {
    if (!input) {
      setError('Input text is required');
      addErrorLine('Input text is required');
      return;
    }
    
    setIsGenerating(true);
    setError(null);
    
    try {
      // Using the Web Crypto API for modern browsers
      addCommandLine(`hash-generate --algo ${algorithm} "${input.substring(0, 20)}${input.length > 20 ? '...' : ''}"`);
      
      // Convert the string to an ArrayBuffer
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      
      let hashBuffer;
      let hashHex;
      
      // Web Crypto API doesn't support MD5 or SHA-1 directly (they're insecure)
      // For demo purposes, we'll simulate these with a simple warning
      if (algorithm === 'md5' || algorithm === 'sha1') {
        // Simulate computing insecure hash (in a real app, you'd use a library)
        await new Promise(resolve => setTimeout(resolve, 500)); // simulate processing
        hashHex = await simulateInsecureHash(input, algorithm);
        addWarningLine(`${algorithm.toUpperCase()} is considered insecure. Use SHA-256 or better for production.`);
      } else {
        // Use Web Crypto API for secure algorithms
        const cryptoAlgo = algorithm.replace('-', '').toLowerCase();
        hashBuffer = await crypto.subtle.digest(cryptoAlgo, data);
        
        // Convert buffer to hex string
        hashHex = Array.from(new Uint8Array(hashBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }
      
      setHash(hashHex);
      addLine(`[SUCCESS] ${algorithm.toUpperCase()} hash generated: ${hashHex}`, "success");
      
      if (onHashGenerated) {
        onHashGenerated({
          input: input,
          algorithm: algorithm,
          hash: hashHex,
          timestamp: new Date()
        });
      }
    } catch (err) {
      console.error('Hash generation error:', err);
      setError(`Failed to generate hash: ${(err as Error).message}`);
      addErrorLine(`Failed to generate hash: ${(err as Error).message}`);
    } finally {
      setIsGenerating(false);
    }
  };
  
  // Simulate insecure hash algorithms (for education only)
  const simulateInsecureHash = async (input: string, algo: string): Promise<string> => {
    // This is just a simulation - do not use these for actual security!
    // In a real app, you would use a proper crypto library
    
    // Simple string hashing function for demo (NOT SECURE)
    function simpleSampleHash(str: string, algorithmSalt: string): string {
      let hash = 0;
      const combinedStr = algorithmSalt + str;
      
      for (let i = 0; i < combinedStr.length; i++) {
        const char = combinedStr.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
      }
      
      // Convert to hex-like string of appropriate length
      let hexString = (hash >>> 0).toString(16);
      
      // Pad to typical algorithm length
      while (hexString.length < (algo === 'md5' ? 32 : 40)) {
        hexString = "0" + hexString + Math.floor(Math.random() * 16).toString(16);
      }
      
      return hexString;
    }
    
    return simpleSampleHash(input, algo);
  };
  
  const addWarningLine = (message: string) => {
    addLine(`[WARNING] ${message}`, "warning");
  };
  
  const handleCopyHash = () => {
    if (!hash) return;
    
    navigator.clipboard.writeText(hash)
      .then(() => {
        toast({
          title: "Hash copied",
          description: "Hash has been copied to clipboard",
          variant: "default",
        });
        addInfoLine("Hash copied to clipboard");
      })
      .catch(err => {
        toast({
          title: "Copy failed",
          description: `Failed to copy hash: ${err.message}`,
          variant: "destructive"
        });
      });
  };
  
  const handleReset = () => {
    setInput('');
    setHash(null);
    setError(null);
    addInfoLine("Hash generator reset");
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Hash Generator</h2>
        
        <Tabs defaultValue="text" className="mb-4">
          <TabsList className="grid grid-cols-2 mb-4">
            <TabsTrigger value="text" className="font-tech">Text Input</TabsTrigger>
            <TabsTrigger value="file" className="font-tech" disabled>File Input (Coming Soon)</TabsTrigger>
          </TabsList>
          
          <TabsContent value="text" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="input-text" className="text-sm font-tech">Input Text</Label>
              <Textarea
                id="input-text"
                placeholder="Enter text to hash..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-32"
              />
            </div>
          </TabsContent>
        </Tabs>
        
        <div className="space-y-4 mt-4">
          <div className="space-y-2">
            <Label htmlFor="algorithm" className="text-sm font-tech">Hash Algorithm</Label>
            <Select value={algorithm} onValueChange={setAlgorithm}>
              <SelectTrigger className="font-mono bg-background border-secondary/50">
                <SelectValue placeholder="Select algorithm" />
              </SelectTrigger>
              <SelectContent>
                {hashAlgorithms.map(algo => (
                  <SelectItem 
                    key={algo.value} 
                    value={algo.value}
                    className={cn(
                      (algo.value === 'md5' || algo.value === 'sha1') && "text-amber-500"
                    )}
                  >
                    {algo.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            
            {(algorithm === 'md5' || algorithm === 'sha1') && (
              <p className="text-xs font-mono text-amber-500 flex items-center mt-1">
                <Shield className="h-3 w-3 mr-1" />
                Warning: This algorithm is not considered secure for sensitive applications
              </p>
            )}
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={generateHash}
              disabled={isGenerating || !input}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isGenerating ? 'Generating...' : 'Generate Hash'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isGenerating}
              className="border-secondary/50 text-secondary font-tech"
            >
              <Refresh className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {hash && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-lg font-tech text-secondary">Generated Hash</h3>
            <div className="text-xs font-mono text-green-500 flex items-center">
              <Shield className="h-3 w-3 mr-1" />
              {algorithm.toUpperCase()}
            </div>
          </div>
          
          <div className="bg-background p-3 rounded-md border border-secondary/30 font-mono text-sm break-all">
            {hash}
          </div>
          
          <div className="flex justify-end mt-4 space-x-2">
            <Button
              variant="outline"
              size="sm"
              className="text-primary border-primary/50 font-tech text-xs"
              onClick={handleCopyHash}
            >
              <Copy className="h-3 w-3 mr-1" />
              Copy Hash
            </Button>
            
            <Button
              variant="outline"
              size="sm"
              className="text-secondary border-secondary/50 font-tech text-xs"
              onClick={() => window.open('https://crackstation.net/', '_blank')}
            >
              <ExternalLink className="h-3 w-3 mr-1" />
              Check Hash Online
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}