import React, { useState } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  FileSearch, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX,
  File,
  RefreshCw,
  CheckCircle2,
  XCircle,
  FileWarning,
  AlertTriangle,
  Code
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface LfiScannerProps {
  onScanComplete?: (result: any) => void;
}

export default function LfiScanner({ onScanComplete }: LfiScannerProps) {
  const [url, setUrl] = useState<string>('');
  const [paramName, setParamName] = useState<string>('');
  const [customPayloads, setCustomPayloads] = useState<string>('');
  const [deepScan, setDeepScan] = useState<boolean>(false);
  const [scanCommonLocations, setScanCommonLocations] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  
  const { addCommandLine, addInfoLine, addErrorLine, addSuccessLine } = useTerminal();
  const { toast } = useToast();
  
  /**
   * Validate if string is a valid URL
   */
  const isValidUrl = (urlString: string): boolean => {
    try {
      // Ensure URL has a protocol
      const normalizedUrl = urlString.startsWith('http') ? urlString : `https://${urlString}`;
      new URL(normalizedUrl);
      return true;
    } catch (err) {
      return false;
    }
  };
  
  const handleScan = async () => {
    // Normalize URL if needed
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    if (!isValidUrl(normalizedUrl)) {
      setError('Invalid URL format. Example: https://example.com');
      addErrorLine('Error: Invalid URL format. Example: https://example.com');
      return;
    }
    
    setError(null);
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    
    addCommandLine(`Starting LFI vulnerability scan for ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Parameter to test: ${paramName || 'Auto-detect'}`);
    addInfoLine(`Deep scan: ${deepScan ? 'Enabled' : 'Disabled'}`);
    
    // Simulate progress for UX
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + 5;
      });
    }, 300);
    
    try {
      const response = await axios.post('/api/security/lfi-scanner', {
        url: normalizedUrl,
        paramName: paramName || undefined,
        customPayloads: customPayloads || undefined,
        deepScan,
        scanCommonLocations
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setScanResults(result);
        
        // Terminal output based on results
        addSuccessLine('LFI scan completed');
        
        if (result.vulnerable) {
          addErrorLine(`WARNING: ${normalizedUrl} is VULNERABLE to Local File Inclusion!`);
          
          if (result.vulnerableParams.length > 0) {
            addErrorLine(`Vulnerable parameters: ${result.vulnerableParams.join(', ')}`);
          }
          
          if (result.successfulPayloads.length > 0) {
            addInfoLine(`Successful payloads: ${result.successfulPayloads.length}`);
            
            // Show a sample of successful payloads
            result.successfulPayloads.slice(0, 2).forEach((payload: any, index: number) => {
              addInfoLine(`${index + 1}. ${payload.param}=${payload.payload}`);
            });
          }
        } else {
          addSuccessLine(`No LFI vulnerabilities detected in ${normalizedUrl}`);
        }
        
        // Add security rating info
        addInfoLine(`Security rating: ${result.scanSummary.riskLevel} (${result.scanSummary.score}/100)`);
        
        if (onScanComplete) {
          onScanComplete(result);
        }
        
        toast({
          title: 'LFI scan completed',
          description: `Result: ${result.scanSummary.riskLevel}`,
          variant: result.vulnerable ? 'destructive' : 'default'
        });
      } else {
        setError(response.data.message || 'Failed to scan for LFI');
        addErrorLine(`Error: ${response.data.message}`);
      }
    } catch (err: any) {
      clearInterval(progressInterval);
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred';
      setError(errorMessage);
      addErrorLine(`Error: ${errorMessage}`);
      
      toast({
        title: 'Scan failed',
        description: errorMessage,
        variant: 'destructive'
      });
    } finally {
      setIsScanning(false);
    }
  };
  
  const handleReset = () => {
    setUrl('');
    setParamName('');
    setCustomPayloads('');
    setScanResults(null);
    setError(null);
    setScanProgress(0);
    addCommandLine('Reset LFI scanner');
  };
  
  // Get color based on risk level
  const getRiskColor = (riskLevel: string): string => {
    switch (riskLevel) {
      case 'Critical':
        return 'text-red-600 border-red-600';
      case 'High Risk':
        return 'text-red-500 border-red-500';
      case 'Medium Risk':
        return 'text-orange-500 border-orange-500';
      case 'Low Risk':
        return 'text-yellow-500 border-yellow-500';
      case 'Safe':
        return 'text-green-500 border-green-500';
      default:
        return 'text-muted-foreground border-muted-foreground';
    }
  };
  
  // Get icon based on risk level
  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'Critical':
        return <ShieldX className="h-5 w-5 text-red-600" />;
      case 'High Risk':
        return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case 'Medium Risk':
        return <AlertCircle className="h-5 w-5 text-orange-500" />;
      case 'Low Risk':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case 'Safe':
        return <ShieldCheck className="h-5 w-5 text-green-500" />;
      default:
        return <Shield className="h-5 w-5 text-muted-foreground" />;
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Local File Inclusion Scanner</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url" className="text-sm font-tech">Target URL</Label>
            <Input
              id="url"
              placeholder="https://example.com/page.php?file=example.txt"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono bg-background border-secondary/50"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the URL of the page that might be vulnerable to LFI
            </p>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="param-name" className="text-sm font-tech">Parameter Name (Optional)</Label>
            <Input
              id="param-name"
              placeholder="file, path, page, etc."
              value={paramName}
              onChange={(e) => setParamName(e.target.value)}
              className="font-mono bg-background border-secondary/50"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Specify a parameter to test, or leave empty to auto-detect
            </p>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="deep-scan" 
                  checked={deepScan}
                  onCheckedChange={(checked) => setDeepScan(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="deep-scan" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Enable deep scan
                </Label>
              </div>
              <p className="text-xs font-mono text-muted-foreground ml-6">
                Tests more payloads and parameters (slower but more thorough)
              </p>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="scan-common" 
                  checked={scanCommonLocations}
                  onCheckedChange={(checked) => setScanCommonLocations(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="scan-common" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Scan common locations
                </Label>
              </div>
              <p className="text-xs font-mono text-muted-foreground ml-6">
                Tests common endpoint patterns for vulnerabilities
              </p>
            </div>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="custom-payloads" className="text-sm font-tech">Custom Payloads (Optional)</Label>
            <Textarea
              id="custom-payloads"
              placeholder="../../../etc/passwd\n../../../../../etc/hosts\n/etc/shadow%00"
              value={customPayloads}
              onChange={(e) => setCustomPayloads(e.target.value)}
              className="font-mono bg-background border-secondary/50 min-h-24"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Add custom LFI payloads, one per line (optional)
            </p>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Scanning for LFI vulnerabilities...</span>
                <span>{scanProgress}%</span>
              </div>
              <div className="h-1.5 w-full bg-secondary/20 rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleScan}
              disabled={isScanning || !url}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isScanning}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid grid-cols-3 mb-4">
              <TabsTrigger value="summary" className="font-tech">Summary</TabsTrigger>
              <TabsTrigger value="payloads" className="font-tech">Payloads</TabsTrigger>
              <TabsTrigger value="recommendations" className="font-tech">Recommendations</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">LFI Scan Results</h3>
                  <p className="text-sm font-mono">{scanResults.url}</p>
                </div>
                <div className={cn(
                  "px-3 py-1 rounded-full border flex items-center space-x-2",
                  getRiskColor(scanResults.scanSummary.riskLevel)
                )}>
                  {getRiskIcon(scanResults.scanSummary.riskLevel)}
                  <span className="font-tech text-sm">{scanResults.scanSummary.riskLevel}</span>
                </div>
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Scan Overview</h4>
                <div className="space-y-2 text-sm font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Vulnerability Status:</span>
                    <span className={scanResults.vulnerable ? "text-red-500" : "text-green-500"}>
                      {scanResults.vulnerable ? "VULNERABLE" : "Not Vulnerable"}
                    </span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Security Score:</span>
                    <span className={
                      scanResults.scanSummary.score > 80 ? "text-red-600" :
                      scanResults.scanSummary.score > 60 ? "text-red-500" :
                      scanResults.scanSummary.score > 40 ? "text-orange-500" :
                      scanResults.scanSummary.score > 20 ? "text-yellow-500" :
                      "text-green-500"
                    }>
                      {scanResults.scanSummary.score}/100
                    </span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Parameters Tested:</span>
                    <span>{scanResults.paramsTested.length}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Total Requests:</span>
                    <span>{scanResults.totalRequests}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Scan Duration:</span>
                    <span>{(scanResults.scanTime / 1000).toFixed(2)} seconds</span>
                  </div>
                </div>
                
                {scanResults.vulnerable && (
                  <div className="mt-4 p-3 bg-red-500/10 rounded-md border border-red-500/30 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    <div>
                      <p className="text-sm font-tech text-red-500">LFI Vulnerability Detected!</p>
                      <p className="text-xs font-mono mt-1">{scanResults.scanSummary.description}</p>
                    </div>
                  </div>
                )}
              </div>
              
              {scanResults.vulnerableParams.length > 0 && (
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2">Vulnerable Parameters</h4>
                  <div className="flex flex-wrap gap-2">
                    {scanResults.vulnerableParams.map((param: string, i: number) => (
                      <Badge key={i} variant="outline" className="bg-red-500/10 text-red-500 border-red-500/30">
                        {param}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="payloads" className="space-y-4">
              {scanResults.successfulPayloads.length > 0 ? (
                <div className="space-y-4">
                  <h4 className="text-sm font-tech text-secondary">Successful Payloads</h4>
                  
                  <div className="space-y-3">
                    {scanResults.successfulPayloads.map((payload: any, i: number) => (
                      <div key={i} className="p-3 bg-background rounded-md border border-secondary/20">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <FileWarning className="h-4 w-4 text-red-500" />
                            <span className="font-tech text-sm">{payload.param}</span>
                          </div>
                          <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/30">
                            Status: {payload.response.status}
                          </Badge>
                        </div>
                        
                        <div className="text-xs font-mono p-2 bg-secondary/5 rounded mb-2 overflow-x-auto">
                          {payload.payload}
                        </div>
                        
                        {payload.response.contentPreview && (
                          <div className="mt-2">
                            <p className="text-xs font-tech text-muted-foreground">Response Preview:</p>
                            <p className="text-xs font-mono mt-1 p-2 bg-secondary/5 rounded">
                              {payload.response.contentPreview}
                            </p>
                          </div>
                        )}
                        
                        {payload.response.indicators && payload.response.indicators.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs font-tech text-red-500">Detection Indicators:</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {payload.response.indicators.map((indicator: string, j: number) => (
                                <Badge key={j} variant="outline" className="text-xs bg-red-500/5 text-red-500 border-red-500/20">
                                  {indicator.substring(0, 20)}{indicator.length > 20 ? '...' : ''}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8">
                  <Shield className="h-12 w-12 text-green-500 mb-4" />
                  <h4 className="text-md font-tech text-green-500 mb-2">No Successful Payloads</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    No successful LFI payloads were detected during the scan.
                    This suggests the target is not vulnerable to Local File Inclusion attacks.
                  </p>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="recommendations" className="space-y-4">
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-4">Security Recommendations</h4>
                
                <div className="space-y-3">
                  {scanResults.recommendations.map((recommendation: string, i: number) => (
                    <div key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5" />
                      <p className="text-sm font-mono">{recommendation}</p>
                    </div>
                  ))}
                </div>
                
                {scanResults.vulnerable && (
                  <div className="mt-6 p-3 bg-amber-500/10 rounded-md border border-amber-500/30">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5" />
                      <div>
                        <p className="text-sm font-tech text-amber-500">Critical Security Issue</p>
                        <p className="text-xs font-mono mt-1">
                          This application has a Local File Inclusion vulnerability that could allow attackers to:
                        </p>
                        <ul className="list-disc list-inside text-xs font-mono mt-2 space-y-1">
                          <li>Access sensitive system files</li>
                          <li>Read application source code</li>
                          <li>Access configuration files with credentials</li>
                          <li>Potentially achieve remote code execution</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-3">Secure Coding Examples</h4>
                
                <div className="space-y-4">
                  <div>
                    <p className="text-xs font-tech text-accent mb-1">PHP - Safe File Inclusion:</p>
                    <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
                      {`// Define allowed files
$allowed_files = ['home', 'about', 'contact'];

// Get file parameter
$file = $_GET['file'] ?? 'home';

// Validate against allowlist (whitelist)
if (in_array($file, $allowed_files)) {
    include "pages/{$file}.php";
} else {
    // Handle invalid input
    include "pages/error.php";
}`}
                    </pre>
                  </div>
                  
                  <div>
                    <p className="text-xs font-tech text-accent mb-1">Node.js - Safe Path Handling:</p>
                    <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
                      {`const path = require('path');
const fs = require('fs');

// Define allowed directory
const CONTENT_DIR = path.join(__dirname, 'content');

// Get file parameter
const requestedFile = req.query.file || 'default';

// Sanitize path - prevent directory traversal
const sanitizedFile = path.basename(requestedFile);

// Construct full path
const filePath = path.join(CONTENT_DIR, sanitizedFile);

// Verify the path is within allowed directory
if (!filePath.startsWith(CONTENT_DIR)) {
    return res.status(403).send('Forbidden');
}

// Check if file exists
if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
} else {
    res.status(404).send('Not found');
}`}
                    </pre>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}