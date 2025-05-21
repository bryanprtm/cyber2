import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress'; 
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertCircle, Play, RotateCw, Shield, Bug, AlertTriangle, Check, X, Info } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface ZapScannerProps {
  onScanComplete?: (result: any) => void;
}

interface Vulnerability {
  id: string;
  name: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  description: string;
  solution: string;
  url: string;
  parameter?: string;
  evidence?: string;
  cwe?: string;
  wascid?: string;
}

interface ScanSummary {
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  scanTime: string;
}

export default function ZapScanner({ onScanComplete }: ZapScannerProps) {
  const [target, setTarget] = useState<string>('');
  const [scanMode, setScanMode] = useState<string>('passive');
  const [scanDepth, setScanDepth] = useState<string>('quick');
  const [spiderScan, setSpiderScan] = useState<boolean>(true);
  const [ajaxScan, setAjaxScan] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Effect to clear errors when inputs change
  useEffect(() => {
    setError(null);
  }, [target, scanMode, scanDepth, spiderScan, ajaxScan]);
  
  // Function to simulate scan progress updates
  useEffect(() => {
    let progressInterval: NodeJS.Timeout;
    
    if (isScanning && scanProgress < 100) {
      progressInterval = setInterval(() => {
        setScanProgress(prev => {
          const increment = Math.floor(Math.random() * 5) + 1;
          const newProgress = Math.min(prev + increment, 100);
          
          // When reaching 100%, complete the scan
          if (newProgress === 100) {
            completeScan();
          }
          
          return newProgress;
        });
      }, scanDepth === 'quick' ? 500 : scanDepth === 'standard' ? 800 : 1200);
    }
    
    return () => {
      if (progressInterval) clearInterval(progressInterval);
    };
  }, [isScanning, scanProgress]);
  
  // Start the scan process
  const startScan = () => {
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
    setScanProgress(0);
    setVulnerabilities([]);
    setScanSummary(null);
    setSelectedVulnerability(null);
    setError(null);
    
    const scanOptions = {
      mode: scanMode,
      depth: scanDepth,
      spider: spiderScan,
      ajax: ajaxScan
    };
    
    addCommandLine(`zap-scan --target ${target} --mode ${scanMode} --depth ${scanDepth}${spiderScan ? ' --spider' : ''}${ajaxScan ? ' --ajax' : ''}`);
    addInfoLine(`Initializing ZAP scan on ${target}`);
    addInfoLine(`Scan mode: ${scanMode}, Depth: ${scanDepth}`);
    
    if (spiderScan) {
      addSystemLine("Starting spider scan to discover content...");
    }
    
    if (scanMode === 'active') {
      addSystemLine("Warning: Active scan mode will attempt to find vulnerabilities by testing the target.");
    }
  };
  
  // Reset the scan
  const resetScan = () => {
    setIsScanning(false);
    setScanProgress(0);
    setVulnerabilities([]);
    setScanSummary(null);
    setSelectedVulnerability(null);
    addInfoLine("ZAP scan reset. Ready for new scan.");
  };
  
  // Simulate completing the scan with randomized results
  const completeScan = () => {
    setIsScanning(false);
    
    // Create simulated vulnerabilities based on scan mode and depth
    const simulatedVulns: Vulnerability[] = [];
    
    // More vulnerabilities found in active mode and deeper scans
    const vulnCount = scanMode === 'active' 
      ? (scanDepth === 'quick' ? 8 : scanDepth === 'standard' ? 15 : 25)
      : (scanDepth === 'quick' ? 3 : scanDepth === 'standard' ? 7 : 12);
    
    // Common web vulnerabilities
    const vulnTemplates = [
      {
        name: "Cross-Site Scripting (XSS)",
        description: "Cross-site Scripting (XSS) is an attack that allows attackers to inject client-side scripts into web pages viewed by other users.",
        solution: "Filter input on arrival. Encode data on output. Use appropriate response headers. Use Content Security Policy.",
        risk: "High",
        cwe: "79",
        wascid: "8"
      },
      {
        name: "SQL Injection",
        description: "SQL injection may be possible. A malicious SQL query could potentially read sensitive data or modify database contents.",
        solution: "Use prepared statements and parameterized queries. Use stored procedures. Validate user input.",
        risk: "High",
        cwe: "89",
        wascid: "19"
      },
      {
        name: "Sensitive Information Disclosure",
        description: "The application may be revealing sensitive information in error messages or HTTP headers.",
        solution: "Ensure proper error handling and disable verbose error messages in production. Configure HTTP headers appropriately.",
        risk: "Medium",
        cwe: "200",
        wascid: "13"
      },
      {
        name: "Cross-Site Request Forgery (CSRF)",
        description: "The application appears to allow Cross-Site Request Forgery attacks. This could allow attackers to perform actions as authenticated users.",
        solution: "Implement anti-CSRF tokens. Use the SameSite cookie attribute. Check the origin header.",
        risk: "Medium",
        cwe: "352",
        wascid: "9"
      },
      {
        name: "Server Information Disclosure",
        description: "The web server is revealing version information in HTTP headers or error messages.",
        solution: "Configure web server to prevent information leakage in headers and error pages.",
        risk: "Low",
        cwe: "200",
        wascid: "13"
      },
      {
        name: "Missing Security Headers",
        description: "The application is missing important security headers that could protect against common attacks.",
        solution: "Implement security headers such as Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options.",
        risk: "Low",
        cwe: "693",
        wascid: "15"
      },
      {
        name: "Cookie Without Secure Flag",
        description: "A cookie is set without the secure flag, which means it can be transmitted over unencrypted connections.",
        solution: "Set the secure flag on all cookies that are used for sensitive functions or authentication.",
        risk: "Low",
        cwe: "614",
        wascid: "13"
      },
      {
        name: "Content Type Not Specified",
        description: "The Content-Type header is missing or not specified, which can lead to content sniffing attacks.",
        solution: "Specify a Content-Type header for all responses and use X-Content-Type-Options: nosniff.",
        risk: "Informational",
        cwe: "173",
        wascid: "15"
      }
    ];
    
    // Generate random set of vulnerabilities
    for (let i = 0; i < vulnCount; i++) {
      // Select random vulnerability template
      const template = vulnTemplates[Math.floor(Math.random() * vulnTemplates.length)];
      
      // Determine risk level with weighted probability
      const riskProb = Math.random();
      let risk: 'High' | 'Medium' | 'Low' | 'Informational';
      
      if (scanMode === 'active') {
        // Active scans find more high/medium risks
        if (riskProb < 0.25) risk = 'High';
        else if (riskProb < 0.5) risk = 'Medium';
        else if (riskProb < 0.8) risk = 'Low';
        else risk = 'Informational';
      } else {
        // Passive scans find mostly low/info risks
        if (riskProb < 0.1) risk = 'High';
        else if (riskProb < 0.3) risk = 'Medium';
        else if (riskProb < 0.7) risk = 'Low';
        else risk = 'Informational';
      }
      
      // Generate random confidence
      const confProb = Math.random();
      let confidence: 'High' | 'Medium' | 'Low';
      
      if (confProb < 0.3) confidence = 'High';
      else if (confProb < 0.7) confidence = 'Medium';
      else confidence = 'Low';
      
      // Generate random paths and parameters
      const paths = [
        '/login',
        '/admin',
        '/search',
        '/profile',
        '/settings',
        '/api/users',
        '/products',
        '/checkout'
      ];
      
      const params = [
        'id',
        'username',
        'q',
        'page',
        'token',
        'redirect',
        'category',
        'sort'
      ];
      
      const path = paths[Math.floor(Math.random() * paths.length)];
      const param = params[Math.floor(Math.random() * params.length)];
      const evidence = risk === 'High' || risk === 'Medium' 
        ? template.name.includes('XSS') 
          ? '<script>alert(1)</script>' 
          : template.name.includes('SQL') 
            ? "' OR 1=1 --" 
            : 'N/A'
        : 'N/A';
      
      // Create vulnerability object
      simulatedVulns.push({
        id: `ZAP-${i+1}`,
        name: template.name,
        risk: risk,
        confidence: confidence,
        description: template.description,
        solution: template.solution,
        url: `${target}${path}${param ? `?${param}=value` : ''}`,
        parameter: param || undefined,
        evidence: evidence !== 'N/A' ? evidence : undefined,
        cwe: template.cwe,
        wascid: template.wascid
      });
    }
    
    // Sort by risk severity
    simulatedVulns.sort((a, b) => {
      const riskOrder = { 'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3 };
      return riskOrder[a.risk] - riskOrder[b.risk];
    });
    
    // Calculate summary
    const high = simulatedVulns.filter(v => v.risk === 'High').length;
    const medium = simulatedVulns.filter(v => v.risk === 'Medium').length;
    const low = simulatedVulns.filter(v => v.risk === 'Low').length;
    const info = simulatedVulns.filter(v => v.risk === 'Informational').length;
    
    const summary: ScanSummary = {
      high,
      medium,
      low,
      info,
      total: simulatedVulns.length,
      scanTime: `${Math.floor(Math.random() * 5) + 1}m ${Math.floor(Math.random() * 50) + 10}s`
    };
    
    // Update state
    setVulnerabilities(simulatedVulns);
    setScanSummary(summary);
    
    // Add terminal output
    addLine(`[COMPLETE] ZAP scan completed in ${summary.scanTime}`, "success");
    addInfoLine(`Found ${summary.total} potential vulnerabilities:`);
    if (high > 0) addLine(`High Risk: ${high}`, "error");
    if (medium > 0) addLine(`Medium Risk: ${medium}`, "warning");
    if (low > 0) addLine(`Low Risk: ${low}`, "info");
    if (info > 0) addLine(`Informational: ${info}`, "info");
    
    // Show toast notification
    toast({
      title: "Scan Complete",
      description: `Found ${summary.total} potential vulnerabilities`,
      variant: "default",
    });
    
    // Call the completion callback if provided
    if (onScanComplete) {
      onScanComplete({
        target,
        options: {
          mode: scanMode,
          depth: scanDepth,
          spider: spiderScan,
          ajax: ajaxScan
        },
        summary,
        vulnerabilities: simulatedVulns,
        timestamp: new Date()
      });
    }
  };
  
  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'High':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'Medium':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'Low':
        return <Bug className="h-4 w-4 text-yellow-500" />;
      default:
        return <Info className="h-4 w-4 text-blue-500" />;
    }
  };
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'High':
        return 'text-red-500';
      case 'Medium':
        return 'text-orange-500';
      case 'Low':
        return 'text-yellow-500';
      default:
        return 'text-blue-500';
    }
  };
  
  const getConfidenceIcon = (confidence: string) => {
    switch (confidence) {
      case 'High':
        return <Check className="h-4 w-4 text-green-500" />;
      case 'Medium':
        return <Check className="h-4 w-4 text-yellow-500" />;
      case 'Low':
        return <X className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">OWASP ZAP Scanner</h2>
        
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
              Enter the full URL of the web application to scan, including http:// or https://
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                  <SelectItem value="passive">Passive (Non-intrusive)</SelectItem>
                  <SelectItem value="active">Active (Tests vulnerabilities)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="scan-depth" className="text-sm font-tech">
                Scan Depth
              </Label>
              <Select 
                defaultValue={scanDepth} 
                onValueChange={setScanDepth}
                disabled={isScanning}
              >
                <SelectTrigger id="scan-depth" className="font-mono">
                  <SelectValue placeholder="Select depth" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="quick">Quick (Basic checks)</SelectItem>
                  <SelectItem value="standard">Standard (Default policies)</SelectItem>
                  <SelectItem value="deep">Deep (All policies)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="spider-scan" 
                checked={spiderScan}
                onCheckedChange={(checked) => setSpiderScan(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="spider-scan" 
                className="text-sm font-tech cursor-pointer"
              >
                Run Spider (crawl site)
              </Label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="ajax-scan" 
                checked={ajaxScan}
                onCheckedChange={(checked) => setAjaxScan(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="ajax-scan" 
                className="text-sm font-tech cursor-pointer"
              >
                AJAX Spider (for JS-heavy apps)
              </Label>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            {!isScanning && (
              <Button
                onClick={startScan}
                className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
              >
                <Play className="h-4 w-4 mr-2" />
                Start Scan
              </Button>
            )}
            
            <Button
              onClick={resetScan}
              variant="outline"
              disabled={isScanning}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
          
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Scan in progress...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="h-2" />
              <p className="text-xs font-mono text-muted-foreground animate-pulse">
                {scanProgress < 25 ? "Initializing scan..." : 
                 scanProgress < 50 ? "Analyzing target..." :
                 scanProgress < 75 ? "Detecting vulnerabilities..." :
                 "Generating report..."}
              </p>
            </div>
          )}
        </div>
      </Card>
      
      {scanSummary && vulnerabilities.length > 0 && (
        <Card className="p-4 border-secondary/30 bg-card">
          <h2 className="text-lg font-tech text-secondary mb-4">Scan Results</h2>
          
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border text-center">
                <div className="text-xs font-mono text-muted-foreground">Total</div>
                <div className="text-2xl font-tech">{scanSummary.total}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-red-500/30 text-center">
                <div className="text-xs font-mono text-muted-foreground">High Risk</div>
                <div className="text-2xl font-tech text-red-500">{scanSummary.high}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-orange-500/30 text-center">
                <div className="text-xs font-mono text-muted-foreground">Medium Risk</div>
                <div className="text-2xl font-tech text-orange-500">{scanSummary.medium}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-yellow-500/30 text-center">
                <div className="text-xs font-mono text-muted-foreground">Low Risk</div>
                <div className="text-2xl font-tech text-yellow-500">{scanSummary.low}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-blue-500/30 text-center">
                <div className="text-xs font-mono text-muted-foreground">Info</div>
                <div className="text-2xl font-tech text-blue-500">{scanSummary.info}</div>
              </div>
            </div>
            
            <Tabs defaultValue="alerts" className="w-full">
              <TabsList className="grid grid-cols-2 mb-2">
                <TabsTrigger value="alerts" className="text-xs font-mono">Alerts ({vulnerabilities.length})</TabsTrigger>
                <TabsTrigger value="details" className="text-xs font-mono" disabled={!selectedVulnerability}>
                  Alert Details
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="alerts" className="border border-border rounded-md">
                <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                  <div className="col-span-1">Risk</div>
                  <div className="col-span-4">Name</div>
                  <div className="col-span-1">CWE</div>
                  <div className="col-span-5">URL</div>
                  <div className="col-span-1">Conf.</div>
                </div>
                
                <div className="max-h-64 overflow-y-auto">
                  {vulnerabilities.map((vuln, index) => (
                    <div 
                      key={index}
                      className={cn(
                        "p-2 grid grid-cols-12 gap-2 font-mono text-xs cursor-pointer hover:bg-primary/5",
                        index % 2 === 0 ? "bg-background" : "bg-muted",
                        selectedVulnerability?.id === vuln.id ? "bg-primary/10 border-l-2 border-l-primary" : ""
                      )}
                      onClick={() => setSelectedVulnerability(vuln)}
                    >
                      <div className="col-span-1 flex items-center">
                        {getRiskIcon(vuln.risk)}
                      </div>
                      <div className="col-span-4 truncate font-medium">
                        {vuln.name}
                      </div>
                      <div className="col-span-1">
                        {vuln.cwe}
                      </div>
                      <div className="col-span-5 truncate text-muted-foreground">
                        {vuln.url}
                      </div>
                      <div className="col-span-1 flex items-center justify-center">
                        {getConfidenceIcon(vuln.confidence)}
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>
              
              <TabsContent value="details">
                {selectedVulnerability && (
                  <div className="border border-border rounded-md p-4 space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <h3 className="text-lg font-tech flex items-center gap-2">
                          {getRiskIcon(selectedVulnerability.risk)}
                          <span>{selectedVulnerability.name}</span>
                        </h3>
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <span className={cn("px-2 py-0.5 rounded-sm", 
                            selectedVulnerability.risk === 'High' ? "bg-red-500/20 text-red-500" :
                            selectedVulnerability.risk === 'Medium' ? "bg-orange-500/20 text-orange-500" :
                            selectedVulnerability.risk === 'Low' ? "bg-yellow-500/20 text-yellow-500" :
                            "bg-blue-500/20 text-blue-500"
                          )}>
                            {selectedVulnerability.risk} Risk
                          </span>
                          <span className="px-2 py-0.5 rounded-sm bg-secondary/20 text-secondary">
                            {selectedVulnerability.confidence} Confidence
                          </span>
                          {selectedVulnerability.cwe && (
                            <span className="px-2 py-0.5 rounded-sm bg-primary/20 text-primary">
                              CWE-{selectedVulnerability.cwe}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    
                    <div className="space-y-3 text-sm font-mono">
                      <div>
                        <h4 className="text-xs text-muted-foreground mb-1">URL</h4>
                        <div className="p-2 bg-background rounded-sm break-all">
                          {selectedVulnerability.url}
                        </div>
                      </div>
                      
                      {selectedVulnerability.parameter && (
                        <div>
                          <h4 className="text-xs text-muted-foreground mb-1">Parameter</h4>
                          <div className="p-2 bg-background rounded-sm">
                            {selectedVulnerability.parameter}
                          </div>
                        </div>
                      )}
                      
                      {selectedVulnerability.evidence && (
                        <div>
                          <h4 className="text-xs text-muted-foreground mb-1">Evidence</h4>
                          <div className="p-2 bg-background rounded-sm font-mono text-primary break-all">
                            {selectedVulnerability.evidence}
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
                        <h4 className="text-xs text-muted-foreground mb-1">Solution</h4>
                        <p className="p-2 bg-background rounded-sm text-xs">
                          {selectedVulnerability.solution}
                        </p>
                      </div>
                      
                      <div className="flex items-center text-xs text-muted-foreground mt-2">
                        <Shield className="h-3 w-3 mr-1" />
                        <span>
                          This is a simulated result for educational purposes. 
                          In a real ZAP integration, this would show actual scan findings.
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </div>
        </Card>
      )}
    </div>
  );
}