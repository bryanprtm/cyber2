import React, { useState } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  AlertCircle, 
  Globe, 
  Shield, 
  ShieldAlert, 
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Info,
  ExternalLink,
  Lock,
  ArrowLeftRight,
  Code
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface CorsTesterProps {
  onTestComplete?: (result: any) => void;
}

export default function CorsTester({ onTestComplete }: CorsTesterProps) {
  const [url, setUrl] = useState<string>('');
  const [withCredentials, setWithCredentials] = useState<boolean>(true);
  const [customMethods, setCustomMethods] = useState<string>('GET,POST,PUT,DELETE,OPTIONS');
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [testResults, setTestResults] = useState<any>(null);
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
  
  const handleTest = async () => {
    // Normalize URL if needed
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    if (!isValidUrl(normalizedUrl)) {
      setError('Invalid URL format. Example: https://example.com');
      addErrorLine('Error: Invalid URL format. Example: https://example.com');
      return;
    }
    
    setError(null);
    setIsTesting(true);
    setProgress(0);
    setTestResults(null);
    
    addCommandLine(`Starting CORS test for ${normalizedUrl}...`);
    addInfoLine(`Testing URL: ${normalizedUrl}`);
    addInfoLine(`Using credentials: ${withCredentials}`);
    addInfoLine(`Testing methods: ${customMethods}`);
    
    // Simulate progress for UX
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + 10;
      });
    }, 300);
    
    try {
      const response = await axios.post('/api/security/cors-tester', {
        url: normalizedUrl,
        methods: customMethods,
        withCredentials
      });
      
      clearInterval(progressInterval);
      setProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setTestResults(result);
        
        // Terminal output based on results
        addSuccessLine('CORS test completed');
        
        if (result.corsEnabled) {
          addInfoLine(`CORS is enabled on ${normalizedUrl}`);
          
          if (result.accessControlAllowOrigin) {
            addInfoLine(`Access-Control-Allow-Origin: ${result.accessControlAllowOrigin}`);
          }
          
          if (result.accessControlAllowMethods) {
            addInfoLine(`Allowed Methods: ${result.accessControlAllowMethods.join(', ')}`);
          }
          
          if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            addErrorLine(`Found ${result.vulnerabilities.length} CORS configuration issues:`);
            result.vulnerabilities.slice(0, 3).forEach((vuln: any) => {
              addErrorLine(`- ${vuln.type} (${vuln.severity}): ${vuln.description}`);
            });
          }
        } else {
          addInfoLine('CORS is not explicitly enabled on this URL');
        }
        
        // Add security rating info
        const securityColor = 
          result.securityRating.overall === 'Safe' ? "text-green-500" :
          result.securityRating.overall === 'Somewhat Safe' ? "text-blue-500" :
          result.securityRating.overall === 'Potentially Unsafe' ? "text-amber-500" :
          "text-red-500";
        
        addInfoLine(`Security Rating: ${result.securityRating.overall} (${result.securityRating.score}/100)`);
        
        if (onTestComplete) {
          onTestComplete(result);
        }
        
        toast({
          title: 'CORS Test completed',
          description: `Results: ${result.securityRating.overall} (${result.securityRating.score}/100)`,
          variant: 'default'
        });
        
      } else {
        setError(response.data.message || 'Failed to test CORS');
        addErrorLine(`Error: ${response.data.message}`);
      }
    } catch (err: any) {
      clearInterval(progressInterval);
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred';
      setError(errorMessage);
      addErrorLine(`Error: ${errorMessage}`);
      
      toast({
        title: 'Test failed',
        description: errorMessage,
        variant: 'destructive'
      });
    } finally {
      setIsTesting(false);
    }
  };
  
  const handleReset = () => {
    setUrl('');
    setTestResults(null);
    setError(null);
    setProgress(0);
    addCommandLine('Reset CORS tester');
  };
  
  // Get color based on security rating
  const getSecurityColor = (rating: string): string => {
    switch (rating) {
      case 'Safe':
        return 'text-green-500 border-green-500';
      case 'Somewhat Safe':
        return 'text-blue-500 border-blue-500';
      case 'Potentially Unsafe':
        return 'text-amber-500 border-amber-500';
      case 'Unsafe':
        return 'text-red-500 border-red-500';
      default:
        return 'text-muted-foreground border-muted-foreground';
    }
  };
  
  // Get icon based on security rating
  const getSecurityIcon = (rating: string) => {
    switch (rating) {
      case 'Safe':
        return <ShieldCheck className="h-5 w-5 text-green-500" />;
      case 'Somewhat Safe':
        return <Shield className="h-5 w-5 text-blue-500" />;
      case 'Potentially Unsafe':
        return <ShieldAlert className="h-5 w-5 text-amber-500" />;
      case 'Unsafe':
        return <AlertCircle className="h-5 w-5 text-red-500" />;
      default:
        return <Shield className="h-5 w-5 text-muted-foreground" />;
    }
  };
  
  // Get color based on severity
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'Critical':
        return 'text-red-600 border-red-600';
      case 'High':
        return 'text-red-500 border-red-500';
      case 'Medium':
        return 'text-amber-500 border-amber-500';
      case 'Low':
        return 'text-yellow-500 border-yellow-500';
      default:
        return 'text-muted-foreground border-muted-foreground';
    }
  };
  
  // Get status indicators
  const getStatusIndicator = (status: boolean) => {
    return status ? 
      <CheckCircle2 className="h-4 w-4 text-green-500" /> : 
      <XCircle className="h-4 w-4 text-red-500" />;
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">CORS Configuration Tester</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url" className="text-sm font-tech">URL to Test</Label>
            <Input
              id="url"
              placeholder="https://example.com/api"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono bg-background border-secondary/50"
              disabled={isTesting}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the URL of the API or resource you want to test for CORS configuration
            </p>
          </div>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="methods" className="text-sm font-tech">HTTP Methods to Test</Label>
              <Input
                id="methods"
                placeholder="GET,POST,PUT,DELETE,OPTIONS"
                value={customMethods}
                onChange={(e) => setCustomMethods(e.target.value)}
                className="font-mono bg-background border-secondary/50"
                disabled={isTesting}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Comma-separated list of HTTP methods to test
              </p>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="with-credentials" 
                checked={withCredentials}
                onCheckedChange={(checked) => setWithCredentials(!!checked)}
                disabled={isTesting}
              />
              <Label 
                htmlFor="with-credentials" 
                className="text-sm font-tech cursor-pointer"
              >
                Test with credentials (cookies, HTTP auth)
              </Label>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          {isTesting && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Testing CORS configuration...</span>
                <span>{progress}%</span>
              </div>
              <div className="h-1.5 w-full bg-secondary/20 rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleTest}
              disabled={isTesting || !url}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isTesting ? 'Testing...' : 'Test CORS'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isTesting}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {testResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid grid-cols-4 mb-4">
              <TabsTrigger value="summary" className="font-tech">Summary</TabsTrigger>
              <TabsTrigger value="config" className="font-tech">Configuration</TabsTrigger>
              <TabsTrigger value="tests" className="font-tech">Test Results</TabsTrigger>
              <TabsTrigger value="issues" className="font-tech">Issues</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">CORS Test Results</h3>
                  <p className="text-sm font-mono">{testResults.url}</p>
                </div>
                <div className={cn(
                  "px-3 py-1 rounded-full border flex items-center space-x-2",
                  getSecurityColor(testResults.securityRating.overall)
                )}>
                  {getSecurityIcon(testResults.securityRating.overall)}
                  <span className="font-tech text-sm">{testResults.securityRating.overall}</span>
                </div>
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Overview</h4>
                <div className="space-y-2 text-sm font-mono">
                  <div className="flex items-center gap-2">
                    {testResults.corsEnabled ? 
                      <CheckCircle2 className="h-4 w-4 text-green-500" /> : 
                      <Info className="h-4 w-4 text-accent" />
                    }
                    <span>{testResults.corsEnabled ? 'CORS is enabled' : 'CORS is not explicitly enabled'}</span>
                  </div>
                  
                  {testResults.corsConfig && (
                    <div className="flex items-center gap-2">
                      <Info className="h-4 w-4 text-accent" />
                      <span>Policy Type: {testResults.corsConfig.policy}</span>
                    </div>
                  )}
                  
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    <span>Security Score: {testResults.securityRating.score}/100</span>
                  </div>
                  
                  {testResults.vulnerabilities && testResults.vulnerabilities.length > 0 ? (
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-500" />
                      <span>Found {testResults.vulnerabilities.length} configuration issues</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span>No CORS configuration issues detected</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1 p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2">Headers</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between items-baseline border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Access-Control-Allow-Origin:</span>
                      <span className="max-w-[150px] truncate">
                        {testResults.accessControlAllowOrigin || 'Not set'}
                      </span>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Allow-Credentials:</span>
                      <span>{testResults.accessControlAllowCredentials ? 'true' : 'Not set'}</span>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Allowed Methods:</span>
                      <span className="max-w-[150px] truncate">
                        {testResults.accessControlAllowMethods ? 
                        testResults.accessControlAllowMethods.join(', ') : 'Not set'}
                      </span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Age:</span>
                      <span>{testResults.accessControlMaxAge || 'Not set'}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex-1 p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2">Request Tests</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Simple Request:</span>
                      <div className="flex items-center gap-1">
                        {getStatusIndicator(testResults.simpleRequest.success)}
                        <span>{testResults.simpleRequest.status}</span>
                      </div>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Preflight Request:</span>
                      <div className="flex items-center gap-1">
                        {getStatusIndicator(testResults.preflight.success)}
                        <span>{testResults.preflight.status}</span>
                      </div>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Cross-Site:</span>
                      <div className="flex items-center gap-1">
                        {getStatusIndicator(testResults.crossSiteRequest.success)}
                        <span>{testResults.crossSiteRequest.status}</span>
                      </div>
                    </div>
                    
                    {testResults.credentialedRequest && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">With Credentials:</span>
                        <div className="flex items-center gap-1">
                          {getStatusIndicator(testResults.credentialedRequest.success)}
                          <span>{testResults.credentialedRequest.status}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="config" className="space-y-4">
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-4">CORS Headers</h4>
                <div className="space-y-4">
                  <div className="space-y-1">
                    <p className="text-xs font-tech text-accent">Access-Control-Allow-Origin</p>
                    <div className="p-2 rounded bg-card border border-secondary/20 text-sm font-mono">
                      {testResults.accessControlAllowOrigin || 'Not set'}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {testResults.accessControlAllowOrigin === '*' ? 
                        'Wildcard allows any origin to access this resource' : 
                        testResults.accessControlAllowOrigin ? 
                          'Specifies which origins can access this resource' :
                          'Without this header, browsers will block cross-origin requests'}
                    </p>
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs font-tech text-accent">Access-Control-Allow-Methods</p>
                    <div className="p-2 rounded bg-card border border-secondary/20 text-sm font-mono">
                      {testResults.accessControlAllowMethods ? 
                        testResults.accessControlAllowMethods.join(', ') : 'Not set'}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Specifies which HTTP methods are allowed when accessing this resource
                    </p>
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs font-tech text-accent">Access-Control-Allow-Headers</p>
                    <div className="p-2 rounded bg-card border border-secondary/20 text-sm font-mono">
                      {testResults.accessControlAllowHeaders ? 
                        testResults.accessControlAllowHeaders.join(', ') : 'Not set'}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Specifies which HTTP headers can be used when making a request
                    </p>
                  </div>
                  
                  <div className="space-y-1">
                    <p className="text-xs font-tech text-accent">Access-Control-Allow-Credentials</p>
                    <div className="p-2 rounded bg-card border border-secondary/20 text-sm font-mono">
                      {testResults.accessControlAllowCredentials ? 'true' : 'Not set'}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Indicates whether the response can be shared when request includes credentials
                    </p>
                  </div>
                  
                  {testResults.accessControlExposeHeaders && (
                    <div className="space-y-1">
                      <p className="text-xs font-tech text-accent">Access-Control-Expose-Headers</p>
                      <div className="p-2 rounded bg-card border border-secondary/20 text-sm font-mono">
                        {testResults.accessControlExposeHeaders.join(', ')}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Specifies which headers are accessible to JavaScript
                      </p>
                    </div>
                  )}
                </div>
              </div>
              
              {testResults.corsConfig && (
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2">CORS Policy Analysis</h4>
                  <div className="space-y-2 text-sm font-mono">
                    <div className="flex items-start gap-2">
                      <Info className="h-4 w-4 text-accent mt-0.5" />
                      <div>
                        <p className="font-tech">Policy Type</p>
                        <p className="text-xs">{testResults.corsConfig.policy}</p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      {testResults.corsConfig.wildcard ? 
                        <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5" /> : 
                        <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5" />
                      }
                      <div>
                        <p className="font-tech">Wildcard Usage</p>
                        <p className="text-xs">
                          {testResults.corsConfig.wildcard ? 
                            'Uses wildcard (*) which allows any origin' : 
                            'No wildcard used - more restrictive security'}
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      {testResults.corsConfig.permissive ? 
                        <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5" /> : 
                        <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5" />
                      }
                      <div>
                        <p className="font-tech">Policy Restrictiveness</p>
                        <p className="text-xs">
                          {testResults.corsConfig.permissive ? 
                            'Permissive - allows multiple origins' : 
                            testResults.corsConfig.restrictive ?
                              'Restrictive - limited to specific origins' :
                              'Unknown policy pattern'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="tests" className="space-y-4">
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-4">Method Support</h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {Object.entries(testResults.methodsSupported).map(([method, supported]) => (
                    <div key={method} className={cn(
                      "p-2 rounded text-center border",
                      supported ? "border-green-500 bg-green-500/5" : "border-secondary/20 bg-card"
                    )}>
                      <div className="font-tech text-sm">{method}</div>
                      <div className="text-xs font-mono mt-1">
                        {supported ? 
                          <span className="text-green-500">Supported</span> : 
                          <span className="text-muted-foreground">Not Supported</span>
                        }
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <ArrowLeftRight className="h-4 w-4 text-primary" />
                    Simple Request Test
                  </h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Status:</span>
                      <span className={testResults.simpleRequest.status >= 200 && testResults.simpleRequest.status < 300 ? 
                        "text-green-500" : "text-amber-500"}>
                        {testResults.simpleRequest.status}
                      </span>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Success:</span>
                      <span className={testResults.simpleRequest.success ? "text-green-500" : "text-red-500"}>
                        {testResults.simpleRequest.success ? "Yes" : "No"}
                      </span>
                    </div>
                    
                    <div className="flex items-start justify-between">
                      <span className="text-muted-foreground">Headers:</span>
                      <div className="text-right">
                        {testResults.accessControlAllowOrigin && (
                          <div className="text-green-500">CORS headers present</div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <Code className="h-4 w-4 text-primary" />
                    Preflight Request Test
                  </h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Status:</span>
                      <span className={testResults.preflight.status >= 200 && testResults.preflight.status < 300 ? 
                        "text-green-500" : "text-amber-500"}>
                        {testResults.preflight.status}
                      </span>
                    </div>
                    
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Success:</span>
                      <span className={testResults.preflight.success ? "text-green-500" : "text-red-500"}>
                        {testResults.preflight.success ? "Yes" : "No"}
                      </span>
                    </div>
                    
                    <div className="flex flex-col mt-1">
                      <span className="text-muted-foreground mb-1">What this means:</span>
                      <span className={testResults.preflight.success ? "text-green-500" : "text-amber-500"}>
                        {testResults.preflight.success ? 
                          "Properly handles OPTIONS preflight requests" : 
                          "May not support complex cross-origin requests"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <ExternalLink className="h-4 w-4 text-primary" />
                    Cross-Site Request Test
                  </h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                      <span className="text-muted-foreground">Foreign Origin:</span>
                      <span className={testResults.crossSiteRequest.success ? "text-green-500" : "text-red-500"}>
                        {testResults.crossSiteRequest.success ? "Allowed" : "Blocked"}
                      </span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Security Assessment:</span>
                      <span className={testResults.crossSiteRequest.success && testResults.accessControlAllowOrigin === '*' ? 
                        "text-amber-500" : "text-green-500"}>
                        {testResults.crossSiteRequest.success && testResults.accessControlAllowOrigin === '*' ? 
                          "Potentially permissive" : 
                          testResults.crossSiteRequest.success ?
                            "Configured for cross-origin" : 
                            "Restrictive"}
                      </span>
                    </div>
                  </div>
                </div>
                
                {testResults.credentialedRequest && (
                  <div className="p-4 bg-background rounded-md border border-secondary/20">
                    <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                      <Lock className="h-4 w-4 text-primary" />
                      Credentialed Request Test
                    </h4>
                    <div className="space-y-2 text-xs font-mono">
                      <div className="flex justify-between border-b border-dashed border-secondary/20 pb-1">
                        <span className="text-muted-foreground">With Credentials:</span>
                        <span className={testResults.credentialedRequest.success ? "text-green-500" : "text-red-500"}>
                          {testResults.credentialedRequest.success ? "Supported" : "Not Supported"}
                        </span>
                      </div>
                      
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Allow-Credentials Header:</span>
                        <span className={testResults.accessControlAllowCredentials ? "text-green-500" : "text-amber-500"}>
                          {testResults.accessControlAllowCredentials ? "Present" : "Missing"}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="issues">
              {testResults.vulnerabilities && testResults.vulnerabilities.length > 0 ? (
                <div className="space-y-4">
                  <h4 className="text-sm font-tech text-secondary">CORS Configuration Issues</h4>
                  
                  <div className="space-y-3">
                    {testResults.vulnerabilities.map((vuln: any, i: number) => (
                      <div key={i} className="p-4 bg-background rounded-md border border-secondary/20">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className={cn("h-4 w-4", getSeverityColor(vuln.severity))} />
                            <h5 className="text-sm font-tech">{vuln.type}</h5>
                          </div>
                          <Badge variant="outline" className={cn("text-xs", getSeverityColor(vuln.severity))}>
                            {vuln.severity}
                          </Badge>
                        </div>
                        
                        <p className="text-xs font-mono mb-2">{vuln.description}</p>
                        
                        {vuln.impact && (
                          <div className="mt-2">
                            <p className="text-xs font-tech text-muted-foreground">Impact:</p>
                            <p className="text-xs font-mono">{vuln.impact}</p>
                          </div>
                        )}
                        
                        {vuln.recommendation && (
                          <div className="mt-2 p-2 bg-green-500/5 rounded border border-green-500/20">
                            <p className="text-xs font-tech text-green-500">Recommendation:</p>
                            <p className="text-xs font-mono">{vuln.recommendation}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8">
                  <ShieldCheck className="h-12 w-12 text-green-500 mb-4" />
                  <h4 className="text-md font-tech text-green-500 mb-2">No Issues Detected</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    The CORS configuration for this resource appears to be secure 
                    and properly implemented based on our tests.
                  </p>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}