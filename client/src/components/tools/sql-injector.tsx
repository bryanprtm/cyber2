import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { 
  Tabs, 
  TabsContent, 
  TabsList, 
  TabsTrigger 
} from "@/components/ui/tabs";
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  Database, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle,
  RefreshCw,
  Code,
  ListFilter,
  Check,
  Copy,
  Braces
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { 
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface SqlInjectorProps {
  onScanComplete?: (result: any) => void;
}

export default function SqlInjector({ onScanComplete }: SqlInjectorProps) {
  const [url, setUrl] = useState<string>('');
  const [method, setMethod] = useState<string>('GET');
  const [paramName, setParamName] = useState<string>('');
  const [payloadType, setPayloadType] = useState<string>('error-based');
  const [dbType, setDbType] = useState<string>('generic');
  const [customPayload, setCustomPayload] = useState<string>('');
  const [testAllParams, setTestAllParams] = useState<boolean>(true);
  const [timeDelay, setTimeDelay] = useState<number>(300);
  
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [availablePayloads, setAvailablePayloads] = useState<any>(null);
  const [selectedPayloadType, setSelectedPayloadType] = useState<string>('errorBased');
  const [selectedPayload, setSelectedPayload] = useState<string>('');
  
  const { addCommandLine, addInfoLine, addErrorLine, addSuccessLine } = useTerminal();
  const { toast } = useToast();
  
  /**
   * Fetch available payloads on component mount
   */
  useEffect(() => {
    fetchAvailablePayloads();
  }, []);
  
  /**
   * Fetch all available payloads from the API
   */
  const fetchAvailablePayloads = async () => {
    try {
      const response = await axios.get('/api/security/sql-injector/payloads');
      if (response.data.success) {
        setAvailablePayloads(response.data.data);
      }
    } catch (err) {
      console.error('Failed to fetch payloads:', err);
    }
  };
  
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
  
  /**
   * Copy payload to clipboard
   */
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({
        title: 'Copied to clipboard',
        description: 'Payload has been copied to your clipboard',
        duration: 2000
      });
    });
  };
  
  /**
   * Apply selected payload to custom payload textarea
   */
  const applySelectedPayload = () => {
    if (selectedPayload) {
      setCustomPayload(selectedPayload);
      toast({
        title: 'Payload applied',
        description: 'Selected payload has been applied to custom payload field',
      });
    }
  };
  
  /**
   * Start SQL injection test
   */
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
    
    addCommandLine(`Starting SQL injection test for ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Method: ${method}`);
    addInfoLine(`Payload type: ${payloadType}`);
    if (paramName) {
      addInfoLine(`Target parameter: ${paramName}`);
    }
    addInfoLine(`Database type: ${dbType}`);
    
    // Simulate progress for UX
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + Math.floor(Math.random() * 5) + 1;
      });
    }, 300);
    
    try {
      const response = await axios.post('/api/security/sql-injector', {
        url: normalizedUrl,
        method,
        paramName: paramName || undefined,
        payloadType,
        customPayload: customPayload || undefined,
        dbType,
        testAllParams,
        timeDelay
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setScanResults(result);
        
        // Terminal output based on results
        addSuccessLine('SQL injection test completed');
        
        if (result.vulnerable) {
          addErrorLine(`WARNING: ${normalizedUrl} is VULNERABLE to SQL injection!`);
          
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
          
          if (result.dbType) {
            addInfoLine(`Detected database type: ${result.dbType}`);
          }
        } else {
          addSuccessLine(`No SQL injection vulnerabilities detected in ${normalizedUrl}`);
        }
        
        if (onScanComplete) {
          onScanComplete(result);
        }
        
        toast({
          title: 'SQL injection test completed',
          description: result.vulnerable ? 'Vulnerabilities detected!' : 'No vulnerabilities found',
          variant: result.vulnerable ? 'destructive' : 'default'
        });
      } else {
        setError(response.data.message || 'Failed to test for SQL injection');
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
      setIsScanning(false);
    }
  };
  
  /**
   * Reset all form fields
   */
  const handleReset = () => {
    setUrl('');
    setMethod('GET');
    setParamName('');
    setPayloadType('error-based');
    setDbType('generic');
    setCustomPayload('');
    setTestAllParams(true);
    setTimeDelay(300);
    setScanResults(null);
    setError(null);
    setScanProgress(0);
    addCommandLine('Reset SQL injector');
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">SQL Injection Testing Tool</h2>
        
        <Tabs defaultValue="scan" className="w-full">
          <TabsList className="grid grid-cols-2 mb-4">
            <TabsTrigger value="scan" className="font-tech">Run Scan</TabsTrigger>
            <TabsTrigger value="payloads" className="font-tech">Payload Library</TabsTrigger>
          </TabsList>
          
          <TabsContent value="scan" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="url" className="text-sm font-tech">Target URL</Label>
              <Input
                id="url"
                placeholder="https://example.com/page.php?id=1"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="font-mono bg-background border-secondary/50"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter the URL with parameters to test for SQL injection vulnerabilities
              </p>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="method" className="text-sm font-tech">HTTP Method</Label>
                <Select
                  value={method}
                  onValueChange={(value) => setMethod(value)}
                  disabled={isScanning}
                >
                  <SelectTrigger id="method" className="bg-background border-secondary/50">
                    <SelectValue placeholder="Select method" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="GET">GET</SelectItem>
                    <SelectItem value="POST">POST</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="param-name" className="text-sm font-tech">Parameter Name (Optional)</Label>
                <Input
                  id="param-name"
                  placeholder="id, user, etc."
                  value={paramName}
                  onChange={(e) => setParamName(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                  disabled={isScanning}
                />
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Leave empty to test all parameters
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="payload-type" className="text-sm font-tech">Payload Type</Label>
                <Select
                  value={payloadType}
                  onValueChange={(value) => setPayloadType(value)}
                  disabled={isScanning}
                >
                  <SelectTrigger id="payload-type" className="bg-background border-secondary/50">
                    <SelectValue placeholder="Select payload type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="error-based">Error-based</SelectItem>
                    <SelectItem value="boolean-based">Boolean-based</SelectItem>
                    <SelectItem value="time-based">Time-based</SelectItem>
                    <SelectItem value="union-based">Union-based</SelectItem>
                    <SelectItem value="auth-bypass">Auth Bypass</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="db-type" className="text-sm font-tech">Database Type</Label>
                <Select
                  value={dbType}
                  onValueChange={(value) => setDbType(value)}
                  disabled={isScanning}
                >
                  <SelectTrigger id="db-type" className="bg-background border-secondary/50">
                    <SelectValue placeholder="Select database type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="generic">Generic (Auto-detect)</SelectItem>
                    <SelectItem value="mysql">MySQL</SelectItem>
                    <SelectItem value="mssql">Microsoft SQL Server</SelectItem>
                    <SelectItem value="postgresql">PostgreSQL</SelectItem>
                    <SelectItem value="oracle">Oracle</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="custom-payload" className="text-sm font-tech">Custom Payload (Optional)</Label>
              <Textarea
                id="custom-payload"
                placeholder="' OR 1=1 --"
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-24"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter your own SQL injection payload or select one from the Payload Library tab
              </p>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="test-all-params" 
                    checked={testAllParams}
                    onCheckedChange={(checked) => setTestAllParams(!!checked)}
                    disabled={isScanning}
                  />
                  <Label 
                    htmlFor="test-all-params" 
                    className="text-sm font-tech cursor-pointer"
                  >
                    Test all parameters
                  </Label>
                </div>
                <p className="text-xs font-mono text-muted-foreground ml-6">
                  When enabled, all URL parameters will be tested
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="time-delay" className="text-sm font-tech">Request Delay (ms)</Label>
                <Input
                  id="time-delay"
                  type="number"
                  min={100}
                  max={2000}
                  value={timeDelay}
                  onChange={(e) => setTimeDelay(Number(e.target.value))}
                  className="font-mono bg-background border-secondary/50"
                  disabled={isScanning}
                />
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Delay between requests (ms)
                </p>
              </div>
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
                  <span>Testing for SQL injection vulnerabilities...</span>
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
                {isScanning ? 'Testing...' : 'Start Test'}
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
          </TabsContent>
          
          <TabsContent value="payloads" className="space-y-4">
            {availablePayloads ? (
              <>
                <div className="space-y-2">
                  <Label htmlFor="payload-category" className="text-sm font-tech">Payload Category</Label>
                  <Select
                    value={selectedPayloadType}
                    onValueChange={(value) => setSelectedPayloadType(value)}
                  >
                    <SelectTrigger id="payload-category" className="bg-background border-secondary/50">
                      <SelectValue placeholder="Select payload category" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="errorBased">Error-based</SelectItem>
                      <SelectItem value="booleanBased">Boolean-based</SelectItem>
                      <SelectItem value="timeBased">Time-based</SelectItem>
                      <SelectItem value="unionBased">Union-based</SelectItem>
                      <SelectItem value="authBypass">Authentication Bypass</SelectItem>
                      <SelectItem value="mysql">MySQL Specific</SelectItem>
                      <SelectItem value="mssql">MSSQL Specific</SelectItem>
                      <SelectItem value="postgresql">PostgreSQL Specific</SelectItem>
                      <SelectItem value="oracle">Oracle Specific</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="bg-background border border-secondary/30 rounded-md p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-md font-tech text-accent">
                      {selectedPayloadType === 'errorBased' && 'Error-based Payloads'}
                      {selectedPayloadType === 'booleanBased' && 'Boolean-based Payloads'}
                      {selectedPayloadType === 'timeBased' && 'Time-based Payloads'}
                      {selectedPayloadType === 'unionBased' && 'Union-based Payloads'}
                      {selectedPayloadType === 'authBypass' && 'Authentication Bypass Payloads'}
                      {selectedPayloadType === 'mysql' && 'MySQL Specific Payloads'}
                      {selectedPayloadType === 'mssql' && 'MSSQL Specific Payloads'}
                      {selectedPayloadType === 'postgresql' && 'PostgreSQL Specific Payloads'}
                      {selectedPayloadType === 'oracle' && 'Oracle Specific Payloads'}
                    </h3>
                    
                    <Badge variant="outline" className="bg-accent/10 border-accent/30 text-accent font-mono">
                      {availablePayloads[selectedPayloadType].length} payloads
                    </Badge>
                  </div>
                  
                  <div className="space-y-2 max-h-60 overflow-y-auto pr-2">
                    {availablePayloads[selectedPayloadType].map((payload: string, index: number) => (
                      <div 
                        key={index}
                        className={cn(
                          "p-2 rounded-md font-mono text-xs border flex items-center justify-between",
                          selectedPayload === payload
                            ? "bg-accent/10 border-accent/50"
                            : "bg-secondary/5 border-secondary/20 hover:border-secondary/40"
                        )}
                        onClick={() => setSelectedPayload(payload)}
                      >
                        <div className="flex items-center">
                          {selectedPayload === payload && (
                            <Check className="h-3 w-3 text-accent mr-2" />
                          )}
                          <code>{payload}</code>
                        </div>
                        
                        <div>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 w-6 p-0 text-muted-foreground hover:text-accent"
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(payload);
                            }}
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  <div className="mt-4 flex justify-end">
                    <Button
                      onClick={applySelectedPayload}
                      disabled={!selectedPayload}
                      size="sm"
                      className="text-xs"
                    >
                      <Code className="h-3.5 w-3.5 mr-1.5" />
                      Apply Selected Payload
                    </Button>
                  </div>
                </div>
                
                <div className="p-3 rounded-md bg-yellow-500/10 border border-yellow-500/30 text-yellow-500 text-xs">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 mt-0.5" />
                    <div>
                      <p className="font-tech">Educational Use Only</p>
                      <p className="mt-1 font-mono">
                        These payloads are provided for educational and authorized security testing purposes only.
                        Unauthorized testing against systems you don't own may be illegal.
                      </p>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center p-6">
                <RefreshCw className="h-5 w-5 mr-2 animate-spin text-muted-foreground" />
                <span className="text-sm font-mono text-muted-foreground">Loading payloads...</span>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid grid-cols-3 mb-4">
              <TabsTrigger value="summary" className="font-tech">Summary</TabsTrigger>
              <TabsTrigger value="payloads" className="font-tech">Successful Payloads</TabsTrigger>
              <TabsTrigger value="details" className="font-tech">Technical Details</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">SQL Injection Test Results</h3>
                  <p className="text-sm font-mono">{scanResults.url}</p>
                </div>
                <div className={cn(
                  "px-3 py-1 rounded-full border flex items-center space-x-2",
                  scanResults.vulnerable
                    ? "text-red-500 border-red-500/50 bg-red-500/10"
                    : "text-green-500 border-green-500/50 bg-green-500/10"
                )}>
                  {scanResults.vulnerable ? (
                    <ShieldAlert className="h-4 w-4" />
                  ) : (
                    <ShieldCheck className="h-4 w-4" />
                  )}
                  <span className="font-tech text-sm">
                    {scanResults.vulnerable ? 'Vulnerable' : 'Not Vulnerable'}
                  </span>
                </div>
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Scan Overview</h4>
                <div className="space-y-3 text-sm font-mono">
                  {scanResults.dbType && (
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Database Type:</span>
                      <Badge className="font-mono bg-accent/20 text-accent border-0">
                        <Database className="h-3 w-3 mr-1" />
                        {scanResults.dbType.toUpperCase()}
                      </Badge>
                    </div>
                  )}
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Detection Method:</span>
                    <span>{scanResults.detectionMethod}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Parameters Tested:</span>
                    <span>{scanResults.testedParams.join(', ') || 'None'}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Vulnerable Parameters:</span>
                    {scanResults.vulnerableParams.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {scanResults.vulnerableParams.map((param: string, i: number) => (
                          <Badge key={i} variant="outline" className="bg-red-500/10 text-red-500 border-red-500/30">
                            {param}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <span>None</span>
                    )}
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
              </div>
              
              {scanResults.vulnerable && (
                <div className="mt-4 p-3 bg-red-500/10 rounded-md border border-red-500/30 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                  <div>
                    <p className="text-sm font-tech text-red-500">SQL Injection Vulnerability Detected!</p>
                    <p className="text-xs font-mono mt-1">
                      The application is vulnerable to SQL injection attacks, which could allow unauthorized
                      access to the database, data theft, or manipulation of database contents.
                    </p>
                    <div className="mt-2">
                      <p className="text-xs font-tech text-red-500">Recommended Actions:</p>
                      <ul className="list-disc list-inside text-xs font-mono mt-1">
                        <li>Use parameterized queries or prepared statements</li>
                        <li>Apply input validation and sanitization</li>
                        <li>Implement proper error handling to prevent information leakage</li>
                        <li>Apply the principle of least privilege for database accounts</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="payloads" className="space-y-4">
              {scanResults.successfulPayloads.length > 0 ? (
                <div className="space-y-4">
                  <h4 className="text-sm font-tech text-secondary">Successful SQL Injection Payloads</h4>
                  
                  <div className="space-y-3">
                    {scanResults.successfulPayloads.map((payload: any, i: number) => (
                      <div key={i} className="p-3 bg-background rounded-md border border-secondary/20">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="font-mono bg-red-500/10 text-red-500 border-red-500/30">
                              Parameter: {payload.param}
                            </Badge>
                          </div>
                          <Badge variant="outline" className="bg-secondary/10 text-secondary border-secondary/30">
                            Status: {payload.response.status}
                          </Badge>
                        </div>
                        
                        <div className="text-xs font-mono p-2 bg-secondary/5 rounded mb-2 overflow-x-auto flex items-center justify-between group">
                          <code>{payload.payload}</code>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 w-6 p-0 text-muted-foreground hover:text-accent opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={() => copyToClipboard(payload.payload)}
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                        
                        {payload.response.indicators && payload.response.indicators.length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs font-tech text-muted-foreground">Detection Indicators:</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {payload.response.indicators.map((indicator: string, j: number) => (
                                <Badge key={j} variant="outline" className="text-xs bg-red-500/5 text-red-500 border-red-500/20">
                                  {indicator}
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
                  <ShieldCheck className="h-12 w-12 text-green-500 mb-4" />
                  <h4 className="text-md font-tech text-green-500 mb-2">No Successful Payloads</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    No successful SQL injection payloads were detected during the scan.
                    This suggests the target is not vulnerable to SQL injection attacks.
                  </p>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="details" className="space-y-4">
              <div className="space-y-4">
                {scanResults.dbType && (
                  <div className="p-4 bg-background rounded-md border border-secondary/20">
                    <h4 className="text-sm font-tech mb-3">Database Information</h4>
                    <div className="flex items-center space-x-2">
                      <Database className="h-4 w-4 text-accent" />
                      <span className="font-tech text-accent">
                        Detected Database: {scanResults.dbType.toUpperCase()}
                      </span>
                    </div>
                    
                    {scanResults.errorMessages && scanResults.errorMessages.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs font-tech text-muted-foreground mb-2">
                          Common Error Messages for {scanResults.dbType.toUpperCase()}:
                        </p>
                        <div className="space-y-1.5">
                          {scanResults.errorMessages.map((error: string, i: number) => (
                            <div key={i} className="text-xs font-mono p-1.5 bg-secondary/5 rounded">
                              {error}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
                
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-3">Test Parameters</h4>
                  
                  <div className="space-y-2 text-xs font-mono">
                    <div className="grid grid-cols-2">
                      <span className="text-muted-foreground">URL:</span>
                      <span className="break-all">{scanResults.url}</span>
                    </div>
                    
                    <div className="grid grid-cols-2">
                      <span className="text-muted-foreground">Payload Type:</span>
                      <span>{scanResults.detectionMethod}</span>
                    </div>
                    
                    <div className="grid grid-cols-2">
                      <span className="text-muted-foreground">Parameters Tested:</span>
                      <span>{scanResults.testedParams.join(', ') || 'None'}</span>
                    </div>
                    
                    <div className="grid grid-cols-2">
                      <span className="text-muted-foreground">Total Payloads:</span>
                      <span>{scanResults.testedPayloads.length}</span>
                    </div>
                    
                    <div className="grid grid-cols-2">
                      <span className="text-muted-foreground">Total Requests:</span>
                      <span>{scanResults.totalRequests}</span>
                    </div>
                  </div>
                </div>
                
                <div className="p-4 bg-background rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-3">Secure Coding Examples</h4>
                  
                  <Accordion type="single" collapsible className="w-full">
                    <AccordionItem value="item-1" className="border-secondary/20">
                      <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                        PHP - Parameterized Queries
                      </AccordionTrigger>
                      <AccordionContent>
                        <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Unsafe code (vulnerable)
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;

// Safe code using parameterized query (PDO)
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();

// Safe code using parameterized query (mysqli)
$id = $_GET['id'];
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();`}
                        </pre>
                      </AccordionContent>
                    </AccordionItem>
                    
                    <AccordionItem value="item-2" className="border-secondary/20">
                      <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                        Node.js - Prepared Statements
                      </AccordionTrigger>
                      <AccordionContent>
                        <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Unsafe code (vulnerable)
const id = req.query.id;
const query = \`SELECT * FROM users WHERE id = \${id}\`;
const result = await db.query(query);

// Safe code using prepared statement (pg)
const id = req.query.id;
const result = await db.query(
  'SELECT * FROM users WHERE id = $1',
  [id]
);

// Safe code using ORM (Sequelize)
const user = await User.findByPk(req.query.id);`}
                        </pre>
                      </AccordionContent>
                    </AccordionItem>
                    
                    <AccordionItem value="item-3" className="border-secondary/20">
                      <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                        Java - Prepared Statements
                      </AccordionTrigger>
                      <AccordionContent>
                        <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Unsafe code (vulnerable)
String id = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + id;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// Safe code using prepared statement
String id = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, id);
ResultSet rs = pstmt.executeQuery();`}
                        </pre>
                      </AccordionContent>
                    </AccordionItem>
                    
                    <AccordionItem value="item-4" className="border-secondary/20">
                      <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                        Python - Parameterized Queries
                      </AccordionTrigger>
                      <AccordionContent>
                        <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`# Unsafe code (vulnerable)
id = request.args.get('id')
query = "SELECT * FROM users WHERE id = " + id
result = cursor.execute(query)

# Safe code using parameterized query
id = request.args.get('id')
query = "SELECT * FROM users WHERE id = %s"
result = cursor.execute(query, (id,))

# Safe code using SQLAlchemy ORM
user = User.query.filter_by(id=request.args.get('id')).first()`}
                        </pre>
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}