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
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  FileSearch, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX,
  Terminal,
  RefreshCw,
  CheckCircle2,
  XCircle,
  FileWarning,
  AlertTriangle,
  FormInput,
  Code
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

interface FormFuzzerProps {
  onScanComplete?: (result: any) => void;
}

export interface FormField {
  name: string;
  type: string;
  id?: string;
  value?: string;
  required?: boolean;
  placeholder?: string;
  options?: string[];
}

export interface FormInfo {
  id?: string;
  action: string;
  method: string;
  fields: FormField[];
  location: string;
}

export interface FormVulnerability {
  formIndex: number;
  field: string;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  payload: string;
  evidence?: string;
}

export default function FormFuzzer({ onScanComplete }: FormFuzzerProps) {
  const [url, setUrl] = useState<string>('');
  const [depth, setDepth] = useState<string>('1');
  const [timeoutMs, setTimeoutMs] = useState<string>('15000');
  const [maxForms, setMaxForms] = useState<string>('10');
  const [followRedirects, setFollowRedirects] = useState<boolean>(true);
  const [selectedFuzzerTypes, setSelectedFuzzerTypes] = useState<string[]>(['xss', 'sqli']);
  
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResults, setScanResults] = useState<any>(null);
  const [selectedFormIndex, setSelectedFormIndex] = useState<number>(0);
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
   * Toggle a fuzzer type in the selected array
   */
  const toggleFuzzerType = (type: string) => {
    setSelectedFuzzerTypes(prev => {
      if (prev.includes(type)) {
        return prev.filter(t => t !== type);
      } else {
        return [...prev, type];
      }
    });
  };
  
  /**
   * Start the form fuzzing scan
   */
  const handleScan = async () => {
    // Normalize URL if needed
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    if (!isValidUrl(normalizedUrl)) {
      setError('Invalid URL format. Example: https://example.com');
      addErrorLine('Error: Invalid URL format. Example: https://example.com');
      return;
    }
    
    if (selectedFuzzerTypes.length === 0) {
      setError('Please select at least one fuzzer type');
      addErrorLine('Error: Please select at least one fuzzer type');
      return;
    }
    
    setError(null);
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    
    addCommandLine(`Starting form fuzzing scan for ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Scan depth: ${depth}`);
    addInfoLine(`Fuzzer types: ${selectedFuzzerTypes.join(', ')}`);
    
    // Simulate progress for UX
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + (Math.random() * 8 + 2); // Random increment between 2-10
      });
    }, 500);
    
    try {
      const response = await axios.post('/api/security/form-fuzzer', {
        url: normalizedUrl,
        depth: depth,
        fuzzerTypes: selectedFuzzerTypes,
        timeoutMs: timeoutMs,
        maxForms: maxForms,
        followRedirects: followRedirects
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setScanResults(result);
        
        // Terminal output based on results
        addSuccessLine('Form fuzzing scan completed');
        addInfoLine(`Found ${result.formsFound} forms, tested ${result.formsScanned} forms`);
        addInfoLine(`Tested ${result.totalFieldsTested} fields with ${result.totalTestsRun} test payloads`);
        
        if (result.vulnerabilities.length > 0) {
          addErrorLine(`WARNING: Found ${result.vulnerabilities.length} potential vulnerabilities!`);
          
          // Group vulnerabilities by type
          const vulnByType: Record<string, number> = {};
          result.vulnerabilities.forEach((vuln: FormVulnerability) => {
            vulnByType[vuln.type] = (vulnByType[vuln.type] || 0) + 1;
          });
          
          Object.entries(vulnByType).forEach(([type, count]) => {
            addErrorLine(`- ${count} ${type.toUpperCase()} vulnerabilities`);
          });
        } else {
          addSuccessLine(`No form vulnerabilities detected in ${normalizedUrl}`);
        }
        
        // Add security rating info
        addInfoLine(`Security rating: ${result.summary.riskLevel} (${result.summary.score}/100)`);
        
        if (onScanComplete) {
          onScanComplete(result);
        }
        
        toast({
          title: 'Form fuzzing completed',
          description: `Found ${result.vulnerabilities.length} potential vulnerabilities`,
          variant: result.vulnerabilities.length > 0 ? 'destructive' : 'default'
        });
      } else {
        setError(response.data.message || 'Failed to scan for form vulnerabilities');
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
  
  /**
   * Reset the form and results
   */
  const handleReset = () => {
    setUrl('');
    setDepth('1');
    setTimeoutMs('15000');
    setMaxForms('10');
    setFollowRedirects(true);
    setSelectedFuzzerTypes(['xss', 'sqli']);
    setScanResults(null);
    setError(null);
    setScanProgress(0);
    addCommandLine('Reset form fuzzer');
  };
  
  /**
   * Get color based on vulnerability severity
   */
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'Critical':
        return 'text-red-600 border-red-600';
      case 'High':
        return 'text-red-500 border-red-500';
      case 'Medium':
        return 'text-orange-500 border-orange-500';
      case 'Low':
        return 'text-yellow-500 border-yellow-500';
      default:
        return 'text-muted-foreground border-muted-foreground';
    }
  };
  
  /**
   * Get icon based on vulnerability type
   */
  const getVulnerabilityIcon = (type: string) => {
    switch (type) {
      case 'xss':
        return <Code className="h-4 w-4 text-red-500" />;
      case 'sqli':
        return <Terminal className="h-4 w-4 text-red-600" />;
      case 'command':
        return <Terminal className="h-4 w-4 text-red-600" />;
      case 'open-redirect':
        return <FileWarning className="h-4 w-4 text-orange-500" />;
      case 'csrf':
        return <ShieldX className="h-4 w-4 text-orange-500" />;
      case 'boundary':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-muted-foreground" />;
    }
  };
  
  /**
   * Get descriptive name for vulnerability type
   */
  const getVulnerabilityTypeName = (type: string): string => {
    switch (type) {
      case 'xss':
        return 'Cross-Site Scripting (XSS)';
      case 'sqli':
        return 'SQL Injection';
      case 'command':
        return 'Command Injection';
      case 'open-redirect':
        return 'Open Redirect';
      case 'csrf':
        return 'Cross-Site Request Forgery (CSRF)';
      case 'boundary':
        return 'Input Validation/Boundary Testing';
      default:
        return type.charAt(0).toUpperCase() + type.slice(1);
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Form Fuzzer</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url" className="text-sm font-tech">Target URL</Label>
            <Input
              id="url"
              placeholder="https://example.com/contact-form"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono bg-background border-secondary/50"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the URL of a page containing forms to test
            </p>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="depth" className="text-sm font-tech">Crawl Depth</Label>
              <Select
                value={depth}
                onValueChange={setDepth}
                disabled={isScanning}
              >
                <SelectTrigger id="depth" className="bg-background border-secondary/50">
                  <SelectValue placeholder="Select depth" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 - Current page only</SelectItem>
                  <SelectItem value="2">2 - Follow one level of links</SelectItem>
                  <SelectItem value="3">3 - Deep crawl (slower)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs font-mono text-muted-foreground mt-1">
                How deeply to crawl the site looking for forms
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="max-forms" className="text-sm font-tech">Max Forms</Label>
              <Input
                id="max-forms"
                type="number"
                min="1"
                max="50"
                placeholder="10"
                value={maxForms}
                onChange={(e) => setMaxForms(e.target.value)}
                className="font-mono bg-background border-secondary/50"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Maximum number of forms to test
              </p>
            </div>
          </div>
          
          <div className="space-y-2">
            <Label className="text-sm font-tech">Fuzzer Types</Label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="fuzzer-xss" 
                  checked={selectedFuzzerTypes.includes('xss')} 
                  onCheckedChange={() => toggleFuzzerType('xss')}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="fuzzer-xss" 
                  className="text-sm font-tech cursor-pointer"
                >
                  XSS
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="fuzzer-sqli" 
                  checked={selectedFuzzerTypes.includes('sqli')} 
                  onCheckedChange={() => toggleFuzzerType('sqli')}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="fuzzer-sqli" 
                  className="text-sm font-tech cursor-pointer"
                >
                  SQL Injection
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="fuzzer-command" 
                  checked={selectedFuzzerTypes.includes('command')} 
                  onCheckedChange={() => toggleFuzzerType('command')}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="fuzzer-command" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Command Injection
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="fuzzer-redirect" 
                  checked={selectedFuzzerTypes.includes('redirect')} 
                  onCheckedChange={() => toggleFuzzerType('redirect')}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="fuzzer-redirect" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Open Redirect
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="fuzzer-boundaries" 
                  checked={selectedFuzzerTypes.includes('boundaries')} 
                  onCheckedChange={() => toggleFuzzerType('boundaries')}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="fuzzer-boundaries" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Boundary Testing
                </Label>
              </div>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <Checkbox 
              id="follow-redirects" 
              checked={followRedirects}
              onCheckedChange={(checked) => setFollowRedirects(!!checked)}
              disabled={isScanning}
            />
            <Label 
              htmlFor="follow-redirects" 
              className="text-sm font-tech cursor-pointer"
            >
              Follow redirects
            </Label>
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
                <span>Scanning forms for vulnerabilities...</span>
                <span>{Math.round(scanProgress)}%</span>
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
              <TabsTrigger value="forms" className="font-tech">Forms</TabsTrigger>
              <TabsTrigger value="vulnerabilities" className="font-tech">Vulnerabilities</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">Form Fuzzing Results</h3>
                  <p className="text-sm font-mono">{scanResults.url}</p>
                </div>
                <div className={cn(
                  "px-3 py-1 rounded-full border flex items-center space-x-2",
                  scanResults.vulnerabilities.length > 0
                    ? "text-red-500 border-red-500/50 bg-red-500/10"
                    : "text-green-500 border-green-500/50 bg-green-500/10"
                )}>
                  {scanResults.vulnerabilities.length > 0 ? (
                    <ShieldAlert className="h-4 w-4" />
                  ) : (
                    <ShieldCheck className="h-4 w-4" />
                  )}
                  <span className="font-tech text-sm">
                    {scanResults.vulnerabilities.length > 0 ? 'Vulnerable' : 'Secure'}
                  </span>
                </div>
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Scan Overview</h4>
                <div className="space-y-2 text-sm font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Forms Found:</span>
                    <span>{scanResults.formsFound}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Forms Tested:</span>
                    <span>{scanResults.formsScanned}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Fields Tested:</span>
                    <span>{scanResults.totalFieldsTested}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Total Tests Run:</span>
                    <span>{scanResults.totalTestsRun}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">URLs Crawled:</span>
                    <span>{scanResults.crawledUrls.length}</span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Security Score:</span>
                    <span className={
                      scanResults.summary.score > 75 ? "text-red-600" :
                      scanResults.summary.score > 50 ? "text-red-500" :
                      scanResults.summary.score > 25 ? "text-orange-500" :
                      scanResults.summary.score > 0 ? "text-yellow-500" :
                      "text-green-500"
                    }>
                      {scanResults.summary.score}/100
                    </span>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Risk Level:</span>
                    <Badge className={cn(
                      "font-mono",
                      scanResults.summary.riskLevel === 'Critical' ? "bg-red-600/20 text-red-600 border-0" :
                      scanResults.summary.riskLevel === 'High Risk' ? "bg-red-500/20 text-red-500 border-0" :
                      scanResults.summary.riskLevel === 'Medium Risk' ? "bg-orange-500/20 text-orange-500 border-0" :
                      scanResults.summary.riskLevel === 'Low Risk' ? "bg-yellow-500/20 text-yellow-500 border-0" :
                      "bg-green-500/20 text-green-500 border-0"
                    )}>
                      {scanResults.summary.riskLevel}
                    </Badge>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Scan Duration:</span>
                    <span>{(scanResults.scanTime / 1000).toFixed(2)} seconds</span>
                  </div>
                </div>
                
                {scanResults.vulnerabilities.length > 0 && (
                  <div className="mt-4 p-3 bg-red-500/10 rounded-md border border-red-500/30 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    <div>
                      <p className="text-sm font-tech text-red-500">Form Vulnerabilities Detected!</p>
                      <p className="text-xs font-mono mt-1">{scanResults.summary.description}</p>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Vulnerability Summary</h4>
                {scanResults.vulnerabilities.length > 0 ? (
                  <div className="space-y-3">
                    {/* Group vulnerabilities by type */}
                    {Object.entries(
                      scanResults.vulnerabilities.reduce((acc: any, vuln: FormVulnerability) => {
                        acc[vuln.type] = (acc[vuln.type] || 0) + 1;
                        return acc;
                      }, {})
                    ).map(([type, count]: [string, any], index) => (
                      <div key={index} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {getVulnerabilityIcon(type)}
                          <span className="text-sm font-mono">{getVulnerabilityTypeName(type)}</span>
                        </div>
                        <Badge variant="outline" className={cn(
                          "bg-secondary/5",
                          type === 'sqli' || type === 'command' ? "text-red-600 border-red-600/30" :
                          type === 'xss' ? "text-red-500 border-red-500/30" :
                          type === 'csrf' || type === 'open-redirect' ? "text-orange-500 border-orange-500/30" :
                          "text-yellow-500 border-yellow-500/30"
                        )}>
                          {count}
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-6">
                    <ShieldCheck className="h-10 w-10 text-green-500 mb-3" />
                    <p className="text-sm font-tech text-green-500">No vulnerabilities detected</p>
                    <p className="text-xs font-mono text-center max-w-md text-muted-foreground mt-2">
                      The forms on this website appear to be secure against the tested attack vectors.
                    </p>
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="forms" className="space-y-4">
              {scanResults.forms.length > 0 ? (
                <div>
                  <h4 className="text-sm font-tech text-secondary mb-3">Forms Detected</h4>
                  
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
                    {scanResults.forms.map((form: FormInfo, index: number) => (
                      <Button
                        key={index}
                        variant={selectedFormIndex === index ? "default" : "outline"} 
                        className={cn(
                          "text-xs h-auto py-2 font-mono justify-start",
                          selectedFormIndex === index ? "bg-primary text-primary-foreground" : "bg-background"
                        )}
                        onClick={() => setSelectedFormIndex(index)}
                      >
                        <FormInput className="h-3.5 w-3.5 mr-2" />
                        <span className="truncate">
                          {form.id ? form.id : `Form ${index + 1}`}
                        </span>
                      </Button>
                    ))}
                  </div>
                  
                  {scanResults.forms[selectedFormIndex] && (
                    <div className="p-4 bg-background rounded-md border border-secondary/20">
                      <div className="flex justify-between items-start mb-3">
                        <h4 className="text-sm font-tech">
                          {scanResults.forms[selectedFormIndex].id ? 
                            scanResults.forms[selectedFormIndex].id : 
                            `Form ${selectedFormIndex + 1}`}
                        </h4>
                        <Badge variant="outline" className="font-mono bg-secondary/5 border-secondary/30">
                          {scanResults.forms[selectedFormIndex].method.toUpperCase()}
                        </Badge>
                      </div>
                      
                      <div className="space-y-3 text-xs font-mono">
                        <div>
                          <span className="text-muted-foreground">Action:</span>
                          <div className="p-1.5 bg-secondary/5 rounded mt-1 break-all">
                            {scanResults.forms[selectedFormIndex].action}
                          </div>
                        </div>
                        
                        <div>
                          <span className="text-muted-foreground">Found on:</span>
                          <div className="p-1.5 bg-secondary/5 rounded mt-1 break-all">
                            {scanResults.forms[selectedFormIndex].location}
                          </div>
                        </div>
                        
                        <div>
                          <span className="text-muted-foreground">Fields:</span>
                          <div className="mt-1 space-y-1.5">
                            {scanResults.forms[selectedFormIndex].fields.map((field: FormField, i: number) => (
                              <div key={i} className="p-1.5 bg-secondary/5 rounded flex justify-between items-center">
                                <div>
                                  <span>{field.name}</span>
                                  <span className="text-muted-foreground ml-2">({field.type})</span>
                                </div>
                                {field.required && (
                                  <Badge className="bg-red-500/10 text-red-500 border-0">required</Badge>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                        
                        {/* Check for vulnerabilities in this form */}
                        {scanResults.vulnerabilities.filter((v: FormVulnerability) => v.formIndex === selectedFormIndex).length > 0 && (
                          <div className="p-2 bg-red-500/10 rounded-md border border-red-500/30 mt-3">
                            <div className="flex items-center gap-2">
                              <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                              <span className="text-red-500">
                                Vulnerabilities detected in this form!
                              </span>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8">
                  <FormInput className="h-16 w-16 text-muted-foreground/50 mb-4" />
                  <h4 className="text-md font-tech text-muted-foreground mb-2">No Forms Found</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    No HTML forms were detected on the scanned URL. Try scanning a different page 
                    or enabling deeper crawling.
                  </p>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="vulnerabilities" className="space-y-4">
              {scanResults.vulnerabilities.length > 0 ? (
                <div className="space-y-4">
                  <h4 className="text-sm font-tech text-secondary mb-2">Detected Vulnerabilities</h4>
                  
                  <Accordion type="single" collapsible className="w-full">
                    {scanResults.vulnerabilities.map((vuln: FormVulnerability, index: number) => (
                      <AccordionItem 
                        key={index} 
                        value={`vuln-${index}`}
                        className="border-secondary/20"
                      >
                        <AccordionTrigger className="text-sm py-3">
                          <div className="flex items-center gap-3 text-left">
                            {getVulnerabilityIcon(vuln.type)}
                            <div>
                              <span className="font-tech">
                                {getVulnerabilityTypeName(vuln.type)}
                              </span>
                              <span className="text-muted-foreground ml-2 text-xs">
                                in field <code className="bg-secondary/10 px-1 rounded">{vuln.field}</code>
                              </span>
                            </div>
                          </div>
                          
                          <Badge 
                            className={cn(
                              "ml-auto mr-3 font-mono",
                              vuln.severity === 'Critical' ? "bg-red-600/20 text-red-600 border-0" :
                              vuln.severity === 'High' ? "bg-red-500/20 text-red-500 border-0" :
                              vuln.severity === 'Medium' ? "bg-orange-500/20 text-orange-500 border-0" :
                              "bg-yellow-500/20 text-yellow-500 border-0"
                            )}
                          >
                            {vuln.severity}
                          </Badge>
                        </AccordionTrigger>
                        
                        <AccordionContent className="text-xs font-mono space-y-3 pb-4">
                          <div>
                            <p className="text-muted-foreground mb-1">Description:</p>
                            <p>{vuln.description}</p>
                          </div>
                          
                          <div>
                            <p className="text-muted-foreground mb-1">Payload:</p>
                            <div className="p-2 bg-secondary/5 rounded break-all">
                              {vuln.payload}
                            </div>
                          </div>
                          
                          {vuln.evidence && (
                            <div>
                              <p className="text-muted-foreground mb-1">Evidence:</p>
                              <div className="p-2 bg-secondary/5 rounded break-all">
                                {vuln.evidence}
                              </div>
                            </div>
                          )}
                          
                          <div>
                            <p className="text-muted-foreground mb-1">Form Location:</p>
                            <div className="p-2 bg-secondary/5 rounded break-all">
                              {scanResults.forms[vuln.formIndex]?.location || 'Unknown'}
                            </div>
                          </div>
                          
                          <div className="p-2 bg-amber-500/10 rounded-md border border-amber-500/30 mt-2">
                            <div className="flex items-center gap-2">
                              <AlertTriangle className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
                              <p className="text-amber-500">
                                {vuln.type === 'xss' && "This vulnerability could allow attackers to inject malicious scripts that execute in users' browsers."}
                                {vuln.type === 'sqli' && "This vulnerability could allow attackers to access, modify, or delete data from your database."}
                                {vuln.type === 'command' && "This vulnerability could allow attackers to execute arbitrary commands on your server."}
                                {vuln.type === 'open-redirect' && "This vulnerability could allow attackers to redirect users to malicious websites."}
                                {vuln.type === 'csrf' && "This vulnerability could allow attackers to perform actions on behalf of authenticated users."}
                                {vuln.type === 'boundary' && "This vulnerability could allow attackers to submit unexpected values that might cause errors or information disclosure."}
                              </p>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                  </Accordion>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8">
                  <ShieldCheck className="h-16 w-16 text-green-500 mb-4" />
                  <h4 className="text-md font-tech text-green-500 mb-2">No Vulnerabilities Detected</h4>
                  <p className="text-sm font-mono text-center max-w-md text-muted-foreground">
                    The forms on this website appear to be secure against the tested attack vectors.
                    This is a good sign, but remember that security testing is an ongoing process.
                  </p>
                </div>
              )}
              
              <div className="p-4 bg-background rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-3">Security Recommendations</h4>
                
                <div className="space-y-2">
                  {scanResults.recommendations.map((recommendation: string, i: number) => (
                    <div key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-green-500 mt-0.5" />
                      <p className="text-sm font-mono">{recommendation}</p>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}