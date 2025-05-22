import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import Terminal from '@/components/terminal';
import { AlertCircle, Search, RotateCw, Shield, Globe, Clock, Loader2, Upload, Code, Database, Server, Check, X } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useTerminal } from '@/hooks/use-terminal';
import { MatrixBackground } from '@/components/matrix-background';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';

// Temporary translation function until full i18n is implemented
const useTranslation = () => {
  return {
    t: (key: string, defaultValue: string) => defaultValue,
    language: 'en',
    setLanguage: () => {}
  };
};

// Define types for shell uploader results
interface UploadAttempt {
  strategy: string;
  filePath?: string;
  fileType?: string;
  status: 'success' | 'failed';
  error?: string;
}

interface ShellUploaderResult {
  scanId?: number;
  url: string;
  targetCms?: string;
  wafDetected: boolean;
  formFound: boolean;
  uploadAttempts: UploadAttempt[];
  possibleShellPaths: string[];
  scanTime: number;
  uploadSuccess: boolean;
  headers: Record<string, string>;
}

export default function ShellUploaderPage() {
  const { t } = useTranslation();
  const [url, setUrl] = useState('');
  const [shellType, setShellType] = useState<'php' | 'asp' | 'jsp' | 'aspx'>('php');
  const [bypassWaf, setBypassWaf] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ShellUploaderResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const { toast } = useToast();
  const { lines, addCommandLine, addInfoLine, addErrorLine, addSuccessLine, clearLines } = useTerminal();

  // Validate URL format
  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch (e) {
      return false;
    }
  };

  // Start shell upload analysis
  const handleScan = async () => {
    // Validate input
    if (!url) {
      setError('Please enter a URL');
      addErrorLine('Error: Please enter a URL');
      return;
    }

    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    if (!isValidUrl(normalizedUrl)) {
      setError('Invalid URL format. Example: https://example.com');
      addErrorLine('Error: Invalid URL format. Example: https://example.com');
      return;
    }

    setError(null);
    setIsScanning(true);
    clearLines();
    addCommandLine(`Starting adaptive shell uploader analysis on ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Shell Type: ${shellType.toUpperCase()}`);
    addInfoLine(`WAF Bypass Mode: ${bypassWaf ? 'Enabled' : 'Disabled'}`);

    try {
      const response = await fetch('/api/scan/shell-uploader', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: normalizedUrl,
          shellType,
          bypassWaf
        })
      }).then(res => res.json());

      if (response.success) {
        setResults(response.data);
        const { wafDetected, targetCms, uploadAttempts, possibleShellPaths, scanTime } = response.data;
        
        addSuccessLine(`Analysis completed for ${normalizedUrl} in ${scanTime}ms`);
        
        if (targetCms) {
          addInfoLine(`Detected CMS: ${targetCms}`);
        }
        
        if (wafDetected) {
          addErrorLine('Web Application Firewall (WAF) detected!');
        }
        
        // Report on upload attempts
        const successfulAttempts = uploadAttempts.filter(a => a.status === 'success');
        addInfoLine(`Upload strategies analyzed: ${uploadAttempts.length}`);
        
        if (successfulAttempts.length > 0) {
          addSuccessLine(`Found ${successfulAttempts.length} potentially successful upload methods`);
          successfulAttempts.slice(0, 3).forEach(attempt => {
            addInfoLine(`Strategy: ${attempt.strategy}`);
          });
        } else {
          addErrorLine('No successful upload methods identified');
        }
        
        // Show possible shell paths
        if (possibleShellPaths.length > 0) {
          addSuccessLine(`Identified ${possibleShellPaths.length} potential file upload locations`);
        }

        // Show scan result ID if available
        if (response.data.scanId) {
          addSuccessLine(`Scan results saved with ID: ${response.data.scanId}`);
        }
      } else {
        throw new Error(response.message || 'Analysis failed');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to analyze target';
      setError(message);
      addErrorLine(`Error: ${message}`);
      toast({
        variant: "destructive",
        title: "Analysis failed",
        description: message
      });
    } finally {
      setIsScanning(false);
    }
  };

  // Reset form
  const handleReset = () => {
    setUrl('');
    setShellType('php');
    setBypassWaf(false);
    setResults(null);
    setError(null);
    setActiveTab('overview');
    clearLines();
    addInfoLine('Shell uploader tool reset');
  };

  // Get vulnerability level based on results
  const getVulnerabilityLevel = (results: ShellUploaderResult): 'low' | 'medium' | 'high' => {
    if (!results.uploadSuccess) return 'low';
    if (results.wafDetected && !results.uploadSuccess) return 'low';
    if (results.wafDetected && results.uploadSuccess) return 'medium';
    if (results.uploadSuccess && results.uploadAttempts.filter(a => a.status === 'success').length > 1) return 'high';
    return 'medium';
  };

  return (
    <div className="container mx-auto py-6 px-4 relative z-10">
      <Helmet>
        <title>Adaptive Shell Uploader - CyberPulse Security Toolkit</title>
        <meta name="description" content="Analyze web applications for shell upload vulnerabilities" />
      </Helmet>
      
      <MatrixBackground className="opacity-5" />
      
      <h1 className="text-3xl font-tech mb-6 text-primary tracking-wider flex items-center">
        <Upload className="inline-block mr-2" />
        {t('shell.uploader.title', 'Adaptive Shell Uploader')}
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="p-4 border-primary/30 bg-card/80 backdrop-blur-sm">
            <h2 className="text-xl font-bold text-primary mb-4">
              {t('shell.uploader.config', 'Scan Configuration')}
            </h2>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">{t('shell.uploader.url', 'Target Website URL')}</Label>
                <Input
                  id="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="bg-background"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="shell-type">{t('shell.uploader.type', 'Shell Type')}</Label>
                <Select 
                  value={shellType} 
                  onValueChange={(value) => setShellType(value as 'php' | 'asp' | 'jsp' | 'aspx')}
                >
                  <SelectTrigger id="shell-type" className="bg-background">
                    <SelectValue placeholder="Select shell type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="php">PHP</SelectItem>
                    <SelectItem value="asp">ASP</SelectItem>
                    <SelectItem value="jsp">JSP</SelectItem>
                    <SelectItem value="aspx">ASPX (.NET)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="bypass-waf"
                  checked={bypassWaf}
                  onCheckedChange={(checked) => setBypassWaf(!!checked)}
                />
                <Label htmlFor="bypass-waf" className="cursor-pointer">
                  {t('shell.uploader.bypass', 'Attempt WAF Bypass')}
                </Label>
              </div>
              
              {error && (
                <div className="bg-red-500/20 text-red-500 p-3 rounded-md flex items-start">
                  <AlertCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              
              <div className="flex space-x-2 pt-2">
                <Button onClick={handleScan} disabled={isScanning} className="flex-1">
                  {isScanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      {t('common.analyzing', 'Analyzing...')}
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4" />
                      {t('common.analyze', 'Analyze')}
                    </>
                  )}
                </Button>
                <Button variant="outline" onClick={handleReset} disabled={isScanning}>
                  <RotateCw className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div className="mt-8">
              <h3 className="text-lg font-semibold mb-2">{t('shell.uploader.terminal', 'Analysis Log')}</h3>
              <Terminal lines={lines} maxHeight="200px" />
            </div>
          </Card>
        </div>
        
        <div className="lg:col-span-2">
          {results ? (
            <Card className="border-primary/30 bg-card/80 backdrop-blur-sm overflow-hidden">
              <div className="p-4 border-b border-border">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h2 className="text-xl font-bold text-primary">
                    {t('shell.uploader.results', 'Analysis Results')}
                  </h2>
                  
                  <div className="flex items-center space-x-3">
                    <div className="flex items-center">
                      <Clock className="mr-1 h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{results.scanTime} ms</span>
                    </div>
                    
                    {getVulnerabilityLevel(results) === 'high' && (
                      <Badge variant="destructive">High Risk</Badge>
                    )}
                    {getVulnerabilityLevel(results) === 'medium' && (
                      <Badge variant="outline" className="bg-orange-500/20 text-orange-500 border-orange-500/50">
                        Medium Risk
                      </Badge>
                    )}
                    {getVulnerabilityLevel(results) === 'low' && (
                      <Badge variant="outline" className="bg-blue-500/20 text-blue-500 border-blue-500/50">
                        Low Risk
                      </Badge>
                    )}
                  </div>
                </div>
                
                <div className="mt-3">
                  <div className="flex items-center">
                    <Globe className="h-4 w-4 mr-1 text-muted-foreground" />
                    <a 
                      href={results.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline flex items-center"
                    >
                      {results.url}
                    </a>
                  </div>
                </div>
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="p-4">
                <TabsList className="mb-4">
                  <TabsTrigger value="overview">{t('shell.uploader.tab.overview', 'Overview')}</TabsTrigger>
                  <TabsTrigger value="upload">{t('shell.uploader.tab.upload', 'Upload Points')}</TabsTrigger>
                  <TabsTrigger value="technical">{t('shell.uploader.tab.technical', 'Technical Details')}</TabsTrigger>
                </TabsList>
                
                <TabsContent value="overview" className="space-y-4 mt-2">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 border-border bg-card/50">
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <Shield className="mr-2 h-5 w-5 text-primary" />
                        {t('shell.uploader.security', 'Security Assessment')}
                      </h3>
                      
                      <div className="space-y-3">
                        <div>
                          <Label className="text-sm text-muted-foreground">Vulnerability Level</Label>
                          <div className="mt-1">
                            {getVulnerabilityLevel(results) === 'high' && (
                              <>
                                <Badge variant="destructive" className="mb-2">High Risk</Badge>
                                <Progress value={90} className="h-2 bg-red-950" indicatorClassName="bg-red-500" />
                              </>
                            )}
                            {getVulnerabilityLevel(results) === 'medium' && (
                              <>
                                <Badge variant="outline" className="bg-orange-500/20 text-orange-500 border-orange-500/50 mb-2">
                                  Medium Risk
                                </Badge>
                                <Progress value={50} className="h-2 bg-orange-950" indicatorClassName="bg-orange-500" />
                              </>
                            )}
                            {getVulnerabilityLevel(results) === 'low' && (
                              <>
                                <Badge variant="outline" className="bg-blue-500/20 text-blue-500 border-blue-500/50 mb-2">
                                  Low Risk
                                </Badge>
                                <Progress value={20} className="h-2 bg-blue-950" indicatorClassName="bg-blue-500" />
                              </>
                            )}
                          </div>
                        </div>
                        
                        <div className="pt-2 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-sm">WAF Protection</span>
                            <Badge variant={results.wafDetected ? "default" : "outline"} className={results.wafDetected ? "bg-blue-600" : ""}>
                              {results.wafDetected ? "Detected" : "Not Detected"}
                            </Badge>
                          </div>
                          
                          <Separator />
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Upload Forms</span>
                            <Badge variant={results.formFound ? "destructive" : "outline"}>
                              {results.formFound ? "Found" : "Not Found"}
                            </Badge>
                          </div>
                          
                          <Separator />
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Upload Vulnerabilities</span>
                            <Badge 
                              variant={results.uploadSuccess ? "destructive" : "outline"}
                              className={results.uploadSuccess ? "" : "bg-green-600"}
                            >
                              {results.uploadSuccess ? "Detected" : "Not Detected"}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </Card>
                    
                    <Card className="p-4 border-border bg-card/50">
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <Database className="mr-2 h-5 w-5 text-primary" />
                        {t('shell.uploader.target', 'Target Information')}
                      </h3>
                      
                      <div className="space-y-3">
                        {results.targetCms ? (
                          <div className="flex items-center gap-2 mb-3">
                            <Server className="h-4 w-4 text-primary" />
                            <span className="font-medium">
                              {results.targetCms.toUpperCase()} CMS Detected
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 mb-3 text-muted-foreground">
                            <Server className="h-4 w-4" />
                            <span>Unknown CMS/Technology</span>
                          </div>
                        )}
                        
                        <div className="text-sm space-y-1">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Server:</span>
                            <span className="font-mono">
                              {results.headers['server'] || results.headers['Server'] || 'Unknown'}
                            </span>
                          </div>
                          
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Powered By:</span>
                            <span className="font-mono">
                              {results.headers['x-powered-by'] || results.headers['X-Powered-By'] || 'Unknown'}
                            </span>
                          </div>
                        </div>
                        
                        <Separator className="my-2" />
                        
                        <div className="pt-1">
                          <h4 className="text-sm font-medium mb-2">
                            {t('shell.uploader.uploadMethods', 'Upload Methods Analysis')}
                          </h4>
                          
                          <div className="space-y-2">
                            {results.uploadAttempts.slice(0, 3).map((attempt, index) => (
                              <div key={index} className="flex items-start gap-2 text-sm">
                                {attempt.status === 'success' ? (
                                  <Check className="h-4 w-4 text-green-500 mt-0.5" />
                                ) : (
                                  <X className="h-4 w-4 text-red-500 mt-0.5" />
                                )}
                                <div>
                                  <span className={attempt.status === 'success' ? "text-green-500" : "text-muted-foreground"}>
                                    {attempt.strategy}
                                  </span>
                                  {attempt.filePath && (
                                    <p className="text-xs text-muted-foreground truncate">{attempt.filePath}</p>
                                  )}
                                </div>
                              </div>
                            ))}
                            
                            {results.uploadAttempts.length > 3 && (
                              <div className="text-xs text-muted-foreground pl-6">
                                + {results.uploadAttempts.length - 3} more methods analyzed
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </Card>
                  </div>
                  
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('shell.uploader.recommendation', 'Security Recommendations')}
                    </h3>
                    
                    <div className="space-y-3 text-sm">
                      {results.uploadSuccess && (
                        <div className="bg-red-500/10 p-3 rounded border border-red-500/30 text-red-500">
                          <p className="font-medium">Critical: File Upload Vulnerability Detected</p>
                          <p className="mt-1">The target website appears vulnerable to malicious file uploads that could lead to remote code execution.</p>
                        </div>
                      )}
                      
                      <Accordion type="single" collapsible className="w-full">
                        <AccordionItem value="item-1">
                          <AccordionTrigger className="text-sm font-medium">Implement File Type Validation</AccordionTrigger>
                          <AccordionContent className="text-muted-foreground">
                            <p>Ensure server-side validation of file types, not just extensions. Validate MIME types and file content signatures.</p>
                            <p className="mt-2">Example PHP code:</p>
                            <pre className="bg-black/20 p-2 rounded text-xs mt-1 overflow-x-auto">
                              {`$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $file['tmp_name']);
$allowed = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime, $allowed)) {
    throw new Exception('Invalid file type');
}`}
                            </pre>
                          </AccordionContent>
                        </AccordionItem>
                        
                        <AccordionItem value="item-2">
                          <AccordionTrigger className="text-sm font-medium">Use WAF Rules for Upload Protection</AccordionTrigger>
                          <AccordionContent className="text-muted-foreground">
                            If you're using a WAF, configure rules to block uploads containing PHP code or other executable content. Example ModSecurity rule:
                            <pre className="bg-black/20 p-2 rounded text-xs mt-1 overflow-x-auto">
                              {`SecRule FILES_TMPNAMES "@rx \.php$" "id:1005,phase:2,t:lowercase,deny,msg:'PHP file upload attempt'"`}
                            </pre>
                          </AccordionContent>
                        </AccordionItem>
                        
                        <AccordionItem value="item-3">
                          <AccordionTrigger className="text-sm font-medium">Rename Files and Change Extensions</AccordionTrigger>
                          <AccordionContent className="text-muted-foreground">
                            Generate random names for uploaded files and ensure file extensions are safe:
                            <pre className="bg-black/20 p-2 rounded text-xs mt-1 overflow-x-auto">
                              {`// PHP example
$newFileName = bin2hex(random_bytes(16)) . '.jpg';
// Store original filename in database if needed
move_uploaded_file($file['tmp_name'], $uploadPath . $newFileName);`}
                            </pre>
                          </AccordionContent>
                        </AccordionItem>
                      </Accordion>
                    </div>
                  </Card>
                </TabsContent>
                
                <TabsContent value="upload" className="space-y-4 mt-2">
                  {results.possibleShellPaths.length > 0 ? (
                    <div className="space-y-3">
                      <h3 className="text-lg font-semibold">
                        {t('shell.uploader.paths', 'Potential Upload Locations')} ({results.possibleShellPaths.length})
                      </h3>
                      
                      <ScrollArea className="h-[300px] rounded-md border p-4">
                        <ul className="space-y-3">
                          {results.possibleShellPaths.map((path, index) => (
                            <li key={index} className="p-2 hover:bg-accent/50 rounded-md border border-border">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center">
                                  <Code className="h-4 w-4 mr-2 text-primary" />
                                  <span className="font-mono text-sm">{path}</span>
                                </div>
                                <div>
                                  <Button variant="ghost" size="sm" className="h-7 px-2">
                                    <a 
                                      href={path} 
                                      target="_blank" 
                                      rel="noopener noreferrer"
                                      className="flex items-center"
                                    >
                                      Check
                                    </a>
                                  </Button>
                                </div>
                              </div>
                            </li>
                          ))}
                        </ul>
                      </ScrollArea>
                      
                      <div className="bg-amber-500/10 p-3 rounded border border-amber-500/30 text-amber-500 text-sm">
                        <p className="font-medium">Security Notice</p>
                        <p className="mt-1">
                          This tool only analyzes for upload vulnerabilities and does not actually upload shells.
                          Attempting to upload malicious files to systems without explicit permission is illegal.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center p-8 text-muted-foreground">
                      <Code className="mx-auto h-12 w-12 mb-3 opacity-20" />
                      <p>{t('shell.uploader.noPaths', 'No potential upload paths were identified')}</p>
                      <p className="text-sm mt-2">
                        This could mean the target is well-protected against malicious uploads.
                      </p>
                    </div>
                  )}
                </TabsContent>
                
                <TabsContent value="technical" className="space-y-4 mt-2">
                  <div className="space-y-3">
                    <h3 className="text-lg font-semibold">
                      {t('shell.uploader.headers', 'HTTP Response Headers')}
                    </h3>
                    
                    <ScrollArea className="h-[200px] rounded-md border p-4">
                      <div className="font-mono text-xs">
                        {Object.entries(results.headers).map(([key, value], index) => (
                          <div key={index} className="py-1 flex">
                            <span className="text-primary font-semibold mr-2">{key}:</span>
                            <span className="text-muted-foreground">{value}</span>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                    
                    <h3 className="text-lg font-semibold mt-4">
                      {t('shell.uploader.strategies', 'Upload Strategies Analyzed')}
                    </h3>
                    
                    <div className="rounded-md border">
                      <div className="grid grid-cols-12 bg-muted/50 px-4 py-2 text-xs font-medium">
                        <div className="col-span-3">Strategy</div>
                        <div className="col-span-4">Path</div>
                        <div className="col-span-3">Type</div>
                        <div className="col-span-2">Status</div>
                      </div>
                      
                      <ScrollArea className="h-[200px]">
                        {results.uploadAttempts.map((attempt, index) => (
                          <div 
                            key={index} 
                            className={`grid grid-cols-12 px-4 py-2 text-xs ${
                              index % 2 === 0 ? 'bg-background' : 'bg-muted/20'
                            } hover:bg-muted/40`}
                          >
                            <div className="col-span-3 font-medium">{attempt.strategy}</div>
                            <div className="col-span-4 font-mono truncate">{attempt.filePath || 'N/A'}</div>
                            <div className="col-span-3">{attempt.fileType || 'N/A'}</div>
                            <div className="col-span-2">
                              {attempt.status === 'success' ? (
                                <Badge variant="success" className="bg-green-600">Success</Badge>
                              ) : (
                                <Badge variant="outline">Failed</Badge>
                              )}
                            </div>
                          </div>
                        ))}
                      </ScrollArea>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </Card>
          ) : (
            <Card className="p-8 border-primary/30 bg-card/80 backdrop-blur-sm h-full flex items-center justify-center">
              <div className="text-center max-w-md">
                <Upload className="h-16 w-16 mx-auto mb-4 text-primary/20" />
                <h3 className="text-xl font-bold mb-2">{t('shell.uploader.instructions', 'Adaptive Shell Uploader')}</h3>
                <p className="text-muted-foreground mb-4">
                  {t('shell.uploader.description', 'Analyze websites for shell upload vulnerabilities by identifying upload points, content filtering, and WAF protections.')}
                </p>
                <div className="text-sm text-muted-foreground space-y-2 text-left">
                  <p>• {t('shell.uploader.tip1', 'Select the appropriate shell type for your target')}</p>
                  <p>• {t('shell.uploader.tip2', 'Enable WAF bypass for sites with security protections')}</p>
                  <p>• {t('shell.uploader.tip3', 'Use this tool for educational and defensive purposes only')}</p>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}