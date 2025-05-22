import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Search, RotateCw, AlertCircle, Loader2, Layers, Code, 
  Database, Server, ChevronRight, Clock, Globe
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { useToast } from '@/hooks/use-toast';
import Terminal from '@/components/terminal';
import { useTerminal } from '@/hooks/use-terminal';
import { MatrixBackground } from '@/components/matrix-background';

// Temporary translation function until full i18n is implemented
const useTranslation = () => {
  return {
    t: (key: string, defaultValue: string) => defaultValue,
    language: 'en',
    setLanguage: () => {}
  };
};

interface TechnologyResult {
  name: string;
  categories: string[];
  confidence: number;
  website?: string;
  icon?: string;
  version?: string;
}

interface TechDetectorResult {
  url: string;
  technologies: TechnologyResult[];
  frameworks: TechnologyResult[];
  cms: TechnologyResult[];
  serverInfo: {
    server?: string;
    poweredBy?: string;
    language?: string;
  };
  jsLibraries: TechnologyResult[];
  analytics: TechnologyResult[];
  headers: Record<string, string>;
  cookies: any[];
  metaTags: Record<string, string>;
  scanTime: number;
}

export default function TechDetectorPage() {
  const { t } = useTranslation();
  const [url, setUrl] = useState('');
  const [deepScan, setDeepScan] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<TechDetectorResult | null>(null);
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

  // Handle starting the scan
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
    addCommandLine(`Starting technology detection on ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Deep Scan: ${deepScan ? 'Enabled' : 'Disabled'}`);

    try {
      const response = await fetch('/api/scan/tech-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: normalizedUrl,
          deepScan,
          checkScripts: true
        })
      }).then(res => res.json());

      if (response.success) {
        setResults(response.data);
        const { technologies, frameworks, cms, jsLibraries, scanTime } = response.data;
        
        addSuccessLine(`Analysis completed for ${normalizedUrl} in ${scanTime}ms`);
        
        // Report detected technologies
        if (technologies.length > 0) {
          addInfoLine(`Detected ${technologies.length} technologies`);
        }
        
        // Report frameworks
        if (frameworks.length > 0) {
          addInfoLine(`Detected frameworks: ${frameworks.map((f: TechnologyResult) => f.name).join(', ')}`);
        }
        
        // Report CMS
        if (cms.length > 0) {
          addSuccessLine(`CMS detected: ${cms.map((c: TechnologyResult) => c.name).join(', ')}`);
        }
        
        // Report JS libraries
        if (jsLibraries.length > 0) {
          addInfoLine(`JavaScript libraries: ${jsLibraries.length} detected`);
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

  // Reset the form
  const handleReset = () => {
    setUrl('');
    setDeepScan(false);
    setResults(null);
    setError(null);
    setActiveTab('overview');
    clearLines();
    addInfoLine('Tech detector tool reset');
  };

  // Render a technology item with badge
  const renderTechItem = (tech: TechnologyResult, index: number) => (
    <div key={index} className="p-3 border border-border rounded-md bg-card/50 hover:bg-card/80 transition-colors">
      <div className="flex justify-between items-start">
        <div>
          <h4 className="font-medium text-foreground">{tech.name}</h4>
          {tech.version && <span className="text-xs text-muted-foreground">v{tech.version}</span>}
        </div>
        <Badge variant="outline" className="bg-primary/10 text-primary">
          {tech.confidence}%
        </Badge>
      </div>
      {tech.categories && tech.categories.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {tech.categories.map((cat, i) => (
            <span key={i} className="inline-block px-2 py-0.5 text-xs bg-secondary/10 text-secondary rounded-full">
              {cat}
            </span>
          ))}
        </div>
      )}
      {tech.website && (
        <a 
          href={tech.website} 
          target="_blank" 
          rel="noopener noreferrer"
          className="mt-2 text-xs text-primary hover:underline inline-flex items-center"
        >
          Learn more <ChevronRight className="h-3 w-3 ml-1" />
        </a>
      )}
    </div>
  );

  return (
    <div className="container mx-auto py-6 px-4 relative z-10">
      <Helmet>
        <title>Tech Detector - CyberPulse Security Toolkit</title>
        <meta name="description" content="Identify technologies used by websites and analyze their tech stack" />
      </Helmet>
      
      <MatrixBackground className="opacity-5" />
      
      <h1 className="text-3xl font-tech mb-6 text-primary tracking-wider flex items-center">
        <Layers className="inline-block mr-2" />
        {t('tech.detector.title', 'Technology Detector')}
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="p-4 border-primary/30 bg-card/80 backdrop-blur-sm">
            <h2 className="text-xl font-bold text-primary mb-4">
              {t('tech.detector.config', 'Scan Configuration')}
            </h2>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">{t('tech.detector.url', 'Target Website URL')}</Label>
                <Input
                  id="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="bg-background"
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="deep-scan"
                  checked={deepScan}
                  onCheckedChange={(checked) => setDeepScan(!!checked)}
                />
                <Label htmlFor="deep-scan" className="cursor-pointer">
                  {t('tech.detector.deepScan', 'Enable Deep Scan')}
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
              <h3 className="text-lg font-semibold mb-2">{t('tech.detector.terminal', 'Analysis Log')}</h3>
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
                    {t('tech.detector.results', 'Analysis Results')}
                  </h2>
                  
                  <div className="flex items-center space-x-3">
                    <div className="flex items-center">
                      <Clock className="mr-1 h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{results.scanTime} ms</span>
                    </div>
                    
                    <Badge variant="default">
                      {results.technologies.length + 
                       results.frameworks.length + 
                       results.cms.length + 
                       results.jsLibraries.length} Technologies
                    </Badge>
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
                  <TabsTrigger value="overview">{t('tech.detector.tab.overview', 'Overview')}</TabsTrigger>
                  <TabsTrigger value="frameworks">{t('tech.detector.tab.frameworks', 'Frameworks')}</TabsTrigger>
                  <TabsTrigger value="server">{t('tech.detector.tab.server', 'Server')}</TabsTrigger>
                  <TabsTrigger value="technical">{t('tech.detector.tab.technical', 'Technical Details')}</TabsTrigger>
                </TabsList>
                
                <TabsContent value="overview" className="space-y-4 mt-2">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 border-border bg-card/50">
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <Database className="mr-2 h-5 w-5 text-primary" />
                        {t('tech.detector.cms', 'Content Management System')}
                      </h3>
                      
                      {results.cms && results.cms.length > 0 ? (
                        <div className="space-y-3">
                          {results.cms.map((cms, index) => (
                            renderTechItem(cms, index)
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 text-muted-foreground text-center">
                          No CMS detected
                        </div>
                      )}
                    </Card>
                    
                    <Card className="p-4 border-border bg-card/50">
                      <h3 className="text-lg font-semibold mb-3 flex items-center">
                        <Server className="mr-2 h-5 w-5 text-primary" />
                        {t('tech.detector.server', 'Server Information')}
                      </h3>
                      
                      <div className="space-y-3">
                        {results.serverInfo.server && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Server:</span>
                            <Badge variant="outline">{results.serverInfo.server}</Badge>
                          </div>
                        )}
                        
                        {results.serverInfo.poweredBy && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Powered By:</span>
                            <Badge variant="outline">{results.serverInfo.poweredBy}</Badge>
                          </div>
                        )}
                        
                        {results.serverInfo.language && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Language:</span>
                            <Badge variant="outline">{results.serverInfo.language}</Badge>
                          </div>
                        )}
                        
                        {!results.serverInfo.server && !results.serverInfo.poweredBy && !results.serverInfo.language && (
                          <div className="p-3 text-muted-foreground text-center">
                            No server information detected
                          </div>
                        )}
                      </div>
                    </Card>
                  </div>
                  
                  <Card className="p-4 border-border bg-card/50 mt-4">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.technologies', 'Detected Technologies')}
                    </h3>
                    
                    {results.technologies && results.technologies.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {results.technologies.slice(0, 6).map((tech, index) => (
                          renderTechItem(tech, index)
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-muted-foreground text-center">
                        No technologies detected
                      </div>
                    )}
                    
                    {results.technologies.length > 6 && (
                      <div className="mt-3 text-center">
                        <Button 
                          variant="link" 
                          className="text-primary"
                          onClick={() => setActiveTab('technical')}
                        >
                          View {results.technologies.length - 6} more technologies
                        </Button>
                      </div>
                    )}
                  </Card>
                </TabsContent>
                
                <TabsContent value="frameworks" className="space-y-4">
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3 flex items-center">
                      <Code className="mr-2 h-5 w-5 text-primary" />
                      {t('tech.detector.frameworks', 'Frameworks & Libraries')}
                    </h3>
                    
                    {results.frameworks && results.frameworks.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {results.frameworks.map((framework, index) => (
                          renderTechItem(framework, index)
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-muted-foreground text-center">
                        No frameworks detected
                      </div>
                    )}
                  </Card>
                  
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.js', 'JavaScript Libraries')}
                    </h3>
                    
                    {results.jsLibraries && results.jsLibraries.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {results.jsLibraries.map((lib, index) => (
                          renderTechItem(lib, index)
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-muted-foreground text-center">
                        No JavaScript libraries detected
                      </div>
                    )}
                  </Card>
                  
                  {results.analytics && results.analytics.length > 0 && (
                    <Card className="p-4 border-border bg-card/50">
                      <h3 className="text-lg font-semibold mb-3">
                        {t('tech.detector.analytics', 'Analytics & Tracking')}
                      </h3>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {results.analytics.map((tool, index) => (
                          renderTechItem(tool, index)
                        ))}
                      </div>
                    </Card>
                  )}
                </TabsContent>
                
                <TabsContent value="server" className="space-y-4">
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.headers', 'HTTP Headers')}
                    </h3>
                    
                    <ScrollArea className="h-[300px] pr-4">
                      <div className="space-y-2">
                        {Object.entries(results.headers).map(([key, value]) => (
                          <div key={key} className="border-b border-border pb-2">
                            <div className="font-mono text-sm text-primary">{key}</div>
                            <div className="font-mono text-xs text-muted-foreground break-all">{value}</div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </Card>
                  
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.cookies', 'Cookies')}
                    </h3>
                    
                    {results.cookies && results.cookies.length > 0 ? (
                      <Accordion type="single" collapsible className="w-full">
                        {results.cookies.map((cookie, index) => (
                          <AccordionItem key={index} value={`cookie-${index}`}>
                            <AccordionTrigger className="text-sm">{cookie.name || `Cookie ${index + 1}`}</AccordionTrigger>
                            <AccordionContent>
                              <div className="space-y-1 p-2 text-xs font-mono">
                                {Object.entries(cookie).map(([key, value]) => (
                                  <div key={key} className="flex justify-between">
                                    <span className="text-muted-foreground">{key}:</span>
                                    <span className="text-foreground">{String(value)}</span>
                                  </div>
                                ))}
                              </div>
                            </AccordionContent>
                          </AccordionItem>
                        ))}
                      </Accordion>
                    ) : (
                      <div className="p-3 text-muted-foreground text-center">
                        No cookies found
                      </div>
                    )}
                  </Card>
                </TabsContent>
                
                <TabsContent value="technical" className="space-y-4">
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.all', 'All Detected Technologies')}
                    </h3>
                    
                    {results.technologies && results.technologies.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {results.technologies.map((tech, index) => (
                          renderTechItem(tech, index)
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-muted-foreground text-center">
                        No technologies detected
                      </div>
                    )}
                  </Card>
                  
                  <Card className="p-4 border-border bg-card/50">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('tech.detector.meta', 'Meta Tags')}
                    </h3>
                    
                    <ScrollArea className="h-[200px] pr-4">
                      <div className="space-y-2">
                        {Object.entries(results.metaTags).length > 0 ? (
                          Object.entries(results.metaTags).map(([key, value]) => (
                            <div key={key} className="border-b border-border pb-2">
                              <div className="font-mono text-sm text-primary">{key}</div>
                              <div className="font-mono text-xs text-muted-foreground break-all">{value}</div>
                            </div>
                          ))
                        ) : (
                          <div className="p-3 text-muted-foreground text-center">
                            No meta tags found
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </Card>
                </TabsContent>
              </Tabs>
            </Card>
          ) : (
            <div className="h-full flex items-center justify-center border border-dashed border-border rounded-md p-12">
              <div className="text-center space-y-3">
                <Layers className="w-12 h-12 text-primary/50 mx-auto" />
                <h3 className="text-xl font-semibold text-foreground">
                  {t('tech.detector.start', 'Technology Analysis')}
                </h3>
                <p className="text-muted-foreground max-w-md">
                  {t('tech.detector.description', 'Identify technologies, frameworks, and libraries used by any website. Enter a URL to begin scanning.')}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}