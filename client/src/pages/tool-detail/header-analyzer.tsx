import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import Terminal from '@/components/terminal';
import { AlertCircle, Search, RotateCw, Database, Globe, Server, Shield, Clock, Loader2, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';
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

// Define types for header analysis results
interface SecurityHeader {
  name: string;
  value: string | null;
  description: string;
  status: 'good' | 'warning' | 'bad' | 'info';
  recommendation?: string;
}

interface HeaderAnalysisResult {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  securityHeaders: SecurityHeader[];
  missingSecurityHeaders: SecurityHeader[];
  serverInfo: {
    server?: string;
    poweredBy?: string;
    technology?: string;
  };
  redirectChain?: Array<{
    url: string;
    statusCode: number;
    headers: Record<string, string>;
  }>;
  totalTime: number;
  securityScore: number;
  contentType?: string;
  cookies?: Array<{
    name: string;
    value: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: string;
  }>;
  requestSummary: {
    method: string;
    url: string;
    redirects: number;
    headersCount: number;
  };
}

export default function HeaderAnalyzerPage() {
  const { t } = useTranslation();
  const [url, setUrl] = useState('');
  const [followRedirects, setFollowRedirects] = useState(true);
  const [userAgent, setUserAgent] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<HeaderAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('security');
  const { toast } = useToast();
  const { addCommandLine, addInfoLine, addErrorLine, addSuccessLine, clearLines } = useTerminal();

  // Validate URL format
  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch (e) {
      return false;
    }
  };

  // Analyze headers
  const handleAnalyze = async () => {
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
    setIsAnalyzing(true);
    clearLines();
    addCommandLine(`Analyzing headers for ${normalizedUrl}...`);
    addInfoLine(`HTTP Request: GET ${normalizedUrl}`);
    if (followRedirects) {
      addInfoLine('Following redirects: Yes (max 5)');
    }
    if (userAgent) {
      addInfoLine(`Using custom User-Agent: ${userAgent}`);
    }

    try {
      const response = await apiMutation({
        url: '/api/analyze/headers',
        method: 'POST',
        data: {
          url: normalizedUrl,
          followRedirects,
          userAgent: userAgent || undefined,
          timeout: 10000
        }
      });

      if (response.success) {
        setResults(response.data);
        const { securityScore, statusCode } = response.data;
        
        addSuccessLine(`Analysis completed for ${normalizedUrl}`);
        addInfoLine(`Security Score: ${securityScore}/100`);
        addInfoLine(`Status Code: ${statusCode}`);
        addInfoLine(`Response Time: ${response.data.totalTime}ms`);
        
        if (securityScore < 50) {
          addErrorLine('Security warning: This site has significant security header issues');
        } else if (securityScore < 80) {
          addInfoLine('Security notice: This site could improve its security headers');
        } else {
          addSuccessLine('Security headers are well configured');
        }

        // Save scan result to database
        await apiMutation({
          url: '/api/scan/save',
          method: 'POST',
          data: {
            toolId: 'header-analyzer',
            targetUrl: normalizedUrl,
            results: response.data,
            timestamp: new Date().toISOString()
          }
        }).then(saveResponse => {
          if (saveResponse.success) {
            addSuccessLine(`Scan results saved with ID: ${saveResponse.data.id}`);
          }
        }).catch(() => {
          addErrorLine('Failed to save scan results to database');
        });
      } else {
        throw new Error(response.message || 'Analysis failed');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to analyze headers';
      setError(message);
      addErrorLine(`Error: ${message}`);
      toast({
        variant: "destructive",
        title: "Analysis failed",
        description: message
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Reset form
  const handleReset = () => {
    setUrl('');
    setFollowRedirects(true);
    setUserAgent('');
    setResults(null);
    setError(null);
    setActiveTab('security');
    clearLines();
    addInfoLine('Header analyzer tool reset');
  };

  // Get status color for badges
  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'good': return 'bg-green-500/20 text-green-500 border-green-500/50';
      case 'warning': return 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50';
      case 'bad': return 'bg-red-500/20 text-red-500 border-red-500/50';
      case 'info': return 'bg-blue-500/20 text-blue-500 border-blue-500/50';
      default: return 'bg-slate-500/20 text-slate-500 border-slate-500/50';
    }
  };

  // Get score color for overall security score
  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-500';
    if (score >= 50) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="container mx-auto py-6 px-4 relative z-10">
      <Helmet>
        <title>Header Analyzer - CyberPulse Security Toolkit</title>
        <meta name="description" content="Analyze HTTP headers for security issues and vulnerabilities" />
      </Helmet>
      
      <MatrixBackground className="opacity-5" />
      
      <h1 className="text-3xl font-tech mb-6 text-primary tracking-wider flex items-center">
        <Server className="inline-block mr-2" />
        {t('header.analyzer.title', 'HTTP Header Security Analyzer')}
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="p-4 border-primary/30 bg-card/80 backdrop-blur-sm">
            <h2 className="text-xl font-bold text-primary mb-4">
              {t('header.analyzer.config', 'Analysis Configuration')}
            </h2>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">{t('header.analyzer.url', 'Target URL')}</Label>
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
                  id="follow-redirects"
                  checked={followRedirects}
                  onCheckedChange={(checked) => setFollowRedirects(checked as boolean)}
                />
                <Label htmlFor="follow-redirects" className="cursor-pointer">
                  {t('header.analyzer.redirects', 'Follow Redirects')}
                </Label>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="user-agent">{t('header.analyzer.useragent', 'Custom User-Agent')} ({t('common.optional', 'Optional')})</Label>
                <Input
                  id="user-agent"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  placeholder="Mozilla/5.0 (compatible; SecurityScanner/1.0)"
                  className="bg-background"
                />
              </div>
              
              {error && (
                <div className="bg-red-500/20 text-red-500 p-3 rounded-md flex items-start">
                  <AlertCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              
              <div className="flex space-x-2 pt-2">
                <Button onClick={handleAnalyze} disabled={isAnalyzing} className="flex-1">
                  {isAnalyzing ? (
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
                <Button variant="outline" onClick={handleReset} disabled={isAnalyzing}>
                  <RotateCw className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div className="mt-8">
              <h3 className="text-lg font-semibold mb-2">{t('header.analyzer.terminal', 'Analysis Log')}</h3>
              <Terminal lines={[]} maxHeight="200px" />
            </div>
          </Card>
        </div>
        
        <div className="lg:col-span-2">
          {results ? (
            <Card className="border-primary/30 bg-card/80 backdrop-blur-sm overflow-hidden">
              <div className="p-4 border-b border-border">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h2 className="text-xl font-bold text-primary">
                    {t('header.analyzer.results', 'Analysis Results')}
                  </h2>
                  
                  <div className="flex items-center space-x-3">
                    <div className="flex items-center">
                      <Clock className="mr-1 h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{results.totalTime} ms</span>
                    </div>
                    
                    <div className="flex items-center">
                      <Shield className="mr-1 h-4 w-4 text-muted-foreground" />
                      <span className={`text-sm font-bold ${getScoreColor(results.securityScore)}`}>
                        {results.securityScore}/100
                      </span>
                    </div>
                    
                    <Badge variant="outline" className={results.statusCode >= 200 && results.statusCode < 300 ? 
                      'bg-green-500/20 text-green-500 border-green-500/50' : 
                      'bg-red-500/20 text-red-500 border-red-500/50'
                    }>
                      {results.statusCode}
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
                      <ExternalLink className="h-3 w-3 ml-1" />
                    </a>
                  </div>
                </div>
                
                {/* Security score progress bar */}
                <div className="mt-4">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium">
                      {t('header.analyzer.securityScore', 'Security Score')}
                    </span>
                    <span className={`text-sm font-bold ${getScoreColor(results.securityScore)}`}>
                      {results.securityScore}%
                    </span>
                  </div>
                  <Progress 
                    value={results.securityScore} 
                    className="h-2"
                    indicatorClassName={cn(
                      results.securityScore >= 80 ? "bg-green-500" : 
                      results.securityScore >= 50 ? "bg-yellow-500" : 
                      "bg-red-500"
                    )}
                  />
                </div>
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="p-4">
                <TabsList className="mb-4">
                  <TabsTrigger value="security">{t('header.analyzer.tab.security', 'Security Headers')}</TabsTrigger>
                  <TabsTrigger value="response">{t('header.analyzer.tab.all', 'All Headers')}</TabsTrigger>
                  <TabsTrigger value="cookies">{t('header.analyzer.tab.cookies', 'Cookies')}</TabsTrigger>
                  <TabsTrigger value="server">{t('header.analyzer.tab.server', 'Server Info')}</TabsTrigger>
                </TabsList>
                
                <TabsContent value="security" className="space-y-4 mt-2">
                  <div className="grid grid-cols-1 gap-4">
                    {results.securityHeaders.length > 0 && (
                      <div className="space-y-3">
                        <h3 className="text-lg font-semibold">
                          {t('header.analyzer.presentHeaders', 'Present Security Headers')}
                        </h3>
                        
                        {results.securityHeaders.map((header) => (
                          <Card key={header.name} className={cn(
                            "p-3 border bg-background/50",
                            header.status === 'good' ? "border-green-500/30" : 
                            header.status === 'warning' ? "border-yellow-500/30" : 
                            header.status === 'bad' ? "border-red-500/30" : 
                            "border-blue-500/30"
                          )}>
                            <div className="flex items-start justify-between">
                              <div>
                                <div className="flex items-center">
                                  <h4 className="font-mono text-sm font-bold">{header.name}</h4>
                                  <Badge variant="outline" className={cn("ml-2", getStatusColor(header.status))}>
                                    {header.status}
                                  </Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{header.description}</p>
                              </div>
                            </div>
                            
                            <div className="mt-2 bg-background/80 p-2 rounded font-mono text-xs break-all">
                              {header.value}
                            </div>
                            
                            {header.recommendation && (
                              <div className="mt-2 text-xs italic text-yellow-500">
                                {header.recommendation}
                              </div>
                            )}
                          </Card>
                        ))}
                      </div>
                    )}
                    
                    {results.missingSecurityHeaders.length > 0 && (
                      <div className="space-y-3 mt-6">
                        <h3 className="text-lg font-semibold">
                          {t('header.analyzer.missingHeaders', 'Missing Security Headers')}
                        </h3>
                        
                        {results.missingSecurityHeaders.map((header) => (
                          <Card key={header.name} className={cn(
                            "p-3 border bg-background/50",
                            header.status === 'info' ? "border-blue-500/30" :
                            header.status === 'warning' ? "border-yellow-500/30" : 
                            "border-red-500/30"
                          )}>
                            <div className="flex items-start justify-between">
                              <div>
                                <div className="flex items-center">
                                  <h4 className="font-mono text-sm font-bold">{header.name}</h4>
                                  <Badge variant="outline" className={cn("ml-2", getStatusColor(header.status))}>
                                    {header.status}
                                  </Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{header.description}</p>
                              </div>
                            </div>
                            
                            {header.recommendation && (
                              <div className="mt-2 text-xs bg-background/80 p-2 rounded">
                                <span className="font-semibold">{t('common.recommendation', 'Recommendation')}:</span> {header.recommendation}
                              </div>
                            )}
                          </Card>
                        ))}
                      </div>
                    )}
                  </div>
                </TabsContent>
                
                <TabsContent value="response" className="space-y-4 mt-2">
                  <Card className="border-primary/20 bg-background/50 p-4">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('header.analyzer.allHeaders', 'All Response Headers')}
                    </h3>
                    
                    <ScrollArea className="h-[400px] pr-4">
                      <div className="space-y-2">
                        {Object.entries(results.headers).map(([name, value]) => (
                          <div key={name} className="border-b border-border pb-2">
                            <div className="font-mono text-sm font-bold">{name}</div>
                            <div className="font-mono text-xs break-all">{value}</div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </Card>
                </TabsContent>
                
                <TabsContent value="cookies" className="space-y-4 mt-2">
                  <Card className="border-primary/20 bg-background/50 p-4">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('header.analyzer.cookies', 'Cookies')}
                    </h3>
                    
                    {results.cookies && results.cookies.length > 0 ? (
                      <div className="space-y-3">
                        {results.cookies.map((cookie, idx) => (
                          <Card key={idx} className="p-3 border-border bg-background/70">
                            <div className="font-mono text-sm font-bold">{cookie.name}</div>
                            <div className="font-mono text-xs break-all mt-1 mb-2">{cookie.value}</div>
                            
                            <div className="flex flex-wrap gap-2">
                              <Badge variant="outline" className={cookie.secure ? 
                                'bg-green-500/20 text-green-500 border-green-500/50' : 
                                'bg-red-500/20 text-red-500 border-red-500/50'
                              }>
                                {cookie.secure ? 'Secure' : 'Not Secure'}
                              </Badge>
                              
                              <Badge variant="outline" className={cookie.httpOnly ? 
                                'bg-green-500/20 text-green-500 border-green-500/50' : 
                                'bg-red-500/20 text-red-500 border-red-500/50'
                              }>
                                {cookie.httpOnly ? 'HttpOnly' : 'Not HttpOnly'}
                              </Badge>
                              
                              {cookie.sameSite && (
                                <Badge variant="outline" className="bg-blue-500/20 text-blue-500 border-blue-500/50">
                                  SameSite: {cookie.sameSite}
                                </Badge>
                              )}
                            </div>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center p-4 text-muted-foreground">
                        {t('header.analyzer.noCookies', 'No cookies found in the response')}
                      </div>
                    )}
                  </Card>
                </TabsContent>
                
                <TabsContent value="server" className="space-y-4 mt-2">
                  <Card className="border-primary/20 bg-background/50 p-4">
                    <h3 className="text-lg font-semibold mb-3">
                      {t('header.analyzer.serverInfo', 'Server Information')}
                    </h3>
                    
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {results.serverInfo.server && (
                          <Card className="p-3 border-border bg-background/70">
                            <h4 className="text-sm font-medium text-muted-foreground">Server</h4>
                            <p className="font-mono text-sm">{results.serverInfo.server}</p>
                          </Card>
                        )}
                        
                        {results.serverInfo.poweredBy && (
                          <Card className="p-3 border-border bg-background/70">
                            <h4 className="text-sm font-medium text-muted-foreground">Powered By</h4>
                            <p className="font-mono text-sm">{results.serverInfo.poweredBy}</p>
                          </Card>
                        )}
                        
                        {results.serverInfo.technology && (
                          <Card className="p-3 border-border bg-background/70">
                            <h4 className="text-sm font-medium text-muted-foreground">Technology</h4>
                            <p className="font-mono text-sm">{results.serverInfo.technology}</p>
                          </Card>
                        )}
                        
                        {results.contentType && (
                          <Card className="p-3 border-border bg-background/70">
                            <h4 className="text-sm font-medium text-muted-foreground">Content Type</h4>
                            <p className="font-mono text-sm">{results.contentType}</p>
                          </Card>
                        )}
                      </div>
                      
                      <div>
                        <h4 className="text-sm font-medium text-muted-foreground mb-2">Request Summary</h4>
                        <Card className="p-3 border-border bg-background/70">
                          <div className="grid grid-cols-2 gap-2 text-sm">
                            <div>
                              <span className="text-muted-foreground">Method:</span> {results.requestSummary.method}
                            </div>
                            <div>
                              <span className="text-muted-foreground">Status:</span> {results.statusCode}
                            </div>
                            <div>
                              <span className="text-muted-foreground">Redirects:</span> {results.requestSummary.redirects}
                            </div>
                            <div>
                              <span className="text-muted-foreground">Headers:</span> {results.requestSummary.headersCount}
                            </div>
                          </div>
                        </Card>
                      </div>
                    </div>
                  </Card>
                </TabsContent>
              </Tabs>
            </Card>
          ) : (
            <Card className="p-6 border-primary/30 bg-card/80 backdrop-blur-sm h-full flex flex-col justify-center items-center text-center">
              <Server className="h-16 w-16 text-primary/50 mb-4" />
              <h2 className="text-xl font-bold text-primary mb-2">
                {t('header.analyzer.instruction', 'HTTP Header Security Analysis')}
              </h2>
              <p className="text-muted-foreground max-w-md">
                {t('header.analyzer.description', 'Enter a URL to analyze HTTP headers for security issues, information disclosure, and best practices compliance.')}
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-8 w-full max-w-2xl">
                <Card className="p-4 border-primary/20 bg-card/50">
                  <h3 className="font-tech text-primary">
                    {t('header.analyzer.feature.secure', 'Security Assessment')}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {t('header.analyzer.feature.secure.desc', 'Evaluate security headers and receive a comprehensive score with recommendations')}
                  </p>
                </Card>
                
                <Card className="p-4 border-primary/20 bg-card/50">
                  <h3 className="font-tech text-primary">
                    {t('header.analyzer.feature.privacy', 'Privacy Analysis')}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {t('header.analyzer.feature.privacy.desc', 'Identify information leakage through headers and analyze cookie security')}
                  </p>
                </Card>
                
                <Card className="p-4 border-primary/20 bg-card/50">
                  <h3 className="font-tech text-primary">
                    {t('header.analyzer.feature.tech', 'Technology Detection')}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {t('header.analyzer.feature.tech.desc', 'Discover server type, frameworks, and technologies in use')}
                  </p>
                </Card>
                
                <Card className="p-4 border-primary/20 bg-card/50">
                  <h3 className="font-tech text-primary">
                    {t('header.analyzer.feature.compliance', 'Best Practices')}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {t('header.analyzer.feature.compliance.desc', 'Check headers against security best practices and industry standards')}
                  </p>
                </Card>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}