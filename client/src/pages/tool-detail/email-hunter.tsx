import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import Terminal from '@/components/terminal';
import { AlertCircle, Search, RotateCw, AtSign, Globe, Clock, Loader2, ExternalLink } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useTerminal } from '@/hooks/use-terminal';
import { MatrixBackground } from '@/components/matrix-background';
import { Badge } from '@/components/ui/badge';

// Temporary translation function until full i18n is implemented
const useTranslation = () => {
  return {
    t: (key: string, defaultValue: string) => defaultValue,
    language: 'en',
    setLanguage: () => {}
  };
};

// Define types for email hunting results
interface EmailHunterResult {
  url: string;
  emailAddresses: string[];
  potentialEmails: string[];
  patternsFound: string[];
  scanTime: number;
  scannedPages: number;
  sources: {
    [url: string]: string[];
  };
  scanId?: number;
}

export default function EmailHunterPage() {
  const { t } = useTranslation();
  const [url, setUrl] = useState('');
  const [maxDepth, setMaxDepth] = useState(1);
  const [followLinks, setFollowLinks] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<EmailHunterResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('emails');
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

  // Start email hunting
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
    addCommandLine(`Scanning for emails on ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Scan depth: ${maxDepth}`);
    if (followLinks) {
      addInfoLine('Following links: Yes (within the same domain)');
    } else {
      addInfoLine('Following links: No (scanning only the target page)');
    }

    try {
      const response = await fetch('/api/scan/email-hunter', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: normalizedUrl,
          maxDepth,
          followLinks,
          timeout: 15000
        })
      }).then(res => res.json());

      if (response.success) {
        setResults(response.data);
        const { emailAddresses, scannedPages, scanTime } = response.data;
        
        addSuccessLine(`Scan completed for ${normalizedUrl}`);
        addInfoLine(`Scanned ${scannedPages} pages in ${scanTime}ms`);
        
        if (emailAddresses.length > 0) {
          addSuccessLine(`Found ${emailAddresses.length} email addresses`);
          emailAddresses.slice(0, 5).forEach((email: string) => {
            addInfoLine(`Email: ${email}`);
          });
          if (emailAddresses.length > 5) {
            addInfoLine(`... and ${emailAddresses.length - 5} more`);
          }
        } else {
          addInfoLine('No email addresses were found');
        }

        // Show scan result ID if available
        if (response.data.scanId) {
          addSuccessLine(`Scan results saved with ID: ${response.data.scanId}`);
        }
      } else {
        throw new Error(response.message || 'Scan failed');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to scan for emails';
      setError(message);
      addErrorLine(`Error: ${message}`);
      toast({
        variant: "destructive",
        title: "Scan failed",
        description: message
      });
    } finally {
      setIsScanning(false);
    }
  };

  // Reset form
  const handleReset = () => {
    setUrl('');
    setMaxDepth(1);
    setFollowLinks(true);
    setResults(null);
    setError(null);
    setActiveTab('emails');
    clearLines();
    addInfoLine('Email hunter tool reset');
  };

  return (
    <div className="container mx-auto py-6 px-4 relative z-10">
      <Helmet>
        <title>Email Hunter - CyberPulse Security Toolkit</title>
        <meta name="description" content="Find email addresses on websites for information gathering" />
      </Helmet>
      
      <MatrixBackground className="opacity-5" />
      
      <h1 className="text-3xl font-tech mb-6 text-primary tracking-wider flex items-center">
        <AtSign className="inline-block mr-2" />
        {t('email.hunter.title', 'Email Address Hunter')}
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card className="p-4 border-primary/30 bg-card/80 backdrop-blur-sm">
            <h2 className="text-xl font-bold text-primary mb-4">
              {t('email.hunter.config', 'Scan Configuration')}
            </h2>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">{t('email.hunter.url', 'Target Website URL')}</Label>
                <Input
                  id="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="bg-background"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="max-depth">{t('email.hunter.depth', 'Maximum Scan Depth')}</Label>
                <Input
                  id="max-depth"
                  type="number"
                  min={1}
                  max={3}
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(parseInt(e.target.value) || 1)}
                  className="bg-background"
                />
                <p className="text-xs text-muted-foreground">
                  {t('email.hunter.depth.description', 'How many levels of links to follow (1-3). Higher values take longer but find more emails.')}
                </p>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="follow-links"
                  checked={followLinks}
                  onCheckedChange={(checked) => setFollowLinks(!!checked)}
                />
                <Label htmlFor="follow-links" className="cursor-pointer">
                  {t('email.hunter.follow', 'Follow Links on Site')}
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
                      {t('common.scanning', 'Scanning...')}
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4" />
                      {t('common.scan', 'Scan')}
                    </>
                  )}
                </Button>
                <Button variant="outline" onClick={handleReset} disabled={isScanning}>
                  <RotateCw className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div className="mt-8">
              <h3 className="text-lg font-semibold mb-2">{t('email.hunter.terminal', 'Scan Log')}</h3>
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
                    {t('email.hunter.results', 'Scan Results')}
                  </h2>
                  
                  <div className="flex items-center space-x-3">
                    <div className="flex items-center">
                      <Clock className="mr-1 h-4 w-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{results.scanTime} ms</span>
                    </div>
                    
                    <Badge variant="outline" className="bg-blue-500/20 text-blue-500 border-blue-500/50">
                      {results.scannedPages} {results.scannedPages === 1 ? 'page' : 'pages'}
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
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab} className="p-4">
                <TabsList className="mb-4">
                  <TabsTrigger value="emails">{t('email.hunter.tab.emails', 'Found Emails')}</TabsTrigger>
                  <TabsTrigger value="potential">{t('email.hunter.tab.potential', 'Potential Emails')}</TabsTrigger>
                  <TabsTrigger value="sources">{t('email.hunter.tab.sources', 'Sources')}</TabsTrigger>
                </TabsList>
                
                <TabsContent value="emails" className="space-y-4 mt-2">
                  {results.emailAddresses.length > 0 ? (
                    <div className="space-y-2">
                      <h3 className="text-lg font-semibold">
                        {t('email.hunter.foundEmails', 'Found Email Addresses')} ({results.emailAddresses.length})
                      </h3>
                      
                      <ScrollArea className="h-[300px] rounded-md border p-4">
                        <ul className="space-y-2">
                          {results.emailAddresses.map((email: string, index) => (
                            <li key={index} className="flex items-center p-2 hover:bg-accent/50 rounded-md">
                              <AtSign className="h-4 w-4 mr-2 text-primary" />
                              <span className="font-mono">{email}</span>
                            </li>
                          ))}
                        </ul>
                      </ScrollArea>
                    </div>
                  ) : (
                    <div className="text-center p-8 text-muted-foreground">
                      <AtSign className="mx-auto h-12 w-12 mb-3 opacity-20" />
                      <p>{t('email.hunter.noEmails', 'No email addresses were found on this website')}</p>
                    </div>
                  )}
                </TabsContent>
                
                <TabsContent value="potential" className="space-y-4 mt-2">
                  {results.potentialEmails.length > 0 ? (
                    <div className="space-y-2">
                      <h3 className="text-lg font-semibold">
                        {t('email.hunter.potentialEmails', 'Potential Email Addresses')} ({results.potentialEmails.length})
                      </h3>
                      <p className="text-sm text-muted-foreground">
                        {t('email.hunter.potentialDesc', 'These might be email addresses that are obfuscated or formatted to prevent scraping')}
                      </p>
                      
                      <ScrollArea className="h-[300px] rounded-md border p-4">
                        <ul className="space-y-2">
                          {results.potentialEmails.map((email, index) => (
                            <li key={index} className="flex items-start p-2 hover:bg-accent/50 rounded-md">
                              <AtSign className="h-4 w-4 mr-2 text-yellow-500 mt-1" />
                              <span className="font-mono">{email}</span>
                            </li>
                          ))}
                        </ul>
                      </ScrollArea>
                    </div>
                  ) : (
                    <div className="text-center p-8 text-muted-foreground">
                      <p>{t('email.hunter.noPotential', 'No potential email patterns were detected')}</p>
                    </div>
                  )}
                  
                  {results.patternsFound.length > 0 && (
                    <div className="mt-4">
                      <h4 className="text-sm font-medium mb-2">
                        {t('email.hunter.patterns', 'Detected Obfuscation Patterns')}
                      </h4>
                      <ul className="space-y-1">
                        {results.patternsFound.map((pattern, index) => (
                          <li key={index} className="text-sm text-muted-foreground">
                            • {pattern}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </TabsContent>
                
                <TabsContent value="sources" className="space-y-4 mt-2">
                  <h3 className="text-lg font-semibold">
                    {t('email.hunter.sources', 'Email Sources')}
                  </h3>
                  
                  <ScrollArea className="h-[300px] rounded-md border p-4">
                    {Object.keys(results.sources).length > 0 ? (
                      Object.entries(results.sources).map(([email, urls], index) => (
                        <div key={index} className="mb-4 pb-4 border-b border-border last:border-0">
                          <div className="font-mono font-medium text-primary mb-2 flex items-center">
                            <AtSign className="h-4 w-4 mr-1 inline" />
                            {email}
                          </div>
                          <div className="pl-6">
                            <p className="text-sm text-muted-foreground mb-1">Found on:</p>
                            <ul className="space-y-1">
                              {urls.map((url, urlIndex) => (
                                <li key={urlIndex} className="text-sm hover:underline">
                                  <a 
                                    href={url} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="flex items-center"
                                  >
                                    <Globe className="h-3 w-3 mr-1 inline text-muted-foreground" />
                                    {url.length > 50 ? url.substring(0, 50) + '...' : url}
                                    <ExternalLink className="h-2 w-2 ml-1 inline" />
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center p-4 text-muted-foreground">
                        <p>{t('email.hunter.noSources', 'No source information available')}</p>
                      </div>
                    )}
                  </ScrollArea>
                </TabsContent>
              </Tabs>
            </Card>
          ) : (
            <Card className="p-8 border-primary/30 bg-card/80 backdrop-blur-sm h-full flex items-center justify-center">
              <div className="text-center max-w-md">
                <AtSign className="h-16 w-16 mx-auto mb-4 text-primary/20" />
                <h3 className="text-xl font-bold mb-2">{t('email.hunter.instructions', 'Email Hunter Tool')}</h3>
                <p className="text-muted-foreground mb-4">
                  {t('email.hunter.description', 'Find email addresses on websites by scanning their content. Enter a URL and set your scan parameters to get started.')}
                </p>
                <div className="text-sm text-muted-foreground space-y-2 text-left">
                  <p>• {t('email.hunter.tip1', 'Higher scan depth will find more emails but takes longer')}</p>
                  <p>• {t('email.hunter.tip2', 'The tool will stay within the same domain')}</p>
                  <p>• {t('email.hunter.tip3', 'Look for potential emails that might be obfuscated')}</p>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}