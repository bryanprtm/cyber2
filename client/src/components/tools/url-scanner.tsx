import React, { useState } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  GlobeIcon, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX,
  AlertTriangle,
  ExternalLink,
  RefreshCw,
  Link2,
  FileText,
  CheckCircle2,
  XCircle,
  Info,
  Server
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface UrlScannerProps {
  onScanComplete?: (result: any) => void;
}

export default function UrlScanner({ onScanComplete }: UrlScannerProps) {
  const [url, setUrl] = useState<string>('');
  const [checkPhishing, setCheckPhishing] = useState<boolean>(true);
  const [checkMalware, setCheckMalware] = useState<boolean>(true);
  const [checkReputation, setCheckReputation] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResults, setScanResults] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addSuccessLine } = useTerminal();
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
    
    addCommandLine(`Starting URL scan for ${normalizedUrl}...`);
    addInfoLine(`Target URL: ${normalizedUrl}`);
    addInfoLine(`Scan Options: Phishing=${checkPhishing}, Malware=${checkMalware}, Reputation=${checkReputation}`);
    
    // Simulate progress for UX
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + 10;
      });
    }, 400);
    
    try {
      const response = await axios.post('/api/security/url-scanner', {
        url: normalizedUrl,
        checkPhishing,
        checkMalware,
        checkReputation
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.success) {
        const result = response.data.data;
        setScanResults(result);
        
        // Send terminal output based on results
        addSuccessLine('URL scan completed');
        
        if (result.securityRating.overall === 'Safe') {
          addSuccessLine(`Security Rating: ${result.securityRating.overall} (Score: ${result.securityRating.score}/100)`);
        } else if (result.securityRating.overall === 'Suspicious') {
          addErrorLine(`Security Rating: ${result.securityRating.overall} (Score: ${result.securityRating.score}/100)`);
        } else {
          addErrorLine(`Security Rating: ${result.securityRating.overall} (Score: ${result.securityRating.score}/100)`);
        }
        
        // Log risk factors if present
        if (result.riskFactors && result.riskFactors.length > 0) {
          addInfoLine(`Found ${result.riskFactors.length} risk factors:`);
          result.riskFactors.forEach((risk: any) => {
            addErrorLine(`- ${risk.type} (${risk.severity}): ${risk.description}`);
          });
        }
        
        if (onScanComplete) {
          onScanComplete(result);
        }
        
        toast({
          title: 'Scan completed',
          description: `${normalizedUrl} analyzed with ${result.securityRating.overall} rating`,
          variant: result.securityRating.overall === 'Safe' ? 'default' : 'destructive'
        });
      } else {
        setError(response.data.message || 'Failed to scan URL');
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
  
  const handleReset = () => {
    setUrl('');
    setScanResults(null);
    setError(null);
    setScanProgress(0);
    addCommandLine('Reset URL scanner');
  };
  
  // Get color based on security rating
  const getSecurityColor = (rating: string): string => {
    switch (rating) {
      case 'Safe':
        return 'text-green-500';
      case 'Suspicious':
        return 'text-amber-500';
      case 'Malicious':
        return 'text-red-500';
      default:
        return 'text-muted-foreground';
    }
  };
  
  // Get icon based on security rating
  const getSecurityIcon = (rating: string) => {
    switch (rating) {
      case 'Safe':
        return <ShieldCheck className="h-5 w-5 text-green-500" />;
      case 'Suspicious':
        return <ShieldAlert className="h-5 w-5 text-amber-500" />;
      case 'Malicious':
        return <ShieldX className="h-5 w-5 text-red-500" />;
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
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">URL Security Scanner</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url" className="text-sm font-tech">URL to Scan</Label>
            <Input
              id="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="font-mono bg-background border-secondary/50"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter a complete URL including the protocol (http:// or https://)
            </p>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="check-phishing" 
                checked={checkPhishing}
                onCheckedChange={(checked) => setCheckPhishing(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="check-phishing" 
                className="text-sm font-tech cursor-pointer"
              >
                Check for phishing
              </Label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="check-malware" 
                checked={checkMalware}
                onCheckedChange={(checked) => setCheckMalware(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="check-malware" 
                className="text-sm font-tech cursor-pointer"
              >
                Check for malware
              </Label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="check-reputation" 
                checked={checkReputation}
                onCheckedChange={(checked) => setCheckReputation(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="check-reputation" 
                className="text-sm font-tech cursor-pointer"
              >
                Check site reputation
              </Label>
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
                <span>Scanning URL...</span>
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
              {isScanning ? 'Scanning...' : 'Scan URL'}
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
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="grid grid-cols-4 mb-4">
              <TabsTrigger value="overview" className="font-tech">Overview</TabsTrigger>
              <TabsTrigger value="security" className="font-tech">Security</TabsTrigger>
              <TabsTrigger value="content" className="font-tech">Content</TabsTrigger>
              <TabsTrigger value="reputation" className="font-tech">Reputation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="overview" className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-tech text-secondary">Scan Results</h3>
                  <p className="text-sm font-mono">{scanResults.normalizedUrl}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <div className={cn(
                    "px-3 py-1 rounded-full border flex items-center space-x-2",
                    getSecurityColor(scanResults.securityRating.overall)
                  )}>
                    {getSecurityIcon(scanResults.securityRating.overall)}
                    <span className="font-tech text-sm">{scanResults.securityRating.overall}</span>
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <GlobeIcon className="h-4 w-4 text-primary" />
                    URL Information
                  </h4>
                  <div className="space-y-1 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Protocol:</span>
                      <span className={scanResults.isSecure ? "text-green-500" : "text-amber-500"}>
                        {scanResults.protocol}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <span>{scanResults.status.code} {scanResults.status.text}</span>
                    </div>
                    {scanResults.ipAddress && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">IP Address:</span>
                        <span>{scanResults.ipAddress}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Redirects:</span>
                      <span>{scanResults.redirects?.length || 0}</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    Security Rating
                  </h4>
                  <div className="space-y-3 text-xs font-mono">
                    <div className="flex flex-col">
                      <div className="flex justify-between mb-1">
                        <span className="text-muted-foreground">Score:</span>
                        <span className={
                          scanResults.securityRating.score > 80 ? "text-green-500" :
                          scanResults.securityRating.score > 50 ? "text-amber-500" : 
                          "text-red-500"
                        }>
                          {scanResults.securityRating.score}/100
                        </span>
                      </div>
                      <div className="w-full bg-secondary/20 h-1.5 rounded-full">
                        <div 
                          className={cn(
                            "h-full rounded-full",
                            scanResults.securityRating.score > 80 ? "bg-green-500" :
                            scanResults.securityRating.score > 50 ? "bg-amber-500" : 
                            "bg-red-500"
                          )} 
                          style={{width: `${scanResults.securityRating.score}%`}}
                        />
                      </div>
                    </div>
                    
                    {scanResults.securityRating.reasons.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Issues:</span>
                        <ul className="mt-1 space-y-1">
                          {scanResults.securityRating.reasons.slice(0, 2).map((reason: string, i: number) => (
                            <li key={i} className="flex items-start gap-1">
                              <AlertTriangle className="h-3 w-3 mt-0.5 text-amber-500 flex-shrink-0" />
                              <span>{reason}</span>
                            </li>
                          ))}
                          {scanResults.securityRating.reasons.length > 2 && (
                            <li className="text-muted-foreground">
                              +{scanResults.securityRating.reasons.length - 2} more issues
                            </li>
                          )}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
              
              {scanResults.riskFactors?.length > 0 && (
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2">Risk Factors</h4>
                  <div className="space-y-2">
                    {scanResults.riskFactors.map((risk: any, i: number) => (
                      <div key={i} className={cn(
                        "text-xs font-mono p-2 rounded border",
                        getSeverityColor(risk.severity)
                      )}>
                        <div className="font-bold">{risk.type} ({risk.severity})</div>
                        <div>{risk.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {scanResults.contentAnalysis?.technologies?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {scanResults.contentAnalysis.technologies.map((tech: string, i: number) => (
                    <Badge key={i} variant="secondary" className="text-xs">
                      {tech}
                    </Badge>
                  ))}
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="security" className="space-y-4">
              <div className="bg-background p-4 rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-3 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-primary" />
                  Security Analysis
                </h4>
                
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className={cn(
                    "p-3 rounded border flex flex-col items-center justify-center",
                    scanResults.phishingDetection?.isPhishing 
                      ? "border-red-500 bg-red-500/5" 
                      : "border-green-500 bg-green-500/5"
                  )}>
                    {scanResults.phishingDetection?.isPhishing 
                      ? <ShieldAlert className="h-6 w-6 text-red-500 mb-1" />
                      : <ShieldCheck className="h-6 w-6 text-green-500 mb-1" />
                    }
                    <span className="text-sm font-tech">
                      {scanResults.phishingDetection?.isPhishing 
                        ? "Phishing Detected" 
                        : "No Phishing"}
                    </span>
                    {scanResults.phishingDetection?.confidence && (
                      <span className="text-xs font-mono text-muted-foreground">
                        Confidence: {scanResults.phishingDetection.confidence}%
                      </span>
                    )}
                  </div>
                  
                  <div className={cn(
                    "p-3 rounded border flex flex-col items-center justify-center",
                    scanResults.malwareDetection?.hasMalware 
                      ? "border-red-500 bg-red-500/5" 
                      : "border-green-500 bg-green-500/5"
                  )}>
                    {scanResults.malwareDetection?.hasMalware 
                      ? <AlertTriangle className="h-6 w-6 text-red-500 mb-1" />
                      : <ShieldCheck className="h-6 w-6 text-green-500 mb-1" />
                    }
                    <span className="text-sm font-tech">
                      {scanResults.malwareDetection?.hasMalware 
                        ? "Malware Detected" 
                        : "No Malware"}
                    </span>
                    {scanResults.malwareDetection?.confidence && (
                      <span className="text-xs font-mono text-muted-foreground">
                        Confidence: {scanResults.malwareDetection.confidence}%
                      </span>
                    )}
                  </div>
                </div>
                
                {scanResults.phishingDetection && scanResults.phishingDetection.indicators?.length > 0 && (
                  <div className="mb-4">
                    <h5 className="text-xs font-tech mb-2">Phishing Indicators</h5>
                    <ul className="space-y-1 text-xs font-mono">
                      {scanResults.phishingDetection.indicators.map((indicator: string, i: number) => (
                        <li key={i} className="flex items-start gap-1">
                          <AlertCircle className="h-3 w-3 text-red-500 mt-0.5 flex-shrink-0" />
                          <span>{indicator}</span>
                        </li>
                      ))}
                    </ul>
                    
                    {scanResults.phishingDetection.targetBrand && (
                      <div className="mt-2 p-2 bg-red-500/10 rounded text-xs font-mono border border-red-500/30">
                        Potential target: {scanResults.phishingDetection.targetBrand}
                      </div>
                    )}
                  </div>
                )}
                
                {scanResults.malwareDetection && scanResults.malwareDetection.detectionType?.length > 0 && (
                  <div>
                    <h5 className="text-xs font-tech mb-2">Malware Details</h5>
                    <div className="space-y-1 text-xs font-mono">
                      <div className="flex items-start gap-1">
                        <AlertCircle className="h-3 w-3 text-red-500 mt-0.5 flex-shrink-0" />
                        <span>Detection: {scanResults.malwareDetection.detectionType.join(', ')}</span>
                      </div>
                      
                      {scanResults.malwareDetection.virusNames && (
                        <div className="flex items-start gap-1">
                          <AlertTriangle className="h-3 w-3 text-red-500 mt-0.5 flex-shrink-0" />
                          <span>Identified as: {scanResults.malwareDetection.virusNames.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
              
              <div className="bg-background p-4 rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-2">Security Features</h4>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="flex items-center gap-1">
                    {scanResults.isSecure 
                      ? <CheckCircle2 className="h-4 w-4 text-green-500" />
                      : <XCircle className="h-4 w-4 text-red-500" />
                    }
                    <span>HTTPS Encryption</span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    {!scanResults.redirects || scanResults.redirects.length === 0
                      ? <CheckCircle2 className="h-4 w-4 text-green-500" />
                      : <Info className="h-4 w-4 text-amber-500" />
                    }
                    <span>
                      {!scanResults.redirects || scanResults.redirects.length === 0
                        ? "No Redirects"
                        : `${scanResults.redirects.length} Redirects`}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    {scanResults.contentAnalysis?.hasLogin && !scanResults.isSecure
                      ? <XCircle className="h-4 w-4 text-red-500" />
                      : scanResults.contentAnalysis?.hasLogin
                        ? <Info className="h-4 w-4 text-amber-500" />
                        : <CheckCircle2 className="h-4 w-4 text-green-500" />
                    }
                    <span>
                      {scanResults.contentAnalysis?.hasLogin && !scanResults.isSecure
                        ? "Insecure Login"
                        : scanResults.contentAnalysis?.hasLogin
                          ? "Login Form Present"
                          : "No Login Form"}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    {scanResults.contentAnalysis?.hasExternalScripts
                      ? <Info className="h-4 w-4 text-amber-500" />
                      : <CheckCircle2 className="h-4 w-4 text-green-500" />
                    }
                    <span>
                      {scanResults.contentAnalysis?.hasExternalScripts
                        ? "External Scripts"
                        : "No External Scripts"}
                    </span>
                  </div>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="content" className="space-y-4">
              <div className="bg-background p-4 rounded-md border border-secondary/20">
                <h4 className="text-sm font-tech mb-3 flex items-center gap-2">
                  <FileText className="h-4 w-4 text-primary" />
                  Page Content Analysis
                </h4>
                
                {scanResults.contentAnalysis?.title && (
                  <div className="mb-3">
                    <h5 className="text-xs font-tech mb-1">Page Title</h5>
                    <p className="text-sm font-mono p-2 bg-secondary/5 rounded">{scanResults.contentAnalysis.title}</p>
                  </div>
                )}
                
                {scanResults.contentAnalysis?.description && (
                  <div className="mb-3">
                    <h5 className="text-xs font-tech mb-1">Meta Description</h5>
                    <p className="text-xs font-mono p-2 bg-secondary/5 rounded">{scanResults.contentAnalysis.description}</p>
                  </div>
                )}
                
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="flex items-center gap-1">
                    {scanResults.contentAnalysis?.hasLogin
                      ? <Info className="h-4 w-4 text-amber-500" />
                      : <Info className="h-4 w-4 text-muted-foreground" />
                    }
                    <span>
                      {scanResults.contentAnalysis?.hasLogin
                        ? "Contains Login Form"
                        : "No Login Form"}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    {scanResults.contentAnalysis?.hasDownloads
                      ? <Info className="h-4 w-4 text-amber-500" />
                      : <Info className="h-4 w-4 text-muted-foreground" />
                    }
                    <span>
                      {scanResults.contentAnalysis?.hasDownloads
                        ? "Contains Downloads"
                        : "No Downloads"}
                    </span>
                  </div>
                </div>
              </div>
              
              {scanResults.contentAnalysis?.externalDomains?.length > 0 && (
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <ExternalLink className="h-4 w-4 text-primary" />
                    External Domains
                  </h4>
                  <div className="space-y-1 text-xs font-mono">
                    {scanResults.contentAnalysis.externalDomains.map((domain: string, i: number) => (
                      <div key={i} className="flex items-center gap-1 p-1 border-b border-dashed border-secondary/20 last:border-0">
                        <Link2 className="h-3 w-3 text-secondary flex-shrink-0" />
                        <span>{domain}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {scanResults.contentAnalysis?.technologies?.length > 0 && (
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-2 flex items-center gap-2">
                    <Server className="h-4 w-4 text-primary" />
                    Technologies Detected
                  </h4>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {scanResults.contentAnalysis.technologies.map((tech: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs">
                        {tech}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="reputation" className="space-y-4">
              {scanResults.reputationInfo ? (
                <div className="bg-background p-4 rounded-md border border-secondary/20">
                  <h4 className="text-sm font-tech mb-3 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    Site Reputation
                  </h4>
                  
                  <div className="mb-4">
                    <h5 className="text-xs font-tech mb-1">Reputation Score</h5>
                    <div className="flex flex-col">
                      <div className="flex justify-between mb-1">
                        <span className="text-xs font-mono text-muted-foreground">Score:</span>
                        <span className={cn(
                          "text-xs font-mono",
                          scanResults.reputationInfo.score > 70 ? "text-green-500" :
                          scanResults.reputationInfo.score > 40 ? "text-amber-500" : 
                          "text-red-500"
                        )}>
                          {scanResults.reputationInfo.score}/100
                        </span>
                      </div>
                      <div className="w-full bg-secondary/20 h-1.5 rounded-full">
                        <div 
                          className={cn(
                            "h-full rounded-full",
                            scanResults.reputationInfo.score > 70 ? "bg-green-500" :
                            scanResults.reputationInfo.score > 40 ? "bg-amber-500" : 
                            "bg-red-500"
                          )} 
                          style={{width: `${scanResults.reputationInfo.score}%`}}
                        />
                      </div>
                    </div>
                  </div>
                  
                  {scanResults.reputationInfo.categories?.length > 0 && (
                    <div className="mb-4">
                      <h5 className="text-xs font-tech mb-1">Categories</h5>
                      <div className="flex flex-wrap gap-1">
                        {scanResults.reputationInfo.categories.map((category: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {category}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    {scanResults.reputationInfo.firstSeen && (
                      <div>
                        <span className="text-muted-foreground">First Seen:</span>
                        <div className="mt-1">
                          {new Date(scanResults.reputationInfo.firstSeen).toLocaleDateString()}
                        </div>
                      </div>
                    )}
                    
                    {scanResults.reputationInfo.lastUpdated && (
                      <div>
                        <span className="text-muted-foreground">Last Updated:</span>
                        <div className="mt-1">
                          {new Date(scanResults.reputationInfo.lastUpdated).toLocaleDateString()}
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <div className="mt-3 text-xs font-mono text-muted-foreground">
                    Source: {scanResults.reputationInfo.source}
                  </div>
                </div>
              ) : (
                <div className="bg-background p-4 rounded-md border border-secondary/20 text-center py-8">
                  <Info className="h-6 w-6 text-muted-foreground mx-auto mb-2" />
                  <p className="text-sm font-mono">Reputation information was not checked for this URL.</p>
                  <p className="text-xs font-mono text-muted-foreground mt-1">
                    Enable "Check site reputation" option to view this data.
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