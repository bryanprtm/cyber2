import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  Play, 
  Lock, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Fingerprint,
  Link,
  Calendar,
  Shield,
  Loader2
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface SslScannerProps {
  onScanComplete?: (result: any) => void;
}

interface Certificate {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  version: string;
  signatureAlgorithm: string;
  keyStrength: number;
  sans: string[];
}

interface Protocol {
  name: string;
  enabled: boolean;
  secure: boolean;
}

interface Cipher {
  name: string;
  strength: 'strong' | 'medium' | 'weak';
  secure: boolean;
}

interface SslScanResult {
  target: string;
  timestamp: Date;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  certificate: Certificate;
  protocols: Protocol[];
  ciphers: Cipher[];
  vulnerabilities: {
    heartbleed: boolean;
    poodle: boolean;
    freak: boolean;
    logjam: boolean;
    drown: boolean;
    beast: boolean;
    lucky13: boolean;
    ticketbleed: boolean;
    zombie: boolean;
    openSslCcs: boolean;
  };
  supportsPfs: boolean;
  supportsHsts: boolean;
  hasMixedContent: boolean;
  hasInsecureRenegotiation: boolean;
  hasSecureTls13: boolean;
  scanDuration: string;
}

export default function SslScanner({ onScanComplete }: SslScannerProps) {
  const [target, setTarget] = useState<string>('');
  const [showDetail, setShowDetail] = useState<boolean>(true);
  const [checkVulns, setCheckVulns] = useState<boolean>(true);
  const [checkCerts, setCheckCerts] = useState<boolean>(true);
  const [checkCiphers, setCheckCiphers] = useState<boolean>(true);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<SslScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Reset error state when inputs change
  useEffect(() => {
    setError(null);
  }, [target, showDetail, checkVulns, checkCerts, checkCiphers]);
  
  // Simulated scan progress
  useEffect(() => {
    let progressInterval: NodeJS.Timeout;
    
    if (isScanning && scanProgress < 100) {
      progressInterval = setInterval(() => {
        setScanProgress(prev => {
          const increment = Math.floor(Math.random() * 3) + 1;
          const newProgress = Math.min(prev + increment, 100);
          
          // Complete scan when reaching 100%
          if (newProgress === 100) {
            setTimeout(() => completeScan(), 500);
          }
          
          return newProgress;
        });
      }, 300);
    }
    
    return () => {
      if (progressInterval) clearInterval(progressInterval);
    };
  }, [isScanning, scanProgress]);
  
  // Start the SSL scan
  const startScan = () => {
    if (!target) {
      setError('Target hostname is required');
      addErrorLine('Target hostname is required');
      return;
    }
    
    // Validate hostname format (simple check)
    const hostnameRegex = /^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])*(\.[a-zA-Z]{2,})$/;
    if (!hostnameRegex.test(target)) {
      setError('Invalid hostname format. Please provide a valid domain name (e.g., example.com)');
      addErrorLine('Invalid hostname format. Please provide a valid domain name (e.g., example.com)');
      return;
    }
    
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    setError(null);
    
    // Log scan settings in terminal
    const commandArgs = [
      `--target ${target}`,
      showDetail ? '--detail' : '',
      checkVulns ? '--check-vulns' : '',
      checkCerts ? '--check-certs' : '',
      checkCiphers ? '--check-ciphers' : ''
    ].filter(Boolean).join(' ');
    
    addCommandLine(`ssl-scan ${commandArgs}`);
    addInfoLine(`Starting SSL scan on ${target}`);
    
    if (showDetail) {
      addInfoLine("Full scan will check certificates, protocols, ciphers, and vulnerabilities");
    }
  };
  
  // Complete the scan with simulated results
  const completeScan = () => {
    setIsScanning(false);
    
    // Generate simulated scan results
    const simulatedResults = generateSimulatedResults();
    setScanResults(simulatedResults);
    
    // Log summary in terminal
    addLine(`[COMPLETE] SSL scan completed in ${simulatedResults.scanDuration}`, "success");
    addInfoLine(`Certificate: ${simulatedResults.certificate.subject}`);
    addInfoLine(`Grade: ${simulatedResults.grade} (Score: ${simulatedResults.score}/100)`);
    
    const allVulnerabilities = Object.entries(simulatedResults.vulnerabilities)
      .filter(([_, isVulnerable]) => isVulnerable)
      .map(([name, _]) => name);
      
    if (allVulnerabilities.length > 0) {
      addLine(`[ALERT] Found ${allVulnerabilities.length} vulnerabilities: ${allVulnerabilities.join(', ')}`, "error");
    } else {
      addLine(`[SECURE] No known SSL/TLS vulnerabilities detected`, "success");
    }
    
    if (simulatedResults.certificate.daysRemaining <= 30) {
      addLine(`[WARNING] Certificate expires in ${simulatedResults.certificate.daysRemaining} days`, "warning");
    }
    
    // Show toast notification
    toast({
      title: "SSL Scan Complete",
      description: `${target} received a grade of ${simulatedResults.grade}`,
      variant: "default",
    });
    
    // Call completion callback if provided
    if (onScanComplete) {
      onScanComplete(simulatedResults);
    }
  };
  
  // Generate simulated scan results
  const generateSimulatedResults = (): SslScanResult => {
    // Randomly determine if the site is highly secure, moderately secure, or insecure
    const securityLevel = Math.random();
    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    let score: number;
    
    if (securityLevel > 0.8) {
      // Highly secure (20% chance)
      grade = 'A+';
      score = Math.floor(Math.random() * 5) + 95; // 95-100
    } else if (securityLevel > 0.6) {
      // Very secure (20% chance)
      grade = 'A';
      score = Math.floor(Math.random() * 10) + 85; // 85-94
    } else if (securityLevel > 0.4) {
      // Moderately secure (20% chance)
      grade = 'B';
      score = Math.floor(Math.random() * 10) + 75; // 75-84
    } else if (securityLevel > 0.25) {
      // Slightly insecure (15% chance)
      grade = 'C';
      score = Math.floor(Math.random() * 15) + 60; // 60-74
    } else if (securityLevel > 0.1) {
      // Insecure (15% chance)
      grade = 'D';
      score = Math.floor(Math.random() * 20) + 40; // 40-59
    } else {
      // Very insecure (10% chance)
      grade = 'F';
      score = Math.floor(Math.random() * 40); // 0-39
    }
    
    // Generate expiration date - more likely to be far in the future for secure sites
    const daysRemaining = securityLevel > 0.7 
      ? Math.floor(Math.random() * 300) + 65 // 65-365 days
      : Math.floor(Math.random() * 180) + 1; // 1-180 days
      
    const validFrom = new Date();
    validFrom.setDate(validFrom.getDate() - Math.floor(Math.random() * 365)); // 0-365 days ago
    
    const validTo = new Date();
    validTo.setDate(validTo.getDate() + daysRemaining);
    
    // Common certificate issuers
    const issuers = [
      "DigiCert Inc", 
      "Let's Encrypt", 
      "Sectigo Limited", 
      "Amazon", 
      "GlobalSign nv-sa",
      "GoDaddy.com, Inc.",
      "Comodo CA Limited"
    ];
    
    const issuer = issuers[Math.floor(Math.random() * issuers.length)];
    
    // Certificate
    const certificate: Certificate = {
      subject: `CN=${target}`,
      issuer: `CN=${issuer}`,
      validFrom: validFrom.toISOString().split('T')[0],
      validTo: validTo.toISOString().split('T')[0],
      daysRemaining,
      serialNumber: Array.from({length: 16}, () => Math.floor(Math.random() * 16).toString(16)).join('').toUpperCase(),
      version: "v3",
      signatureAlgorithm: securityLevel > 0.5 ? "SHA256withRSA" : "SHA1withRSA",
      keyStrength: securityLevel > 0.7 ? 4096 : securityLevel > 0.4 ? 2048 : 1024,
      sans: [`*.${target}`, `www.${target}`]
    };
    
    // Protocols (more likely to have insecure protocols enabled for lower grades)
    const protocols: Protocol[] = [
      {
        name: "TLS 1.3",
        enabled: securityLevel > 0.2,
        secure: true
      },
      {
        name: "TLS 1.2",
        enabled: true, // Almost always enabled
        secure: true
      },
      {
        name: "TLS 1.1",
        enabled: securityLevel < 0.7,
        secure: false
      },
      {
        name: "TLS 1.0",
        enabled: securityLevel < 0.6,
        secure: false
      },
      {
        name: "SSL 3.0",
        enabled: securityLevel < 0.3,
        secure: false
      },
      {
        name: "SSL 2.0",
        enabled: securityLevel < 0.15,
        secure: false
      }
    ];
    
    // Ciphers (more secure ciphers for higher grades)
    const strongCiphers = [
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_128_GCM_SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES256-GCM-SHA384"
    ];
    
    const mediumCiphers = [
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-SHA384",
      "ECDHE-RSA-AES128-SHA256",
      "ECDHE-RSA-AES256-SHA",
      "ECDHE-RSA-AES128-SHA"
    ];
    
    const weakCiphers = [
      "AES256-SHA",
      "AES128-SHA",
      "DES-CBC3-SHA",
      "RC4-SHA",
      "RC4-MD5"
    ];
    
    const ciphers: Cipher[] = [];
    
    // Add strong ciphers (more likely for secure sites)
    const strongCount = securityLevel > 0.8 ? 5 : securityLevel > 0.6 ? 3 : securityLevel > 0.4 ? 2 : 1;
    for (let i = 0; i < strongCount; i++) {
      ciphers.push({
        name: strongCiphers[i],
        strength: 'strong',
        secure: true
      });
    }
    
    // Add medium ciphers
    const mediumCount = securityLevel > 0.7 ? 2 : securityLevel > 0.4 ? 3 : 5;
    for (let i = 0; i < mediumCount; i++) {
      ciphers.push({
        name: mediumCiphers[i],
        strength: 'medium',
        secure: true
      });
    }
    
    // Add weak ciphers (more likely for insecure sites)
    const weakCount = securityLevel > 0.8 ? 0 : securityLevel > 0.6 ? 1 : securityLevel > 0.4 ? 2 : 5;
    for (let i = 0; i < weakCount; i++) {
      ciphers.push({
        name: weakCiphers[i],
        strength: 'weak',
        secure: false
      });
    }
    
    // Vulnerabilities (more likely to be present in lower grades)
    const vulnerabilities = {
      heartbleed: securityLevel < 0.2,
      poodle: securityLevel < 0.3,
      freak: securityLevel < 0.25,
      logjam: securityLevel < 0.35,
      drown: securityLevel < 0.3,
      beast: securityLevel < 0.4,
      lucky13: securityLevel < 0.3,
      ticketbleed: securityLevel < 0.2,
      zombie: securityLevel < 0.25,
      openSslCcs: securityLevel < 0.3
    };
    
    // Other security features (more likely to be present in higher grades)
    const supportsPfs = securityLevel > 0.4;
    const supportsHsts = securityLevel > 0.5;
    const hasMixedContent = securityLevel < 0.6;
    const hasInsecureRenegotiation = securityLevel < 0.4;
    const hasSecureTls13 = securityLevel > 0.7;
    
    // Generate scan duration
    const scanDuration = `${Math.floor(Math.random() * 2)}m ${Math.floor(Math.random() * 50) + 10}s`;
    
    // Return complete result object
    return {
      target,
      timestamp: new Date(),
      grade,
      score,
      certificate,
      protocols,
      ciphers,
      vulnerabilities,
      supportsPfs,
      supportsHsts,
      hasMixedContent,
      hasInsecureRenegotiation,
      hasSecureTls13,
      scanDuration
    };
  };
  
  // Get grade color based on the grade
  const getGradeColor = (grade: string): string => {
    switch (grade) {
      case 'A+':
        return 'bg-green-500 text-white';
      case 'A':
        return 'bg-green-400 text-white';
      case 'B':
        return 'bg-blue-500 text-white';
      case 'C':
        return 'bg-yellow-500 text-white';
      case 'D':
        return 'bg-orange-500 text-white';
      case 'F':
        return 'bg-red-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  };
  
  // Get progress color based on score
  const getProgressColor = (score: number): string => {
    if (score >= 90) return 'bg-green-500';
    if (score >= 80) return 'bg-green-400';
    if (score >= 70) return 'bg-blue-500';
    if (score >= 60) return 'bg-yellow-500';
    if (score >= 40) return 'bg-orange-500';
    return 'bg-red-500';
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">SSL/TLS Scanner</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-hostname" className="text-sm font-tech">
              Target Hostname
            </Label>
            <Input
              id="target-hostname"
              placeholder="example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-mono"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter a domain name to analyze its SSL/TLS configuration
            </p>
          </div>
          
          <div className="border border-border rounded-md p-3">
            <h3 className="text-sm font-tech mb-2">Scan Options</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="show-detail" 
                  checked={showDetail}
                  onCheckedChange={(checked) => setShowDetail(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="show-detail" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Show detailed results
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="check-vulns" 
                  checked={checkVulns}
                  onCheckedChange={(checked) => setCheckVulns(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="check-vulns" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Check for vulnerabilities
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="check-certs" 
                  checked={checkCerts}
                  onCheckedChange={(checked) => setCheckCerts(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="check-certs" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Verify certificate
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="check-ciphers" 
                  checked={checkCiphers}
                  onCheckedChange={(checked) => setCheckCiphers(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="check-ciphers" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Check cipher suites
                </Label>
              </div>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={startScan}
              disabled={isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isScanning ? (
                <span className="flex items-center">
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning...
                </span>
              ) : (
                <span className="flex items-center">
                  <Lock className="h-4 w-4 mr-2" />
                  Start SSL Scan
                </span>
              )}
            </Button>
          </div>
          
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Scan in progress...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="h-2" />
              <p className="text-xs font-mono text-muted-foreground animate-pulse">
                {scanProgress < 25 ? "Connecting to server..." : 
                 scanProgress < 50 ? "Analyzing protocols..." :
                 scanProgress < 75 ? "Checking ciphers and vulnerabilities..." :
                 "Verifying certificate..."}
              </p>
            </div>
          )}
        </div>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-tech text-secondary">SSL Scan Results</h2>
            <div className="flex items-center space-x-2">
              <div className={cn("text-2xl font-bold p-2 rounded-md w-12 h-12 flex items-center justify-center", getGradeColor(scanResults.grade))}>
                {scanResults.grade}
              </div>
              <div className="text-xs font-mono text-muted-foreground">
                Score: {scanResults.score}/100
              </div>
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Server</div>
                <div className="text-base font-tech mt-1">{target}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Certificate</div>
                <div className="text-base font-mono mt-1 truncate" title={scanResults.certificate.subject}>
                  {scanResults.certificate.subject}
                </div>
              </div>
            </div>
            
            <div className="w-full bg-background/50 rounded-full h-2.5 mb-1">
              <div 
                className={cn("h-2.5 rounded-full", getProgressColor(scanResults.score))} 
                style={{ width: `${scanResults.score}%` }}
              ></div>
            </div>
            
            <Tabs defaultValue="overview" onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid grid-cols-4 mb-2">
                <TabsTrigger value="overview" className="text-xs font-mono">Overview</TabsTrigger>
                <TabsTrigger value="certificate" className="text-xs font-mono">Certificate</TabsTrigger>
                <TabsTrigger value="protocols" className="text-xs font-mono">Protocols</TabsTrigger>
                <TabsTrigger value="vulnerabilities" className="text-xs font-mono">Vulnerabilities</TabsTrigger>
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className="bg-background p-3 rounded-md border border-border flex flex-col items-center justify-center">
                    {scanResults.certificate.daysRemaining > 30 ? (
                      <CheckCircle2 className="h-8 w-8 text-green-500 mb-2" />
                    ) : scanResults.certificate.daysRemaining > 7 ? (
                      <AlertTriangle className="h-8 w-8 text-yellow-500 mb-2" />
                    ) : (
                      <XCircle className="h-8 w-8 text-red-500 mb-2" />
                    )}
                    <div className="text-xs font-mono text-muted-foreground">Certificate Expires</div>
                    <div className="text-sm font-tech mt-1">{scanResults.certificate.daysRemaining} days</div>
                  </div>
                  
                  <div className="bg-background p-3 rounded-md border border-border flex flex-col items-center justify-center">
                    {scanResults.hasSecureTls13 ? (
                      <CheckCircle2 className="h-8 w-8 text-green-500 mb-2" />
                    ) : (
                      <XCircle className="h-8 w-8 text-orange-500 mb-2" />
                    )}
                    <div className="text-xs font-mono text-muted-foreground">TLS 1.3 Support</div>
                    <div className="text-sm font-tech mt-1">
                      {scanResults.hasSecureTls13 ? "Yes" : "No"}
                    </div>
                  </div>
                  
                  <div className="bg-background p-3 rounded-md border border-border flex flex-col items-center justify-center">
                    {Object.values(scanResults.vulnerabilities).some(v => v) ? (
                      <ShieldAlert className="h-8 w-8 text-red-500 mb-2" />
                    ) : (
                      <ShieldCheck className="h-8 w-8 text-green-500 mb-2" />
                    )}
                    <div className="text-xs font-mono text-muted-foreground">Vulnerabilities</div>
                    <div className="text-sm font-tech mt-1">
                      {Object.values(scanResults.vulnerabilities).filter(v => v).length}
                    </div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-sm font-tech">Key Findings</h3>
                  
                  <div className="space-y-2">
                    <div className={cn(
                      "p-2 border rounded-md flex items-start gap-2 text-xs font-mono",
                      scanResults.certificate.daysRemaining > 30 ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5"
                    )}>
                      <Calendar className={cn(
                        "h-4 w-4 mt-0.5",
                        scanResults.certificate.daysRemaining > 30 ? "text-green-500" : "text-red-500"
                      )} />
                      <div>
                        <div className="font-medium">Certificate Validity</div>
                        <div className="text-muted-foreground mt-1">
                          Valid from {scanResults.certificate.validFrom} to {scanResults.certificate.validTo} ({scanResults.certificate.daysRemaining} days remaining)
                        </div>
                      </div>
                    </div>
                    
                    <div className={cn(
                      "p-2 border rounded-md flex items-start gap-2 text-xs font-mono",
                      scanResults.supportsPfs ? "border-green-500/30 bg-green-500/5" : "border-orange-500/30 bg-orange-500/5"
                    )}>
                      <Fingerprint className={cn(
                        "h-4 w-4 mt-0.5",
                        scanResults.supportsPfs ? "text-green-500" : "text-orange-500"
                      )} />
                      <div>
                        <div className="font-medium">Perfect Forward Secrecy</div>
                        <div className="text-muted-foreground mt-1">
                          {scanResults.supportsPfs 
                            ? "Server supports Perfect Forward Secrecy" 
                            : "Server does not support Perfect Forward Secrecy"}
                        </div>
                      </div>
                    </div>
                    
                    <div className={cn(
                      "p-2 border rounded-md flex items-start gap-2 text-xs font-mono",
                      !scanResults.hasMixedContent ? "border-green-500/30 bg-green-500/5" : "border-orange-500/30 bg-orange-500/5"
                    )}>
                      <Link className={cn(
                        "h-4 w-4 mt-0.5",
                        !scanResults.hasMixedContent ? "text-green-500" : "text-orange-500"
                      )} />
                      <div>
                        <div className="font-medium">Mixed Content</div>
                        <div className="text-muted-foreground mt-1">
                          {scanResults.hasMixedContent 
                            ? "Site contains mixed HTTP/HTTPS content" 
                            : "No mixed content detected"}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="certificate" className="space-y-4">
                <div className="bg-background p-4 rounded-md border border-border">
                  <h3 className="text-sm font-tech mb-3">Certificate Details</h3>
                  
                  <div className="space-y-3 text-xs font-mono">
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Subject:</div>
                      <div className="col-span-2">{scanResults.certificate.subject}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Issuer:</div>
                      <div className="col-span-2">{scanResults.certificate.issuer}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Valid From:</div>
                      <div className="col-span-2">{scanResults.certificate.validFrom}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Valid To:</div>
                      <div className="col-span-2">{scanResults.certificate.validTo}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Serial Number:</div>
                      <div className="col-span-2">{scanResults.certificate.serialNumber}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Version:</div>
                      <div className="col-span-2">{scanResults.certificate.version}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Signature Algorithm:</div>
                      <div className="col-span-2">{scanResults.certificate.signatureAlgorithm}</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Key Strength:</div>
                      <div className="col-span-2">{scanResults.certificate.keyStrength} bits</div>
                    </div>
                    
                    <div className="grid grid-cols-3 gap-1">
                      <div className="text-muted-foreground">Subject Alternative Names:</div>
                      <div className="col-span-2">
                        {scanResults.certificate.sans.map((san, idx) => (
                          <div key={idx}>{san}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="p-3 border border-border rounded-md bg-background/50">
                  <h3 className="text-sm font-tech mb-2">Security Assessment</h3>
                  
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-start gap-2">
                      {scanResults.certificate.keyStrength >= 2048 ? (
                        <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 text-green-500" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 mt-0.5 text-red-500" />
                      )}
                      <div className="text-muted-foreground">
                        Key strength: {scanResults.certificate.keyStrength} bits 
                        {scanResults.certificate.keyStrength >= 2048 
                          ? " (Good - 2048 bits or more is secure)" 
                          : " (Weak - Less than 2048 bits is considered insecure)"}
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      {scanResults.certificate.signatureAlgorithm.includes("SHA256") ? (
                        <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 text-green-500" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 mt-0.5 text-red-500" />
                      )}
                      <div className="text-muted-foreground">
                        Signature algorithm: {scanResults.certificate.signatureAlgorithm}
                        {scanResults.certificate.signatureAlgorithm.includes("SHA256") 
                          ? " (Good - SHA256 or better is secure)" 
                          : " (Weak - SHA1 is deprecated and considered insecure)"}
                      </div>
                    </div>
                    
                    <div className="flex items-start gap-2">
                      {scanResults.certificate.daysRemaining > 30 ? (
                        <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 text-green-500" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 mt-0.5 text-red-500" />
                      )}
                      <div className="text-muted-foreground">
                        Expiration: {scanResults.certificate.daysRemaining} days remaining
                        {scanResults.certificate.daysRemaining > 30 
                          ? " (Good - More than 30 days until expiration)" 
                          : " (Critical - Certificate will expire soon)"}
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="protocols" className="space-y-4">
                <div className="bg-background p-4 rounded-md border border-border">
                  <h3 className="text-sm font-tech mb-3">Supported Protocols</h3>
                  
                  <div className="space-y-2">
                    {scanResults.protocols.map((protocol, idx) => (
                      <div 
                        key={idx}
                        className={cn(
                          "flex items-center justify-between p-2 text-xs font-mono border rounded-md",
                          protocol.enabled && protocol.secure 
                            ? "border-green-500/30 bg-green-500/5" 
                            : protocol.enabled && !protocol.secure 
                              ? "border-red-500/30 bg-red-500/5"
                              : "border-border bg-background/50"
                        )}
                      >
                        <div className="flex items-center gap-2">
                          {protocol.enabled ? (
                            protocol.secure ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                            ) : (
                              <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                            )
                          ) : (
                            <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                          )}
                          <span>{protocol.name}</span>
                        </div>
                        <Badge 
                          variant="outline" 
                          className={cn(
                            "ml-auto",
                            !protocol.enabled 
                              ? "bg-muted text-muted-foreground" 
                              : protocol.secure 
                                ? "bg-green-500/10 text-green-500" 
                                : "bg-red-500/10 text-red-500"
                          )}
                        >
                          {!protocol.enabled 
                            ? "Disabled" 
                            : protocol.secure 
                              ? "Secure" 
                              : "Insecure"}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="bg-background p-4 rounded-md border border-border">
                  <h3 className="text-sm font-tech mb-3">Cipher Suites ({scanResults.ciphers.length})</h3>
                  
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {scanResults.ciphers.map((cipher, idx) => (
                      <div 
                        key={idx}
                        className={cn(
                          "flex items-center justify-between p-2 text-xs font-mono border rounded-md",
                          cipher.strength === 'strong' 
                            ? "border-green-500/30 bg-green-500/5" 
                            : cipher.strength === 'medium' 
                              ? "border-blue-500/30 bg-blue-500/5"
                              : "border-red-500/30 bg-red-500/5"
                        )}
                      >
                        <div className="truncate">{cipher.name}</div>
                        <Badge 
                          variant="outline" 
                          className={cn(
                            "ml-2 min-w-[80px] text-center",
                            cipher.strength === 'strong' 
                              ? "bg-green-500/10 text-green-500" 
                              : cipher.strength === 'medium' 
                                ? "bg-blue-500/10 text-blue-500"
                                : "bg-red-500/10 text-red-500"
                          )}
                        >
                          {cipher.strength}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="p-3 rounded-md bg-primary/5 border border-primary/20 text-xs font-mono">
                  <p className="flex items-center text-primary font-tech">
                    <Shield className="h-3.5 w-3.5 mr-1.5" />
                    Recommendation
                  </p>
                  <div className="mt-2 text-muted-foreground space-y-2">
                    <p>For maximum security:</p>
                    <ul className="list-disc list-inside ml-2 space-y-1">
                      <li>Enable only TLS 1.2 and TLS 1.3</li>
                      <li>Disable all older protocols (TLS 1.0, TLS 1.1, SSL 3.0, SSL 2.0)</li>
                      <li>Use only strong cipher suites with Perfect Forward Secrecy</li>
                      <li>Implement HTTP Strict Transport Security (HSTS)</li>
                    </ul>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="vulnerabilities" className="space-y-4">
                <div className="bg-background p-4 rounded-md border border-border">
                  <h3 className="text-sm font-tech mb-3">Known Vulnerabilities</h3>
                  
                  {Object.entries(scanResults.vulnerabilities).filter(([_, isVulnerable]) => isVulnerable).length === 0 ? (
                    <div className="flex items-center justify-center p-8 text-green-500">
                      <ShieldCheck className="h-10 w-10 mr-3" />
                      <div>
                        <div className="text-lg font-tech">No vulnerabilities detected</div>
                        <div className="text-xs font-mono text-muted-foreground mt-1">
                          The server appears to be secure against common SSL/TLS vulnerabilities
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {Object.entries(scanResults.vulnerabilities)
                        .filter(([_, isVulnerable]) => isVulnerable)
                        .map(([vulnName, _], idx) => {
                          // Get descriptions and impacts based on vulnerability type
                          const vulnInfo = getVulnerabilityInfo(vulnName);
                          
                          return (
                            <div 
                              key={idx}
                              className="p-3 border border-red-500/30 bg-red-500/5 rounded-md text-xs font-mono"
                            >
                              <div className="flex items-center text-red-500 font-tech">
                                <ShieldAlert className="h-3.5 w-3.5 mr-1.5" />
                                <span className="uppercase">{formatVulnName(vulnName)}</span>
                              </div>
                              <div className="mt-2 text-muted-foreground">
                                <p>{vulnInfo.description}</p>
                                <p className="mt-1"><span className="text-red-500">Impact:</span> {vulnInfo.impact}</p>
                                <p className="mt-1"><span className="text-green-500">Remediation:</span> {vulnInfo.remediation}</p>
                              </div>
                            </div>
                          );
                        })
                      }
                    </div>
                  )}
                </div>
                
                <div className="bg-background p-4 rounded-md border border-border">
                  <h3 className="text-sm font-tech mb-3">Security Features</h3>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-2 text-xs font-mono border rounded-md border-border">
                      <div className="flex items-center gap-2">
                        {scanResults.supportsPfs ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-500" />
                        )}
                        <span>Perfect Forward Secrecy (PFS)</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={cn(
                          scanResults.supportsPfs 
                            ? "bg-green-500/10 text-green-500" 
                            : "bg-red-500/10 text-red-500"
                        )}
                      >
                        {scanResults.supportsPfs ? "Supported" : "Not Supported"}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-2 text-xs font-mono border rounded-md border-border">
                      <div className="flex items-center gap-2">
                        {scanResults.supportsHsts ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-500" />
                        )}
                        <span>HTTP Strict Transport Security (HSTS)</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={cn(
                          scanResults.supportsHsts 
                            ? "bg-green-500/10 text-green-500" 
                            : "bg-red-500/10 text-red-500"
                        )}
                      >
                        {scanResults.supportsHsts ? "Enabled" : "Not Enabled"}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-2 text-xs font-mono border rounded-md border-border">
                      <div className="flex items-center gap-2">
                        {!scanResults.hasMixedContent ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-500" />
                        )}
                        <span>Mixed Content</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={cn(
                          !scanResults.hasMixedContent 
                            ? "bg-green-500/10 text-green-500" 
                            : "bg-red-500/10 text-red-500"
                        )}
                      >
                        {!scanResults.hasMixedContent ? "None Detected" : "Present"}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-2 text-xs font-mono border rounded-md border-border">
                      <div className="flex items-center gap-2">
                        {!scanResults.hasInsecureRenegotiation ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-500" />
                        )}
                        <span>Secure Renegotiation</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={cn(
                          !scanResults.hasInsecureRenegotiation 
                            ? "bg-green-500/10 text-green-500" 
                            : "bg-red-500/10 text-red-500"
                        )}
                      >
                        {!scanResults.hasInsecureRenegotiation ? "Secure" : "Insecure"}
                      </Badge>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
            
            <div className="flex items-center text-xs text-muted-foreground mt-2">
              <Shield className="h-3 w-3 mr-1" />
              <span>
                This is a simulated result for educational purposes only.
                In a real SSL scanner, this would show actual server configurations.
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

// Helper functions
const formatVulnName = (name: string): string => {
  // Format camelCase to readable text
  const result = name.replace(/([A-Z])/g, ' $1');
  return result.charAt(0).toUpperCase() + result.slice(1);
};

const getVulnerabilityInfo = (vulnName: string): { description: string, impact: string, remediation: string } => {
  const vulnInfoMap: Record<string, { description: string, impact: string, remediation: string }> = {
    heartbleed: {
      description: "The Heartbleed bug (CVE-2014-0160) is a serious vulnerability in the OpenSSL cryptographic software library that allows stealing information protected by SSL/TLS encryption.",
      impact: "Attackers can steal sensitive server data including private keys, authentication credentials, and user data.",
      remediation: "Update OpenSSL to version 1.0.1g or later, revoke and reissue certificates, and prompt users to change passwords."
    },
    poodle: {
      description: "POODLE (Padding Oracle On Downgraded Legacy Encryption) is a vulnerability that exploits the fallback to SSL 3.0.",
      impact: "Allows attackers to extract sensitive information from encrypted communications through a man-in-the-middle attack.",
      remediation: "Disable SSL 3.0 support entirely, use TLS 1.2 or higher, and implement the TLS_FALLBACK_SCSV extension."
    },
    freak: {
      description: "FREAK (Factoring RSA Export Keys) allows attackers to intercept HTTPS connections and force them to use weakened encryption.",
      impact: "Allows man-in-the-middle attackers to downgrade the security of TLS connections and potentially break the encryption.",
      remediation: "Disable support for export cipher suites on servers and update client software to prevent use of weak keys."
    },
    logjam: {
      description: "Logjam affects Diffie-Hellman key exchange cryptography, downgrading TLS connections to use weaker key exchange parameters.",
      impact: "Allows attackers with enough computing power to break the encryption and read or modify data in transit.",
      remediation: "Use 2048-bit or larger Diffie-Hellman parameters, disable export ciphersuites, and prioritize ECDHE over DHE."
    },
    drown: {
      description: "DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) exploits servers that still support SSLv2 protocol.",
      impact: "Allows attackers to decrypt communications even from modern TLS connections by reusing server's SSLv2 key.",
      remediation: "Fully disable SSLv2 on all servers that share the same certificate or key, update OpenSSL, and consider getting new certificates."
    },
    beast: {
      description: "BEAST (Browser Exploit Against SSL/TLS) targets the CBC encryption mode used in TLS 1.0 and earlier.",
      impact: "Allows attackers to decrypt parts of encrypted HTTPS traffic through a complex man-in-the-middle attack.",
      remediation: "Configure servers to prioritize RC4 or AES-GCM cipher suites, or better yet, disable TLS 1.0 and earlier protocols."
    },
    lucky13: {
      description: "Lucky 13 is a timing attack against implementations of CBC-mode ciphersuites in TLS.",
      impact: "Allows sophisticated attackers to recover plaintext from encrypted communications in certain scenarios.",
      remediation: "Update to the latest version of your TLS/SSL library and prioritize AEAD ciphersuites like AES-GCM."
    },
    ticketbleed: {
      description: "Ticketbleed is a vulnerability in F5 BIG-IP load balancers that leaks session ticket data.",
      impact: "Allows attackers to extract up to 31 bytes of memory, potentially including private keys and session data.",
      remediation: "Update F5 BIG-IP firmware to a patched version or disable session tickets functionality."
    },
    zombie: {
      description: "ZOMBIE (Zero Option Massive Browser Infection Engine), also known as POODLE TLS, affects TLS implementations with improper padding validation.",
      impact: "Allows attackers to decrypt secured communications through a padding oracle attack.",
      remediation: "Apply vendor patches for TLS libraries and server software to ensure proper padding validation."
    },
    openSslCcs: {
      description: "OpenSSL CCS (ChangeCipherSpec) Injection vulnerability allows attackers to trigger use of uninitialized memory.",
      impact: "Could lead to disclosure of sensitive information or man-in-the-middle attacks depending on the implementation.",
      remediation: "Update OpenSSL to version 0.9.8za, 1.0.0m, or 1.0.1h or later to address this vulnerability."
    }
  };
  
  return vulnInfoMap[vulnName] || {
    description: "An SSL/TLS vulnerability that may affect the security of encrypted communications.",
    impact: "Could potentially lead to information disclosure or man-in-the-middle attacks.",
    remediation: "Update your SSL/TLS implementation to the latest version and disable vulnerable protocols and ciphers."
  };
};