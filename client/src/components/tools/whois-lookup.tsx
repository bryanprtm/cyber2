import { useState } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { useToast } from "@/hooks/use-toast";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Progress } from "@/components/ui/progress";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import {
  AlertCircle,
  CheckCircle,
  Copy,
  Download,
  Loader2,
  Play,
  Globe,
  User,
  Mail,
  MapPin,
  Building,
  Calendar,
  Server,
  Shield,
  Clock,
  Search,
  RefreshCw,
  FileText,
  ExternalLink,
  AlertTriangle,
  Info,
  Lock,
  ArrowRight,
  Link2
} from "lucide-react";

// Types
interface WhoisResult {
  domainName: string;
  registrar?: string;
  registrarUrl?: string;
  creationDate?: string;
  expiryDate?: string;
  updatedDate?: string;
  nameServers?: string[];
  status?: string[];
  registrant?: {
    name?: string;
    organization?: string;
    email?: string;
    country?: string;
    city?: string;
    street?: string;
    postalCode?: string;
    phone?: string;
  };
  admin?: {
    name?: string;
    organization?: string;
    email?: string;
    country?: string;
  };
  tech?: {
    name?: string;
    organization?: string;
    email?: string;
    country?: string;
  };
  dnssec?: string;
  domainAvailability?: boolean;
  privacyProtected?: boolean;
  analytics?: {
    domainAge?: number;
    expiresIn?: number;
    securityScore?: number;
    privacyScore?: number;
    lastUpdated?: number;
  };
  similarDomains?: string[];
  errors?: string[];
  warnings?: string[];
  rawText?: string;
}

interface ApiResponse {
  status: string;
  message: string;
  data?: WhoisResult;
}

export default function WhoisLookup() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine, addSuccessLine, clearLines } = useTerminal();
  
  const [domain, setDomain] = useState<string>("");
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [result, setResult] = useState<WhoisResult | null>(null);
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [showRawData, setShowRawData] = useState<boolean>(false);
  
  // Function to search for WHOIS information
  const searchWhois = async () => {
    if (!domain) {
      toast({
        variant: "destructive",
        title: "Missing Domain",
        description: "Please enter a domain name to lookup"
      });
      return;
    }
    
    // Validate the domain format (basic validation)
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      toast({
        variant: "destructive",
        title: "Invalid Domain Format",
        description: "Please enter a valid domain name (e.g., example.com)"
      });
      return;
    }
    
    try {
      setIsSearching(true);
      clearLines();
      setResult(null);
      
      addSystemLine(`Starting WHOIS lookup for ${domain}`);
      addInfoLine("Initializing lookup process...");
      
      // Simulate API calls with different timings
      await new Promise(resolve => setTimeout(resolve, 500));
      addInfoLine(`Querying WHOIS servers for ${domain}...`);
      
      await new Promise(resolve => setTimeout(resolve, 800));
      addInfoLine("Retrieving registrar information...");
      
      await new Promise(resolve => setTimeout(resolve, 700));
      addInfoLine("Fetching name server data...");
      
      await new Promise(resolve => setTimeout(resolve, 600));
      addInfoLine("Processing domain status codes...");
      
      await new Promise(resolve => setTimeout(resolve, 900));
      addInfoLine("Checking domain availability and registration...");
      
      await new Promise(resolve => setTimeout(resolve, 500));
      addInfoLine("Analyzing domain security and privacy...");
      
      // Generate a simulated result based on the domain
      const generatedResult = generateWhoisResult(domain);
      setResult(generatedResult);
      
      // Log the results
      addSuccessLine("WHOIS lookup completed successfully");
      
      if (generatedResult.errors && generatedResult.errors.length > 0) {
        generatedResult.errors.forEach(error => {
          addErrorLine(`Error: ${error}`);
        });
      }
      
      if (generatedResult.warnings && generatedResult.warnings.length > 0) {
        generatedResult.warnings.forEach(warning => {
          addInfoLine(`Warning: ${warning}`);
        });
      }
      
      toast({
        title: "Lookup Complete",
        description: "WHOIS information has been retrieved successfully"
      });
      
    } catch (error) {
      addErrorLine(`Error during WHOIS lookup: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      toast({
        variant: "destructive",
        title: "Lookup Failed",
        description: "An error occurred while retrieving WHOIS information"
      });
    } finally {
      setIsSearching(false);
    }
  };
  
  // Function to generate realistic-looking but simulated WHOIS data
  const generateWhoisResult = (domainName: string): WhoisResult => {
    // Extract TLD and domain parts
    const domainParts = domainName.split('.');
    const tld = domainParts[domainParts.length - 1];
    const domainWithoutTld = domainParts.slice(0, -1).join('.');
    
    // Create dates
    const now = new Date();
    
    // Creation date (1-8 years in the past)
    const creationDate = new Date(now);
    creationDate.setFullYear(now.getFullYear() - Math.floor(Math.random() * 7) - 1);
    
    // Expiry date (1-3 years in the future)
    const expiryDate = new Date(now);
    expiryDate.setFullYear(now.getFullYear() + Math.floor(Math.random() * 3) + 1);
    
    // Updated date (0-6 months in the past)
    const updatedDate = new Date(now);
    updatedDate.setMonth(now.getMonth() - Math.floor(Math.random() * 6));
    
    // Registrar selection based on TLD
    const registrars: Record<string, string> = {
      'com': 'GoDaddy.com, LLC',
      'net': 'Network Solutions, LLC',
      'org': 'Public Interest Registry',
      'io': 'Afilias Ltd.',
      'co': 'GoDaddy.com, LLC',
      'ai': 'Nic.ai',
      'dev': 'Google Domains'
    };
    const registrar = registrars[tld] || 'Example Registrar, Inc.';
    
    // Common status codes
    const possibleStatuses = [
      'clientDeleteProhibited',
      'clientRenewProhibited',
      'clientTransferProhibited',
      'clientUpdateProhibited',
      'serverDeleteProhibited',
      'serverTransferProhibited',
      'serverUpdateProhibited'
    ];
    
    // Randomly select 2-4 status codes
    const statusCount = Math.floor(Math.random() * 3) + 2;
    const statusCodes = [];
    for (let i = 0; i < statusCount; i++) {
      const randomStatus = possibleStatuses[Math.floor(Math.random() * possibleStatuses.length)];
      if (!statusCodes.includes(randomStatus)) {
        statusCodes.push(randomStatus);
      }
    }
    
    // Generate nameservers
    const nameServerCount = Math.floor(Math.random() * 2) + 2; // 2-3 nameservers
    const nameServers = [];
    
    const nsProviders = ['ns1.example.com', 'ns2.example.com', 'ns1.cloudflare.com', 'ns2.cloudflare.com', 'ns1.google.com', 'ns2.google.com'];
    
    for (let i = 0; i < nameServerCount; i++) {
      nameServers.push(nsProviders[i % nsProviders.length].replace('example.com', domainName));
    }
    
    // Decide if privacy protection is enabled (70% chance)
    const privacyProtected = Math.random() > 0.3;
    
    // Create similar domains
    const similarDomains = [];
    const alternativeTlds = ['com', 'net', 'org', 'io', 'co'];
    const domainVariations = [
      domainWithoutTld,
      `${domainWithoutTld}s`,
      `my${domainWithoutTld}`,
      `${domainWithoutTld}app`,
      `${domainWithoutTld}site`
    ];
    
    // Add some similar domains
    for (let i = 0; i < 3; i++) {
      const altTld = alternativeTlds[Math.floor(Math.random() * alternativeTlds.length)];
      if (altTld !== tld) {
        similarDomains.push(`${domainWithoutTld}.${altTld}`);
      }
    }
    
    // Add some domain variations
    for (let i = 0; i < 2; i++) {
      const variation = domainVariations[Math.floor(Math.random() * domainVariations.length)];
      similarDomains.push(`${variation}.${tld}`);
    }
    
    // Calculate domain analytics
    const domainAge = Math.floor((now.getTime() - creationDate.getTime()) / (1000 * 60 * 60 * 24 * 365));
    const expiresIn = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24 * 30)); // months
    const lastUpdated = Math.floor((now.getTime() - updatedDate.getTime()) / (1000 * 60 * 60 * 24)); // days
    
    // Security score based on domain age, status codes, etc.
    // Higher score = better security
    let securityScore = 0;
    securityScore += domainAge > 3 ? 30 : (domainAge > 1 ? 15 : 5); // Older domains are more trustworthy
    securityScore += statusCodes.includes('clientTransferProhibited') ? 15 : 0; // Transfer lock is good
    securityScore += statusCodes.includes('clientUpdateProhibited') ? 10 : 0; // Update lock is good
    securityScore += nameServers.length >= 3 ? 10 : 5; // More nameservers is better
    securityScore += Math.floor(Math.random() * 25) + 5; // Random factor
    securityScore = Math.min(securityScore, 100); // Cap at 100
    
    // Privacy score based on privacy protection, etc.
    // Higher score = better privacy
    let privacyScore = 0;
    privacyScore += privacyProtected ? 50 : 0; // Privacy protection is a big factor
    privacyScore += Math.floor(Math.random() * 40) + 10; // Random factor
    privacyScore = Math.min(privacyScore, 100); // Cap at 100
    
    // Potential warnings or errors
    const warnings = [];
    const errors = [];
    
    if (expiresIn < 3) {
      warnings.push("Domain expiring soon. Renewal recommended.");
    }
    
    if (!statusCodes.includes('clientTransferProhibited')) {
      warnings.push("Domain transfer lock not enabled. Consider enabling for security.");
    }
    
    if (domainAge < 1) {
      warnings.push("Recently registered domain. Exercise caution with new domains.");
    }
    
    // Create the result object
    const result: WhoisResult = {
      domainName: domainName,
      registrar: registrar,
      registrarUrl: `https://www.${registrar.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com`,
      creationDate: creationDate.toISOString().split('T')[0],
      expiryDate: expiryDate.toISOString().split('T')[0],
      updatedDate: updatedDate.toISOString().split('T')[0],
      nameServers: nameServers,
      status: statusCodes,
      dnssec: Math.random() > 0.7 ? "signedDelegation" : "unsigned",
      domainAvailability: false,
      privacyProtected: privacyProtected,
      analytics: {
        domainAge: domainAge,
        expiresIn: expiresIn,
        securityScore: securityScore,
        privacyScore: privacyScore,
        lastUpdated: lastUpdated
      },
      similarDomains: similarDomains,
      warnings: warnings.length > 0 ? warnings : undefined,
      errors: errors.length > 0 ? errors : undefined
    };
    
    // Add registrant info if not privacy protected
    if (!privacyProtected) {
      result.registrant = {
        name: "Domain Administrator",
        organization: `${domainWithoutTld.charAt(0).toUpperCase() + domainWithoutTld.slice(1)} Inc.`,
        email: `admin@${domainName}`,
        country: "US",
        city: "New York",
        street: "123 Main Street",
        postalCode: "10001",
        phone: "+1.2125551234"
      };
      
      result.admin = {
        name: "Admin Contact",
        organization: `${domainWithoutTld.charAt(0).toUpperCase() + domainWithoutTld.slice(1)} Inc.`,
        email: `admin@${domainName}`,
        country: "US"
      };
      
      result.tech = {
        name: "Technical Contact",
        organization: `${domainWithoutTld.charAt(0).toUpperCase() + domainWithoutTld.slice(1)} Inc.`,
        email: `tech@${domainName}`,
        country: "US"
      };
    } else {
      // Add redacted info for privacy protected domains
      result.registrant = {
        name: "REDACTED FOR PRIVACY",
        organization: "REDACTED FOR PRIVACY",
        email: `REDACTED FOR PRIVACY`,
        country: "REDACTED FOR PRIVACY"
      };
      
      result.admin = {
        name: "REDACTED FOR PRIVACY",
        organization: "REDACTED FOR PRIVACY",
        email: `REDACTED FOR PRIVACY`,
        country: "REDACTED FOR PRIVACY"
      };
      
      result.tech = {
        name: "REDACTED FOR PRIVACY",
        organization: "REDACTED FOR PRIVACY",
        email: `REDACTED FOR PRIVACY`,
        country: "REDACTED FOR PRIVACY"
      };
    }
    
    // Generate raw text
    result.rawText = generateRawWhoisText(result);
    
    return result;
  };
  
  // Generate raw WHOIS text output
  const generateRawWhoisText = (result: WhoisResult): string => {
    let rawText = `Domain Name: ${result.domainName.toUpperCase()}\n`;
    rawText += `Registry Domain ID: ${Math.random().toString(36).substring(2, 15).toUpperCase()}_DOMAIN_${result.domainName.split('.')[1].toUpperCase()}\n`;
    rawText += `Registrar WHOIS Server: whois.${result.registrar?.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com\n`;
    rawText += `Registrar URL: ${result.registrarUrl}\n`;
    rawText += `Updated Date: ${result.updatedDate}T00:00:00Z\n`;
    rawText += `Creation Date: ${result.creationDate}T00:00:00Z\n`;
    rawText += `Registry Expiry Date: ${result.expiryDate}T00:00:00Z\n`;
    rawText += `Registrar: ${result.registrar}\n`;
    rawText += `Registrar IANA ID: ${Math.floor(Math.random() * 2000) + 100}\n`;
    rawText += `Registrar Abuse Contact Email: abuse@${result.registrar?.toLowerCase().replace(', llc', '').replace(', inc', '').replace(' ', '')}.com\n`;
    rawText += `Registrar Abuse Contact Phone: +1.${Math.floor(Math.random() * 9000000000) + 1000000000}\n`;
    
    rawText += `Domain Status: ${result.status?.join(' ')}\n\n`;
    
    if (result.registrant) {
      rawText += `Registry Registrant ID: ${result.privacyProtected ? 'REDACTED FOR PRIVACY' : Math.random().toString(36).substring(2, 10).toUpperCase()}\n`;
      rawText += `Registrant Name: ${result.registrant.name}\n`;
      rawText += `Registrant Organization: ${result.registrant.organization}\n`;
      if (!result.privacyProtected) {
        rawText += `Registrant Street: ${result.registrant.street}\n`;
        rawText += `Registrant City: ${result.registrant.city}\n`;
        rawText += `Registrant State/Province: NY\n`;
        rawText += `Registrant Postal Code: ${result.registrant.postalCode}\n`;
      }
      rawText += `Registrant Country: ${result.registrant.country}\n`;
      rawText += `Registrant Phone: ${result.privacyProtected ? 'REDACTED FOR PRIVACY' : result.registrant.phone}\n`;
      rawText += `Registrant Email: ${result.registrant.email}\n\n`;
    }
    
    rawText += `Name Server: ${result.nameServers?.join('\nName Server: ')}\n`;
    rawText += `DNSSEC: ${result.dnssec}\n\n`;
    
    rawText += `>>> Last update of WHOIS database: ${new Date().toISOString().split('.')[0]}Z <<<\n\n`;
    
    return rawText;
  };
  
  // Copy result to clipboard
  const copyToClipboard = () => {
    if (result) {
      const resultText = showRawData ? result.rawText : JSON.stringify(result, null, 2);
      navigator.clipboard.writeText(resultText || "");
      
      toast({
        title: "Copied to Clipboard",
        description: "WHOIS information has been copied to clipboard"
      });
    }
  };
  
  // Download result as JSON or TXT
  const downloadResult = () => {
    if (result) {
      const resultText = showRawData ? result.rawText : JSON.stringify(result, null, 2);
      const blob = new Blob([resultText || ""], { type: showRawData ? "text/plain" : "application/json" });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement("a");
      a.href = url;
      a.download = showRawData 
        ? `whois_${result.domainName}.txt` 
        : `whois_${result.domainName}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };
  
  // Calculate expiry status (expired, expiring soon, valid)
  const getExpiryStatus = (expiryDate: string) => {
    const now = new Date();
    const expiry = new Date(expiryDate);
    const diffMonths = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24 * 30);
    
    if (diffMonths <= 0) {
      return { status: "expired", label: "Expired", color: "destructive" };
    } else if (diffMonths <= 3) {
      return { status: "expiring", label: "Expiring Soon", color: "warning" };
    } else {
      return { status: "valid", label: "Valid", color: "success" };
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <Globe className="mr-2 h-5 w-5 text-primary" />
          WHOIS Domain Lookup
        </h2>
        
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 space-y-2">
              <Label htmlFor="domain">Domain Name</Label>
              <div className="flex gap-2">
                <Input
                  id="domain"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="flex-1"
                />
                <Button onClick={searchWhois} disabled={isSearching}>
                  {isSearching ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4" />
                      Lookup
                    </>
                  )}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Enter a domain name without 'http://' or 'www'. Example: example.com
              </p>
            </div>
          </div>
          
          {isSearching && (
            <div className="py-8 flex items-center justify-center">
              <div className="text-center">
                <Loader2 className="h-8 w-8 animate-spin mx-auto mb-2 text-primary" />
                <p className="text-sm text-muted-foreground">Looking up WHOIS information...</p>
              </div>
            </div>
          )}
          
          {result && !isSearching && (
            <div className="space-y-6">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-lg font-semibold text-primary">{result.domainName}</h3>
                  <p className="text-sm text-muted-foreground">
                    Registered with {result.registrar}
                  </p>
                </div>
                
                <div className="flex items-center gap-2">
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={copyToClipboard}
                    className="hidden md:flex"
                  >
                    <Copy className="mr-2 h-4 w-4" />
                    Copy
                  </Button>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={downloadResult}
                    className="hidden md:flex"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download
                  </Button>
                  <Button
                    variant={showRawData ? "default" : "outline"}
                    size="sm"
                    onClick={() => setShowRawData(!showRawData)}
                  >
                    <FileText className="mr-2 h-4 w-4" />
                    {showRawData ? "Formatted View" : "Raw Data"}
                  </Button>
                </div>
              </div>
              
              {result.warnings && result.warnings.length > 0 && (
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-md p-3">
                  <h4 className="font-medium text-yellow-500 flex items-center gap-2 mb-2">
                    <AlertTriangle size={16} />
                    Warnings
                  </h4>
                  <ul className="list-disc pl-5 space-y-1">
                    {result.warnings.map((warning, index) => (
                      <li key={index} className="text-sm">{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              {result.errors && result.errors.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3">
                  <h4 className="font-medium text-red-500 flex items-center gap-2 mb-2">
                    <AlertCircle size={16} />
                    Errors
                  </h4>
                  <ul className="list-disc pl-5 space-y-1">
                    {result.errors.map((error, index) => (
                      <li key={index} className="text-sm">{error}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              {showRawData ? (
                <div className="bg-muted rounded-md p-4 overflow-auto">
                  <pre className="text-sm font-mono whitespace-pre-wrap">{result.rawText}</pre>
                </div>
              ) : (
                <>
                  <Tabs value={activeTab} onValueChange={setActiveTab}>
                    <TabsList className="grid grid-cols-4 mb-4">
                      <TabsTrigger value="overview" className="font-tech">Overview</TabsTrigger>
                      <TabsTrigger value="registrant" className="font-tech">Registrant</TabsTrigger>
                      <TabsTrigger value="technical" className="font-tech">Technical</TabsTrigger>
                      <TabsTrigger value="analytics" className="font-tech">Analytics</TabsTrigger>
                    </TabsList>
                    
                    {/* Overview Tab */}
                    <TabsContent value="overview" className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Globe size={16} className="text-primary" />
                            Domain Information
                          </h4>
                          
                          <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Registration Date</div>
                              <div className="text-sm">
                                {result.creationDate || "Unknown"}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Expiration Date</div>
                              <div className="text-sm flex items-center">
                                {result.expiryDate || "Unknown"}
                                {result.expiryDate && (
                                  <Badge 
                                    variant={getExpiryStatus(result.expiryDate).color as any}
                                    className="ml-2 text-xs"
                                  >
                                    {getExpiryStatus(result.expiryDate).label}
                                  </Badge>
                                )}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Last Updated</div>
                              <div className="text-sm">
                                {result.updatedDate || "Unknown"}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Registrar</div>
                              <div className="text-sm">
                                {result.registrar || "Unknown"}
                              </div>
                            </div>
                            
                            {result.registrarUrl && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Registrar URL</div>
                                <div className="text-sm">
                                  <a 
                                    href={result.registrarUrl} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="text-primary hover:underline flex items-center"
                                  >
                                    Visit
                                    <ExternalLink size={12} className="ml-1" />
                                  </a>
                                </div>
                              </div>
                            )}
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">DNSSEC</div>
                              <div className="text-sm">
                                {result.dnssec || "Unknown"}
                              </div>
                            </div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Shield size={16} className="text-primary" />
                            Domain Status
                          </h4>
                          
                          <div className="space-y-3">
                            {result.status && result.status.map((status, index) => (
                              <div key={index} className="flex items-center">
                                <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                                <span className="text-sm">{status}</span>
                              </div>
                            ))}
                            
                            {(!result.status || result.status.length === 0) && (
                              <div className="text-sm text-muted-foreground">
                                No status codes available
                              </div>
                            )}
                          </div>
                          
                          <h4 className="text-sm font-semibold mt-6 mb-3 flex items-center gap-2">
                            <Server size={16} className="text-primary" />
                            Name Servers
                          </h4>
                          
                          <div className="space-y-2">
                            {result.nameServers && result.nameServers.map((ns, index) => (
                              <div key={index} className="bg-muted p-2 rounded-md text-sm font-mono">
                                {ns}
                              </div>
                            ))}
                            
                            {(!result.nameServers || result.nameServers.length === 0) && (
                              <div className="text-sm text-muted-foreground">
                                No name servers available
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                    
                    {/* Registrant Tab */}
                    <TabsContent value="registrant" className="space-y-4">
                      {result.privacyProtected ? (
                        <div className="bg-muted rounded-md p-6 text-center">
                          <Lock className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                          <h3 className="text-lg font-semibold mb-2">Privacy Protection Enabled</h3>
                          <p className="text-sm text-muted-foreground max-w-md mx-auto">
                            The registrant information for this domain is protected by a privacy or proxy service.
                            This means the domain owner's personal details are hidden from public view.
                          </p>
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div>
                            <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                              <Building size={16} className="text-primary" />
                              Registrant Information
                            </h4>
                            
                            <div className="space-y-3">
                              {result.registrant?.organization && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Organization</div>
                                  <div className="text-sm">{result.registrant.organization}</div>
                                </div>
                              )}
                              
                              {result.registrant?.name && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Name</div>
                                  <div className="text-sm">{result.registrant.name}</div>
                                </div>
                              )}
                              
                              {result.registrant?.email && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Email</div>
                                  <div className="text-sm">{result.registrant.email}</div>
                                </div>
                              )}
                              
                              {result.registrant?.phone && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Phone</div>
                                  <div className="text-sm">{result.registrant.phone}</div>
                                </div>
                              )}
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                              <MapPin size={16} className="text-primary" />
                              Registrant Address
                            </h4>
                            
                            <div className="space-y-3">
                              {result.registrant?.street && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Street</div>
                                  <div className="text-sm">{result.registrant.street}</div>
                                </div>
                              )}
                              
                              {result.registrant?.city && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">City</div>
                                  <div className="text-sm">{result.registrant.city}</div>
                                </div>
                              )}
                              
                              {result.registrant?.postalCode && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Postal Code</div>
                                  <div className="text-sm">{result.registrant.postalCode}</div>
                                </div>
                              )}
                              
                              {result.registrant?.country && (
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="text-sm font-medium">Country</div>
                                  <div className="text-sm">{result.registrant.country}</div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                      
                      <Separator className="my-6" />
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <User size={16} className="text-primary" />
                            Administrative Contact
                          </h4>
                          
                          <div className="space-y-3">
                            {result.admin?.organization && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Organization</div>
                                <div className="text-sm">{result.admin.organization}</div>
                              </div>
                            )}
                            
                            {result.admin?.name && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Name</div>
                                <div className="text-sm">{result.admin.name}</div>
                              </div>
                            )}
                            
                            {result.admin?.email && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Email</div>
                                <div className="text-sm">{result.admin.email}</div>
                              </div>
                            )}
                            
                            {result.admin?.country && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Country</div>
                                <div className="text-sm">{result.admin.country}</div>
                              </div>
                            )}
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <User size={16} className="text-primary" />
                            Technical Contact
                          </h4>
                          
                          <div className="space-y-3">
                            {result.tech?.organization && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Organization</div>
                                <div className="text-sm">{result.tech.organization}</div>
                              </div>
                            )}
                            
                            {result.tech?.name && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Name</div>
                                <div className="text-sm">{result.tech.name}</div>
                              </div>
                            )}
                            
                            {result.tech?.email && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Email</div>
                                <div className="text-sm">{result.tech.email}</div>
                              </div>
                            )}
                            
                            {result.tech?.country && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Country</div>
                                <div className="text-sm">{result.tech.country}</div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                    
                    {/* Technical Tab */}
                    <TabsContent value="technical" className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Server size={16} className="text-primary" />
                            Name Servers
                          </h4>
                          
                          <div className="space-y-2">
                            {result.nameServers && result.nameServers.map((ns, index) => (
                              <div key={index} className="bg-muted p-2 rounded-md text-sm font-mono">
                                {ns}
                              </div>
                            ))}
                            
                            {(!result.nameServers || result.nameServers.length === 0) && (
                              <div className="text-sm text-muted-foreground">
                                No name servers available
                              </div>
                            )}
                          </div>
                          
                          <h4 className="text-sm font-semibold mt-6 mb-3 flex items-center gap-2">
                            <Shield size={16} className="text-primary" />
                            Domain Status
                          </h4>
                          
                          <div className="space-y-3">
                            {result.status && result.status.map((status, index) => (
                              <div key={index} className="flex items-start">
                                <div className="w-2 h-2 rounded-full bg-green-500 mr-2 mt-1.5"></div>
                                <div>
                                  <span className="text-sm font-medium">{status}</span>
                                  <p className="text-xs text-muted-foreground mt-0.5">
                                    {getStatusDescription(status)}
                                  </p>
                                </div>
                              </div>
                            ))}
                            
                            {(!result.status || result.status.length === 0) && (
                              <div className="text-sm text-muted-foreground">
                                No status codes available
                              </div>
                            )}
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Calendar size={16} className="text-primary" />
                            Important Dates
                          </h4>
                          
                          <div className="space-y-3">
                            {result.creationDate && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Registration Date</div>
                                <div className="text-sm">{result.creationDate}</div>
                              </div>
                            )}
                            
                            {result.expiryDate && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Expiration Date</div>
                                <div className="text-sm flex items-center">
                                  {result.expiryDate}
                                  <Badge 
                                    variant={getExpiryStatus(result.expiryDate).color as any}
                                    className="ml-2 text-xs"
                                  >
                                    {getExpiryStatus(result.expiryDate).label}
                                  </Badge>
                                </div>
                              </div>
                            )}
                            
                            {result.updatedDate && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Last Updated</div>
                                <div className="text-sm">{result.updatedDate}</div>
                              </div>
                            )}
                            
                            {result.analytics?.domainAge !== undefined && (
                              <div className="grid grid-cols-2 gap-2">
                                <div className="text-sm font-medium">Domain Age</div>
                                <div className="text-sm">
                                  {result.analytics.domainAge} {result.analytics.domainAge === 1 ? 'year' : 'years'}
                                </div>
                              </div>
                            )}
                          </div>
                          
                          <h4 className="text-sm font-semibold mt-6 mb-3 flex items-center gap-2">
                            <Lock size={16} className="text-primary" />
                            Security Features
                          </h4>
                          
                          <div className="space-y-3">
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">DNSSEC</div>
                              <div className="text-sm">
                                {result.dnssec === "signedDelegation" ? (
                                  <span className="text-green-500 flex items-center">
                                    <CheckCircle size={14} className="mr-1" /> Enabled
                                  </span>
                                ) : (
                                  <span className="text-yellow-500 flex items-center">
                                    <AlertTriangle size={14} className="mr-1" /> Not enabled
                                  </span>
                                )}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Transfer Lock</div>
                              <div className="text-sm">
                                {result.status?.includes("clientTransferProhibited") ? (
                                  <span className="text-green-500 flex items-center">
                                    <CheckCircle size={14} className="mr-1" /> Enabled
                                  </span>
                                ) : (
                                  <span className="text-yellow-500 flex items-center">
                                    <AlertTriangle size={14} className="mr-1" /> Not enabled
                                  </span>
                                )}
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                              <div className="text-sm font-medium">Privacy Protection</div>
                              <div className="text-sm">
                                {result.privacyProtected ? (
                                  <span className="text-green-500 flex items-center">
                                    <CheckCircle size={14} className="mr-1" /> Enabled
                                  </span>
                                ) : (
                                  <span className="text-yellow-500 flex items-center">
                                    <AlertTriangle size={14} className="mr-1" /> Not enabled
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                    
                    {/* Analytics Tab */}
                    <TabsContent value="analytics" className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Shield size={16} className="text-primary" />
                            Security Analysis
                          </h4>
                          
                          {result.analytics && (
                            <div className="space-y-4">
                              <div className="space-y-2">
                                <div className="flex justify-between text-sm">
                                  <span>Security Score</span>
                                  <span className="font-medium">{result.analytics.securityScore}/100</span>
                                </div>
                                <Progress 
                                  value={result.analytics.securityScore} 
                                  max={100}
                                  className={
                                    result.analytics.securityScore > 70 
                                      ? "bg-green-200 text-green-700" 
                                      : result.analytics.securityScore > 40
                                        ? "bg-yellow-200 text-yellow-700"
                                        : "bg-red-200 text-red-700"
                                  }
                                />
                                
                                <div className="mt-1 text-xs text-muted-foreground">
                                  {result.analytics.securityScore > 70 
                                    ? "Good security configuration" 
                                    : result.analytics.securityScore > 40
                                      ? "Moderate security, improvements possible"
                                      : "Poor security, immediate attention needed"
                                  }
                                </div>
                              </div>
                              
                              <div className="space-y-2">
                                <div className="flex justify-between text-sm">
                                  <span>Privacy Score</span>
                                  <span className="font-medium">{result.analytics.privacyScore}/100</span>
                                </div>
                                <Progress 
                                  value={result.analytics.privacyScore} 
                                  max={100}
                                  className={
                                    result.analytics.privacyScore > 70 
                                      ? "bg-green-200 text-green-700" 
                                      : result.analytics.privacyScore > 40
                                        ? "bg-yellow-200 text-yellow-700"
                                        : "bg-red-200 text-red-700"
                                  }
                                />
                                
                                <div className="mt-1 text-xs text-muted-foreground">
                                  {result.analytics.privacyScore > 70 
                                    ? "Good privacy protection" 
                                    : result.analytics.privacyScore > 40
                                      ? "Moderate privacy, some details exposed"
                                      : "Poor privacy, personal information exposed"
                                  }
                                </div>
                              </div>
                              
                              <div className="bg-muted p-4 rounded-md space-y-3">
                                <h5 className="text-sm font-medium">Security Factors</h5>
                                
                                <div className="space-y-2 text-sm">
                                  <div className="flex items-start">
                                    <div className={`w-2 h-2 rounded-full mt-1.5 ${result.analytics.domainAge > 2 ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                                    <div className="ml-2">
                                      <span className="font-medium">Domain Age: {result.analytics.domainAge} {result.analytics.domainAge === 1 ? 'year' : 'years'}</span>
                                      <p className="text-xs text-muted-foreground">
                                        {result.analytics.domainAge > 2 
                                          ? "Established domains are generally more trustworthy" 
                                          : "Newer domains should be treated with more caution"
                                        }
                                      </p>
                                    </div>
                                  </div>
                                  
                                  <div className="flex items-start">
                                    <div className={`w-2 h-2 rounded-full mt-1.5 ${result.status?.includes("clientTransferProhibited") ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                                    <div className="ml-2">
                                      <span className="font-medium">Transfer Lock: {result.status?.includes("clientTransferProhibited") ? 'Enabled' : 'Not Enabled'}</span>
                                      <p className="text-xs text-muted-foreground">
                                        {result.status?.includes("clientTransferProhibited") 
                                          ? "Prevents unauthorized domain transfers" 
                                          : "Domain could be transferred without additional verification"
                                        }
                                      </p>
                                    </div>
                                  </div>
                                  
                                  <div className="flex items-start">
                                    <div className={`w-2 h-2 rounded-full mt-1.5 ${result.dnssec === "signedDelegation" ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                                    <div className="ml-2">
                                      <span className="font-medium">DNSSEC: {result.dnssec === "signedDelegation" ? 'Enabled' : 'Not Enabled'}</span>
                                      <p className="text-xs text-muted-foreground">
                                        {result.dnssec === "signedDelegation"
                                          ? "Adds cryptographic protection to DNS lookups" 
                                          : "DNS lookups are not cryptographically protected"
                                        }
                                      </p>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <Globe size={16} className="text-primary" />
                            Domain Analysis
                          </h4>
                          
                          <div className="space-y-4">
                            {result.analytics && (
                              <div className="space-y-2">
                                <div className="flex justify-between">
                                  <span className="text-sm">Domain Age</span>
                                  <span className="text-sm font-medium">
                                    {result.analytics.domainAge} {result.analytics.domainAge === 1 ? 'year' : 'years'}
                                  </span>
                                </div>
                                
                                <div className="flex justify-between">
                                  <span className="text-sm">Expires In</span>
                                  <span className="text-sm font-medium">
                                    {result.analytics.expiresIn} {result.analytics.expiresIn === 1 ? 'month' : 'months'}
                                  </span>
                                </div>
                                
                                <div className="flex justify-between">
                                  <span className="text-sm">Last Updated</span>
                                  <span className="text-sm font-medium">
                                    {result.analytics.lastUpdated} {result.analytics.lastUpdated === 1 ? 'day' : 'days'} ago
                                  </span>
                                </div>
                              </div>
                            )}
                            
                            {result.similarDomains && result.similarDomains.length > 0 && (
                              <div className="mt-6">
                                <h5 className="text-sm font-medium mb-2">Similar Domains</h5>
                                <div className="space-y-2">
                                  {result.similarDomains.map((domain, index) => (
                                    <div key={index} className="flex items-center justify-between bg-muted p-2 rounded-md">
                                      <span className="text-sm font-mono">{domain}</span>
                                      <Button 
                                        variant="ghost" 
                                        size="sm"
                                        className="h-6 px-2"
                                        onClick={() => {
                                          setDomain(domain);
                                          searchWhois();
                                        }}
                                      >
                                        <Search size={12} className="mr-1" />
                                        <span className="text-xs">Lookup</span>
                                      </Button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            
                            <div className="mt-6 p-4 bg-muted rounded-md">
                              <h5 className="text-sm font-medium mb-2 flex items-center gap-2">
                                <Info size={14} />
                                Domain Analysis
                              </h5>
                              <p className="text-sm text-muted-foreground">
                                {result.analytics?.domainAge && result.analytics.domainAge > 3 
                                  ? "This is an established domain that has been registered for several years. Established domains are generally more trustworthy than newly registered ones."
                                  : "This domain is relatively new. Exercise caution as newer domains are sometimes used for malicious purposes."
                                }
                                {result.status?.includes("clientTransferProhibited")
                                  ? " The domain has transfer protection enabled, which is a good security practice."
                                  : " The domain doesn't have transfer protection, which could be a security risk."
                                }
                                {result.privacyProtected
                                  ? " Privacy protection is enabled, hiding the registrant's personal information."
                                  : " Privacy protection is not enabled, exposing the registrant's personal information."
                                }
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                </>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// Helper function to get status code descriptions
function getStatusDescription(status: string): string {
  const descriptions: Record<string, string> = {
    'clientTransferProhibited': 'Prevents unauthorized transfers to another registrar',
    'clientUpdateProhibited': 'Prevents changes to the domain registration',
    'clientDeleteProhibited': 'Prevents deletion of the domain registration',
    'clientHold': 'Domain is not published in DNS',
    'serverTransferProhibited': 'Registrar-enforced transfer prohibition',
    'serverUpdateProhibited': 'Registrar-enforced update prohibition',
    'serverDeleteProhibited': 'Registrar-enforced deletion prohibition',
    'serverHold': 'Registrar has removed the domain from DNS',
    'serverRenewProhibited': 'Registrar-enforced renewal prohibition',
    'renewPeriod': 'Domain is in the renewal grace period',
    'autoRenewPeriod': 'Domain is in the auto-renewal grace period',
    'transferPeriod': 'Domain is in the transfer grace period',
    'redemptionPeriod': 'Domain is in the redemption grace period',
    'pendingDelete': 'Domain is pending deletion',
    'addPeriod': 'Domain is in the add grace period'
  };
  
  return descriptions[status] || 'Status code for domain registration';
}