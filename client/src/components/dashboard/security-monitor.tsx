import { useState, useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { useToast } from "@/hooks/use-toast";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
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
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Layers,
  BarChart,
  FileText,
  Server,
  Search,
  Globe,
  Lock,
  AlertTriangle,
  Calendar,
  Clock,
  Network,
  Database,
  Bug,
  Radar,
  BarChart2,
  Map,
  Zap,
  Cpu,
  Wifi,
  Eye,
  Activity,
  Anchor,
  Radio
} from "lucide-react";
import { tools } from "@/data/tool-categories";

// Types
interface ScanResult {
  id: string;
  target: string;
  category: string;
  toolName: string;
  status: "success" | "error" | "warning" | "info" | "pending";
  summary: string;
  details: any;
  timestamp: Date;
  riskLevel: "critical" | "high" | "medium" | "low" | "info";
  recommendation?: string;
}

interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface CategoryStats {
  name: string;
  count: number;
  vulnerabilities: number;
}

interface SecurityOverview {
  status: "safe" | "warning" | "danger";
  score: number;
  lastAnalyzed: Date;
  statusText: string;
}

interface CVEEntry {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  affectedComponent: string;
  publishedDate: Date;
  fixAvailable: boolean;
}

interface ThreatIntelligence {
  isPhishing: boolean;
  isMalware: boolean;
  isBotnet: boolean;
  isBlacklisted: boolean;
  blacklistSources: string[];
  abuseReports: number;
  lastReportDate?: Date;
  riskScore: number;
}

interface SecurityRecommendation {
  id: string;
  category: "critical" | "important" | "recommended";
  title: string;
  description: string;
  impact: "high" | "medium" | "low";
  effort: "high" | "medium" | "low";
  status: "new" | "in-progress" | "completed" | "ignored";
}

interface TimelineEntry {
  date: Date;
  status: "safe" | "warning" | "danger";
  score: number;
  events: string[];
}

interface ThreatOrigin {
  country: string;
  countryCode: string;
  attackType: string;
  count: number;
  lastSeen: Date;
}

// Utility functions
const isValidTarget = (target: string): boolean => {
  // Basic validation for IP address or URL
  const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const urlRegex = /^(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;
  
  return ipRegex.test(target) || urlRegex.test(target);
};

const getRiskColor = (level: string): string => {
  switch(level) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    case 'low': return 'text-blue-500';
    case 'info': return 'text-green-500';
    default: return 'text-slate-500';
  }
};

const getRiskBgColor = (level: string): string => {
  switch(level) {
    case 'critical': return 'bg-red-500/10 border-red-500/50';
    case 'high': return 'bg-orange-500/10 border-orange-500/50';
    case 'medium': return 'bg-yellow-500/10 border-yellow-500/50';
    case 'low': return 'bg-blue-500/10 border-blue-500/50';
    case 'info': return 'bg-green-500/10 border-green-500/50';
    default: return 'bg-slate-500/10 border-slate-500/50';
  }
};

const getRiskIcon = (level: string) => {
  switch(level) {
    case 'critical': return <ShieldAlert className="h-5 w-5 text-red-500" />;
    case 'high': return <AlertCircle className="h-5 w-5 text-orange-500" />;
    case 'medium': return <ShieldAlert className="h-5 w-5 text-yellow-500" />;
    case 'low': return <Shield className="h-5 w-5 text-blue-500" />;
    case 'info': return <ShieldCheck className="h-5 w-5 text-green-500" />;
    default: return <Shield className="h-5 w-5 text-slate-500" />;
  }
};

// Main component
export default function SecurityMonitor() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine, clearLines } = useTerminal();
  
  const [target, setTarget] = useState<string>("");
  const [targetDetails, setTargetDetails] = useState<any>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [currentTool, setCurrentTool] = useState<string>("");
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [vulnerabilityStats, setVulnerabilityStats] = useState<VulnerabilityStats>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0
  });
  const [categoryStats, setCategoryStats] = useState<CategoryStats[]>([]);
  const [conclusion, setConclusion] = useState<string>("");
  const [topVulnerabilities, setTopVulnerabilities] = useState<ScanResult[]>([]);
  
  // New states for additional features
  const [securityOverview, setSecurityOverview] = useState<SecurityOverview | null>(null);
  const [cveEntries, setCveEntries] = useState<CVEEntry[]>([]);
  const [threatIntelligence, setThreatIntelligence] = useState<ThreatIntelligence | null>(null);
  const [securityRecommendations, setSecurityRecommendations] = useState<SecurityRecommendation[]>([]);
  const [timelineEntries, setTimelineEntries] = useState<TimelineEntry[]>([]);
  const [threatOrigins, setThreatOrigins] = useState<ThreatOrigin[]>([]);
  const [securityScore, setSecurityScore] = useState<number>(0);
  const [securityHistory, setSecurityHistory] = useState<{date: Date, score: number}[]>([]);
  
  // Set up available tools
  const availableTools = tools.filter(tool => 
    ["network", "vulnerability", "web", "security", "info"].includes(tool.category)
  );
  
  // Reset state when target changes
  useEffect(() => {
    if (!target) {
      setTargetDetails(null);
      setScanResults([]);
      setVulnerabilityStats({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0
      });
      setCategoryStats([]);
      setConclusion("");
      setTopVulnerabilities([]);
      setSecurityOverview(null);
      setCveEntries([]);
      setThreatIntelligence(null);
      setSecurityRecommendations([]);
      setTimelineEntries([]);
      setThreatOrigins([]);
      setSecurityScore(0);
      setSecurityHistory([]);
    }
  }, [target]);
  
  // Generate simulated CVE entries
  const generateCveEntries = (): CVEEntry[] => {
    const cveList: CVEEntry[] = [];
    const components = ['WordPress', 'Apache', 'OpenSSL', 'jQuery', 'PHP', 'MySQL', 'Nginx'];
    const severities: ("critical" | "high" | "medium" | "low")[] = ['critical', 'high', 'medium', 'low'];
    
    // Generate 0-5 CVEs
    const numCves = Math.floor(Math.random() * 6);
    
    for (let i = 0; i < numCves; i++) {
      const year = 2020 + Math.floor(Math.random() * 6); // 2020-2025
      const id = Math.floor(Math.random() * 10000) + 1000;
      const component = components[Math.floor(Math.random() * components.length)];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      
      cveList.push({
        id: `CVE-${year}-${id}`,
        severity,
        description: getRandomCveDescription(component, severity),
        affectedComponent: component,
        publishedDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random date in last 30 days
        fixAvailable: Math.random() > 0.3 // 70% chance fix is available
      });
    }
    
    return cveList;
  };
  
  // Generate threat intelligence data
  const generateThreatIntelligence = (): ThreatIntelligence => {
    const isPhishing = Math.random() < 0.15;
    const isMalware = Math.random() < 0.1;
    const isBotnet = Math.random() < 0.05;
    const isBlacklisted = isPhishing || isMalware || isBotnet || Math.random() < 0.1;
    
    const blacklistSources = [];
    if (isBlacklisted) {
      const sources = ['Google Safe Browsing', 'VirusTotal', 'PhishTank', 'Spamhaus', 'SURBL', 'Barracuda'];
      const numSources = Math.floor(Math.random() * 3) + 1;
      
      for (let i = 0; i < numSources; i++) {
        const randIndex = Math.floor(Math.random() * sources.length);
        blacklistSources.push(sources[randIndex]);
        sources.splice(randIndex, 1); // Remove to avoid duplicates
      }
    }
    
    const abuseReports = isBlacklisted ? Math.floor(Math.random() * 10) + 1 : 0;
    
    let riskScore = 0;
    if (isPhishing) riskScore += 40;
    if (isMalware) riskScore += 50;
    if (isBotnet) riskScore += 60;
    if (blacklistSources.length > 0) riskScore += 20 * blacklistSources.length;
    
    // Cap at 100
    riskScore = Math.min(100, riskScore);
    
    return {
      isPhishing,
      isMalware,
      isBotnet,
      isBlacklisted,
      blacklistSources,
      abuseReports,
      lastReportDate: abuseReports > 0 ? new Date(Date.now() - Math.random() * 60 * 24 * 60 * 60 * 1000) : undefined,
      riskScore
    };
  };
  
  // Generate security recommendations
  const generateSecurityRecommendations = (
    vulnerabilityStats: VulnerabilityStats,
    cveEntries: CVEEntry[],
    threatIntel: ThreatIntelligence
  ): SecurityRecommendation[] => {
    const recommendations: SecurityRecommendation[] = [];
    
    // SSL recommendations
    if (Math.random() > 0.7) {
      recommendations.push({
        id: 'rec-ssl-1',
        category: 'important',
        title: 'Update SSL Certificate Configuration',
        description: 'SSL certificate uses an outdated protocol. Update to TLS 1.3 and disable older TLS/SSL versions.',
        impact: 'medium',
        effort: 'low',
        status: 'new'
      });
    }
    
    // Port recommendations
    if (Math.random() > 0.6) {
      recommendations.push({
        id: 'rec-port-1',
        category: Math.random() > 0.5 ? 'critical' : 'important',
        title: 'Close Unnecessary Open Ports',
        description: 'Unnecessary ports are open including port 21 (FTP) and 3306 (MySQL). Close these ports or restrict access.',
        impact: 'high',
        effort: 'medium',
        status: 'new'
      });
    }
    
    // CMS recommendations
    if (cveEntries.some(cve => cve.affectedComponent === 'WordPress')) {
      recommendations.push({
        id: 'rec-cms-1',
        category: 'critical',
        title: 'Update WordPress Core and Plugins',
        description: 'WordPress installation has critical vulnerabilities. Update WordPress core and all plugins immediately.',
        impact: 'high',
        effort: 'medium',
        status: 'new'
      });
    }
    
    // Firewall recommendations
    if (vulnerabilityStats.high > 0 || vulnerabilityStats.critical > 0) {
      recommendations.push({
        id: 'rec-fw-1',
        category: 'important',
        title: 'Configure Web Application Firewall',
        description: 'Implement and configure a web application firewall to protect against common attacks.',
        impact: 'high',
        effort: 'high',
        status: 'new'
      });
    }
    
    // DNSSEC recommendations
    if (Math.random() > 0.8) {
      recommendations.push({
        id: 'rec-dns-1',
        category: 'recommended',
        title: 'Enable DNSSEC',
        description: 'DNSSEC is not enabled for this domain. Enable DNSSEC to protect against DNS spoofing attacks.',
        impact: 'medium',
        effort: 'medium',
        status: 'new'
      });
    }
    
    // Blacklist remediation
    if (threatIntel.isBlacklisted) {
      recommendations.push({
        id: 'rec-bl-1',
        category: 'critical',
        title: 'Address Blacklisting Issues',
        description: `The domain is blacklisted on ${threatIntel.blacklistSources.join(', ')}. Investigate and remediate issues causing blacklisting.`,
        impact: 'high',
        effort: 'high',
        status: 'new'
      });
    }
    
    // Add a few more random recommendations
    const possibleRecommendations: SecurityRecommendation[] = [
      {
        id: 'rec-sec-1',
        category: 'recommended',
        title: 'Implement HTTP Security Headers',
        description: 'Add security headers such as Content-Security-Policy, X-XSS-Protection, and X-Content-Type-Options.',
        impact: 'medium',
        effort: 'low',
        status: 'new'
      },
      {
        id: 'rec-sec-2',
        category: 'recommended',
        title: 'Enable Two-Factor Authentication',
        description: 'Implement two-factor authentication for all admin access points.',
        impact: 'medium',
        effort: 'medium',
        status: 'new'
      },
      {
        id: 'rec-sec-3',
        category: 'important',
        title: 'Set Proper File Permissions',
        description: 'File permissions are too permissive. Restrict file permissions to minimum necessary.',
        impact: 'medium',
        effort: 'medium',
        status: 'new'
      }
    ];
    
    // Add 1-3 random recommendations
    const numRandomRecs = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numRandomRecs && i < possibleRecommendations.length; i++) {
      recommendations.push(possibleRecommendations[i]);
    }
    
    return recommendations;
  };
  
  // Generate security timeline data for the last 7 days
  const generateTimelineData = (): TimelineEntry[] => {
    const timeline: TimelineEntry[] = [];
    const now = new Date();
    
    // Generate data for last 7 days
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      // Random status weighted toward "safe"
      let status: "safe" | "warning" | "danger";
      const rand = Math.random();
      if (rand < 0.7) status = "safe";
      else if (rand < 0.9) status = "warning";
      else status = "danger";
      
      // Score based on status
      let score: number;
      if (status === "safe") score = 80 + Math.floor(Math.random() * 20);
      else if (status === "warning") score = 50 + Math.floor(Math.random() * 30);
      else score = 20 + Math.floor(Math.random() * 30);
      
      // Random events
      const events: string[] = [];
      if (status !== "safe" || Math.random() < 0.3) {
        const possibleEvents = [
          "Security scan completed",
          "SSL certificate status checked",
          "New vulnerability detected",
          "Suspicious login attempt",
          "Security patch applied",
          "Configuration change detected",
          "Firewall rule updated",
          "DNS configuration changed"
        ];
        
        const numEvents = Math.floor(Math.random() * 3) + 1;
        for (let j = 0; j < numEvents; j++) {
          events.push(possibleEvents[Math.floor(Math.random() * possibleEvents.length)]);
        }
      }
      
      timeline.push({
        date,
        status,
        score,
        events
      });
    }
    
    return timeline;
  };
  
  // Generate threat origins (countries attempting attacks)
  const generateThreatOrigins = (): ThreatOrigin[] => {
    const origins: ThreatOrigin[] = [];
    const countries = [
      { name: 'Russian Federation', code: 'RU' },
      { name: 'China', code: 'CN' },
      { name: 'United States', code: 'US' },
      { name: 'Brazil', code: 'BR' },
      { name: 'Nigeria', code: 'NG' },
      { name: 'India', code: 'IN' },
      { name: 'Netherlands', code: 'NL' },
      { name: 'Ukraine', code: 'UA' },
      { name: 'Vietnam', code: 'VN' },
      { name: 'Korea, Republic of', code: 'KR' }
    ];
    
    const attackTypes = [
      'Brute Force', 
      'SQL Injection', 
      'XSS', 
      'DDOS', 
      'Port Scanning',
      'Credential Stuffing'
    ];
    
    // Generate 0-5 threat origins
    const numOrigins = Math.floor(Math.random() * 6);
    
    // Clone countries array to avoid modifying the original
    const availableCountries = [...countries];
    
    for (let i = 0; i < numOrigins && availableCountries.length > 0; i++) {
      const randCountryIndex = Math.floor(Math.random() * availableCountries.length);
      const country = availableCountries[randCountryIndex];
      availableCountries.splice(randCountryIndex, 1); // Remove to avoid duplicates
      
      const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
      const count = Math.floor(Math.random() * 100) + 1;
      
      // Random date in last week
      const lastSeen = new Date();
      lastSeen.setDate(lastSeen.getDate() - Math.floor(Math.random() * 7));
      
      origins.push({
        country: country.name,
        countryCode: country.code,
        attackType,
        count,
        lastSeen
      });
    }
    
    // Sort by count (descending)
    return origins.sort((a, b) => b.count - a.count);
  };
  
  // Helper function to generate random CVE descriptions
  const getRandomCveDescription = (component: string, severity: string): string => {
    const vulnTypes = [
      'buffer overflow',
      'SQL injection',
      'cross-site scripting (XSS)',
      'remote code execution',
      'privilege escalation',
      'information disclosure',
      'authentication bypass'
    ];
    
    const vulnType = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
    
    const descriptions = [
      `A ${severity} ${vulnType} vulnerability in ${component} allows attackers to compromise the system.`,
      `${component} contains a ${severity} ${vulnType} vulnerability that can lead to system compromise.`,
      `Improper input validation in ${component} leads to ${severity} ${vulnType} vulnerability.`,
      `${component} fails to properly validate user input, resulting in ${severity} ${vulnType} vulnerability.`
    ];
    
    return descriptions[Math.floor(Math.random() * descriptions.length)];
  };
  
  // Run a single tool scan (simulation)
  const runToolScan = async (toolId: string, target: string): Promise<ScanResult> => {
    // This is a simulation - in a real app this would call the API for each tool
    return new Promise((resolve) => {
      setTimeout(() => {
        // Simulate different results based on the tool
        const tool = tools.find(t => t.id === toolId);
        const timestamp = new Date();
        
        // Generate random but plausible results
        const randomStatus = () => {
          const statuses = ["success", "error", "warning", "info"] as const;
          const weights = [0.5, 0.15, 0.25, 0.1]; // Weighted probabilities
          const rand = Math.random();
          let sum = 0;
          for (let i = 0; i < statuses.length; i++) {
            sum += weights[i];
            if (rand < sum) return statuses[i];
          }
          return "success";
        };
        
        const randomRiskLevel = (toolCategory: string) => {
          // Different tools have different risk profiles
          let levels: Array<"critical" | "high" | "medium" | "low" | "info">;
          let weights: number[];
          
          switch(toolCategory) {
            case "vulnerability":
              levels = ["critical", "high", "medium", "low", "info"];
              weights = [0.15, 0.25, 0.3, 0.2, 0.1];
              break;
            case "network":
              levels = ["critical", "high", "medium", "low", "info"];
              weights = [0.05, 0.15, 0.3, 0.3, 0.2];
              break;
            case "info":
              levels = ["critical", "high", "medium", "low", "info"];
              weights = [0.01, 0.04, 0.15, 0.3, 0.5];
              break;
            default:
              levels = ["critical", "high", "medium", "low", "info"];
              weights = [0.1, 0.2, 0.3, 0.2, 0.2];
          }
          
          const rand = Math.random();
          let sum = 0;
          for (let i = 0; i < levels.length; i++) {
            sum += weights[i];
            if (rand < sum) return levels[i];
          }
          return "low";
        };
        
        // Generate specific results based on the tool type
        let simulatedResult: ScanResult;
        const status = randomStatus();
        const riskLevel = randomRiskLevel(tool?.category || "");
        
        switch(toolId) {
          case "port-scanner":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "network",
              toolName: "Port Scanner",
              status,
              summary: status === "success" 
                ? `Found ${Math.floor(Math.random() * 10) + 1} open ports` 
                : "Error scanning ports",
              details: {
                openPorts: [80, 443, 22, 21, 8080, 3306].slice(0, Math.floor(Math.random() * 6) + 1),
                closedPorts: [25, 110, 115, 3389],
                filteredPorts: [137, 138, 139]
              },
              timestamp,
              riskLevel,
              recommendation: "Close unnecessary ports and implement proper firewall rules"
            };
            break;
            
          case "sql-injector":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "vulnerability",
              toolName: "SQL Injector",
              status,
              summary: status === "success" 
                ? `${Math.random() > 0.7 ? "Vulnerable" : "Not vulnerable"} to SQL injection` 
                : "Error testing SQL injection",
              details: {
                vulnerable: Math.random() > 0.7,
                testedParameters: ["id", "username", "search"],
                vulnerableParameters: Math.random() > 0.7 ? ["id"] : []
              },
              timestamp,
              riskLevel,
              recommendation: "Use parameterized queries and validate input"
            };
            break;
            
          case "xss-detector":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "vulnerability",
              toolName: "XSS Detector",
              status,
              summary: status === "success" 
                ? `${Math.random() > 0.6 ? "Detected" : "No"} XSS vulnerabilities` 
                : "Error testing XSS vulnerabilities",
              details: {
                vulnerable: Math.random() > 0.6,
                testedParameters: ["comment", "search", "message"],
                vulnerableParameters: Math.random() > 0.6 ? ["comment"] : []
              },
              timestamp,
              riskLevel,
              recommendation: "Implement proper output encoding and Content-Security-Policy"
            };
            break;
            
          case "tech-detector":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "info",
              toolName: "Tech Detector",
              status,
              summary: status === "success" 
                ? `Detected ${Math.floor(Math.random() * 8) + 2} technologies` 
                : "Error detecting technologies",
              details: {
                technologies: ["Apache", "PHP", "MySQL", "jQuery", "Bootstrap", "WordPress", "CloudFlare"].slice(0, Math.floor(Math.random() * 6) + 2),
                serverInfo: {
                  server: "Apache/2.4.41",
                  language: "PHP/7.4.3"
                }
              },
              timestamp,
              riskLevel: "info",
              recommendation: "Keep all detected technologies updated to their latest versions"
            };
            break;
            
          case "header-analyzer":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "security",
              toolName: "Header Analyzer",
              status,
              summary: status === "success" 
                ? `${Math.random() > 0.5 ? "Missing" : "Found all"} security headers` 
                : "Error analyzing headers",
              details: {
                missingHeaders: Math.random() > 0.5 
                  ? ["Content-Security-Policy", "X-XSS-Protection", "X-Content-Type-Options"] 
                  : [],
                presentHeaders: ["Strict-Transport-Security", "X-Frame-Options"]
              },
              timestamp,
              riskLevel,
              recommendation: "Implement all recommended security headers"
            };
            break;
            
          case "ssl-scanner":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "security",
              toolName: "SSL Scanner",
              status,
              summary: status === "success" 
                ? `SSL Rating: ${Math.random() > 0.7 ? "A+" : Math.random() > 0.4 ? "B" : "C"}` 
                : "Error checking SSL configuration",
              details: {
                certificate: {
                  issuer: "Let's Encrypt",
                  validUntil: new Date(Date.now() + 86400000 * 90),
                  bits: 2048,
                },
                protocols: ["TLS 1.2", "TLS 1.3"],
                vulnerabilities: Math.random() > 0.7 ? [] : ["SWEET32", "POODLE"]
              },
              timestamp,
              riskLevel,
              recommendation: "Disable old SSL/TLS protocols and update OpenSSL"
            };
            break;
            
          case "lfi-scanner":
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: "vulnerability",
              toolName: "LFI Scanner",
              status,
              summary: status === "success" 
                ? `${Math.random() > 0.8 ? "Vulnerable" : "Not vulnerable"} to LFI` 
                : "Error testing LFI vulnerabilities",
              details: {
                vulnerable: Math.random() > 0.8,
                testedPaths: ["../../../etc/passwd", "../../../etc/hosts"],
                accessibleFiles: Math.random() > 0.8 ? ["../../../etc/passwd"] : []
              },
              timestamp,
              riskLevel,
              recommendation: "Validate and sanitize file paths, implement proper permissions"
            };
            break;
            
          default:
            simulatedResult = {
              id: `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
              target,
              category: tool?.category || "other",
              toolName: tool?.name || toolId,
              status,
              summary: status === "success" 
                ? `${tool?.name || toolId} scan completed` 
                : `${tool?.name || toolId} scan failed`,
              details: {
                notes: "Generic scan result"
              },
              timestamp,
              riskLevel,
              recommendation: "Review detailed results for specific recommendations"
            };
        }
        
        resolve(simulatedResult);
      }, Math.random() * 500 + 100); // Simulate variable scan times
    });
  };
  
  // Start comprehensive scan
  const startScan = async () => {
    if (!target) {
      toast({
        variant: "destructive",
        title: "Missing Target",
        description: "Please enter a target URL or IP address"
      });
      return;
    }
    
    if (!isValidTarget(target)) {
      toast({
        variant: "destructive",
        title: "Invalid Target",
        description: "Please enter a valid URL or IP address"
      });
      return;
    }
    
    try {
      setIsScanning(true);
      setProgress(0);
      clearLines();
      setScanResults([]);
      setActiveTab("dashboard");
      
      addSystemLine(`Starting comprehensive security scan of ${target}`);
      addInfoLine("Initializing scan modules...");
      
      // Simulation of target details acquisition
      const normalizedTarget = target.startsWith('http') ? target : `http://${target}`;
      setTargetDetails({
        target: normalizedTarget,
        ip: "192.168.1." + Math.floor(Math.random() * 254 + 1),
        domain: target.replace(/^https?:\/\//, '').split('/')[0],
        scanStartTime: new Date()
      });
      
      // Run each tool sequentially (in a real app could use Promise.all for some)
      const results: ScanResult[] = [];
      const totalTools = availableTools.length;
      
      for (let i = 0; i < totalTools; i++) {
        const tool = availableTools[i];
        const progressPercent = Math.floor((i / totalTools) * 100);
        setProgress(progressPercent);
        setCurrentTool(tool.name);
        
        addInfoLine(`Running ${tool.name}...`);
        
        try {
          const result = await runToolScan(tool.id, normalizedTarget);
          results.push(result);
          
          // Log result to terminal
          if (result.status === "success") {
            addInfoLine(`${tool.name}: ${result.summary}`);
          } else if (result.status === "error") {
            addErrorLine(`${tool.name}: ${result.summary}`);
          } else {
            addInfoLine(`${tool.name}: ${result.summary}`);
          }
        } catch (error) {
          addErrorLine(`Error running ${tool.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
          
          // Add a failure result
          results.push({
            id: `error-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            target: normalizedTarget,
            category: tool.category,
            toolName: tool.name,
            status: "error",
            summary: `Error running ${tool.name}`,
            details: { error: 'Scan failed' },
            timestamp: new Date(),
            riskLevel: "info"
          });
        }
      }
      
      setProgress(100);
      setIsScanning(false);
      setScanResults(results);
      
      // Start analysis phase
      await analyzeResults(results);
      
    } catch (error) {
      setIsScanning(false);
      addErrorLine(`Scan error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      toast({
        variant: "destructive",
        title: "Scan Failed",
        description: "An error occurred during the security scan"
      });
    }
  };
  
  // Analyze scan results
  const analyzeResults = async (results: ScanResult[]) => {
    setIsAnalyzing(true);
    addSystemLine("Analyzing scan results...");
    
    // Calculate vulnerability statistics
    const stats: VulnerabilityStats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: results.length
    };
    
    // Simulate some analysis time
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Count vulnerabilities by risk level
    results.forEach(result => {
      stats[result.riskLevel]++;
    });
    
    setVulnerabilityStats(stats);
    
    // Calculate category statistics
    const categories = Array.from(new Set(results.map(r => r.category)));
    const catStats: CategoryStats[] = categories.map(cat => {
      const catResults = results.filter(r => r.category === cat);
      const vulnCount = catResults.filter(r => ['critical', 'high', 'medium'].includes(r.riskLevel)).length;
      
      return {
        name: cat,
        count: catResults.length,
        vulnerabilities: vulnCount
      };
    });
    
    setCategoryStats(catStats);
    
    // Find top vulnerabilities
    const criticalAndHighVulns = results
      .filter(r => ['critical', 'high'].includes(r.riskLevel))
      .sort((a, b) => {
        // Sort by risk level first
        const riskLevels = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        return riskLevels[b.riskLevel] - riskLevels[a.riskLevel];
      });
    
    setTopVulnerabilities(criticalAndHighVulns.slice(0, 5));
    
    // Generate additional analysis data (CVEs, Threat Intel, etc.)
    const cves = generateCveEntries();
    setCveEntries(cves);
    
    const threatIntel = generateThreatIntelligence();
    setThreatIntelligence(threatIntel);
    
    const recommendations = generateSecurityRecommendations(stats, cves, threatIntel);
    setSecurityRecommendations(recommendations);
    
    const timeline = generateTimelineData();
    setTimelineEntries(timeline);
    
    const threatOrigins = generateThreatOrigins();
    setThreatOrigins(threatOrigins);
    
    // Calculate security score (0-100)
    let score = 100;
    
    // Deduct points for vulnerabilities
    score -= stats.critical * 20;
    score -= stats.high * 10;
    score -= stats.medium * 5;
    score -= stats.low * 2;
    
    // Deduct points for threat intelligence
    if (threatIntel.isPhishing) score -= 20;
    if (threatIntel.isMalware) score -= 20;
    if (threatIntel.isBotnet) score -= 20;
    if (threatIntel.isBlacklisted) score -= 15;
    
    // Deduct points for CVEs
    cves.forEach(cve => {
      if (cve.severity === 'critical') score -= 10;
      else if (cve.severity === 'high') score -= 5;
      else if (cve.severity === 'medium') score -= 3;
      else score -= 1;
    });
    
    // Ensure score is between 0-100
    score = Math.max(0, Math.min(100, score));
    setSecurityScore(score);
    
    // Create security history (last 7 days data)
    const history = timeline.map(entry => ({
      date: entry.date,
      score: entry.score
    }));
    setSecurityHistory(history);
    
    // Set security overview
    let status: "safe" | "warning" | "danger";
    let statusText: string;
    
    if (score >= 80) {
      status = "safe";
      statusText = "AMAN";
    } else if (score >= 50) {
      status = "warning";
      statusText = "WARNING";
    } else {
      status = "danger";
      statusText = "BERBAHAYA";
    }
    
    setSecurityOverview({
      status,
      score,
      lastAnalyzed: new Date(),
      statusText
    });
    
    // Generate conclusion
    let conclusionText = "";
    
    if (stats.critical > 0 || stats.high > 3) {
      conclusionText = `CRITICAL SECURITY ISSUES DETECTED: The target ${target} has ${stats.critical} critical and ${stats.high} high-risk vulnerabilities that require immediate attention. These vulnerabilities could allow unauthorized access to sensitive data or systems.`;
    } else if (stats.high > 0 || stats.medium > 5) {
      conclusionText = `SIGNIFICANT SECURITY CONCERNS: The target ${target} has ${stats.high} high and ${stats.medium} medium-risk issues. While not immediately critical, these vulnerabilities should be addressed promptly to improve security posture.`;
    } else if (stats.medium > 0) {
      conclusionText = `MODERATE SECURITY ISSUES: The target ${target} has ${stats.medium} medium-risk vulnerabilities. These should be addressed as part of regular security maintenance.`;
    } else {
      conclusionText = `GOOD SECURITY POSTURE: The target ${target} appears to have a relatively strong security configuration. Continue regular security testing and maintenance.`;
    }
    
    // Add specific recommendations
    const recommendationTexts = topVulnerabilities
      .filter(v => v.recommendation)
      .map(v => `• ${v.toolName}: ${v.recommendation}`)
      .join('\n');
    
    if (recommendationTexts) {
      conclusionText += `\n\nKEY RECOMMENDATIONS:\n${recommendationTexts}`;
    }
    
    setConclusion(conclusionText);
    setIsAnalyzing(false);
    
    addSystemLine("Analysis complete");
    addInfoLine(`Found ${stats.critical} critical, ${stats.high} high, ${stats.medium} medium, and ${stats.low} low-risk issues`);
    
    toast({
      title: "Scan Complete",
      description: `Found ${stats.critical + stats.high + stats.medium} significant issues`
    });
  };
  
  // Generate PDF Report (Simulation)
  const generateReport = () => {
    toast({
      title: "Report Generation",
      description: "PDF report would be generated here in a real implementation"
    });
    
    addSystemLine("Generating security assessment report");
    
    // In a real implementation, this would generate a PDF report
    setTimeout(() => {
      toast({
        title: "Report Generated",
        description: "Security assessment report is ready for download"
      });
      
      addInfoLine("Report generated successfully");
    }, 2000);
  };
  
  // Rescan Target
  const rescanTarget = () => {
    if (target) {
      startScan();
    }
  };
  
  // Reset scan
  const resetScan = () => {
    setTarget("");
    setTargetDetails(null);
    setScanResults([]);
    setVulnerabilityStats({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0
    });
    setCategoryStats([]);
    setConclusion("");
    setTopVulnerabilities([]);
    clearLines();
    
    addSystemLine("Security monitor reset");
    addInfoLine("Ready for new scan");
  };
  
  // Copy conclusion to clipboard
  const copyConclusion = () => {
    navigator.clipboard.writeText(conclusion);
    toast({
      title: "Copied",
      description: "Assessment has been copied to clipboard"
    });
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Security Operation Center Dashboard</h2>
        
        <div className="space-y-6">
          {/* Target Input */}
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-grow">
              <Label htmlFor="target-input">Target URL or IP Address</Label>
              <div className="flex mt-1">
                <Input
                  id="target-input"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or 192.168.1.1"
                  disabled={isScanning}
                  className="rounded-r-none focus-visible:ring-0 focus-visible:ring-primary/20"
                />
                <Button 
                  onClick={startScan} 
                  disabled={isScanning || !target}
                  className="rounded-l-none"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" />
                      Scan Target
                    </>
                  )}
                </Button>
              </div>
            </div>
            
            {scanResults.length > 0 && (
              <div className="flex space-x-2">
                <Button variant="outline" onClick={rescanTarget} disabled={isScanning}>
                  Rescan
                </Button>
                <Button variant="outline" onClick={resetScan} disabled={isScanning}>
                  Reset
                </Button>
              </div>
            )}
          </div>
          
          {/* Progress Bar */}
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Scanning: {currentTool}</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
          
          {/* Analysis Loading */}
          {isAnalyzing && (
            <div className="text-center py-4">
              <Loader2 className="h-8 w-8 animate-spin mx-auto" />
              <p className="mt-2 text-muted-foreground">Analyzing results...</p>
            </div>
          )}
          
          {/* Results Content */}
          {scanResults.length > 0 && !isScanning && !isAnalyzing && (
            <>
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="grid grid-cols-6 mb-4">
                  <TabsTrigger value="dashboard" className="font-tech">Dashboard</TabsTrigger>
                  <TabsTrigger value="vulnerabilities" className="font-tech">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="threat-intel" className="font-tech">Threat Intel</TabsTrigger>
                  <TabsTrigger value="recommendations" className="font-tech">Recommendations</TabsTrigger>
                  <TabsTrigger value="visualizations" className="font-tech">Visualizations</TabsTrigger>
                  <TabsTrigger value="analysis" className="font-tech">Analysis</TabsTrigger>
                </TabsList>
                
                {/* Dashboard Tab */}
                <TabsContent value="dashboard" className="space-y-6">
                  {/* Security Overview Card - Big status card at the top */}
                  {targetDetails && securityOverview && (
                    <Card className={`p-4 mb-6 border-2 ${
                      securityOverview.status === "safe" 
                        ? "border-green-500/50 bg-green-500/5" 
                        : securityOverview.status === "warning"
                          ? "border-yellow-500/50 bg-yellow-500/5"
                          : "border-red-500/50 bg-red-500/5"
                    }`}>
                      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                        <div className="lg:col-span-1 flex flex-col items-center justify-center">
                          {securityOverview.status === "safe" ? (
                            <CheckCircle className="h-16 w-16 text-green-500" />
                          ) : securityOverview.status === "warning" ? (
                            <AlertTriangle className="h-16 w-16 text-yellow-500" />
                          ) : (
                            <AlertCircle className="h-16 w-16 text-red-500" />
                          )}
                          <h3 className="text-2xl font-tech mt-2 text-center">
                            {securityOverview.statusText}
                          </h3>
                        </div>
                        
                        <div className="lg:col-span-3 space-y-3">
                          <div className="flex justify-between items-baseline">
                            <h3 className="text-xl font-tech">
                              Security Assessment Summary
                            </h3>
                            <div className="flex items-center space-x-3">
                              <Clock className="h-4 w-4 text-muted-foreground" />
                              <span className="text-sm text-muted-foreground">
                                Terakhir diperiksa: {securityOverview.lastAnalyzed.toLocaleDateString()} {securityOverview.lastAnalyzed.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          
                          <div className="text-lg font-medium">
                            <span className="font-tech">{targetDetails.domain}</span> dinilai <span className={`font-tech ${
                              securityOverview.status === "safe" 
                                ? "text-green-500" 
                                : securityOverview.status === "warning"
                                  ? "text-yellow-500"
                                  : "text-red-500"
                            }`}>{securityOverview.statusText}</span> dengan skor <span className="font-tech">{securityOverview.score}</span> dari 100.
                          </div>
                          
                          <div className="flex flex-col space-y-2">
                            <div className="flex justify-between text-sm">
                              <span>Security Score</span>
                              <span>{securityOverview.score}/100</span>
                            </div>
                            <div className="h-2 w-full bg-background rounded overflow-hidden">
                              <div 
                                className={`h-full ${
                                  securityOverview.status === "safe" 
                                    ? "bg-green-500" 
                                    : securityOverview.status === "warning"
                                      ? "bg-yellow-500"
                                      : "bg-red-500"
                                }`} 
                                style={{ width: `${securityOverview.score}%` }}
                              />
                            </div>
                          </div>
                          
                          <div className="grid grid-cols-3 gap-2 text-sm mt-2">
                            <div className="flex items-center space-x-2">
                              <AlertCircle className="h-4 w-4 text-red-500" />
                              <span>Critical: {vulnerabilityStats.critical}</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <AlertTriangle className="h-4 w-4 text-yellow-500" />
                              <span>Medium: {vulnerabilityStats.medium}</span>
                            </div>
                            {cveEntries.length > 0 && (
                              <div className="flex items-center space-x-2">
                                <Bug className="h-4 w-4 text-purple-500" />
                                <span>CVEs: {cveEntries.length}</span>
                              </div>
                            )}
                            <div className="flex items-center space-x-2">
                              <AlertTriangle className="h-4 w-4 text-orange-500" />
                              <span>High: {vulnerabilityStats.high}</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Shield className="h-4 w-4 text-blue-500" />
                              <span>Low: {vulnerabilityStats.low}</span>
                            </div>
                            {threatIntelligence?.isBlacklisted && (
                              <div className="flex items-center space-x-2">
                                <AlertCircle className="h-4 w-4 text-red-500" />
                                <span>Blacklisted</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </Card>
                  )}
                  
                  {/* Target Info & Summary Cards */}
                  {targetDetails && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card className="p-4 bg-card/80 border-secondary/30">
                        <div className="flex items-center space-x-2">
                          <Globe className="h-5 w-5 text-secondary" />
                          <h3 className="font-tech text-secondary">Target</h3>
                        </div>
                        <div className="mt-2 space-y-1 text-sm">
                          <p className="font-mono">{targetDetails.target}</p>
                          <p className="text-muted-foreground">IP: {targetDetails.ip}</p>
                          <p className="text-muted-foreground">Domain: {targetDetails.domain}</p>
                        </div>
                      </Card>
                      
                      <Card className="p-4 bg-card/80 border-secondary/30">
                        <div className="flex items-center space-x-2">
                          <Network className="h-5 w-5 text-secondary" />
                          <h3 className="font-tech text-secondary">Network Overview</h3>
                        </div>
                        <div className="mt-2 space-y-1 text-sm">
                          {(() => {
                            const portResult = scanResults.find(r => r.toolName === "Port Scanner");
                            const openPorts = portResult?.details?.openPorts || [];
                            const sslResult = scanResults.find(r => r.toolName === "SSL Scanner");
                            const sslRating = sslResult?.summary?.split(": ")[1] || "Unknown";
                            
                            return (
                              <>
                                <div className="flex justify-between">
                                  <span>Open Ports:</span>
                                  <span className="font-mono">{openPorts.length}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>SSL Rating:</span>
                                  <span className="font-mono">{sslRating}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Firewall Detected:</span>
                                  <span className="font-mono">{Math.random() > 0.5 ? "Yes" : "No"}</span>
                                </div>
                              </>
                            );
                          })()}
                        </div>
                      </Card>
                      
                      <Card className="p-4 bg-card/80 border-secondary/30">
                        <div className="flex items-center space-x-2">
                          <Database className="h-5 w-5 text-secondary" />
                          <h3 className="font-tech text-secondary">Tech Stack</h3>
                        </div>
                        <div className="mt-2 space-y-1 text-sm">
                          {(() => {
                            const techResult = scanResults.find(r => r.toolName === "Tech Detector");
                            const technologies = techResult?.details?.technologies || [];
                            const detectedCMS = technologies.find(t => ["WordPress", "Joomla", "Drupal"].includes(t));
                            
                            return (
                              <>
                                <div className="flex justify-between">
                                  <span>CMS:</span>
                                  <span className="font-mono">{detectedCMS || "None detected"}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Server:</span>
                                  <span className="font-mono">{techResult?.details?.serverInfo?.server || "Unknown"}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Language:</span>
                                  <span className="font-mono">{techResult?.details?.serverInfo?.language || "Unknown"}</span>
                                </div>
                              </>
                            );
                          })()}
                        </div>
                      </Card>
                    </div>
                  )}
                  
                  {/* Top Vulnerabilities */}
                  {topVulnerabilities.length > 0 && (
                    <Card className="p-4 bg-card/80 border-destructive/30">
                      <div className="flex items-center space-x-2 mb-4">
                        <ShieldAlert className="h-5 w-5 text-destructive" />
                        <h3 className="font-tech text-destructive">Top Vulnerabilities</h3>
                      </div>
                      
                      <div className="space-y-3">
                        {topVulnerabilities.map((vuln, index) => (
                          <div 
                            key={vuln.id}
                            className={`p-3 border rounded-md ${getRiskBgColor(vuln.riskLevel)}`}
                          >
                            <div className="flex items-start">
                              {getRiskIcon(vuln.riskLevel)}
                              <div className="ml-2">
                                <h4 className={`font-tech text-sm ${getRiskColor(vuln.riskLevel)}`}>
                                  {vuln.toolName}: {vuln.summary}
                                </h4>
                                {vuln.recommendation && (
                                  <p className="text-xs text-muted-foreground mt-1">
                                    {vuln.recommendation}
                                  </p>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                  
                  {/* Conclusion */}
                  {conclusion && (
                    <Card className="p-4 bg-card/80 border-primary/30">
                      <div className="flex justify-between items-center mb-4">
                        <div className="flex items-center space-x-2">
                          <FileText className="h-5 w-5 text-primary" />
                          <h3 className="font-tech text-primary">Security Assessment</h3>
                        </div>
                        <div className="flex space-x-2">
                          <Button variant="outline" size="sm" onClick={copyConclusion}>
                            <Copy className="h-4 w-4 mr-1" />
                            Copy
                          </Button>
                          <Button variant="outline" size="sm" onClick={generateReport}>
                            <Download className="h-4 w-4 mr-1" />
                            Report
                          </Button>
                        </div>
                      </div>
                      
                      <div className="whitespace-pre-line font-mono text-sm">
                        {conclusion}
                      </div>
                    </Card>
                  )}
                </TabsContent>
                
                {/* Vulnerabilities Tab */}
                <TabsContent value="vulnerabilities" className="space-y-6">
                  <Card className="p-4 bg-card/80 border-secondary/30">
                    <h3 className="font-tech text-secondary mb-4">🔍 Vulnerability Scan</h3>
                    
                    {/* Port Information */}
                    <div className="mb-6">
                      <h4 className="text-primary text-sm font-tech mb-2 flex items-center">
                        <Server className="w-4 h-4 mr-2" />
                        Port Scan Results
                      </h4>
                      
                      {(() => {
                        const portResult = scanResults.find(r => r.toolName === "Port Scanner");
                        if (!portResult || portResult.status !== "success") {
                          return <p className="text-sm text-muted-foreground">No port information available</p>;
                        }
                        
                        const openPorts = portResult.details.openPorts || [];
                        const commonServices: Record<number, string> = {
                          21: "FTP",
                          22: "SSH",
                          23: "Telnet",
                          25: "SMTP",
                          53: "DNS",
                          80: "HTTP",
                          110: "POP3",
                          143: "IMAP",
                          443: "HTTPS",
                          3306: "MySQL",
                          3389: "RDP",
                          5432: "PostgreSQL",
                          8080: "HTTP-Alt"
                        };
                        
                        return (
                          <>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2">
                              {openPorts.map((port: number) => (
                                <div key={port} className="flex justify-between items-center bg-green-500/10 text-sm p-2 rounded">
                                  <span className="font-mono font-bold">{port}</span>
                                  <span className="text-xs text-muted-foreground">{commonServices[port] || "Unknown"}</span>
                                </div>
                              ))}
                            </div>
                            
                            {openPorts.length === 0 && (
                              <p className="text-sm text-muted-foreground">No open ports detected</p>
                            )}
                            
                            {openPorts.length > 0 && openPorts.some(p => [21, 23, 3306, 5432].includes(p)) && (
                              <div className="mt-2 text-xs bg-yellow-500/10 p-2 rounded-md border border-yellow-500/30">
                                <AlertTriangle className="h-3 w-3 text-yellow-500 inline mr-1" />
                                <span className="text-yellow-500 font-semibold">Security Warning:</span> Some potentially risky ports are open (FTP, Telnet, or database ports).
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                    
                    {/* SSL/TLS Information */}
                    <div className="mb-6">
                      <h4 className="text-primary text-sm font-tech mb-2 flex items-center">
                        <Lock className="w-4 h-4 mr-2" />
                        SSL/TLS Configuration
                      </h4>
                      
                      {(() => {
                        const sslResult = scanResults.find(r => r.toolName === "SSL Scanner");
                        if (!sslResult || sslResult.status !== "success") {
                          return <p className="text-sm text-muted-foreground">No SSL information available</p>;
                        }
                        
                        const sslRating = sslResult.summary?.split(": ")[1] || "Unknown";
                        const cert = sslResult.details?.certificate || {};
                        const protocols = sslResult.details?.protocols || [];
                        const vulnerabilities = sslResult.details?.vulnerabilities || [];
                        
                        return (
                          <div className="space-y-2">
                            <div className="flex items-center">
                              <div className={`text-xl font-bold px-3 py-1 rounded ${
                                sslRating === "A+" ? "bg-green-500/20 text-green-500" :
                                sslRating === "A" ? "bg-green-400/20 text-green-500" :
                                sslRating === "B" ? "bg-yellow-500/20 text-yellow-500" :
                                "bg-red-500/20 text-red-500"
                              }`}>
                                {sslRating}
                              </div>
                              <span className="ml-2 text-sm">SSL Rating</span>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2 text-sm">
                              <div>
                                <p className="text-xs text-muted-foreground">Certificate Issuer</p>
                                <p>{cert.issuer || "Unknown"}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">Valid Until</p>
                                <p>{cert.validUntil ? new Date(cert.validUntil).toLocaleDateString() : "Unknown"}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">Key Strength</p>
                                <p>{cert.bits ? `${cert.bits} bits` : "Unknown"}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">Protocols</p>
                                <p>{protocols.join(", ") || "Unknown"}</p>
                              </div>
                            </div>
                            
                            {vulnerabilities.length > 0 && (
                              <div className="mt-2 text-xs bg-yellow-500/10 p-2 rounded-md border border-yellow-500/30">
                                <AlertTriangle className="h-3 w-3 text-yellow-500 inline mr-1" />
                                <span className="text-yellow-500 font-semibold">SSL Vulnerabilities Detected:</span> {vulnerabilities.join(", ")}
                              </div>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                    
                    {/* CMS Detection */}
                    <div className="mb-6">
                      <h4 className="text-primary text-sm font-tech mb-2 flex items-center">
                        <Database className="w-4 h-4 mr-2" />
                        CMS & Plugin Detection
                      </h4>
                      
                      {(() => {
                        const techResult = scanResults.find(r => r.toolName === "Tech Detector");
                        if (!techResult || techResult.status !== "success") {
                          return <p className="text-sm text-muted-foreground">No CMS information available</p>;
                        }
                        
                        const technologies = techResult.details?.technologies || [];
                        const detectedCMS = technologies.find(t => ["WordPress", "Joomla", "Drupal"].includes(t));
                        
                        if (!detectedCMS) {
                          return <p className="text-sm text-muted-foreground">No CMS detected</p>;
                        }
                        
                        // Simulate some plugin detection for WordPress
                        const wpPlugins = detectedCMS === "WordPress" ? [
                          { name: "Contact Form 7", version: "5.5.3", vulnerable: false },
                          { name: "Yoast SEO", version: "17.8", vulnerable: false },
                          { name: "WooCommerce", version: "6.3.1", vulnerable: Math.random() > 0.7 }
                        ] : [];
                        
                        return (
                          <div className="space-y-2">
                            <div className="flex items-center">
                              <span className="font-semibold">{detectedCMS}</span>
                              <span className="ml-2 text-xs text-muted-foreground">
                                Version: {Math.floor(Math.random() * 3) + 3}.{Math.floor(Math.random() * 9)}.{Math.floor(Math.random() * 9)}
                              </span>
                            </div>
                            
                            {wpPlugins.length > 0 && (
                              <div>
                                <p className="text-xs text-muted-foreground mt-2 mb-1">Detected Plugins:</p>
                                <div className="space-y-1">
                                  {wpPlugins.map((plugin, idx) => (
                                    <div key={idx} className="flex justify-between text-xs p-1 bg-background/50 rounded">
                                      <span>{plugin.name} (v{plugin.version})</span>
                                      {plugin.vulnerable ? (
                                        <span className="text-red-500 flex items-center">
                                          <AlertCircle className="h-3 w-3 mr-1" />
                                          Vulnerable
                                        </span>
                                      ) : (
                                        <span className="text-green-500 flex items-center">
                                          <CheckCircle className="h-3 w-3 mr-1" />
                                          Up to date
                                        </span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                    
                    {/* CVE Vulnerabilities */}
                    <div className="mb-4">
                      <h4 className="text-primary text-sm font-tech mb-2 flex items-center">
                        <Bug className="w-4 h-4 mr-2" />
                        CVE Vulnerabilities
                      </h4>
                      
                      {cveEntries.length > 0 ? (
                        <div className="space-y-2">
                          {cveEntries.map(cve => (
                            <div key={cve.id} className={`p-2 text-sm border rounded-md ${
                              cve.severity === "critical" ? "bg-red-500/10 border-red-500/30" :
                              cve.severity === "high" ? "bg-orange-500/10 border-orange-500/30" :
                              cve.severity === "medium" ? "bg-yellow-500/10 border-yellow-500/30" :
                              "bg-blue-500/10 border-blue-500/30"
                            }`}>
                              <div className="flex justify-between">
                                <span className="font-mono font-bold">{cve.id}</span>
                                <span className="capitalize">{cve.severity}</span>
                              </div>
                              <p className="text-xs mt-1">{cve.description}</p>
                              <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                                <span>Affects: {cve.affectedComponent}</span>
                                <span>Fix Available: {cve.fixAvailable ? "Yes" : "No"}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">No CVE vulnerabilities detected</p>
                      )}
                    </div>
                    
                    {/* General Vulnerabilities Summary */}
                    <div className="space-y-4 mt-6">
                      <h4 className="text-primary text-sm font-tech mb-2">Other Vulnerabilities by Severity</h4>
                      
                      {['critical', 'high', 'medium', 'low'].map((level) => {
                        const levelResults = scanResults.filter(r => r.riskLevel === level);
                        if (levelResults.length === 0) return null;
                        
                        return (
                          <div key={level} className={`p-4 border ${getRiskBgColor(level)} rounded-md`}>
                            <h4 className={`font-tech text-sm ${getRiskColor(level)} mb-2 flex items-center`}>
                              {getRiskIcon(level)}
                              <span className="ml-2 capitalize">{level} Risk ({levelResults.length})</span>
                            </h4>
                            
                            <div className="space-y-2">
                              {levelResults.map(result => (
                                <div key={result.id} className="bg-background/50 p-2 rounded text-sm">
                                  <div className="flex justify-between">
                                    <span className="font-semibold">{result.toolName}</span>
                                    <span className="text-xs text-muted-foreground">
                                      {new Date(result.timestamp).toLocaleTimeString()}
                                    </span>
                                  </div>
                                  <p className="mt-1">{result.summary}</p>
                                  {result.recommendation && (
                                    <p className="mt-1 text-xs border-t pt-1 border-secondary/20">
                                      <span className="font-semibold">Recommendation:</span> {result.recommendation}
                                    </p>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </Card>
                </TabsContent>
                
                {/* Threat Intelligence Tab */}
                <TabsContent value="threat-intel" className="space-y-6">
                  <Card className="p-4 bg-card/80 border-secondary/30">
                    <h3 className="font-tech text-secondary mb-4">🧬 Threat Intelligence</h3>
                    
                    {threatIntelligence && (
                      <div className="space-y-6">
                        {/* Threat Summary */}
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                          <Card className={`p-3 ${threatIntelligence.isPhishing ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                            <div className="flex flex-col items-center justify-center h-full py-2">
                              <div className="mb-2">
                                {threatIntelligence.isPhishing ? 
                                  <AlertCircle className="h-8 w-8 text-red-500" /> : 
                                  <CheckCircle className="h-8 w-8 text-green-500" />
                                }
                              </div>
                              <h4 className="font-tech text-center">Phishing Status</h4>
                              <p className="text-sm mt-1 text-center">{threatIntelligence.isPhishing ? 'Suspected Phishing' : 'No Phishing Detected'}</p>
                            </div>
                          </Card>
                          
                          <Card className={`p-3 ${threatIntelligence.isMalware ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                            <div className="flex flex-col items-center justify-center h-full py-2">
                              <div className="mb-2">
                                {threatIntelligence.isMalware ? 
                                  <AlertCircle className="h-8 w-8 text-red-500" /> : 
                                  <CheckCircle className="h-8 w-8 text-green-500" />
                                }
                              </div>
                              <h4 className="font-tech text-center">Malware Status</h4>
                              <p className="text-sm mt-1 text-center">{threatIntelligence.isMalware ? 'Suspected Malware' : 'No Malware Detected'}</p>
                            </div>
                          </Card>
                          
                          <Card className={`p-3 ${threatIntelligence.isBotnet ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                            <div className="flex flex-col items-center justify-center h-full py-2">
                              <div className="mb-2">
                                {threatIntelligence.isBotnet ? 
                                  <AlertCircle className="h-8 w-8 text-red-500" /> : 
                                  <CheckCircle className="h-8 w-8 text-green-500" />
                                }
                              </div>
                              <h4 className="font-tech text-center">Botnet Status</h4>
                              <p className="text-sm mt-1 text-center">{threatIntelligence.isBotnet ? 'Botnet C2 Detected' : 'No Botnet Activity'}</p>
                            </div>
                          </Card>
                          
                          <Card className={`p-3 ${threatIntelligence.isBlacklisted ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
                            <div className="flex flex-col items-center justify-center h-full py-2">
                              <div className="mb-2">
                                {threatIntelligence.isBlacklisted ? 
                                  <AlertCircle className="h-8 w-8 text-red-500" /> : 
                                  <CheckCircle className="h-8 w-8 text-green-500" />
                                }
                              </div>
                              <h4 className="font-tech text-center">Blacklist Status</h4>
                              <p className="text-sm mt-1 text-center">
                                {threatIntelligence.isBlacklisted 
                                  ? `Blacklisted (${threatIntelligence.blacklistSources.length} sources)` 
                                  : 'Not Blacklisted'}
                              </p>
                            </div>
                          </Card>
                        </div>
                        
                        {/* Risk Score Card */}
                        <Card className="p-4 bg-card border-primary/20">
                          <div className="flex justify-between items-center mb-4">
                            <h4 className="font-tech text-primary flex items-center">
                              <Activity className="h-5 w-5 mr-2" />
                              Threat Risk Score
                            </h4>
                            <div className={`text-lg font-bold px-3 py-1 rounded-full ${
                              threatIntelligence.riskScore < 20 ? "bg-green-500/20 text-green-500" :
                              threatIntelligence.riskScore < 50 ? "bg-yellow-500/20 text-yellow-500" :
                              "bg-red-500/20 text-red-500"
                            }`}>
                              {threatIntelligence.riskScore}/100
                            </div>
                          </div>
                          
                          <div className="w-full bg-background h-3 rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${
                                threatIntelligence.riskScore < 20 ? "bg-green-500" :
                                threatIntelligence.riskScore < 50 ? "bg-yellow-500" :
                                "bg-red-500"
                              }`} 
                              style={{ width: `${threatIntelligence.riskScore}%` }}
                            />
                          </div>
                          
                          <p className="text-sm mt-4 text-muted-foreground">
                            {threatIntelligence.riskScore < 20 
                              ? "Low threat risk. The domain appears to be safe and has no significant threat indicators."
                              : threatIntelligence.riskScore < 50
                                ? "Moderate threat risk. The domain has some suspicious indicators but no definitive malicious activity."
                                : "High threat risk. The domain shows strong indicators of malicious activity and should be approached with caution."}
                          </p>
                        </Card>
                        
                        {/* Blacklist Details */}
                        {threatIntelligence.isBlacklisted && (
                          <Card className="p-4 bg-card border-destructive/20">
                            <h4 className="font-tech text-destructive mb-4 flex items-center">
                              <Eye className="h-5 w-5 mr-2" />
                              Blacklist Details
                            </h4>
                            
                            <div className="space-y-3">
                              <div>
                                <p className="text-sm text-muted-foreground mb-2">Blacklisted on the following services:</p>
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                  {threatIntelligence.blacklistSources.map((source, idx) => (
                                    <div key={idx} className="bg-destructive/10 text-destructive text-sm py-1 px-3 rounded text-center">
                                      {source}
                                    </div>
                                  ))}
                                </div>
                              </div>
                              
                              {threatIntelligence.abuseReports > 0 && (
                                <div>
                                  <p className="text-sm text-muted-foreground mb-2">Abuse Reports: {threatIntelligence.abuseReports}</p>
                                  {threatIntelligence.lastReportDate && (
                                    <p className="text-xs text-muted-foreground">
                                      Last reported: {threatIntelligence.lastReportDate.toLocaleDateString()}
                                    </p>
                                  )}
                                </div>
                              )}
                            </div>
                          </Card>
                        )}
                        
                        {/* Threat Origins Map */}
                        {threatOrigins.length > 0 && (
                          <Card className="p-4 bg-card border-secondary/20">
                            <h4 className="font-tech text-secondary mb-4 flex items-center">
                              <Map className="h-5 w-5 mr-2" />
                              Threat Origins
                            </h4>
                            
                            <div className="space-y-3">
                              <div className="h-48 bg-background/80 border border-secondary/20 rounded-md relative mb-4">
                                <div className="p-4 text-xs text-center text-muted-foreground absolute inset-0 flex items-center justify-center">
                                  [Threat Map Visualization - In a real implementation, this would be an interactive map showing attack origins]
                                </div>
                              </div>
                              
                              <div>
                                <p className="text-sm text-muted-foreground mb-2">Top attack sources:</p>
                                <div className="space-y-2">
                                  {threatOrigins.map((origin, idx) => (
                                    <div key={idx} className="flex justify-between text-sm p-2 bg-background/60 rounded">
                                      <div>
                                        <span className="font-semibold">{origin.country}</span>
                                        <span className="text-xs ml-2 text-muted-foreground">({origin.countryCode})</span>
                                      </div>
                                      <div className="text-xs flex items-center">
                                        <span className="text-muted-foreground mr-2">{origin.attackType}</span>
                                        <span className="font-mono bg-primary/10 px-2 py-0.5 rounded">{origin.count}</span>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </Card>
                        )}
                      </div>
                    )}
                  </Card>
                </TabsContent>
                
                {/* Analysis Tab */}
                <TabsContent value="analysis" className="space-y-6">
                  <Card className="p-4 bg-card/80 border-secondary/30">
                    <h3 className="font-tech text-secondary mb-4">Security Analysis</h3>
                    
                    <div className="space-y-6">
                      {/* Target Profile */}
                      <div className="space-y-2">
                        <h4 className="font-tech text-primary text-sm">Target Profile</h4>
                        <div className="grid grid-cols-2 gap-4 font-mono text-sm">
                          <div>
                            <p className="text-xs text-muted-foreground">Host</p>
                            <p>{targetDetails?.target}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">IP Address</p>
                            <p>{targetDetails?.ip}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Scan Time</p>
                            <p>{targetDetails?.scanStartTime.toLocaleString()}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground">Total Scans</p>
                            <p>{scanResults.length}</p>
                          </div>
                        </div>
                      </div>
                      
                      <Separator />
                      
                      {/* Technology Detection */}
                      <div className="space-y-2">
                        <h4 className="font-tech text-primary text-sm">Detected Technologies</h4>
                        
                        {(() => {
                          const techResult = scanResults.find(r => r.toolName === "Tech Detector");
                          if (!techResult || techResult.status !== "success") {
                            return <p className="text-sm text-muted-foreground">No technology information available</p>;
                          }
                          
                          return (
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                              {techResult.details.technologies.map((tech: string, index: number) => (
                                <div key={index} className="bg-secondary/10 p-2 rounded text-sm text-center">
                                  {tech}
                                </div>
                              ))}
                            </div>
                          );
                        })()}
                      </div>
                      
                      <Separator />
                      
                      {/* Port Information */}
                      <div className="space-y-2">
                        <h4 className="font-tech text-primary text-sm">Port and Service Information</h4>
                        
                        {(() => {
                          const portResult = scanResults.find(r => r.toolName === "Port Scanner");
                          if (!portResult || portResult.status !== "success") {
                            return <p className="text-sm text-muted-foreground">No port information available</p>;
                          }
                          
                          const commonServices: Record<number, string> = {
                            21: "FTP",
                            22: "SSH",
                            23: "Telnet",
                            25: "SMTP",
                            53: "DNS",
                            80: "HTTP",
                            110: "POP3",
                            143: "IMAP",
                            443: "HTTPS",
                            3306: "MySQL",
                            3389: "RDP",
                            5432: "PostgreSQL",
                            8080: "HTTP-Alt"
                          };
                          
                          return (
                            <div className="space-y-2">
                              <div className="grid grid-cols-3 gap-x-4 gap-y-2 text-sm">
                                {portResult.details.openPorts.map((port: number) => (
                                  <div key={port} className="flex justify-between items-center bg-green-500/10 p-2 rounded">
                                    <span className="font-mono">{port}</span>
                                    <span className="text-xs text-muted-foreground">{commonServices[port] || "Unknown"}</span>
                                    <span className="text-green-500 text-xs">OPEN</span>
                                  </div>
                                ))}
                              </div>
                              
                              {portResult.details.openPorts.length === 0 && (
                                <p className="text-sm text-muted-foreground">No open ports detected</p>
                              )}
                            </div>
                          );
                        })()}
                      </div>
                      
                      <Separator />
                      
                      {/* Security Headers */}
                      <div className="space-y-2">
                        <h4 className="font-tech text-primary text-sm">Security Headers Analysis</h4>
                        
                        {(() => {
                          const headerResult = scanResults.find(r => r.toolName === "Header Analyzer");
                          if (!headerResult || headerResult.status !== "success") {
                            return <p className="text-sm text-muted-foreground">No header information available</p>;
                          }
                          
                          const missingHeaders = headerResult.details.missingHeaders || [];
                          const presentHeaders = headerResult.details.presentHeaders || [];
                          
                          return (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <h5 className="text-xs text-muted-foreground mb-2">Present Headers</h5>
                                {presentHeaders.length > 0 ? (
                                  <ul className="space-y-1">
                                    {presentHeaders.map((header: string, index: number) => (
                                      <li key={index} className="flex items-center text-sm">
                                        <CheckCircle className="h-3 w-3 text-green-500 mr-2" />
                                        {header}
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <p className="text-sm text-muted-foreground">No security headers found</p>
                                )}
                              </div>
                              
                              <div>
                                <h5 className="text-xs text-muted-foreground mb-2">Missing Headers</h5>
                                {missingHeaders.length > 0 ? (
                                  <ul className="space-y-1">
                                    {missingHeaders.map((header: string, index: number) => (
                                      <li key={index} className="flex items-center text-sm">
                                        <XCircle className="h-3 w-3 text-destructive mr-2" />
                                        {header}
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <p className="text-sm text-green-500">All recommended headers present</p>
                                )}
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                  </Card>
                </TabsContent>
              </Tabs>
            </>
          )}
        </div>
      </Card>
    </div>
  );
}