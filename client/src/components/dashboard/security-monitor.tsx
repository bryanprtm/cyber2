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
  Lock
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
    }
  }, [target]);
  
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
    const recommendations = topVulnerabilities
      .filter(v => v.recommendation)
      .map(v => `• ${v.toolName}: ${v.recommendation}`)
      .join('\n');
    
    if (recommendations) {
      conclusionText += `\n\nKEY RECOMMENDATIONS:\n${recommendations}`;
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
                <TabsList className="grid grid-cols-3 mb-4">
                  <TabsTrigger value="dashboard" className="font-tech">Dashboard</TabsTrigger>
                  <TabsTrigger value="vulnerabilities" className="font-tech">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="analysis" className="font-tech">Analysis</TabsTrigger>
                </TabsList>
                
                {/* Dashboard Tab */}
                <TabsContent value="dashboard" className="space-y-6">
                  {/* Target Info */}
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
                          <Shield className="h-5 w-5 text-secondary" />
                          <h3 className="font-tech text-secondary">Security Score</h3>
                        </div>
                        <div className="mt-2 space-y-1">
                          {vulnerabilityStats && (
                            <div className="flex justify-center">
                              <div className="text-4xl font-bold relative">
                                {(() => {
                                  if (vulnerabilityStats.critical > 0) return 'F';
                                  if (vulnerabilityStats.high > 2) return 'D';
                                  if (vulnerabilityStats.high > 0) return 'C';
                                  if (vulnerabilityStats.medium > 2) return 'B';
                                  return 'A';
                                })()}
                                <span className="absolute text-sm top-0 right-0 transform translate-x-full -translate-y-1/4">
                                  {vulnerabilityStats.critical === 0 && vulnerabilityStats.high === 0 ? '+' : ''}
                                </span>
                              </div>
                            </div>
                          )}
                          <p className="text-center text-sm text-muted-foreground mt-2">
                            {vulnerabilityStats.critical > 0 
                              ? 'Critical vulnerabilities found' 
                              : vulnerabilityStats.high > 0 
                                ? 'Significant security issues' 
                                : 'Good security posture'}
                          </p>
                        </div>
                      </Card>
                      
                      <Card className="p-4 bg-card/80 border-secondary/30">
                        <div className="flex items-center space-x-2">
                          <Layers className="h-5 w-5 text-secondary" />
                          <h3 className="font-tech text-secondary">Summary</h3>
                        </div>
                        <div className="mt-2 space-y-1 text-sm">
                          <div className="grid grid-cols-2 gap-1">
                            <div className="flex items-center space-x-1 text-red-500">
                              <AlertCircle className="h-3 w-3" />
                              <span>Critical:</span>
                              <span className="font-bold">{vulnerabilityStats.critical}</span>
                            </div>
                            <div className="flex items-center space-x-1 text-orange-500">
                              <AlertCircle className="h-3 w-3" />
                              <span>High:</span>
                              <span className="font-bold">{vulnerabilityStats.high}</span>
                            </div>
                            <div className="flex items-center space-x-1 text-yellow-500">
                              <AlertCircle className="h-3 w-3" />
                              <span>Medium:</span>
                              <span className="font-bold">{vulnerabilityStats.medium}</span>
                            </div>
                            <div className="flex items-center space-x-1 text-blue-500">
                              <Shield className="h-3 w-3" />
                              <span>Low:</span>
                              <span className="font-bold">{vulnerabilityStats.low}</span>
                            </div>
                          </div>
                          <p className="text-muted-foreground mt-1">
                            Total issues: {vulnerabilityStats.critical + vulnerabilityStats.high + vulnerabilityStats.medium + vulnerabilityStats.low}
                          </p>
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
                    <h3 className="font-tech text-secondary mb-4">Vulnerability Summary</h3>
                    
                    <div className="space-y-4">
                      {['critical', 'high', 'medium', 'low', 'info'].map((level) => {
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