import React, { useState, useEffect } from 'react';
import { useWebSocket } from '@/hooks/use-websocket';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  AlertCircle, 
  Play, 
  RotateCw, 
  Save, 
  Database,
  Clock,
  Zap,
  Activity,
  BarChart
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';

interface PortScanResult {
  port: number;
  status: 'open' | 'closed' | 'filtered';
  service?: string;
}

interface PortScanSummary {
  open: number;
  closed: number;
  filtered: number;
  total: number;
  openServices: string[];
}

interface PortScannerProps {
  onScanComplete?: (results: any) => void;
}

// Mocked user ID for demo - would be replaced with actual user auth
const MOCK_USER_ID = 1;

export default function PortScanner({ onScanComplete }: PortScannerProps) {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('1-1000');
  const [timeout, setTimeout] = useState(2000);
  const [concurrent, setConcurrent] = useState(50);
  const [scanMode, setScanMode] = useState('range');
  const [isScanning, setIsScanning] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [results, setResults] = useState<PortScanResult[]>([]);
  const [summary, setSummary] = useState<PortScanSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanStats, setScanStats] = useState<{
    portsScanned: number;
    portsTotal: number;
    startTime: number;
    elapsedTime: string;
    estimatedTimeRemaining: string;
    rate: number;
  }>({
    portsScanned: 0,
    portsTotal: 0,
    startTime: 0,
    elapsedTime: "0s",
    estimatedTimeRemaining: "Calculating...",
    rate: 0
  });
  const [activityLog, setActivityLog] = useState<{
    message: string;
    timestamp: Date;
    type: 'info' | 'success' | 'warning' | 'error' | 'progress';
  }[]>([]);
  
  const { isConnected, sendMessage, messageHistory, lastMessage, clearMessages } = useWebSocket();
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Update scan statistics and timer
  useEffect(() => {
    let timer: NodeJS.Timeout;
    
    if (isScanning && scanStats.startTime > 0) {
      timer = setInterval(() => {
        const now = Date.now();
        const elapsedMs = now - scanStats.startTime;
        const elapsedSeconds = Math.floor(elapsedMs / 1000);
        
        // Format elapsed time
        const minutes = Math.floor(elapsedSeconds / 60);
        const seconds = elapsedSeconds % 60;
        const elapsedTime = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
        
        // Calculate scan rate (ports per second)
        const rate = elapsedSeconds > 0 ? Math.round(scanStats.portsScanned / elapsedSeconds) : 0;
        
        // Estimate time remaining
        let estimatedTimeRemaining = "Calculating...";
        if (rate > 0 && scanStats.portsTotal > 0) {
          const remainingPorts = scanStats.portsTotal - scanStats.portsScanned;
          const remainingSeconds = Math.ceil(remainingPorts / rate);
          
          if (remainingSeconds > 60) {
            const mins = Math.floor(remainingSeconds / 60);
            const secs = remainingSeconds % 60;
            estimatedTimeRemaining = `~${mins}m ${secs}s`;
          } else {
            estimatedTimeRemaining = `~${remainingSeconds}s`;
          }
        }
        
        setScanStats(prev => ({
          ...prev,
          elapsedTime,
          estimatedTimeRemaining,
          rate
        }));
      }, 1000);
    }
    
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isScanning, scanStats.startTime, scanStats.portsScanned, scanStats.portsTotal]);

  // Process incoming WebSocket messages
  useEffect(() => {
    if (!lastMessage) return;
    
    switch (lastMessage.type) {
      case 'connected':
        addInfoLine(`Tool server connection established`);
        break;
        
      case 'scan_start':
        addCommandLine(`port-scan ${target} ${ports}`);
        addInfoLine(`Starting port scan on ${target}...`);
        setIsScanning(true);
        setResults([]);
        setSummary(null);
        setError(null);
        setScanProgress(0);
        
        // Initialize scan statistics
        const portsTotal = lastMessage.data.totalPorts || 0;
        setScanStats({
          portsScanned: 0,
          portsTotal,
          startTime: Date.now(),
          elapsedTime: "0s",
          estimatedTimeRemaining: "Calculating...",
          rate: 0
        });
        
        // Clear previous activity log and add initial entry
        setActivityLog([{
          message: `Scan started on ${target} (${ports})`,
          timestamp: new Date(),
          type: 'info'
        }]);
        break;
        
      case 'scan_progress':
        // Update scan progress
        const progressData = lastMessage.data;
        const { completed, total, port, status } = progressData;
        
        // Calculate percentage progress
        const progressPercent = Math.floor((completed / total) * 100);
        setScanProgress(progressPercent);
        
        // Update scan stats
        setScanStats(prev => ({
          ...prev,
          portsScanned: completed,
          portsTotal: total
        }));
        
        // Add to activity log (but not for every port to avoid flooding)
        if (status === 'open' || (completed % Math.max(Math.floor(total / 50), 1) === 0)) {
          setActivityLog(prev => {
            const newLog = {
              message: status === 'open' 
                ? `Found open port: ${port}${progressData.service ? ` (${progressData.service})` : ''}` 
                : `Scanned ${completed}/${total} ports (${progressPercent}%)`,
              timestamp: new Date(),
              type: status === 'open' ? 'success' : 'progress' as any
            };
            
            // Keep log size manageable (latest 100 entries)
            const updatedLog = [newLog, ...prev].slice(0, 100);
            return updatedLog;
          });
          
          // Log open ports to terminal for visibility
          if (status === 'open') {
            addLine(`Found open port: ${port}${progressData.service ? ` (${progressData.service})` : ''}`, "success");
          }
          
          // Occasionally update scan progress in terminal
          if (completed % Math.max(Math.floor(total / 10), 1) === 0) {
            addInfoLine(`Scan progress: ${progressPercent}% (${completed}/${total} ports)`);
          }
        }
        break;
        
      case 'scan_results':
        setResults(lastMessage.data.results);
        setSummary(lastMessage.data.summary);
        break;
        
      case 'scan_complete':
        setIsScanning(false);
        addSystemLine(`Port scan complete`);
        
        // Add final log entry
        setActivityLog(prev => [{
          message: `Scan completed in ${scanStats.elapsedTime}`,
          timestamp: new Date(),
          type: 'info'
        }, ...prev]);
        
        // Save results to database if option is checked
        if (saveToDatabase) {
          saveScanResults(lastMessage.data.results, lastMessage.data.summary);
        }
        
        if (onScanComplete) {
          onScanComplete(results);
        }
        break;
        
      case 'error':
        setIsScanning(false);
        setError(lastMessage.data.message);
        addErrorLine(lastMessage.data.message);
        
        // Add to activity log
        setActivityLog(prev => [{
          message: `Error: ${lastMessage.data.message}`,
          timestamp: new Date(),
          type: 'error'
        }, ...prev]);
        break;
    }
  }, [lastMessage, addSystemLine, addInfoLine, addErrorLine, addCommandLine, target, ports, onScanComplete, results, saveToDatabase]);
  
  // Save scan results to database
  const saveScanResults = async (scanResults: PortScanResult[], scanSummary: PortScanSummary) => {
    try {
      setIsSaving(true);
      addInfoLine(`Saving scan results to database...`);
      
      // Calculate scan duration from results timestamps (in a real app)
      const scanDuration = ((Math.random() * 5) + 1).toFixed(2); // Mock for demo
      
      // Prepare data for API
      const scanData = {
        userId: MOCK_USER_ID,
        toolId: 'port-scanner',
        target: target,
        results: scanResults,
        status: 'completed',
        duration: scanDuration
      };
      
      // Save to database through our API
      const response = await apiMutation('POST', '/api/scan/port', {
        ...scanData,
        ports,
        timeout,
        concurrent
      });
      
      if (response.success) {
        addLine(`[SUCCESS] Scan results saved to database with ID: ${response.scanId || 'unknown'}`, "success");
        toast({
          title: "Scan Saved",
          description: "Results have been stored in the database",
          variant: "default"
        });
      } else {
        throw new Error(response.message || 'Failed to save scan results');
      }
    } catch (error) {
      addErrorLine(`Failed to save scan results: ${(error as Error).message}`);
      toast({
        title: "Save Failed",
        description: "Could not save results to database",
        variant: "destructive"
      });
    } finally {
      setIsSaving(false);
    }
  };
  
  // Handle form submission
  const handleScan = () => {
    if (!target) {
      setError('Target is required');
      addErrorLine('Target is required');
      return;
    }
    
    if (!ports) {
      setError('Port range is required');
      addErrorLine('Port range is required');
      return;
    }
    
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }
    
    // Send scan request via WebSocket
    const success = sendMessage('port_scan', {
      target,
      ports,
      timeout,
      concurrent
    });
    
    if (success) {
      setIsScanning(true);
    }
  };
  
  const handleViewHistory = () => {
    // Using window.location for simple navigation
    window.location.pathname = '/scan-history';
  };
  
  const handleReset = () => {
    setTarget('');
    setPorts('1-1000');
    setTimeout(2000);
    setConcurrent(50);
    setScanMode('range');
    setResults([]);
    setSummary(null);
    setError(null);
    clearMessages();
    addInfoLine('Port scanner reset');
  };
  
  // Handle scan mode change
  const handleScanModeChange = (value: string) => {
    setScanMode(value);
    
    // Set default port values based on mode
    switch (value) {
      case 'range':
        setPorts('1-1000');
        break;
      case 'common':
        setPorts('21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443');
        break;
      case 'all':
        setPorts('1-65535');
        break;
      case 'custom':
        // Keep current value
        break;
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Port Scanner</h2>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="target" className="text-sm font-tech">Target Host/IP</Label>
              <Input
                id="target"
                placeholder="example.com or 192.168.1.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="font-mono bg-background border-secondary/50"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="scan-mode" className="text-sm font-tech">Scan Mode</Label>
              <Select value={scanMode} onValueChange={handleScanModeChange}>
                <SelectTrigger className="font-mono bg-background border-secondary/50">
                  <SelectValue placeholder="Select mode" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="range">Standard (1-1000)</SelectItem>
                  <SelectItem value="common">Common Ports</SelectItem>
                  <SelectItem value="all">All Ports (1-65535)</SelectItem>
                  <SelectItem value="custom">Custom Range</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          {scanMode === 'custom' && (
            <div className="space-y-2">
              <Label htmlFor="ports" className="text-sm font-tech">
                Port Range (e.g., "80,443" or "1-1000")
              </Label>
              <Input
                id="ports"
                placeholder="80,443,8080 or 1-1000"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                className="font-mono bg-background border-secondary/50"
              />
            </div>
          )}
          
          <div className="space-y-2">
            <Label htmlFor="timeout" className="text-sm font-tech">
              Timeout: {timeout}ms
            </Label>
            <Slider
              id="timeout"
              min={500}
              max={10000}
              step={500}
              value={[timeout]}
              onValueChange={(value) => setTimeout(value[0])}
              className="my-4"
            />
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="concurrent" className="text-sm font-tech">
              Concurrent Scans: {concurrent}
            </Label>
            <Slider
              id="concurrent"
              min={10}
              max={100}
              step={10}
              value={[concurrent]}
              onValueChange={(value) => setConcurrent(value[0])}
              className="my-4"
            />
          </div>
          
          <div className="flex items-center space-x-2">
            <Checkbox 
              id="save-to-db" 
              checked={saveToDatabase} 
              onCheckedChange={(checked) => setSaveToDatabase(!!checked)} 
            />
            <Label 
              htmlFor="save-to-db" 
              className="text-sm font-tech cursor-pointer flex items-center"
            >
              <Database className="h-3 w-3 mr-1 text-primary" />
              Save results to database
            </Label>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleScan}
              disabled={isScanning || !target || isSaving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Play className="h-4 w-4 mr-2" />
              {isScanning ? 'Scanning...' : 'Start Scan'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isScanning || isSaving}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
            
            <Button
              onClick={handleViewHistory}
              variant="outline"
              className="border-primary/50 text-primary font-tech mt-auto"
            >
              <Database className="h-4 w-4 mr-2" />
              View History
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Scan Progress Section */}
      {isScanning && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-primary flex items-center">
              <Activity className="h-4 w-4 mr-2" />
              Scan Progress
            </h3>
            <div className="text-xs font-mono flex items-center gap-2">
              <Badge variant="outline" className="bg-primary/10 text-primary">
                <Clock className="h-3 w-3 mr-1" />
                {scanStats.elapsedTime}
              </Badge>
              <Badge variant="outline" className="bg-secondary/10 text-secondary">
                <Zap className="h-3 w-3 mr-1" />
                {scanStats.rate} ports/sec
              </Badge>
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Scanning ports... {scanProgress}%</span>
                <span>{scanStats.portsScanned} / {scanStats.portsTotal} ports</span>
              </div>
              <Progress value={scanProgress} className="h-2" />
              <div className="flex justify-between text-xs font-mono text-muted-foreground">
                <span>ETA: {scanStats.estimatedTimeRemaining}</span>
                <span>Target: {target}</span>
              </div>
            </div>
            
            <div className="border border-border rounded-md">
              <div className="bg-muted p-2 flex justify-between items-center font-tech text-xs border-b border-border">
                <div>Activity Log</div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse mr-2"></div>
                  <span>Live</span>
                </div>
              </div>
              
              <div className="max-h-48 overflow-y-auto p-2 space-y-1 bg-black/30">
                {activityLog.map((entry, index) => (
                  <div 
                    key={index} 
                    className={cn(
                      "text-xs font-mono flex items-start p-1 rounded",
                      entry.type === 'success' && "text-green-400",
                      entry.type === 'error' && "text-red-400",
                      entry.type === 'warning' && "text-yellow-400",
                      entry.type === 'info' && "text-blue-400",
                      entry.type === 'progress' && "text-muted-foreground"
                    )}
                  >
                    <span className="opacity-70 mr-2 flex-shrink-0">
                      {entry.timestamp.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'})}
                    </span>
                    <span>{entry.message}</span>
                  </div>
                ))}
                {activityLog.length === 0 && (
                  <div className="text-xs font-mono text-muted-foreground p-2">
                    No activity yet. Waiting for scan to start...
                  </div>
                )}
              </div>
            </div>
          </div>
        </Card>
      )}
      
      {/* Scan Results Section */}
      {results.length > 0 && summary && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <BarChart className="h-4 w-4 mr-2" />
              Scan Results
            </h3>
            <div className="flex items-center gap-2">
              {saveToDatabase && (
                <div className="text-xs font-mono text-green-500 flex items-center">
                  <Database className="h-3 w-3 mr-1" />
                  {isSaving ? 'Saving to database...' : 'Results saved'}
                </div>
              )}
              {!isScanning && scanStats.elapsedTime !== "0s" && (
                <Badge variant="outline" className="bg-primary/5 text-xs">
                  Completed in {scanStats.elapsedTime}
                </Badge>
              )}
            </div>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="bg-background p-3 rounded-md border border-primary/30 text-center">
              <div className="text-2xl font-tech text-primary">{summary.open}</div>
              <div className="text-xs font-mono text-muted-foreground">Open Ports</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-secondary/30 text-center">
              <div className="text-2xl font-tech text-secondary">{summary.closed}</div>
              <div className="text-xs font-mono text-muted-foreground">Closed Ports</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-accent/30 text-center">
              <div className="text-2xl font-tech text-accent">{summary.filtered}</div>
              <div className="text-xs font-mono text-muted-foreground">Filtered Ports</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-border text-center">
              <div className="text-2xl font-tech">{summary.total}</div>
              <div className="text-xs font-mono text-muted-foreground">Total Scanned</div>
            </div>
          </div>
          
          <div className="border border-border rounded-md overflow-hidden">
            <div className="bg-muted p-2 grid grid-cols-4 gap-4 font-tech text-xs border-b border-border">
              <div>Port</div>
              <div>Status</div>
              <div>Service</div>
              <div>Details</div>
            </div>
            
            <div className="max-h-64 overflow-y-auto">
              {results
                .filter(result => result.status === 'open')
                .map((result, index) => (
                  <div 
                    key={index}
                    className={cn(
                      "p-2 grid grid-cols-4 gap-4 font-mono text-xs",
                      index % 2 === 0 ? "bg-background" : "bg-muted"
                    )}
                  >
                    <div className="text-primary">{result.port}</div>
                    <div className={
                      result.status === 'open' 
                        ? 'text-primary' 
                        : result.status === 'filtered' 
                          ? 'text-accent' 
                          : 'text-muted-foreground'
                    }>
                      {result.status}
                    </div>
                    <div>{result.service || 'Unknown'}</div>
                    <div className="text-muted-foreground">
                      {result.service 
                        ? `${result.service} service running` 
                        : 'No service identified'}
                    </div>
                  </div>
                ))}
                
              {results.filter(result => result.status === 'open').length === 0 && (
                <div className="p-4 text-center text-xs font-mono text-muted-foreground">
                  No open ports detected. Target may be offline or firewalled.
                </div>
              )}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}