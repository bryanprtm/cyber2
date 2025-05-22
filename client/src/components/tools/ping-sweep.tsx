import React, { useState, useEffect, useRef } from 'react';
import { useWebSocket } from '@/hooks/use-websocket';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertCircle,
  Play,
  RotateCw,
  Database,
  Clock,
  Network,
  Radio,
  Save,
  Wifi,
  Loader2,
  Signal
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';

interface PingSweepResult {
  ip: string;
  status: 'alive' | 'dead';
  responseTime?: number;
  hostname?: string;
}

interface PingSweepSummary {
  total: number;
  alive: number;
  dead: number;
  averageResponseTime: number;
}

interface PingSweepProps {
  onScanComplete?: (results: any) => void;
}

// Mocked user ID for demo
const MOCK_USER_ID = 1;

export default function PingSweep({ onScanComplete }: PingSweepProps) {
  const [target, setTarget] = useState('');
  const [ipRange, setIpRange] = useState('');
  const [timeout, setTimeout] = useState(1000);
  const [parallel, setParallel] = useState(20);
  const [retries, setRetries] = useState(1);
  const [resolveHostnames, setResolveHostnames] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [results, setResults] = useState<PingSweepResult[]>([]);
  const [summary, setSummary] = useState<PingSweepSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [scanProgress, setScanProgress] = useState<number>(0);
  
  // Activity log for real-time updates
  const [activityLog, setActivityLog] = useState<{
    message: string;
    timestamp: Date;
    type: 'info' | 'success' | 'warning' | 'error' | 'progress';
  }[]>([]);
  
  // Scan statistics
  const [scanStats, setScanStats] = useState<{
    hostsScanned: number;
    hostsTotal: number;
    startTime: number;
    elapsedTime: string;
    estimatedTimeRemaining: string;
    rate: number;
  }>({
    hostsScanned: 0,
    hostsTotal: 0,
    startTime: 0,
    elapsedTime: "0s",
    estimatedTimeRemaining: "Calculating...",
    rate: 0
  });
  
  const { isConnected, sendMessage, lastMessage } = useWebSocket();
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
        
        // Calculate scan rate (hosts per second)
        const rate = elapsedSeconds > 0 ? Math.round(scanStats.hostsScanned / elapsedSeconds * 10) / 10 : 0;
        
        // Estimate time remaining
        let estimatedTimeRemaining = "Calculating...";
        if (rate > 0 && scanStats.hostsTotal > 0) {
          const remainingHosts = scanStats.hostsTotal - scanStats.hostsScanned;
          const remainingSeconds = Math.ceil(remainingHosts / rate);
          
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
  }, [isScanning, scanStats.startTime, scanStats.hostsScanned, scanStats.hostsTotal]);
  
  // Process incoming WebSocket messages
  useEffect(() => {
    if (!lastMessage) return;
    
    switch (lastMessage.type) {
      case 'connected':
        addInfoLine(`Tool server connection established`);
        break;
        
      case 'sweep_start':
        addCommandLine(`ping-sweep ${target || ipRange}`);
        addInfoLine(`Starting ping sweep on ${target || ipRange}...`);
        setIsScanning(true);
        setResults([]);
        setSummary(null);
        setError(null);
        setScanProgress(0);
        
        // Initialize scan statistics
        const hostsTotal = lastMessage.data.totalHosts || 0;
        setScanStats({
          hostsScanned: 0,
          hostsTotal,
          startTime: Date.now(),
          elapsedTime: "0s",
          estimatedTimeRemaining: "Calculating...",
          rate: 0
        });
        
        // Clear previous logs and add initial entry
        setActivityLog([{
          message: `Ping sweep started on ${target || ipRange}`,
          timestamp: new Date(),
          type: 'info'
        }]);
        break;
        
      case 'sweep_progress':
        // Update scan progress for individual hosts
        const progressData = lastMessage.data;
        const { completed, total, host, status, responseTime } = progressData;
        
        // Calculate percentage progress
        const progressPercent = Math.floor((completed / total) * 100);
        setScanProgress(progressPercent);
        
        // Update scan stats
        setScanStats(prev => ({
          ...prev,
          hostsScanned: completed,
          hostsTotal: total
        }));
        
        // Add to activity log for alive hosts only (to avoid log clutter)
        if (status === 'alive') {
          const message = responseTime 
            ? `Host ${host} is alive (${responseTime}ms)${progressData.hostname ? ` - ${progressData.hostname}` : ''}` 
            : `Host ${host} is alive`;
          
          setActivityLog(prev => {
            const newLog = {
              message,
              timestamp: new Date(progressData.timestamp || Date.now()),
              type: 'success' as any
            };
            
            // Keep log manageable (latest 100 entries)
            const updatedLog = [newLog, ...prev].slice(0, 100);
            return updatedLog;
          });
          
          // Log alive hosts to terminal
          addLine(message, "success");
        }
        
        break;
        
      case 'sweep_batch_progress':
        // Update overall scan progress from batch updates
        const batchData = lastMessage.data;
        const batchCompleted = batchData.completed;
        const batchTotal = batchData.total;
        
        // Calculate percentage progress
        const batchProgress = Math.floor((batchCompleted / batchTotal) * 100);
        setScanProgress(batchProgress);
        
        // Calculate elapsed time, rate, and ETA
        const now = Date.now();
        const elapsedMs = now - scanStats.startTime;
        const elapsedSeconds = elapsedMs / 1000;
        const rate = elapsedSeconds > 0 ? Math.round((batchCompleted / elapsedSeconds) * 10) / 10 : 0;
        const remainingHosts = batchTotal - batchCompleted;
        const etaSeconds = rate > 0 ? remainingHosts / rate : 0;
        
        // Format times for display
        const elapsedTime = formatTime(elapsedSeconds);
        const eta = formatTime(etaSeconds);
        
        setScanStats(prev => ({
          ...prev,
          hostsScanned: batchCompleted,
          hostsTotal: batchTotal,
          elapsedTime,
          estimatedTimeRemaining: eta,
          rate
        }));
        
        // Occasionally update scan progress in terminal and log
        if (batchCompleted % Math.max(Math.floor(batchTotal / 10), 1) === 0) {
          const progressMessage = `Scan progress: ${batchProgress}% (${batchCompleted}/${batchTotal} hosts)`;
          addInfoLine(progressMessage);
          
          setActivityLog(prev => {
            const newLog = {
              message: progressMessage,
              timestamp: new Date(batchData.timestamp || Date.now()),
              type: 'progress' as any
            };
            
            // Keep log manageable
            const updatedLog = [newLog, ...prev].slice(0, 100);
            return updatedLog;
          });
        }
        break;
        
      case 'sweep_info':
        // Display informational messages
        const infoData = lastMessage.data;
        setActivityLog(prev => {
          const newLog = {
            message: infoData.message,
            timestamp: new Date(infoData.timestamp || Date.now()),
            type: 'info' as any
          };
          
          // Keep log manageable
          const updatedLog = [newLog, ...prev].slice(0, 100);
          return updatedLog;
        });
        break;
        
      case 'sweep_batch_complete':
        // Handle batch completion events
        const batchCompleteData = lastMessage.data;
        const batchIndex = batchCompleteData.batchIndex;
        const totalBatches = batchCompleteData.totalBatches;
        
        // Log batch completion
        if (batchIndex !== undefined && totalBatches !== undefined) {
          const batchMessage = `Completed batch ${batchIndex + 1} of ${totalBatches}`;
          
          setActivityLog(prev => {
            const newLog = {
              message: batchMessage,
              timestamp: new Date(batchCompleteData.timestamp || Date.now()),
              type: 'info' as any
            };
            
            // Keep log manageable
            const updatedLog = [newLog, ...prev].slice(0, 100);
            return updatedLog;
          });
        }
        break;
        
      case 'sweep_results':
        setResults(lastMessage.data.results);
        setSummary(lastMessage.data.summary);
        break;
        
      case 'sweep_complete':
        setIsScanning(false);
        addSystemLine(`Ping sweep complete`);
        
        // Add final log entry
        setActivityLog(prev => [{
          message: `Sweep completed in ${scanStats.elapsedTime}`,
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
  }, [lastMessage, addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine, target, ipRange, results, onScanComplete, saveToDatabase, scanStats.elapsedTime]);
  
  // Save scan results to database
  const saveScanResults = async (sweepResults: PingSweepResult[], sweepSummary: PingSweepSummary) => {
    try {
      setIsSaving(true);
      addInfoLine(`Saving scan results to database...`);
      
      // Calculate scan duration from stats
      const scanDuration = scanStats.elapsedTime || "0s";
      
      // Prepare data for API
      const scanData = {
        userId: MOCK_USER_ID,
        toolId: 'ping-sweep',
        target: target || ipRange,
        results: sweepResults,
        status: 'completed',
        duration: scanDuration
      };
      
      // Save to database through API
      const response = await apiMutation('POST', '/api/scan/ping-sweep', {
        ...scanData,
        timeout,
        parallel,
        retries,
        resolveHostnames
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
  
  // Parse IP ranges for validation
  const parseIpRanges = (input: string): string[] => {
    try {
      const ips: string[] = [];
      
      // Handle CIDR notation (e.g., 192.168.0.0/24)
      if (input.includes('/')) {
        // For demo purposes, we'll just verify format
        const [baseIp, cidr] = input.split('/');
        const cidrNum = parseInt(cidr);
        
        if (isValidIP(baseIp) && cidrNum >= 0 && cidrNum <= 32) {
          return [input]; // Return as is for backend processing
        }
      }
      
      // Handle IP range with dash (e.g., 192.168.0.1-192.168.0.254)
      if (input.includes('-')) {
        const [startIp, endIp] = input.split('-');
        if (isValidIP(startIp) && isValidIP(endIp)) {
          return [input]; // Return as is for backend processing
        }
      }
      
      // Handle IP with wildcards (e.g., 192.168.0.*)
      if (input.includes('*')) {
        const parts = input.split('.');
        if (parts.length === 4 && parts.filter(p => p === '*').length <= 1) {
          if (parts.every(p => p === '*' || (parseInt(p) >= 0 && parseInt(p) <= 255))) {
            return [input]; // Return as is for backend processing
          }
        }
      }
      
      // Handle single IP
      if (isValidIP(input)) {
        return [input];
      }
      
      // Handle comma-separated IPs
      if (input.includes(',')) {
        const ips = input.split(',').map(ip => ip.trim());
        if (ips.every(ip => isValidIP(ip))) {
          return ips;
        }
      }
      
      throw new Error('Invalid IP address or range format');
    } catch (error) {
      return [];
    }
  };
  
  // Validate IP address format
  const isValidIP = (ip: string): boolean => {
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return pattern.test(ip);
  };
  
  // Handle form submission
  const handleScan = () => {
    // Determine which tab is active and get the input from the right field
    const targetInput = target || ipRange;
    
    if (!targetInput) {
      setError('Target IP or IP range is required');
      addErrorLine('Target IP or IP range is required');
      return;
    }
    
    // Using a simpler validation approach to make it more robust
    if (!isValidIP(targetInput) && !targetInput.includes('/') && !targetInput.includes('-') && !targetInput.includes('*')) {
      setError('Invalid IP address or range format');
      addErrorLine('Invalid IP address or range format. Try examples like: 192.168.0.1, 192.168.0.1-254, 192.168.0.0/24');
      return;
    }
    
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }

    // Start animation immediately to indicate activity
    setIsScanning(true);
    setScanProgress(0);
    setResults([]);
    setSummary(null);
    setError(null);
    
    // Initialize scan statistics preemptively
    setScanStats({
      hostsScanned: 0,
      hostsTotal: 1, // Will be updated when we get real data
      startTime: Date.now(),
      elapsedTime: "0s",
      estimatedTimeRemaining: "Calculating...",
      rate: 0
    });
    
    // Add initial log entry
    setActivityLog([{
      message: `Starting ping sweep on ${targetInput}...`,
      timestamp: new Date(),
      type: 'info'
    }]);
    
    // Send scan request via WebSocket
    const success = sendMessage('ping_sweep', {
      target: targetInput,
      timeout,
      parallel,
      retries,
      resolveHostnames
    });
    
    if (!success) {
      setIsScanning(false);
      setError('Failed to send ping sweep request. Please try again.');
      addErrorLine('Failed to send ping sweep request. Please try again.');
    }
  };
  
  const handleReset = () => {
    setTarget('');
    setIpRange('');
    setTimeout(1000);
    setParallel(20);
    setRetries(1);
    setResolveHostnames(true);
    setResults([]);
    setSummary(null);
    setError(null);
    setScanProgress(0);
    setActivityLog([]);
    addInfoLine('Ping sweep tool reset');
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Wifi className="h-5 w-5" />
          Ping Sweep
        </h2>
        
        <div className="space-y-4">
          <Tabs defaultValue="single" className="w-full">
            <TabsList>
              <TabsTrigger value="single">Single Target</TabsTrigger>
              <TabsTrigger value="range">IP Range</TabsTrigger>
            </TabsList>
            
            <TabsContent value="single" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target" className="text-sm font-tech">Target IP</Label>
                <Input
                  id="target"
                  placeholder="192.168.0.1"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
              </div>
            </TabsContent>
            
            <TabsContent value="range" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="ip-range" className="text-sm font-tech">IP Range</Label>
                <Input
                  id="ip-range"
                  placeholder="192.168.0.1-254 or 192.168.0.0/24"
                  value={ipRange}
                  onChange={(e) => setIpRange(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
                <p className="text-xs text-muted-foreground">
                  Supports CIDR (192.168.0.0/24), ranges (192.168.0.1-192.168.0.254), and wildcards (192.168.0.*)
                </p>
              </div>
            </TabsContent>
          </Tabs>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="timeout" className="text-sm font-tech">
                Timeout: {timeout}ms
              </Label>
              <Slider
                id="timeout"
                min={200}
                max={5000}
                step={100}
                value={[timeout]}
                onValueChange={(value) => setTimeout(value[0])}
                className="my-2"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="parallel" className="text-sm font-tech">
                Parallel Scans: {parallel}
              </Label>
              <Slider
                id="parallel"
                min={1}
                max={50}
                step={1}
                value={[parallel]}
                onValueChange={(value) => setParallel(value[0])}
                className="my-2"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="retries" className="text-sm font-tech">
                Retries: {retries}
              </Label>
              <Slider
                id="retries"
                min={0}
                max={5}
                step={1}
                value={[retries]}
                onValueChange={(value) => setRetries(value[0])}
                className="my-2"
              />
            </div>
            
            <div className="flex items-center space-x-2 pt-6">
              <Checkbox 
                id="resolve-hostnames" 
                checked={resolveHostnames} 
                onCheckedChange={(checked) => setResolveHostnames(!!checked)}
              />
              <Label 
                htmlFor="resolve-hostnames" 
                className="text-sm font-tech cursor-pointer"
              >
                Resolve hostnames (DNS)
              </Label>
            </div>
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
              disabled={isScanning || (!target && !ipRange) || isSaving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Play className="h-4 w-4 mr-2" />
              {isScanning ? 'Scanning...' : 'Start Sweep'}
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
          </div>
        </div>
      </Card>
      
      {/* Scan Progress Section */}
      {isScanning && (
        <Card className="p-4 border-primary/30 bg-card relative">
          {/* Animated scanning pulse overlay */}
          <div className="absolute inset-0 bg-primary/5 border border-primary/30 rounded-lg overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/10 to-transparent -translate-x-full animate-[scanning_2s_ease-in-out_infinite]"></div>
          </div>
          
          <div className="flex justify-between items-center mb-4 relative z-10">
            <h3 className="text-lg font-tech text-primary flex items-center">
              <Signal className="h-4 w-4 mr-2 animate-pulse" />
              Sweep Progress
            </h3>
            <div className="text-xs font-mono flex items-center gap-2">
              <Badge variant="outline" className="bg-primary/10 text-primary">
                <Clock className="h-3 w-3 mr-1" />
                {scanStats.elapsedTime}
              </Badge>
              <Badge variant="outline" className="bg-secondary/10 text-secondary">
                <Radio className="h-3 w-3 mr-1 animate-ping" />
                {scanStats.rate} hosts/sec
              </Badge>
            </div>
          </div>
          
          <div className="space-y-4 relative z-10">
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="flex items-center">
                  <Loader2 className="h-3 w-3 mr-1.5 animate-spin text-primary" />
                  Scanning hosts... {scanProgress}%
                </span>
                <span className="font-bold text-primary">{scanStats.hostsScanned} / {scanStats.hostsTotal} hosts</span>
              </div>
              <div className="relative h-2 w-full bg-muted rounded-full overflow-hidden">
                <div 
                  className="absolute top-0 left-0 h-full bg-gradient-to-r from-primary to-secondary rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                ></div>
                <div className="absolute top-0 left-0 h-full w-full bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full animate-[scanning_1.5s_ease-in-out_infinite]"></div>
              </div>
              <div className="flex justify-between text-xs font-mono text-muted-foreground">
                <span>ETA: {scanStats.estimatedTimeRemaining}</span>
                <span>Target: <span className="text-primary">{target || ipRange}</span></span>
              </div>
            </div>
            
            <div className="border border-border rounded-md bg-card/80">
              <div className="bg-muted p-2 flex justify-between items-center font-tech text-xs border-b border-border">
                <div className="flex items-center">
                  <Network className="h-3.5 w-3.5 mr-1.5 text-primary" />
                  Activity Log
                </div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-green-500 animate-[pulse_1s_ease-in-out_infinite] mr-2"></div>
                  <span>Live</span>
                </div>
              </div>
              
              <div className="max-h-48 overflow-y-auto p-2 space-y-1 bg-black/30 overflow-x-hidden">
                {activityLog.map((entry, index) => (
                  <div 
                    key={index} 
                    className={cn(
                      "text-xs font-mono flex items-start p-1 rounded",
                      "animate-[fadeIn_0.3s_ease-out]",
                      entry.type === 'success' && "text-green-400 border-l-2 border-green-500 pl-2",
                      entry.type === 'error' && "text-red-400 border-l-2 border-red-500 pl-2",
                      entry.type === 'warning' && "text-yellow-400 border-l-2 border-yellow-500 pl-2",
                      entry.type === 'info' && "text-blue-400 border-l-2 border-blue-500 pl-2",
                      entry.type === 'progress' && "text-muted-foreground"
                    )}
                  >
                    <span className="opacity-70 mr-2 flex-shrink-0 text-xs">
                      {entry.timestamp.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'})}
                    </span>
                    <span>{entry.message}</span>
                  </div>
                ))}
                {activityLog.length === 0 && (
                  <div className="text-xs font-mono text-muted-foreground p-2 flex items-center justify-center">
                    <Loader2 className="h-3 w-3 mr-2 animate-spin" />
                    Initializing scan, please wait...
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
            <h3 className="text-lg font-tech text-secondary">Sweep Results</h3>
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
              <div className="text-2xl font-tech text-primary">{summary.alive}</div>
              <div className="text-xs font-mono text-muted-foreground">Alive Hosts</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-secondary/30 text-center">
              <div className="text-2xl font-tech text-secondary">{summary.dead}</div>
              <div className="text-xs font-mono text-muted-foreground">Dead Hosts</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-accent/30 text-center">
              <div className="text-2xl font-tech text-accent">{Math.round(summary.averageResponseTime)}ms</div>
              <div className="text-xs font-mono text-muted-foreground">Avg Response</div>
            </div>
            
            <div className="bg-background p-3 rounded-md border border-border text-center">
              <div className="text-2xl font-tech">{summary.total}</div>
              <div className="text-xs font-mono text-muted-foreground">Total Hosts</div>
            </div>
          </div>
          
          <div className="border border-border rounded-md overflow-hidden">
            <div className="bg-muted p-2 grid grid-cols-4 gap-4 font-tech text-xs border-b border-border">
              <div>IP Address</div>
              <div>Status</div>
              <div>Response Time</div>
              <div>Hostname</div>
            </div>
            
            <div className="max-h-64 overflow-y-auto">
              {results
                .filter(result => result.status === 'alive')
                .map((result, index) => (
                  <div 
                    key={index}
                    className={cn(
                      "p-2 grid grid-cols-4 gap-4 font-mono text-xs",
                      index % 2 === 0 ? "bg-background" : "bg-muted"
                    )}
                  >
                    <div className="text-primary">{result.ip}</div>
                    <div className="text-green-500">
                      {result.status === 'alive' ? 'Online' : 'Offline'}
                    </div>
                    <div>{result.responseTime ? `${result.responseTime}ms` : 'N/A'}</div>
                    <div className="text-muted-foreground">
                      {result.hostname || 'Not resolved'}
                    </div>
                  </div>
                ))}
                
              {results.filter(result => result.status === 'alive').length === 0 && (
                <div className="p-4 text-center text-xs font-mono text-muted-foreground">
                  No alive hosts detected. Network may be offline or blocking ICMP packets.
                </div>
              )}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}