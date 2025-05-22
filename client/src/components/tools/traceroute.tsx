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
import { Badge } from '@/components/ui/badge';
import {
  AlertCircle,
  Play,
  RotateCw,
  Database,
  Network,
  LocateFixed,
  Router,
  Globe,
  Server
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';

interface HopResult {
  hopNumber: number;
  ip: string;
  hostname?: string;
  rtt1?: number;
  rtt2?: number;
  rtt3?: number;
  avgRtt?: number;
  packetLoss?: number;
  asn?: string;
  isp?: string;
  location?: string;
}

interface TracerouteResult {
  target: string;
  hops: HopResult[];
  totalHops: number;
  reachedTarget: boolean;
  executionTime: number;
}

interface TracerouteProps {
  onScanComplete?: (results: any) => void;
}

// Mocked user ID for demo
const MOCK_USER_ID = 1;

export default function Traceroute({ onScanComplete }: TracerouteProps) {
  const [target, setTarget] = useState('');
  const [maxHops, setMaxHops] = useState(30);
  const [timeout, setTimeout] = useState(2000);
  const [protocol, setProtocol] = useState<'icmp' | 'udp' | 'tcp'>('icmp');
  const [resolve, setResolve] = useState(true);
  const [geoInfo, setGeoInfo] = useState(true);
  const [isTracing, setIsTracing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [results, setResults] = useState<TracerouteResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [activityLog, setActivityLog] = useState<{
    message: string;
    timestamp: Date;
    type: 'info' | 'success' | 'warning' | 'error' | 'progress';
  }[]>([]);
  
  const { isConnected, sendMessage, lastMessage } = useWebSocket();
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  useEffect(() => {
    if (!lastMessage) return;
    
    switch (lastMessage.type) {
      case 'connected':
        addInfoLine(`Tool server connection established`);
        break;
        
      case 'trace_start':
        addCommandLine(`traceroute ${target} --max-hops ${maxHops} --protocol ${protocol}`);
        addInfoLine(`Starting traceroute to ${target}...`);
        setIsTracing(true);
        setResults(null);
        setError(null);
        
        // Clear previous activity log and add initial entry
        setActivityLog([{
          message: `Traceroute started to ${target}`,
          timestamp: new Date(),
          type: 'info'
        }]);
        break;
        
      case 'trace_hop':
        const hopData = lastMessage.data;
        const { hopNumber, ip, hostname, avgRtt } = hopData;
        
        // Add to activity log
        setActivityLog(prev => {
          const message = hostname 
            ? `Hop ${hopNumber}: ${ip} (${hostname}) - ${avgRtt ? `${avgRtt}ms` : 'timeout'}`
            : `Hop ${hopNumber}: ${ip} - ${avgRtt ? `${avgRtt}ms` : 'timeout'}`;
            
          const newLog = {
            message,
            timestamp: new Date(),
            type: avgRtt ? 'success' : 'warning' as any
          };
          
          // Keep log manageable (latest 100 entries)
          const updatedLog = [newLog, ...prev].slice(0, 100);
          return updatedLog;
        });
        
        // Log hop to terminal
        addLine(
          `Hop ${hopNumber}: ${ip}${hostname ? ` (${hostname})` : ''} - ${avgRtt ? `${avgRtt}ms` : '* * *'}`,
          avgRtt ? "info" : "warning"
        );
        break;
        
      case 'trace_results':
        setResults(lastMessage.data);
        break;
        
      case 'trace_complete':
        setIsTracing(false);
        addSystemLine(`Traceroute complete`);
        
        // Add final log entry
        setActivityLog(prev => [{
          message: `Traceroute completed in ${lastMessage.data.executionTime}ms`,
          timestamp: new Date(),
          type: 'info'
        }, ...prev]);
        
        // Save results to database if option is checked
        if (saveToDatabase && results) {
          saveTraceResults(results);
        }
        
        if (onScanComplete && results) {
          onScanComplete(results);
        }
        break;
        
      case 'error':
        setIsTracing(false);
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
  }, [lastMessage, addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine, target, maxHops, protocol, results, onScanComplete, saveToDatabase]);
  
  // Save trace results to database
  const saveTraceResults = async (traceResults: TracerouteResult) => {
    try {
      setIsSaving(true);
      addInfoLine(`Saving traceroute results to database...`);
      
      // Prepare data for API
      const scanData = {
        userId: MOCK_USER_ID,
        toolId: 'traceroute',
        target: target,
        results: traceResults,
        status: 'completed',
        duration: `${Math.round(traceResults.executionTime / 1000)}s`
      };
      
      // Save to database through API
      const response = await apiMutation('POST', '/api/scan/traceroute', {
        ...scanData,
        maxHops,
        timeout,
        protocol,
        resolve,
        geoInfo
      });
      
      if (response.success) {
        addLine(`[SUCCESS] Traceroute results saved to database with ID: ${response.scanId || 'unknown'}`, "success");
        toast({
          title: "Results Saved",
          description: "Traceroute results have been stored in the database",
          variant: "default"
        });
      } else {
        throw new Error(response.message || 'Failed to save traceroute results');
      }
    } catch (error) {
      addErrorLine(`Failed to save results: ${(error as Error).message}`);
      toast({
        title: "Save Failed",
        description: "Could not save results to database",
        variant: "destructive"
      });
    } finally {
      setIsSaving(false);
    }
  };
  
  // Validate domain or IP address format
  const isValidTarget = (target: string): boolean => {
    // Check if it's an IP address
    const ipPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    // Check if it's a domain name
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    
    return ipPattern.test(target) || domainPattern.test(target);
  };
  
  // Handle form submission
  const handleTrace = () => {
    if (!target) {
      setError('Target host is required');
      addErrorLine('Target host is required');
      return;
    }
    
    if (!isValidTarget(target)) {
      setError('Invalid target format. Please enter a valid IP address or domain name');
      addErrorLine('Invalid target format. Please enter a valid IP address or domain name');
      return;
    }
    
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }
    
    // Send traceroute request via WebSocket
    const success = sendMessage('traceroute', {
      target,
      maxHops,
      timeout,
      protocol,
      resolve,
      geoInfo
    });
    
    if (success) {
      setIsTracing(true);
    }
  };
  
  const handleReset = () => {
    setTarget('');
    setMaxHops(30);
    setTimeout(2000);
    setProtocol('icmp');
    setResolve(true);
    setGeoInfo(true);
    setResults(null);
    setError(null);
    setActivityLog([]);
    addInfoLine('Traceroute tool reset');
  };
  
  // Get color for RTT visualization
  const getRttColor = (rtt?: number): string => {
    if (!rtt) return 'bg-gray-300 dark:bg-gray-700';
    if (rtt < 20) return 'bg-green-500';
    if (rtt < 100) return 'bg-yellow-500';
    if (rtt < 200) return 'bg-orange-500';
    return 'bg-red-500';
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Router className="h-5 w-5" />
          Traceroute
        </h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target" className="text-sm font-tech">Target Host/IP</Label>
            <Input
              id="target"
              placeholder="example.com or 8.8.8.8"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-mono bg-background border-secondary/50"
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="protocol" className="text-sm font-tech">Protocol</Label>
              <Select value={protocol} onValueChange={(value: 'icmp' | 'udp' | 'tcp') => setProtocol(value)}>
                <SelectTrigger className="font-mono bg-background border-secondary/50">
                  <SelectValue placeholder="Select protocol" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="icmp">ICMP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="max-hops" className="text-sm font-tech">
                Max Hops: {maxHops}
              </Label>
              <Slider
                id="max-hops"
                min={1}
                max={64}
                step={1}
                value={[maxHops]}
                onValueChange={(value) => setMaxHops(value[0])}
                className="my-2"
              />
            </div>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="timeout" className="text-sm font-tech">
              Timeout: {timeout}ms
            </Label>
            <Slider
              id="timeout"
              min={500}
              max={5000}
              step={100}
              value={[timeout]}
              onValueChange={(value) => setTimeout(value[0])}
              className="my-2"
            />
          </div>
          
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="resolve-hostnames" 
                checked={resolve} 
                onCheckedChange={(checked) => setResolve(!!checked)}
              />
              <Label 
                htmlFor="resolve-hostnames" 
                className="text-sm font-tech cursor-pointer"
              >
                Resolve hostnames
              </Label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="geo-info" 
                checked={geoInfo} 
                onCheckedChange={(checked) => setGeoInfo(!!checked)}
              />
              <Label 
                htmlFor="geo-info" 
                className="text-sm font-tech cursor-pointer"
              >
                Include geo information
              </Label>
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
                Save to database
              </Label>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleTrace}
              disabled={isTracing || !target || isSaving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Play className="h-4 w-4 mr-2" />
              {isTracing ? 'Tracing...' : 'Start Trace'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isTracing || isSaving}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Trace Progress Section */}
      {isTracing && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-primary flex items-center">
              <LocateFixed className="h-4 w-4 mr-2" />
              Trace Progress
            </h3>
            <Badge variant="outline" className="bg-primary/10 text-primary">Live</Badge>
          </div>
          
          <div className="border border-border rounded-md">
            <div className="bg-muted p-2 flex justify-between items-center font-tech text-xs border-b border-border">
              <div>Activity Log</div>
              <div className="flex items-center">
                <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse mr-2"></div>
                <span>Tracing in progress</span>
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
                  No activity yet. Waiting for trace to start...
                </div>
              )}
            </div>
          </div>
        </Card>
      )}
      
      {/* Trace Results Section */}
      {results && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Globe className="h-4 w-4 mr-2" />
              Traceroute Results
            </h3>
            <div className="flex items-center gap-2">
              {saveToDatabase && (
                <div className="text-xs font-mono text-green-500 flex items-center">
                  <Database className="h-3 w-3 mr-1" />
                  {isSaving ? 'Saving to database...' : 'Results saved'}
                </div>
              )}
              <Badge variant="outline" className="bg-primary/5 text-xs">
                Completed in {(results.executionTime / 1000).toFixed(2)}s
              </Badge>
            </div>
          </div>
          
          <div className="flex flex-col">
            <div className="bg-background p-3 rounded-md border border-secondary/30 mb-4">
              <div className="flex items-center">
                <Server className="h-4 w-4 mr-2 text-primary" />
                <span className="font-tech text-sm">Target: </span>
                <span className="font-mono ml-2 text-primary">{results.target}</span>
              </div>
              <div className="flex items-center mt-2">
                <LocateFixed className="h-4 w-4 mr-2 text-secondary" />
                <span className="font-tech text-sm">Status: </span>
                <span className={cn(
                  "font-mono ml-2",
                  results.reachedTarget ? "text-green-500" : "text-red-500"
                )}>
                  {results.reachedTarget ? 'Target reached' : 'Target unreachable'}
                </span>
              </div>
              <div className="flex items-center mt-2">
                <Router className="h-4 w-4 mr-2 text-secondary" />
                <span className="font-tech text-sm">Total hops: </span>
                <span className="font-mono ml-2">{results.totalHops}</span>
              </div>
            </div>
            
            <div className="border border-border rounded-md overflow-hidden">
              <div className="bg-muted p-2 grid grid-cols-7 gap-2 font-tech text-xs border-b border-border">
                <div>Hop</div>
                <div className="col-span-2">IP / Hostname</div>
                <div>Avg RTT</div>
                <div>Loss</div>
                <div>ASN</div>
                <div>Location</div>
              </div>
              
              <div className="max-h-96 overflow-y-auto">
                {results.hops.map((hop, index) => (
                  <div 
                    key={index}
                    className={cn(
                      "p-2 grid grid-cols-7 gap-2 font-mono text-xs",
                      index % 2 === 0 ? "bg-background" : "bg-muted"
                    )}
                  >
                    <div className="font-medium">{hop.hopNumber}</div>
                    <div className="col-span-2">
                      <div className="text-primary">{hop.ip}</div>
                      {hop.hostname && <div className="text-xs text-muted-foreground truncate">{hop.hostname}</div>}
                    </div>
                    <div className="flex items-center gap-2">
                      {hop.avgRtt ? (
                        <>
                          <div className={cn("w-2 h-2 rounded-full", getRttColor(hop.avgRtt))}></div>
                          <span>{hop.avgRtt.toFixed(2)}ms</span>
                        </>
                      ) : (
                        <span className="text-muted-foreground">* * *</span>
                      )}
                    </div>
                    <div>
                      {hop.packetLoss !== undefined ? `${hop.packetLoss}%` : 'N/A'}
                    </div>
                    <div className="text-muted-foreground">
                      {hop.asn || 'N/A'}
                    </div>
                    <div className="text-muted-foreground truncate">
                      {hop.location || 'Unknown'}
                    </div>
                  </div>
                ))}
                
                {results.hops.length === 0 && (
                  <div className="p-4 text-center text-xs font-mono text-muted-foreground">
                    No route could be traced to the target.
                  </div>
                )}
              </div>
            </div>
            
            {/* Visual traceroute path would go here */}
            <div className="mt-4 p-3 bg-background rounded-md border border-border">
              <p className="text-xs text-muted-foreground text-center">
                Network path visualization would be displayed here in the complete implementation.
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}