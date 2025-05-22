import React, { useState, useEffect } from 'react';
import { useWebSocket } from '@/hooks/use-websocket';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
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
  Zap,
  Activity,
  Network,
  Save,
  Pause,
  Wifi,
  Server,
  Eye,
  BarChart4,
  Filter
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';

interface Packet {
  id: number;
  timestamp: string;
  srcIP: string;
  dstIP: string;
  srcPort?: number;
  dstPort?: number;
  protocol: string;
  length: number;
  ttl?: number;
  flags?: string[];
  data?: string;
}

interface PacketSummary {
  totalPackets: number;
  totalSize: number;
  protocols: Record<string, number>;
  topSources: Array<{ ip: string; count: number }>;
  topDestinations: Array<{ ip: string; count: number }>;
  captureTime: number;
}

interface PacketAnalyzerProps {
  onCaptureComplete?: (results: any) => void;
}

// Mocked user ID for demo
const MOCK_USER_ID = 1;

export default function PacketAnalyzer({ onCaptureComplete }: PacketAnalyzerProps) {
  const [interface_, setInterface] = useState('any');
  const [filter, setFilter] = useState('');
  const [captureLimit, setCaptureLimit] = useState(100);
  const [timeLimit, setTimeLimit] = useState(30);
  const [bufferSize, setBufferSize] = useState(1024);
  const [promiscuousMode, setPromiscuousMode] = useState(true);
  const [isCapturing, setIsCapturing] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [summary, setSummary] = useState<PacketSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [interfaces, setInterfaces] = useState<string[]>(['any', 'eth0', 'wlan0']);
  const [captureProgress, setCaptureProgress] = useState<number>(0);
  const [filterTab, setFilterTab] = useState<string>('all');
  
  // Activity log for real-time updates
  const [activityLog, setActivityLog] = useState<{
    message: string;
    timestamp: Date;
    type: 'info' | 'success' | 'warning' | 'error' | 'system';
  }[]>([]);
  
  const { isConnected, sendMessage, lastMessage } = useWebSocket();
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Process incoming WebSocket messages
  useEffect(() => {
    if (!lastMessage) return;
    
    switch (lastMessage.type) {
      case 'connected':
        addInfoLine(`Tool server connection established`);
        break;
        
      case 'interfaces_list':
        setInterfaces([...lastMessage.data.interfaces]);
        addInfoLine(`Detected network interfaces: ${lastMessage.data.interfaces.join(', ')}`);
        break;
        
      case 'capture_start':
        const cmd = `packet-analyzer -i ${interface_}${filter ? ` -f "${filter}"` : ''} -c ${captureLimit}`;
        addCommandLine(cmd);
        addInfoLine(`Starting packet capture on interface ${interface_}...`);
        setIsCapturing(true);
        setPackets([]);
        setSummary(null);
        setError(null);
        setSelectedPacket(null);
        setCaptureProgress(0);
        
        // Clear previous activity log and add initial entry
        setActivityLog([{
          message: `Packet capture started on ${interface_}${filter ? ` with filter: ${filter}` : ''}`,
          timestamp: new Date(),
          type: 'info'
        }]);
        break;
        
      case 'packet_captured':
        const packet = lastMessage.data.packet as Packet;
        
        // Update packet list
        setPackets(prev => [...prev, packet]);
        
        // Update capture progress
        const progress = Math.min((packets.length / captureLimit) * 100, 100);
        setCaptureProgress(progress);
        
        // Add to activity log (but not for every packet to avoid flooding)
        if (packets.length % 10 === 0 || packets.length < 10) {
          setActivityLog(prev => {
            const newLog = {
              message: `Captured ${packets.length} packets${
                progress < 100 ? ` (${progress.toFixed(0)}%)` : ''
              }`,
              timestamp: new Date(),
              type: 'info' as any
            };
            
            // Keep log manageable (latest 100 entries)
            const updatedLog = [newLog, ...prev].slice(0, 100);
            return updatedLog;
          });
        }
        
        // Occasionally update capture progress in terminal
        if (packets.length % 50 === 0) {
          addInfoLine(`Captured ${packets.length} packets (${progress.toFixed(0)}%)`);
        }
        break;
        
      case 'capture_pause':
        setIsPaused(true);
        addInfoLine('Packet capture paused');
        
        // Add to activity log
        setActivityLog(prev => [{
          message: 'Packet capture paused',
          timestamp: new Date(),
          type: 'system'
        }, ...prev]);
        break;
        
      case 'capture_resume':
        setIsPaused(false);
        addInfoLine('Packet capture resumed');
        
        // Add to activity log
        setActivityLog(prev => [{
          message: 'Packet capture resumed',
          timestamp: new Date(),
          type: 'system'
        }, ...prev]);
        break;
        
      case 'capture_summary':
        setSummary(lastMessage.data.summary);
        break;
        
      case 'capture_complete':
        setIsCapturing(false);
        setIsPaused(false);
        addSystemLine(`Packet capture complete`);
        
        // Add final log entry
        setActivityLog(prev => [{
          message: `Capture completed with ${packets.length} packets`,
          timestamp: new Date(),
          type: 'success'
        }, ...prev]);
        
        // Save results to database if option is checked
        if (saveToDatabase && packets.length > 0) {
          saveCaptureResults(packets, lastMessage.data.summary);
        }
        
        if (onCaptureComplete) {
          onCaptureComplete({
            packets,
            summary: lastMessage.data.summary
          });
        }
        break;
        
      case 'error':
        if (isCapturing) {
          setIsCapturing(false);
          setIsPaused(false);
        }
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
  }, [lastMessage, addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine, interface_, filter, captureLimit, packets.length, onCaptureComplete, saveToDatabase]);
  
  // Save capture results to database
  const saveCaptureResults = async (capturedPackets: Packet[], packetSummary: PacketSummary) => {
    try {
      setIsSaving(true);
      addInfoLine(`Saving packet capture results to database...`);
      
      // Prepare data for API
      const captureData = {
        userId: MOCK_USER_ID,
        toolId: 'packet-analyzer',
        target: interface_,
        filter: filter || 'none',
        results: {
          packets: capturedPackets,
          summary: packetSummary
        },
        status: 'completed',
        duration: `${Math.round(packetSummary.captureTime)}s`
      };
      
      // Save to database through API
      const response = await apiMutation('POST', '/api/analysis/packet-capture', {
        ...captureData,
        captureLimit,
        timeLimit,
        promiscuousMode
      });
      
      if (response.success) {
        addLine(`[SUCCESS] Packet capture results saved to database with ID: ${response.captureId || 'unknown'}`, "success");
        toast({
          title: "Capture Saved",
          description: "Results have been stored in the database",
          variant: "default"
        });
      } else {
        throw new Error(response.message || 'Failed to save capture results');
      }
    } catch (error) {
      addErrorLine(`Failed to save capture results: ${(error as Error).message}`);
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
  const handleCapture = () => {
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }
    
    // Handle BPF filter validation
    if (filter) {
      // Simple validation for demo purposes
      if (filter.includes("&&") || filter.includes("||")) {
        if (!filter.includes("(") || !filter.includes(")")) {
          setError('Invalid BPF filter. Complex filters should use parentheses');
          addErrorLine('Invalid BPF filter format. Example: "(host 192.168.1.1) && tcp"');
          return;
        }
      }
    }
    
    // Send capture request via WebSocket
    const success = sendMessage('packet_capture', {
      interface: interface_,
      filter,
      captureLimit,
      timeLimit,
      bufferSize,
      promiscuousMode
    });
    
    if (success) {
      setIsCapturing(true);
    }
  };
  
  const handlePauseResume = () => {
    if (!isConnected || !isCapturing) return;
    
    if (isPaused) {
      // Resume capture
      sendMessage('resume_capture', {});
    } else {
      // Pause capture
      sendMessage('pause_capture', {});
    }
  };
  
  const handleStop = () => {
    if (!isConnected || !isCapturing) return;
    
    // Stop capture
    sendMessage('stop_capture', {});
    addInfoLine('Stopping packet capture...');
  };
  
  const handleReset = () => {
    setInterface('any');
    setFilter('');
    setCaptureLimit(100);
    setTimeLimit(30);
    setBufferSize(1024);
    setPromiscuousMode(true);
    setPackets([]);
    setSummary(null);
    setError(null);
    setSelectedPacket(null);
    setFilterTab('all');
    setActivityLog([]);
    addInfoLine('Packet analyzer reset');
  };
  
  // Get unique protocols for filtering
  const getUniqueProtocols = (): string[] => {
    const protocols = new Set<string>();
    packets.forEach(packet => protocols.add(packet.protocol));
    return Array.from(protocols).sort();
  };
  
  // Filter packets by protocol
  const getFilteredPackets = (): Packet[] => {
    if (filterTab === 'all') return packets;
    return packets.filter(packet => packet.protocol === filterTab);
  };
  
  // Get color for protocol
  const getProtocolColor = (protocol: string): string => {
    switch (protocol.toLowerCase()) {
      case 'tcp': return 'bg-blue-500';
      case 'udp': return 'bg-green-500';
      case 'icmp': return 'bg-yellow-500';
      case 'arp': return 'bg-purple-500';
      case 'dns': return 'bg-indigo-500';
      case 'http': return 'bg-red-500';
      case 'https': return 'bg-pink-500';
      case 'dhcp': return 'bg-orange-500';
      default: return 'bg-gray-500';
    }
  };
  
  // Format bytes to human-readable size
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${sizes[i]}`;
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Activity className="h-5 w-5" />
          Packet Analyzer
        </h2>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="interface" className="text-sm font-tech">Network Interface</Label>
              <Select value={interface_} onValueChange={setInterface}>
                <SelectTrigger className="font-mono bg-background border-secondary/50">
                  <SelectValue placeholder="Select interface" />
                </SelectTrigger>
                <SelectContent>
                  {interfaces.map((intf) => (
                    <SelectItem key={intf} value={intf}>
                      {intf}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="filter" className="text-sm font-tech">
                Capture Filter (BPF Syntax)
              </Label>
              <Input
                id="filter"
                placeholder="tcp port 80 or port 443"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="font-mono bg-background border-secondary/50"
              />
              <p className="text-xs text-muted-foreground">
                Examples: "host 192.168.1.1", "tcp port 80", "not arp", "(src 10.0.0.1) && tcp"
              </p>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="captureLimit" className="text-sm font-tech">
                Packet Limit: {captureLimit}
              </Label>
              <Slider
                id="captureLimit"
                min={10}
                max={1000}
                step={10}
                value={[captureLimit]}
                onValueChange={(value) => setCaptureLimit(value[0])}
                className="my-2"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="timeLimit" className="text-sm font-tech">
                Time Limit: {timeLimit} seconds
              </Label>
              <Slider
                id="timeLimit"
                min={5}
                max={300}
                step={5}
                value={[timeLimit]}
                onValueChange={(value) => setTimeLimit(value[0])}
                className="my-2"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="bufferSize" className="text-sm font-tech">
                Buffer Size: {bufferSize} KB
              </Label>
              <Slider
                id="bufferSize"
                min={512}
                max={8192}
                step={512}
                value={[bufferSize]}
                onValueChange={(value) => setBufferSize(value[0])}
                className="my-2"
              />
            </div>
            
            <div className="flex items-center space-x-2 pt-6">
              <Checkbox 
                id="promiscuous-mode" 
                checked={promiscuousMode} 
                onCheckedChange={(checked) => setPromiscuousMode(!!checked)}
              />
              <Label 
                htmlFor="promiscuous-mode" 
                className="text-sm font-tech cursor-pointer"
              >
                Promiscuous Mode (capture all packets)
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
              onClick={handleCapture}
              disabled={isCapturing || !interface_ || isSaving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Play className="h-4 w-4 mr-2" />
              {isCapturing ? 'Capturing...' : 'Start Capture'}
            </Button>
            
            {isCapturing && (
              <>
                <Button
                  onClick={handlePauseResume}
                  variant="outline"
                  className="border-yellow-500/50 text-yellow-500 font-tech"
                >
                  {isPaused ? (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Resume
                    </>
                  ) : (
                    <>
                      <Pause className="h-4 w-4 mr-2" />
                      Pause
                    </>
                  )}
                </Button>
                
                <Button
                  onClick={handleStop}
                  variant="outline"
                  className="border-destructive/50 text-destructive font-tech"
                >
                  <AlertCircle className="h-4 w-4 mr-2" />
                  Stop
                </Button>
              </>
            )}
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isCapturing || isSaving}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Capture Progress Section */}
      {isCapturing && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-primary flex items-center">
              <Zap className="h-4 w-4 mr-2" />
              Capture Status {isPaused && '(Paused)'}
            </h3>
            <div className="text-xs font-mono flex items-center gap-2">
              <Badge variant="outline" className="bg-primary/10 text-primary">
                <Wifi className="h-3 w-3 mr-1" />
                {interface_}
              </Badge>
              <Badge variant="outline" className="bg-secondary/10 text-secondary">
                <Activity className="h-3 w-3 mr-1" />
                {packets.length} packets
              </Badge>
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Capturing packets... {captureProgress.toFixed(0)}%</span>
                <span>{packets.length} / {captureLimit} packets</span>
              </div>
              <Progress value={captureProgress} className="h-2" />
            </div>
            
            <div className="border border-border rounded-md">
              <div className="bg-muted p-2 flex justify-between items-center font-tech text-xs border-b border-border">
                <div>Activity Log</div>
                <div className="flex items-center">
                  <div className={cn(
                    "h-2 w-2 rounded-full mr-2",
                    isPaused ? "bg-yellow-500" : "bg-green-500 animate-pulse"
                  )}></div>
                  <span>{isPaused ? 'Paused' : 'Live'}</span>
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
                      entry.type === 'system' && "text-purple-400"
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
                    No activity yet. Waiting for capture to start...
                  </div>
                )}
              </div>
            </div>
          </div>
        </Card>
      )}
      
      {/* Capture Results Section */}
      {packets.length > 0 && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Network className="h-4 w-4 mr-2" />
              Packet Analysis
            </h3>
            <div className="flex items-center gap-2">
              {saveToDatabase && (
                <div className="text-xs font-mono text-green-500 flex items-center">
                  <Database className="h-3 w-3 mr-1" />
                  {isSaving ? 'Saving to database...' : 'Results saved'}
                </div>
              )}
              {summary && (
                <Badge variant="outline" className="bg-primary/5 text-xs">
                  {summary.totalPackets} packets ({formatBytes(summary.totalSize)})
                </Badge>
              )}
            </div>
          </div>
          
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-primary/30 text-center">
                <div className="text-2xl font-tech text-primary">{summary.totalPackets}</div>
                <div className="text-xs font-mono text-muted-foreground">Total Packets</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-secondary/30 text-center">
                <div className="text-2xl font-tech text-secondary">{formatBytes(summary.totalSize)}</div>
                <div className="text-xs font-mono text-muted-foreground">Total Size</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-accent/30 text-center">
                <div className="text-2xl font-tech text-accent">
                  {Object.keys(summary.protocols).length}
                </div>
                <div className="text-xs font-mono text-muted-foreground">Protocols</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border text-center">
                <div className="text-2xl font-tech">{summary.captureTime.toFixed(2)}s</div>
                <div className="text-xs font-mono text-muted-foreground">Capture Time</div>
              </div>
            </div>
          )}
          
          <div className="space-y-4">
            <Tabs 
              defaultValue="all" 
              value={filterTab}
              onValueChange={setFilterTab}
              className="w-full"
            >
              <div className="flex items-center justify-between mb-2">
                <TabsList className="h-8">
                  <TabsTrigger value="all" className="text-xs h-8 px-3">
                    All
                  </TabsTrigger>
                  {getUniqueProtocols().map(protocol => (
                    <TabsTrigger 
                      key={protocol} 
                      value={protocol} 
                      className="text-xs h-8 px-3"
                    >
                      {protocol}
                    </TabsTrigger>
                  ))}
                </TabsList>
                
                <div className="flex items-center text-xs">
                  <Filter className="h-3 w-3 mr-1 text-muted-foreground" />
                  <span className="text-muted-foreground">
                    Showing {getFilteredPackets().length} of {packets.length} packets
                  </span>
                </div>
              </div>
              
              <div className="border border-border rounded-md overflow-hidden">
                <div className="bg-muted p-2 grid grid-cols-9 gap-2 font-tech text-xs border-b border-border">
                  <div className="col-span-1">No.</div>
                  <div className="col-span-1">Time</div>
                  <div className="col-span-1">Protocol</div>
                  <div className="col-span-2">Source</div>
                  <div className="col-span-2">Destination</div>
                  <div className="col-span-1">Length</div>
                  <div className="col-span-1">Info</div>
                </div>
                
                <div className="max-h-64 overflow-y-auto">
                  {getFilteredPackets().map((packet, index) => (
                    <div 
                      key={packet.id}
                      className={cn(
                        "p-2 grid grid-cols-9 gap-2 font-mono text-xs cursor-pointer",
                        index % 2 === 0 ? "bg-background" : "bg-muted/30",
                        selectedPacket?.id === packet.id && "bg-primary/10 border-l-2 border-primary"
                      )}
                      onClick={() => setSelectedPacket(packet)}
                    >
                      <div className="col-span-1 text-muted-foreground">{packet.id}</div>
                      <div className="col-span-1 text-muted-foreground">
                        {new Date(packet.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                          fractionalSecondDigits: 3
                        })}
                      </div>
                      <div className="col-span-1">
                        <Badge className={cn("px-1.5 py-0 text-[10px]", getProtocolColor(packet.protocol))}>
                          {packet.protocol}
                        </Badge>
                      </div>
                      <div className="col-span-2 truncate">
                        {packet.srcIP}{packet.srcPort ? `:${packet.srcPort}` : ''}
                      </div>
                      <div className="col-span-2 truncate">
                        {packet.dstIP}{packet.dstPort ? `:${packet.dstPort}` : ''}
                      </div>
                      <div className="col-span-1 text-muted-foreground">{packet.length} bytes</div>
                      <div className="col-span-1 truncate text-muted-foreground">
                        {packet.flags ? packet.flags.join(',') : 'Standard'}
                      </div>
                    </div>
                  ))}
                  
                  {getFilteredPackets().length === 0 && (
                    <div className="p-4 text-center text-xs font-mono text-muted-foreground">
                      No packets found matching the selected filter.
                    </div>
                  )}
                </div>
              </div>
            </Tabs>
            
            {/* Packet Details Section */}
            {selectedPacket && (
              <div className="border border-border rounded-md overflow-hidden mt-4">
                <div className="bg-muted p-2 font-tech text-sm border-b border-border flex justify-between">
                  <div className="flex items-center">
                    <Eye className="h-4 w-4 mr-2" />
                    Packet Details
                  </div>
                  <Badge className={cn("text-xs", getProtocolColor(selectedPacket.protocol))}>
                    {selectedPacket.protocol}
                  </Badge>
                </div>
                
                <div className="p-3 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <div className="text-xs font-tech text-muted-foreground">General</div>
                      <div className="bg-muted/20 p-2 rounded-md space-y-1">
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Packet Number:</span>
                          <span className="text-xs font-mono">{selectedPacket.id}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Time:</span>
                          <span className="text-xs font-mono">
                            {new Date(selectedPacket.timestamp).toLocaleTimeString([], {
                              hour: '2-digit', 
                              minute: '2-digit', 
                              second: '2-digit',
                              fractionalSecondDigits: 6
                            })}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Length:</span>
                          <span className="text-xs font-mono">{selectedPacket.length} bytes</span>
                        </div>
                        {selectedPacket.ttl !== undefined && (
                          <div className="flex justify-between">
                            <span className="text-xs font-mono text-muted-foreground">TTL:</span>
                            <span className="text-xs font-mono">{selectedPacket.ttl}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="text-xs font-tech text-muted-foreground">Addresses</div>
                      <div className="bg-muted/20 p-2 rounded-md space-y-1">
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Source:</span>
                          <span className="text-xs font-mono text-primary">
                            {selectedPacket.srcIP}{selectedPacket.srcPort ? `:${selectedPacket.srcPort}` : ''}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Destination:</span>
                          <span className="text-xs font-mono text-secondary">
                            {selectedPacket.dstIP}{selectedPacket.dstPort ? `:${selectedPacket.dstPort}` : ''}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-xs font-mono text-muted-foreground">Protocol:</span>
                          <span className="text-xs font-mono text-accent">{selectedPacket.protocol}</span>
                        </div>
                        {selectedPacket.flags && selectedPacket.flags.length > 0 && (
                          <div className="flex justify-between">
                            <span className="text-xs font-mono text-muted-foreground">Flags:</span>
                            <span className="text-xs font-mono">
                              {selectedPacket.flags.join(', ')}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {selectedPacket.data && (
                    <div className="space-y-2">
                      <div className="text-xs font-tech text-muted-foreground">Payload</div>
                      <div className="bg-black/20 p-3 rounded-md overflow-x-auto">
                        <pre className="text-xs font-mono">
                          {selectedPacket.data}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
            
            {/* Protocol Distribution Chart */}
            {summary && (
              <div className="border border-border rounded-md overflow-hidden mt-4">
                <div className="bg-muted p-2 font-tech text-sm border-b border-border">
                  <div className="flex items-center">
                    <BarChart4 className="h-4 w-4 mr-2" />
                    Protocol Distribution
                  </div>
                </div>
                
                <div className="p-3">
                  <div className="h-6 w-full flex rounded-full overflow-hidden">
                    {Object.entries(summary.protocols).map(([protocol, count], i) => {
                      const percentage = (count / summary.totalPackets) * 100;
                      return (
                        <div 
                          key={protocol}
                          className={cn(
                            "h-full flex items-center justify-center text-[9px] font-mono text-white",
                            getProtocolColor(protocol)
                          )}
                          style={{ width: `${percentage}%` }}
                          title={`${protocol}: ${count} packets (${percentage.toFixed(1)}%)`}
                        >
                          {percentage > 5 ? `${protocol}` : ''}
                        </div>
                      );
                    })}
                  </div>
                  
                  <div className="mt-2 flex flex-wrap gap-2">
                    {Object.entries(summary.protocols).map(([protocol, count]) => {
                      const percentage = (count / summary.totalPackets) * 100;
                      return (
                        <div key={protocol} className="flex items-center text-xs">
                          <div className={cn("w-3 h-3 mr-1 rounded-sm", getProtocolColor(protocol))}></div>
                          <span>{protocol}: {count} ({percentage.toFixed(1)}%)</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}