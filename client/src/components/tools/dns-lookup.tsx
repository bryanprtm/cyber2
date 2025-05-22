import React, { useState, useEffect } from 'react';
import { useWebSocket } from '@/hooks/use-websocket';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
  AlertCircle,
  Play,
  RotateCw,
  Database,
  Globe,
  Server,
  Clock,
  Copy
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { apiMutation } from '@/lib/queryClient';

interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl?: number;
  priority?: number;
  class?: string;
}

interface DnsLookupResult {
  domain: string;
  records: {
    A?: DnsRecord[];
    AAAA?: DnsRecord[];
    MX?: DnsRecord[];
    NS?: DnsRecord[];
    TXT?: DnsRecord[];
    SOA?: DnsRecord[];
    CNAME?: DnsRecord[];
    PTR?: DnsRecord[];
    SRV?: DnsRecord[];
    CAA?: DnsRecord[];
    DNSKEY?: DnsRecord[];
    [key: string]: DnsRecord[] | undefined;
  };
  nameservers?: string[];
  executionTime: number;
}

interface DnsLookupProps {
  onLookupComplete?: (results: any) => void;
}

// Mocked user ID for demo
const MOCK_USER_ID = 1;

export default function DnsLookup({ onLookupComplete }: DnsLookupProps) {
  const [domain, setDomain] = useState('');
  const [recordTypes, setRecordTypes] = useState<string[]>(['A', 'AAAA', 'MX', 'TXT', 'NS']);
  const [specificType, setSpecificType] = useState('A');
  const [allRecordTypes, setAllRecordTypes] = useState(false);
  const [verbose, setVerbose] = useState(false);
  const [isLooking, setIsLooking] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [results, setResults] = useState<DnsLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saveToDatabase, setSaveToDatabase] = useState(true);
  const [activeTab, setActiveTab] = useState<string>('all');
  
  // Activity log for real-time updates
  const [activityLog, setActivityLog] = useState<{
    message: string;
    timestamp: Date;
    type: 'info' | 'success' | 'warning' | 'error';
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
        
      case 'dns_lookup_start':
        const types = allRecordTypes ? 'ALL' : recordTypes.join(',');
        addCommandLine(`dns-lookup ${domain} --types ${types}`);
        addInfoLine(`Starting DNS lookup for ${domain}...`);
        setIsLooking(true);
        setResults(null);
        setError(null);
        
        // Clear previous activity log and add initial entry
        setActivityLog([{
          message: `DNS lookup started for ${domain}`,
          timestamp: new Date(),
          type: 'info'
        }]);
        break;
        
      case 'dns_record_found':
        const recordData = lastMessage.data;
        const { type, name, value } = recordData;
        
        // Add to activity log
        setActivityLog(prev => {
          const newLog = {
            message: `${type} record found: ${value}`,
            timestamp: new Date(),
            type: 'success' as any
          };
          
          // Keep log manageable (latest 100 entries)
          const updatedLog = [newLog, ...prev].slice(0, 100);
          return updatedLog;
        });
        
        // Log record to terminal
        addLine(`${type} record for ${name}: ${value}`, "success");
        break;
        
      case 'dns_lookup_results':
        setResults(lastMessage.data);
        break;
        
      case 'dns_lookup_complete':
        setIsLooking(false);
        addSystemLine(`DNS lookup complete`);
        
        // Add final log entry
        setActivityLog(prev => [{
          message: `Lookup completed in ${lastMessage.data.executionTime}ms`,
          timestamp: new Date(),
          type: 'info'
        }, ...prev]);
        
        // Save results to database if option is checked
        if (saveToDatabase && results) {
          saveLookupResults(results);
        }
        
        if (onLookupComplete && results) {
          onLookupComplete(results);
        }
        break;
        
      case 'error':
        setIsLooking(false);
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
  }, [lastMessage, addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine, domain, recordTypes, allRecordTypes, results, onLookupComplete, saveToDatabase]);
  
  // Save lookup results to database
  const saveLookupResults = async (lookupResults: DnsLookupResult) => {
    try {
      setIsSaving(true);
      addInfoLine(`Saving DNS lookup results to database...`);
      
      // Prepare data for API
      const scanData = {
        userId: MOCK_USER_ID,
        toolId: 'dns-lookup',
        target: domain,
        results: lookupResults,
        status: 'completed',
        duration: `${Math.round(lookupResults.executionTime / 1000)}s`
      };
      
      // Save to database through API
      const response = await apiMutation('POST', '/api/scan/dns-lookup', {
        ...scanData,
        recordTypes: allRecordTypes ? 'ALL' : recordTypes,
        verbose
      });
      
      if (response.success) {
        addLine(`[SUCCESS] DNS lookup results saved to database with ID: ${response.scanId || 'unknown'}`, "success");
        toast({
          title: "Results Saved",
          description: "DNS lookup results have been stored in the database",
          variant: "default"
        });
      } else {
        throw new Error(response.message || 'Failed to save DNS lookup results');
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
  
  // Toggle record type in the selection array
  const toggleRecordType = (type: string) => {
    if (recordTypes.includes(type)) {
      setRecordTypes(recordTypes.filter(t => t !== type));
    } else {
      setRecordTypes([...recordTypes, type]);
    }
  };
  
  // Handle all record types toggle
  const handleAllRecordTypesChange = (checked: boolean) => {
    setAllRecordTypes(checked);
    
    // If all types is selected, disable individual selection
    if (checked) {
      setRecordTypes([]);
    } else {
      // Default to A record if turning off "all"
      setRecordTypes(['A']);
    }
  };
  
  // Validate domain name format
  const isValidDomain = (domain: string): boolean => {
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainPattern.test(domain);
  };
  
  // Handle form submission
  const handleLookup = () => {
    if (!domain) {
      setError('Domain name is required');
      addErrorLine('Domain name is required');
      return;
    }
    
    if (!isValidDomain(domain)) {
      setError('Invalid domain format. Please enter a valid domain name');
      addErrorLine('Invalid domain format. Please enter a valid domain name (e.g., example.com)');
      return;
    }
    
    if (!allRecordTypes && recordTypes.length === 0) {
      setError('Please select at least one record type or enable "All Record Types"');
      addErrorLine('Please select at least one record type or enable "All Record Types"');
      return;
    }
    
    if (!isConnected) {
      setError('Not connected to tool server');
      addErrorLine('Not connected to tool server. Please try again.');
      return;
    }
    
    // Send DNS lookup request via WebSocket
    const success = sendMessage('dns_lookup', {
      domain,
      recordTypes: allRecordTypes ? 'ALL' : recordTypes,
      verbose
    });
    
    if (success) {
      setIsLooking(true);
    }
  };
  
  const handleReset = () => {
    setDomain('');
    setRecordTypes(['A', 'AAAA', 'MX', 'TXT', 'NS']);
    setSpecificType('A');
    setAllRecordTypes(false);
    setVerbose(false);
    setResults(null);
    setError(null);
    setActivityLog([]);
    setActiveTab('all');
    addInfoLine('DNS lookup tool reset');
  };
  
  // Copy results to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({
        title: "Copied!",
        description: "DNS information copied to clipboard",
        variant: "default"
      });
    }).catch((err) => {
      toast({
        title: "Copy Failed",
        description: "Could not copy text to clipboard",
        variant: "destructive"
      });
    });
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Globe className="h-5 w-5" />
          DNS Lookup
        </h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="domain" className="text-sm font-tech">Domain Name</Label>
            <Input
              id="domain"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="font-mono bg-background border-secondary/50"
            />
          </div>
          
          <div className="space-y-2">
            <Label className="text-sm font-tech mb-2 block">Record Types</Label>
            
            <div className="flex items-center space-x-2 mb-2">
              <Checkbox 
                id="all-record-types" 
                checked={allRecordTypes} 
                onCheckedChange={(checked) => handleAllRecordTypesChange(!!checked)}
              />
              <Label 
                htmlFor="all-record-types" 
                className="text-sm font-tech cursor-pointer"
              >
                All Record Types
              </Label>
            </div>
            
            {!allRecordTypes && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                {['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'].map(type => (
                  <div key={type} className="flex items-center space-x-2">
                    <Checkbox 
                      id={`type-${type}`} 
                      checked={recordTypes.includes(type)} 
                      onCheckedChange={() => toggleRecordType(type)}
                    />
                    <Label 
                      htmlFor={`type-${type}`} 
                      className="text-sm font-mono cursor-pointer"
                    >
                      {type}
                    </Label>
                  </div>
                ))}
              </div>
            )}
          </div>
          
          <div className="flex items-center space-x-2">
            <Checkbox 
              id="verbose" 
              checked={verbose} 
              onCheckedChange={(checked) => setVerbose(!!checked)}
            />
            <Label 
              htmlFor="verbose" 
              className="text-sm font-tech cursor-pointer"
            >
              Verbose output (include additional DNS information)
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
              onClick={handleLookup}
              disabled={isLooking || !domain || isSaving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Play className="h-4 w-4 mr-2" />
              {isLooking ? 'Looking up...' : 'Lookup DNS'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isLooking || isSaving}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Lookup Progress Section */}
      {isLooking && (
        <Card className="p-4 border-primary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-primary flex items-center">
              <Clock className="h-4 w-4 mr-2" />
              Lookup Progress
            </h3>
            <Badge variant="outline" className="bg-primary/10 text-primary">Live</Badge>
          </div>
          
          <div className="border border-border rounded-md">
            <div className="bg-muted p-2 flex justify-between items-center font-tech text-xs border-b border-border">
              <div>Activity Log</div>
              <div className="flex items-center">
                <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse mr-2"></div>
                <span>Lookup in progress</span>
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
                    entry.type === 'info' && "text-blue-400"
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
                  No activity yet. Waiting for lookup to start...
                </div>
              )}
            </div>
          </div>
        </Card>
      )}
      
      {/* Lookup Results Section */}
      {results && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Server className="h-4 w-4 mr-2" />
              DNS Lookup Results
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
              <Button 
                variant="outline" 
                size="sm" 
                className="h-7 px-2 text-xs"
                onClick={() => copyToClipboard(JSON.stringify(results, null, 2))}
              >
                <Copy className="h-3 w-3 mr-1" />
                Copy
              </Button>
            </div>
          </div>
          
          <div className="bg-background p-3 rounded-md border border-secondary/30 mb-4">
            <div className="flex items-center">
              <Globe className="h-4 w-4 mr-2 text-primary" />
              <span className="font-tech text-sm">Domain: </span>
              <span className="font-mono ml-2 text-primary">{results.domain}</span>
            </div>
            {results.nameservers && results.nameservers.length > 0 && (
              <div className="flex items-start mt-2">
                <Server className="h-4 w-4 mr-2 text-secondary mt-0.5" />
                <span className="font-tech text-sm">Nameservers: </span>
                <div className="font-mono ml-2 text-secondary flex flex-col">
                  {results.nameservers.map((ns, i) => (
                    <span key={i}>{ns}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          <Tabs 
            defaultValue="all" 
            value={activeTab} 
            onValueChange={setActiveTab}
            className="w-full"
          >
            <TabsList className="mb-4 flex flex-wrap h-auto">
              <TabsTrigger value="all">All Records</TabsTrigger>
              {Object.keys(results.records).map(recordType => (
                <TabsTrigger key={recordType} value={recordType}>
                  {recordType}
                  {results.records[recordType] && (
                    <Badge variant="secondary" className="ml-2 bg-secondary/20">
                      {results.records[recordType]!.length}
                    </Badge>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
            
            <TabsContent value="all">
              <div className="space-y-4">
                {Object.entries(results.records).map(([recordType, records]) => {
                  if (!records || records.length === 0) return null;
                  
                  return (
                    <div key={recordType} className="border border-border rounded-md overflow-hidden">
                      <div className="bg-muted p-2 font-tech text-sm border-b border-border">
                        {recordType} Records
                      </div>
                      
                      <div className="bg-background">
                        {records.map((record, index) => (
                          <div 
                            key={index}
                            className={cn(
                              "p-3 font-mono text-xs",
                              index % 2 === 0 ? "bg-background" : "bg-muted/30"
                            )}
                          >
                            <div className="flex items-start justify-between">
                              <div>
                                <span className="text-primary">{record.name}</span>
                                <span className="text-muted-foreground ml-2">
                                  {record.ttl && `${record.ttl}s`}
                                </span>
                              </div>
                              {record.priority !== undefined && (
                                <Badge variant="outline" className="text-xs">
                                  Priority: {record.priority}
                                </Badge>
                              )}
                            </div>
                            <div className="mt-1 text-secondary break-all">{record.value}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
                
                {Object.values(results.records).every(r => !r || r.length === 0) && (
                  <div className="p-4 text-center text-xs font-mono text-muted-foreground border border-border rounded-md">
                    No DNS records found for this domain.
                  </div>
                )}
              </div>
            </TabsContent>
            
            {/* Individual record type tabs */}
            {Object.entries(results.records).map(([recordType, records]) => (
              <TabsContent key={recordType} value={recordType}>
                <div className="border border-border rounded-md overflow-hidden">
                  <div className="bg-muted p-2 font-tech text-sm border-b border-border flex justify-between">
                    <span>{recordType} Records</span>
                    <span className="text-xs text-muted-foreground">
                      {records ? records.length : 0} records found
                    </span>
                  </div>
                  
                  <div className="bg-background">
                    {records && records.length > 0 ? (
                      records.map((record, index) => (
                        <div 
                          key={index}
                          className={cn(
                            "p-3 font-mono text-xs",
                            index % 2 === 0 ? "bg-background" : "bg-muted/30"
                          )}
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <span className="text-primary">{record.name}</span>
                              <span className="text-muted-foreground ml-2">
                                {record.ttl && `${record.ttl}s`}
                              </span>
                            </div>
                            {record.priority !== undefined && (
                              <Badge variant="outline" className="text-xs">
                                Priority: {record.priority}
                              </Badge>
                            )}
                          </div>
                          <div className="mt-1 text-secondary break-all">{record.value}</div>
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-center text-xs font-mono text-muted-foreground">
                        No {recordType} records found for this domain.
                      </div>
                    )}
                  </div>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        </Card>
      )}
    </div>
  );
}