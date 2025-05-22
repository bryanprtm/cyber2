import React, { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertCircle,
  Calculator,
  RotateCw,
  Copy,
  Network,
  Globe,
  Grid,
  Check
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useTerminal } from '@/hooks/use-terminal';

interface SubnetInfo {
  inputNotation: string;
  networkAddress: string;
  subnetMask: string;
  cidrNotation: string;
  wildcardMask: string;
  broadcastAddress: string;
  firstHostAddress: string;
  lastHostAddress: string;
  totalHosts: number;
  usableHosts: number;
  ipClass: string;
  ipType: string;
}

interface SubnetCalculatorProps {}

export default function SubnetCalculator({}: SubnetCalculatorProps) {
  const [ipAddress, setIpAddress] = useState('');
  const [subnetMask, setSubnetMask] = useState('');
  const [cidrValue, setCidrValue] = useState('');
  const [calculationMode, setCalculationMode] = useState<'subnet-mask' | 'cidr'>('subnet-mask');
  const [subnetInfo, setSubnetInfo] = useState<SubnetInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  
  const { toast } = useToast();
  const { addInfoLine, addCommandLine } = useTerminal();
  
  // Helper: Convert subnet mask to CIDR notation
  const subnetMaskToCidr = (mask: string): number => {
    const parts = mask.split('.');
    if (parts.length !== 4) return -1;
    
    let cidr = 0;
    parts.forEach(part => {
      const num = parseInt(part, 10);
      // Convert to binary and count 1s
      const binary = num.toString(2).padStart(8, '0');
      cidr += binary.split('').filter(bit => bit === '1').length;
    });
    
    return cidr;
  };
  
  // Helper: Convert CIDR to subnet mask
  const cidrToSubnetMask = (cidr: number): string => {
    if (cidr < 0 || cidr > 32) return '';
    
    const mask: number[] = [0, 0, 0, 0];
    let fullOctets = Math.floor(cidr / 8);
    let partialOctet = cidr % 8;
    
    // Fill full octets
    for (let i = 0; i < fullOctets; i++) {
      mask[i] = 255;
    }
    
    // Fill partial octet if any
    if (fullOctets < 4 && partialOctet > 0) {
      // Calculate value for partial octet (e.g., for /19, we need 11100000 = 224)
      let value = 0;
      for (let i = 0; i < partialOctet; i++) {
        value |= (1 << (7 - i));
      }
      mask[fullOctets] = value;
    }
    
    return mask.join('.');
  };
  
  // Helper: Calculate wildcard mask
  const calculateWildcardMask = (subnetMask: string): string => {
    const parts = subnetMask.split('.');
    return parts.map(part => 255 - parseInt(part, 10)).join('.');
  };
  
  // Helper: Calculate network address
  const calculateNetworkAddress = (ip: string, mask: string): string => {
    const ipParts = ip.split('.').map(part => parseInt(part, 10));
    const maskParts = mask.split('.').map(part => parseInt(part, 10));
    
    return ipParts.map((part, i) => part & maskParts[i]).join('.');
  };
  
  // Helper: Calculate broadcast address
  const calculateBroadcastAddress = (networkAddress: string, wildcardMask: string): string => {
    const networkParts = networkAddress.split('.').map(part => parseInt(part, 10));
    const wildcardParts = wildcardMask.split('.').map(part => parseInt(part, 10));
    
    return networkParts.map((part, i) => part | wildcardParts[i]).join('.');
  };
  
  // Helper: Get IP class and type
  const getIpClassAndType = (ip: string): { ipClass: string; ipType: string } => {
    const firstOctet = parseInt(ip.split('.')[0], 10);
    
    // Determine IP class
    let ipClass = '';
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'A';
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'B';
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'C';
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'D (Multicast)';
    else if (firstOctet >= 240 && firstOctet <= 255) ipClass = 'E (Reserved)';
    else ipClass = 'Invalid';
    
    // Determine IP type
    let ipType = 'Public';
    
    // Check for private IP ranges
    if (
      (firstOctet === 10) ||
      (firstOctet === 172 && parseInt(ip.split('.')[1], 10) >= 16 && parseInt(ip.split('.')[1], 10) <= 31) ||
      (firstOctet === 192 && parseInt(ip.split('.')[1], 10) === 168)
    ) {
      ipType = 'Private';
    }
    
    // Check for loopback
    if (firstOctet === 127) {
      ipType = 'Loopback';
    }
    
    return { ipClass, ipType };
  };
  
  // Function to calculate subnet information
  const calculateSubnet = () => {
    try {
      if (!ipAddress) {
        setError('IP address is required');
        return;
      }
      
      // Validate IP address format
      const ipPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      if (!ipPattern.test(ipAddress)) {
        setError('Invalid IP address format');
        return;
      }
      
      let effectiveSubnetMask = '';
      let effectiveCidr = 0;
      
      if (calculationMode === 'subnet-mask') {
        // Validate subnet mask format and validity
        const maskPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!maskPattern.test(subnetMask)) {
          setError('Invalid subnet mask format');
          return;
        }
        
        // Verify it's a valid subnet mask (continuous 1s followed by continuous 0s)
        const maskParts = subnetMask.split('.').map(part => parseInt(part, 10));
        const binaryMask = maskParts.map(part => part.toString(2).padStart(8, '0')).join('');
        
        if (!/^1*0*$/.test(binaryMask)) {
          setError('Invalid subnet mask. Must be continuous 1s followed by continuous 0s');
          return;
        }
        
        effectiveSubnetMask = subnetMask;
        effectiveCidr = subnetMaskToCidr(subnetMask);
        
        // Update the CIDR field with the correct value
        setCidrValue(`/${effectiveCidr}`);
      } else {
        // Validate CIDR notation
        const cidrPattern = /^\/(\d+)$/;
        const match = cidrValue.match(cidrPattern);
        
        if (!match) {
          setError('Invalid CIDR notation format. Must be like "/24"');
          return;
        }
        
        effectiveCidr = parseInt(match[1], 10);
        
        if (effectiveCidr < 0 || effectiveCidr > 32) {
          setError('CIDR value must be between 0 and 32');
          return;
        }
        
        effectiveSubnetMask = cidrToSubnetMask(effectiveCidr);
        
        // Update the subnet mask field with the correct value
        setSubnetMask(effectiveSubnetMask);
      }
      
      // Calculate all subnet information
      const wildcardMask = calculateWildcardMask(effectiveSubnetMask);
      const networkAddress = calculateNetworkAddress(ipAddress, effectiveSubnetMask);
      const broadcastAddress = calculateBroadcastAddress(networkAddress, wildcardMask);
      
      // Calculate first and last host addresses
      const networkParts = networkAddress.split('.').map(part => parseInt(part, 10));
      const broadcastParts = broadcastAddress.split('.').map(part => parseInt(part, 10));
      
      // For /31 and /32 networks, special rules apply
      let firstHostAddress: string;
      let lastHostAddress: string;
      let usableHosts: number;
      
      if (effectiveCidr >= 31) {
        // /31 has 2 IPs (RFC 3021): network and broadcast are usable
        // /32 has 1 IP: the network address itself
        firstHostAddress = networkAddress;
        lastHostAddress = broadcastAddress;
        usableHosts = Math.pow(2, 32 - effectiveCidr);
      } else {
        // Calculate first host (network address + 1)
        const firstHostParts = [...networkParts];
        firstHostParts[3] += 1;
        firstHostAddress = firstHostParts.join('.');
        
        // Calculate last host (broadcast address - 1)
        const lastHostParts = [...broadcastParts];
        lastHostParts[3] -= 1;
        lastHostAddress = lastHostParts.join('.');
        
        // Calculate usable hosts
        usableHosts = Math.pow(2, 32 - effectiveCidr) - 2;
      }
      
      // Get IP class and type
      const { ipClass, ipType } = getIpClassAndType(ipAddress);
      
      // Record the calculation in the terminal
      addCommandLine(`subnet-calc ${ipAddress} ${effectiveSubnetMask}`);
      addInfoLine(`Calculated subnet information for ${ipAddress}/${effectiveCidr}`);
      
      // Set all calculated info
      setSubnetInfo({
        inputNotation: `${ipAddress}/${effectiveCidr}`,
        networkAddress,
        subnetMask: effectiveSubnetMask,
        cidrNotation: `/${effectiveCidr}`,
        wildcardMask,
        broadcastAddress,
        firstHostAddress,
        lastHostAddress,
        totalHosts: Math.pow(2, 32 - effectiveCidr),
        usableHosts,
        ipClass,
        ipType
      });
      
      // Clear any previous error
      setError(null);
    } catch (err) {
      setError(`Calculation error: ${(err as Error).message}`);
    }
  };
  
  // Handle form submission
  const handleCalculate = () => {
    calculateSubnet();
  };
  
  // Handle reset
  const handleReset = () => {
    setIpAddress('');
    setSubnetMask('');
    setCidrValue('');
    setSubnetInfo(null);
    setError(null);
    setCopied(false);
    addInfoLine('Subnet calculator reset');
  };
  
  // Copy results to clipboard
  const copyToClipboard = () => {
    if (!subnetInfo) return;
    
    const textToCopy = `
Subnet Information for ${subnetInfo.inputNotation}
--------------------------------------------
Network Address: ${subnetInfo.networkAddress}
Subnet Mask: ${subnetInfo.subnetMask}
CIDR Notation: ${subnetInfo.cidrNotation}
Wildcard Mask: ${subnetInfo.wildcardMask}
Broadcast Address: ${subnetInfo.broadcastAddress}
First Host: ${subnetInfo.firstHostAddress}
Last Host: ${subnetInfo.lastHostAddress}
Total Hosts: ${subnetInfo.totalHosts}
Usable Hosts: ${subnetInfo.usableHosts}
IP Class: ${subnetInfo.ipClass}
IP Type: ${subnetInfo.ipType}
    `.trim();
    
    navigator.clipboard.writeText(textToCopy).then(() => {
      setCopied(true);
      toast({
        title: "Copied!",
        description: "Subnet information copied to clipboard",
        variant: "default"
      });
      
      // Reset copied state after 2 seconds
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      toast({
        title: "Copy Failed",
        description: "Could not copy text to clipboard",
        variant: "destructive"
      });
    });
  };
  
  // Visualization: Binary representation of IP and subnet mask
  const getBinaryRepresentation = (ip: string): string[] => {
    return ip.split('.').map(part => parseInt(part, 10).toString(2).padStart(8, '0'));
  };
  
  // Simplified CIDR visualization
  const getCidrVisualization = (cidr: number): string => {
    const binaryString = '1'.repeat(cidr) + '0'.repeat(32 - cidr);
    const parts = [];
    for (let i = 0; i < 32; i += 8) {
      parts.push(binaryString.substring(i, i + 8));
    }
    return parts.join('.');
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4 flex items-center gap-2">
          <Calculator className="h-5 w-5" />
          Subnet Calculator
        </h2>
        
        <div className="space-y-4">
          <Tabs 
            defaultValue="subnet-mask" 
            value={calculationMode}
            onValueChange={(v) => setCalculationMode(v as 'subnet-mask' | 'cidr')}
            className="w-full"
          >
            <TabsList>
              <TabsTrigger value="subnet-mask">Subnet Mask</TabsTrigger>
              <TabsTrigger value="cidr">CIDR Notation</TabsTrigger>
            </TabsList>
            
            <TabsContent value="subnet-mask" className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label htmlFor="ip-address" className="text-sm font-tech">IP Address</Label>
                <Input
                  id="ip-address"
                  placeholder="192.168.1.1"
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="subnet-mask" className="text-sm font-tech">Subnet Mask</Label>
                <Input
                  id="subnet-mask"
                  placeholder="255.255.255.0"
                  value={subnetMask}
                  onChange={(e) => setSubnetMask(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
              </div>
            </TabsContent>
            
            <TabsContent value="cidr" className="space-y-4 pt-2">
              <div className="space-y-2">
                <Label htmlFor="ip-address-cidr" className="text-sm font-tech">IP Address</Label>
                <Input
                  id="ip-address-cidr"
                  placeholder="192.168.1.1"
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="cidr" className="text-sm font-tech">CIDR Notation</Label>
                <Input
                  id="cidr"
                  placeholder="/24"
                  value={cidrValue}
                  onChange={(e) => setCidrValue(e.target.value)}
                  className="font-mono bg-background border-secondary/50"
                />
              </div>
            </TabsContent>
          </Tabs>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleCalculate}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              <Calculator className="h-4 w-4 mr-2" />
              Calculate
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              className="border-secondary/50 text-secondary font-tech"
            >
              <RotateCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {/* Results Section */}
      {subnetInfo && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-tech text-secondary flex items-center">
              <Network className="h-4 w-4 mr-2" />
              Subnet Information
            </h3>
            <Button 
              variant="outline" 
              size="sm" 
              className="h-8 px-3"
              onClick={copyToClipboard}
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 mr-1.5" />
                  Copied!
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5 mr-1.5" />
                  Copy Results
                </>
              )}
            </Button>
          </div>
          
          <div className="space-y-6">
            {/* Summary section */}
            <div className="bg-background p-3 rounded-md border border-secondary/30">
              <div className="flex items-center">
                <Globe className="h-4 w-4 mr-2 text-primary" />
                <span className="font-tech text-sm">Input: </span>
                <span className="font-mono ml-2 text-primary">{subnetInfo.inputNotation}</span>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-3">
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">Network</span>
                  <span className="font-mono text-sm">{subnetInfo.networkAddress}</span>
                </div>
                
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">Subnet Mask</span>
                  <span className="font-mono text-sm">{subnetInfo.subnetMask}</span>
                </div>
                
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">CIDR</span>
                  <span className="font-mono text-sm">{subnetInfo.cidrNotation}</span>
                </div>
                
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">Broadcast</span>
                  <span className="font-mono text-sm">{subnetInfo.broadcastAddress}</span>
                </div>
                
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">Wildcard Mask</span>
                  <span className="font-mono text-sm">{subnetInfo.wildcardMask}</span>
                </div>
                
                <div className="flex flex-col">
                  <span className="text-xs font-tech text-muted-foreground">IP Class & Type</span>
                  <div className="flex gap-1">
                    <Badge className="text-xs">{subnetInfo.ipClass}</Badge>
                    <Badge variant="outline" className="text-xs">{subnetInfo.ipType}</Badge>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Host information */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-background p-3 rounded-md border border-primary/30 text-center">
                <div className="text-xl font-tech text-primary">{subnetInfo.totalHosts.toLocaleString()}</div>
                <div className="text-xs font-mono text-muted-foreground">Total Hosts</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-secondary/30 text-center">
                <div className="text-xl font-tech text-secondary">{subnetInfo.usableHosts.toLocaleString()}</div>
                <div className="text-xs font-mono text-muted-foreground">Usable Hosts</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-primary/30 text-center">
                <div className="text-sm font-mono text-primary truncate">{subnetInfo.firstHostAddress}</div>
                <div className="text-xs font-mono text-muted-foreground">First Host</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-secondary/30 text-center">
                <div className="text-sm font-mono text-secondary truncate">{subnetInfo.lastHostAddress}</div>
                <div className="text-xs font-mono text-muted-foreground">Last Host</div>
              </div>
            </div>
            
            {/* Binary visualization */}
            <div className="border border-border rounded-md overflow-hidden">
              <div className="bg-muted p-2 font-tech text-sm border-b border-border">
                Binary Representation
              </div>
              
              <div className="p-3 space-y-3">
                <div className="grid grid-cols-8 gap-1">
                  <div className="col-span-2 font-tech text-xs text-muted-foreground">IP Address</div>
                  {getBinaryRepresentation(ipAddress).map((octet, i) => (
                    <div key={i} className="font-mono text-xs text-primary text-center">
                      {octet}
                    </div>
                  ))}
                </div>
                
                <div className="grid grid-cols-8 gap-1">
                  <div className="col-span-2 font-tech text-xs text-muted-foreground">Subnet Mask</div>
                  {getBinaryRepresentation(subnetInfo.subnetMask).map((octet, i) => (
                    <div key={i} className="font-mono text-xs text-secondary text-center">
                      {octet}
                    </div>
                  ))}
                </div>
                
                <div className="grid grid-cols-8 gap-1">
                  <div className="col-span-2 font-tech text-xs text-muted-foreground">Network</div>
                  {getBinaryRepresentation(subnetInfo.networkAddress).map((octet, i) => (
                    <div key={i} className="font-mono text-xs text-accent text-center">
                      {octet}
                    </div>
                  ))}
                </div>
                
                <div className="h-px w-full bg-border my-2"></div>
                
                <div className="font-tech text-xs text-muted-foreground">CIDR Visualization</div>
                <div className="flex items-center bg-muted/30 p-2 rounded-md">
                  <Grid className="h-4 w-4 mr-2 text-muted-foreground" />
                  <div className="font-mono text-xs">
                    {getCidrVisualization(parseInt(subnetInfo.cidrNotation.substring(1), 10))
                      .split('')
                      .map((char, i) => (
                        <span 
                          key={i} 
                          className={cn(
                            char === '1' ? 'text-primary' : 'text-muted-foreground',
                            i % 9 === 8 ? 'mx-1' : ''
                          )}
                        >
                          {char}
                        </span>
                      ))}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Range visualization would be here in a full implementation */}
            <div className="border border-border rounded-md overflow-hidden">
              <div className="bg-muted p-2 font-tech text-sm border-b border-border">
                IP Range
              </div>
              
              <div className="p-3">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between">
                  <div className="font-mono text-xs">
                    <span className="text-muted-foreground mr-2">From:</span>
                    <span className="text-primary">{subnetInfo.firstHostAddress}</span>
                  </div>
                  
                  <div className="font-mono text-xs mt-2 md:mt-0">
                    <span className="text-muted-foreground mr-2">To:</span>
                    <span className="text-secondary">{subnetInfo.lastHostAddress}</span>
                  </div>
                </div>
                
                {/* Here we'd have a visual representation of the IP range */}
                <div className="mt-3 p-3 bg-muted/20 rounded-md">
                  <p className="text-xs text-muted-foreground text-center">
                    Interactive IP range visualization would be displayed here in the complete implementation.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}