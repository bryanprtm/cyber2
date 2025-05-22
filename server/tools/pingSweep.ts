import { EventEmitter } from 'events';
import { exec } from 'child_process';
import { promisify } from 'util';
import { hostname } from 'os';
import dns from 'dns';

const execPromise = promisify(exec);
const dnsLookupPromise = promisify(dns.lookup);
const dnsReverseLookupPromise = promisify(dns.reverse);

export interface PingSweepOptions {
  target: string;
  timeout?: number;
  parallel?: number;
  retries?: number;
  resolveHostnames?: boolean;
}

export interface PingSweepResult {
  ip: string;
  status: 'alive' | 'dead';
  responseTime?: number;
  hostname?: string;
}

export interface PingSweepProgress {
  host: string;
  status: 'alive' | 'dead';
  responseTime?: number;
  hostname?: string;
  completed: number;
  total: number;
}

// Scanner class for ping sweep with progress reporting
export class PingSweepScanner extends EventEmitter {
  private target: string;
  private ipList: string[] = [];
  private timeout: number;
  private parallel: number;
  private retries: number;
  private resolveHostnames: boolean;
  private results: PingSweepResult[] = [];
  private completed: number = 0;
  private total: number = 0;
  private isStopped: boolean = false;
  
  constructor(options: PingSweepOptions) {
    super();
    this.target = options.target;
    this.timeout = options.timeout || 1000;
    this.parallel = options.parallel || 20;
    this.retries = options.retries || 1;
    this.resolveHostnames = options.resolveHostnames !== false;
  }
  
  /**
   * Start the ping sweep process
   */
  async start(): Promise<PingSweepResult[]> {
    try {
      // Parse target into list of IPs to scan
      this.ipList = await this.parseTargetToIpList(this.target);
      this.total = this.ipList.length;
      this.results = [];
      this.completed = 0;
      this.isStopped = false;
      
      // If no IPs to scan, return empty results
      if (this.ipList.length === 0) {
        return [];
      }
      
      // Process IPs in batches with limited concurrency
      const ipBatches: string[][] = [];
      for (let i = 0; i < this.ipList.length; i += this.parallel) {
        ipBatches.push(this.ipList.slice(i, i + this.parallel));
      }
      
      // Process each batch
      for (const batch of ipBatches) {
        if (this.isStopped) break;
        
        // Process the batch in parallel
        const batchResults = await Promise.all(
          batch.map(ip => this.pingHost(ip))
        );
        
        // Add results
        this.results.push(...batchResults);
      }
      
      // Sort by IP
      this.results.sort((a, b) => {
        const aOctets = a.ip.split('.').map(Number);
        const bOctets = b.ip.split('.').map(Number);
        
        for (let i = 0; i < 4; i++) {
          if (aOctets[i] !== bOctets[i]) {
            return aOctets[i] - bOctets[i];
          }
        }
        
        return 0;
      });
      
      return this.results;
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Stop an in-progress sweep
   */
  stop(): void {
    this.isStopped = true;
    this.emit('stopped', {
      completed: this.completed,
      total: this.total
    });
  }
  
  /**
   * Ping a single host and get status
   */
  private async pingHost(ip: string): Promise<PingSweepResult> {
    if (this.isStopped) {
      return { ip, status: 'dead' };
    }
    
    // Use system ping command
    // Adjust based on OS
    const pingCount = this.retries > 1 ? this.retries : 1;
    const isWindows = process.platform === 'win32';
    const pingCommand = isWindows
      ? `ping -n ${pingCount} -w ${this.timeout} ${ip}`
      : `ping -c ${pingCount} -W ${Math.ceil(this.timeout / 1000)} ${ip}`;
    
    try {
      const startTime = Date.now();
      const { stdout } = await execPromise(pingCommand);
      const endTime = Date.now();
      
      const responseTime = endTime - startTime;
      const isAlive = isWindows
        ? stdout.includes('Reply from')
        : stdout.includes(' 0% packet loss');
      
      let hostResult: PingSweepResult = {
        ip,
        status: isAlive ? 'alive' : 'dead',
        responseTime: isAlive ? responseTime : undefined
      };
      
      // Resolve hostname if requested and host is alive
      if (this.resolveHostnames && isAlive) {
        try {
          const hostnames = await dnsReverseLookupPromise(ip);
          if (hostnames && hostnames.length > 0) {
            hostResult.hostname = hostnames[0];
          }
        } catch (error) {
          // Hostname resolution failed, continue without hostname
        }
      }
      
      // Update progress
      this.completed++;
      this.emitProgress(hostResult);
      
      return hostResult;
    } catch (error) {
      // Ping command failed, host is considered dead
      this.completed++;
      
      const result: PingSweepResult = {
        ip,
        status: 'dead'
      };
      
      this.emitProgress(result);
      return result;
    }
  }
  
  /**
   * Emit a progress update
   */
  private emitProgress(result: PingSweepResult): void {
    this.emit('progress', {
      ...result,
      completed: this.completed,
      total: this.total
    });
  }
  
  /**
   * Parse target string into list of IP addresses to scan
   */
  private async parseTargetToIpList(target: string): Promise<string[]> {
    const ips: string[] = [];
    
    // Check if target is a domain name
    if (/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(target)) {
      try {
        const { address } = await dnsLookupPromise(target);
        ips.push(address);
        return ips;
      } catch (error) {
        throw new Error(`Could not resolve domain name ${target}`);
      }
    }
    
    // Handle CIDR notation (e.g., 192.168.0.0/24)
    if (target.includes('/')) {
      return this.expandCidr(target);
    }
    
    // Handle IP range with dash (e.g., 192.168.0.1-192.168.0.254)
    if (target.includes('-')) {
      return this.expandIpRange(target);
    }
    
    // Handle IP with wildcards (e.g., 192.168.0.*)
    if (target.includes('*')) {
      return this.expandWildcardIp(target);
    }
    
    // Handle comma-separated IPs
    if (target.includes(',')) {
      const ipList = target.split(',').map(ip => ip.trim());
      
      for (const ip of ipList) {
        if (this.isValidIp(ip)) {
          ips.push(ip);
        }
      }
      
      return ips;
    }
    
    // Handle single IP
    if (this.isValidIp(target)) {
      ips.push(target);
      return ips;
    }
    
    throw new Error('Invalid target format');
  }
  
  /**
   * Expand a CIDR notation to list of IPs
   */
  private expandCidr(cidr: string): string[] {
    const [network, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    
    if (mask < 0 || mask > 32 || !this.isValidIp(network)) {
      throw new Error('Invalid CIDR format');
    }
    
    const networkParts = network.split('.').map(Number);
    const ip = (networkParts[0] << 24) + (networkParts[1] << 16) + 
               (networkParts[2] << 8) + networkParts[3];
    
    // Calculate the first and last IP address in the CIDR range
    const maskValue = 0xffffffff << (32 - mask);
    const firstIp = ip & maskValue;
    const lastIp = firstIp + (1 << (32 - mask)) - 1;
    
    // Return if range is too large (more than 1024 hosts)
    if (lastIp - firstIp > 1024) {
      throw new Error('IP range too large. Maximum 1024 hosts allowed.');
    }
    
    const ips: string[] = [];
    for (let i = firstIp + 1; i < lastIp; i++) {
      const octet1 = (i >> 24) & 255;
      const octet2 = (i >> 16) & 255;
      const octet3 = (i >> 8) & 255;
      const octet4 = i & 255;
      ips.push(`${octet1}.${octet2}.${octet3}.${octet4}`);
    }
    
    return ips;
  }
  
  /**
   * Expand an IP range with dash notation to list of IPs
   */
  private expandIpRange(range: string): string[] {
    const [startIp, endIp] = range.split('-').map(ip => ip.trim());
    
    if (!this.isValidIp(startIp)) {
      throw new Error('Invalid start IP in range');
    }
    
    const startParts = startIp.split('.').map(Number);
    
    // Handle cases like 192.168.0.1-254 (partial end ip)
    if (!endIp.includes('.')) {
      const endOctet = parseInt(endIp, 10);
      if (isNaN(endOctet) || endOctet < 1 || endOctet > 255) {
        throw new Error('Invalid end octet in range');
      }
      
      const fullEndIp = `${startParts[0]}.${startParts[1]}.${startParts[2]}.${endOctet}`;
      
      if (!this.isValidIp(fullEndIp)) {
        throw new Error('Invalid end IP in range');
      }
      
      // Generate IPs in range
      const ips: string[] = [];
      for (let i = startParts[3]; i <= endOctet; i++) {
        ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
      }
      
      return ips;
    } else {
      // Full end IP
      if (!this.isValidIp(endIp)) {
        throw new Error('Invalid end IP in range');
      }
      
      const endParts = endIp.split('.').map(Number);
      
      // Only support ranges in the same subnet
      if (startParts[0] !== endParts[0] || startParts[1] !== endParts[1] || startParts[2] !== endParts[2]) {
        throw new Error('IP range must be within the same /24 subnet');
      }
      
      if (endParts[3] <= startParts[3]) {
        throw new Error('End IP must be greater than start IP');
      }
      
      if (endParts[3] - startParts[3] > 254) {
        throw new Error('IP range too large. Maximum 254 hosts allowed.');
      }
      
      // Generate IPs in range
      const ips: string[] = [];
      for (let i = startParts[3]; i <= endParts[3]; i++) {
        ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
      }
      
      return ips;
    }
  }
  
  /**
   * Expand a wildcard IP to list of IPs
   */
  private expandWildcardIp(wildcardIp: string): string[] {
    const parts = wildcardIp.split('.');
    
    if (parts.length !== 4) {
      throw new Error('Invalid IP format');
    }
    
    const ips: string[] = [];
    
    // Find which octet has the wildcard
    const wildcardIndex = parts.findIndex(part => part === '*');
    
    if (wildcardIndex === -1) {
      throw new Error('No wildcard found in IP');
    }
    
    // Verify other octets are valid
    for (let i = 0; i < 4; i++) {
      if (i === wildcardIndex) continue;
      
      const octet = parseInt(parts[i], 10);
      if (isNaN(octet) || octet < 0 || octet > 255) {
        throw new Error(`Invalid octet at position ${i+1}`);
      }
    }
    
    // Generate IPs with wildcard
    for (let i = 1; i <= 254; i++) {
      const newParts = [...parts];
      newParts[wildcardIndex] = i.toString();
      ips.push(newParts.join('.'));
    }
    
    return ips;
  }
  
  /**
   * Validate an IP address format
   */
  private isValidIp(ip: string): boolean {
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return pattern.test(ip);
  }
}

/**
 * Main ping sweep function that creates and runs a scanner
 */
export async function pingSweep(
  options: PingSweepOptions,
  progressCallback?: (progress: PingSweepProgress) => void
): Promise<PingSweepResult[]> {
  const scanner = new PingSweepScanner(options);
  
  // If a progress callback is provided, hook it up to the progress events
  if (progressCallback) {
    scanner.on('progress', progressCallback);
  }
  
  return scanner.start();
}