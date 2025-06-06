import { EventEmitter } from 'events';
import { exec } from 'child_process';
import { promisify } from 'util';
import { hostname } from 'os';
import dns from 'dns';
// @ts-ignore: Import the ping module with type definitions from our custom declaration file
import ping from 'ping';

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
   * Start the ping sweep process with improved progress reporting
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
      
      // Emit initial progress event to set up UI
      this.emit('progress', {
        host: this.target,
        status: 'pending',
        completed: 0,
        total: this.total,
        timestamp: new Date()
      });
      
      // Throttle progress updates to avoid overwhelming the UI
      let lastProgressUpdate = Date.now();
      let pendingUpdates = 0;
      
      // Improved batching with better progress reporting
      const processBatch = async (ips: string[]) => {
        // Announce batch start
        this.emit('info', {
          message: `Processing batch of ${ips.length} hosts...`,
          timestamp: new Date()
        });
        
        // Process batch in parallel with controlled concurrency
        const batchResults = await Promise.allSettled(
          ips.map(ip => this.pingHost(ip).then(result => {
            // Throttle UI updates for better performance
            pendingUpdates++;
            const now = Date.now();
            if (now - lastProgressUpdate > 300 || pendingUpdates > 5) {
              lastProgressUpdate = now;
              pendingUpdates = 0;
              this.emit('batch_progress', {
                completed: this.completed,
                total: this.total,
                pendingHosts: this.total - this.completed,
                timestamp: new Date()
              });
            }
            return result;
          }))
        );
        
        // Process results from Promise.allSettled and filter for successful ones only
        const successfulResults = batchResults
          .filter((r): r is PromiseFulfilledResult<PingSweepResult> => r.status === 'fulfilled')
          .map(r => r.value);
        
        return successfulResults;
      };
      
      // Create batches for better concurrency control
      const batches: string[][] = [];
      for (let i = 0; i < this.ipList.length; i += this.parallel) {
        batches.push(this.ipList.slice(i, i + this.parallel));
      }
      
      // Process all batches sequentially
      for (let i = 0; i < batches.length; i++) {
        if (this.isStopped) break;
        
        // Announce batch number
        this.emit('info', {
          message: `Starting batch ${i + 1} of ${batches.length}...`,
          timestamp: new Date()
        });
        
        const batchResults = await processBatch(batches[i]);
        this.results.push(...batchResults);
        
        // Force a progress update after each batch
        this.emit('batch_complete', {
          batchIndex: i,
          totalBatches: batches.length,
          completed: this.completed,
          total: this.total,
          pendingHosts: this.total - this.completed,
          timestamp: new Date()
        });
      }
      
      // Sort results by IP for better display
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
      
      // Emit final completion event
      this.emit('sweep_complete', {
        totalHosts: this.total,
        aliveHosts: this.results.filter(r => r.status === 'alive').length,
        deadHosts: this.results.filter(r => r.status === 'dead').length,
        timestamp: new Date()
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
   * Ping a single host and get status using the ping package
   */
  private async pingHost(ip: string): Promise<PingSweepResult> {
    if (this.isStopped) {
      return { ip, status: 'dead' };
    }
    
    try {
      // Use the ping package which provides better cross-platform support
      const pingConfig = {
        timeout: this.timeout / 1000, // ping package needs seconds
        min_reply: 1,
        extra: ['-c', this.retries.toString()],
        numeric: true
      };
      
      const startTime = Date.now();
      
      // Emit early progress to show active scanning
      this.emit('progress', {
        host: ip,
        status: 'unknown', // Status not determined yet
        completed: this.completed,
        total: this.total
      });
      
      // Perform the actual ping
      const pingResult = await ping.promise.probe(ip, pingConfig);
      const endTime = Date.now();
      const responseTime = pingResult.time === 'unknown' ? undefined : parseFloat(pingResult.time);
      
      const isAlive = pingResult.alive;
      
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
      // Ping failed, host is considered dead
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