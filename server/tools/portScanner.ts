import { createConnection, Socket } from 'net';
import { EventEmitter } from 'events';

export interface PortScannerOptions {
  target: string;
  ports: string; // Could be a single port, comma-separated list, or range (e.g., "80", "80,443,8080", "20-1000")
  timeout?: number;
  concurrent?: number;
}

export interface PortScanResult {
  port: number;
  status: 'open' | 'closed' | 'filtered';
  service?: string;
}

export interface PortScanProgress {
  port: number;
  status: 'open' | 'closed' | 'filtered';
  service?: string;
  completed: number;
  total: number;
  elapsedTime: number;
}

// More comprehensive service mapping for common ports
const COMMON_SERVICES: Record<number, string> = {
  20: 'FTP Data',
  21: 'FTP Control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP Server',
  68: 'DHCP Client',
  69: 'TFTP',
  80: 'HTTP',
  88: 'Kerberos',
  110: 'POP3',
  119: 'NNTP',
  123: 'NTP',
  137: 'NetBIOS Name',
  138: 'NetBIOS Datagram',
  139: 'NetBIOS Session',
  143: 'IMAP',
  161: 'SNMP',
  194: 'IRC',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  500: 'IPsec/IKE',
  514: 'Syslog',
  587: 'SMTP Submission',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1080: 'SOCKS',
  1194: 'OpenVPN',
  1433: 'MS SQL',
  1521: 'Oracle DB',
  1723: 'PPTP',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5222: 'XMPP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP Proxy',
  8443: 'HTTPS Alt',
  9000: 'Prometheus',
  9090: 'Prometheus Alt',
  9200: 'Elasticsearch',
  9418: 'Git',
  27017: 'MongoDB',
  // Add more services as needed
};

// Constants for scanner configuration
const DEFAULT_TIMEOUT = 2000;      // 2 seconds (reduced for faster scanning)
const DEFAULT_CONCURRENT = 100;    // Increased concurrent connections
const DEFAULT_BATCH_SIZE = 500;    // Process results in batches
const MAX_SOCKET_ERRORS = 50;      // Maximum allowed socket errors before warning about rate limiting

// Scanner class to handle port scanning with progress reporting
export class PortScanner extends EventEmitter {
  private target: string;
  private ports: number[];
  private timeout: number;
  private concurrent: number;
  private results: PortScanResult[] = [];
  private completed: number = 0;
  private total: number = 0;
  private startTime: number = 0;
  private socketErrors: number = 0;
  private isStopped: boolean = false;
  
  constructor(options: PortScannerOptions) {
    super();
    this.target = options.target;
    this.ports = this.parsePortRange(options.ports);
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.concurrent = options.concurrent || DEFAULT_CONCURRENT;
    this.total = this.ports.length;
    
    // Adjust concurrent connections based on total ports to avoid excessive connections
    if (this.total > 10000) {
      this.concurrent = Math.min(this.concurrent, 250);
    } else if (this.total > 5000) {
      this.concurrent = Math.min(this.concurrent, 200);
    }
  }
  
  /**
   * Start the port scanning process
   */
  async start(): Promise<PortScanResult[]> {
    this.startTime = Date.now();
    this.results = [];
    this.completed = 0;
    this.socketErrors = 0;
    this.isStopped = false;
    
    // Initialize empty results array with closed status
    // This helps with showing a complete results list at the end
    this.results = this.ports.map(port => ({ 
      port, 
      status: 'closed', 
      service: COMMON_SERVICES[port]
    }));
    
    // Process ports in batches with limited concurrency for better performance
    const portBatches: number[][] = [];
    for (let i = 0; i < this.ports.length; i += DEFAULT_BATCH_SIZE) {
      portBatches.push(this.ports.slice(i, i + DEFAULT_BATCH_SIZE));
    }
    
    // Use a throttled approach to scan ports in batches
    for (const batch of portBatches) {
      if (this.isStopped) break;
      
      // Create a queue for current batch processing
      const queue = [...batch];
      const inProgress = new Set();
      const batchResults: PortScanResult[] = [];
      
      // Process the queue with limited concurrency
      while (queue.length > 0 || inProgress.size > 0) {
        if (this.isStopped) break;
        
        // Fill up to concurrent limit
        while (queue.length > 0 && inProgress.size < this.concurrent) {
          const port = queue.shift()!;
          inProgress.add(port);
          
          // Scan each port
          this.scanPort(this.target, port, this.timeout)
            .then(result => {
              // Store the result
              batchResults.push(result);
              inProgress.delete(port);
              
              // Update the main results array
              const index = this.results.findIndex(r => r.port === result.port);
              if (index !== -1) {
                this.results[index] = result;
              }
              
              // Update progress
              this.completed++;
              const progress = this.completed / this.total;
              
              // Emit progress event (but not too frequently)
              if (result.status === 'open' || this.completed % Math.max(Math.floor(this.total / 200), 1) === 0) {
                this.emitProgress(result);
              }
            })
            .catch(err => {
              // Handle errors
              inProgress.delete(port);
              this.socketErrors++;
              this.completed++;
              
              // Fallback result for errors
              const result: PortScanResult = {
                port,
                status: 'filtered',
                service: COMMON_SERVICES[port]
              };
              batchResults.push(result);
              
              // Warn about possible rate limiting
              if (this.socketErrors > MAX_SOCKET_ERRORS && this.socketErrors % MAX_SOCKET_ERRORS === 0) {
                this.emit('warning', {
                  message: `High number of connection errors (${this.socketErrors}). Target might be blocking scans.`,
                  socketErrors: this.socketErrors
                });
              }
              
              // Still emit progress
              this.emitProgress(result);
            });
        }
        
        // Short delay to prevent event loop from being blocked
        if (inProgress.size >= this.concurrent || queue.length === 0) {
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }
    }
    
    // Ensure all results are accounted for in case of early termination
    if (this.completed < this.total) {
      this.completed = this.total;
    }
    
    // Sort results by port number
    this.results.sort((a, b) => a.port - b.port);
    
    return this.results;
  }
  
  /**
   * Stop an in-progress scan
   */
  stop(): void {
    this.isStopped = true;
    this.emit('stopped', {
      completed: this.completed,
      total: this.total,
      elapsedTime: Date.now() - this.startTime
    });
  }
  
  /**
   * Emit a progress update
   */
  private emitProgress(result: PortScanResult): void {
    this.emit('progress', {
      ...result,
      completed: this.completed,
      total: this.total,
      elapsedTime: Date.now() - this.startTime
    });
  }
  
  /**
   * Scan an individual port
   */
  private scanPort(host: string, port: number, timeout: number): Promise<PortScanResult> {
    return new Promise((resolve, reject) => {
      // Skip if scan has been stopped
      if (this.isStopped) {
        resolve({ port, status: 'filtered' });
        return;
      }
      
      const socket = createConnection({
        host,
        port,
        timeout
      });
      
      // Set a shorter timeout for overall operation
      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ port, status: 'filtered' });
      }, timeout);
      
      socket.on('connect', () => {
        clearTimeout(timeoutId);
        const service = COMMON_SERVICES[port];
        socket.destroy();
        resolve({ port, status: 'open', service });
      });
      
      socket.on('timeout', () => {
        clearTimeout(timeoutId);
        socket.destroy();
        resolve({ port, status: 'filtered' });
      });
      
      socket.on('error', (error) => {
        clearTimeout(timeoutId);
        socket.destroy();
        
        // ECONNREFUSED means the port is reachable but closed
        if (error.message.includes('ECONNREFUSED')) {
          resolve({ port, status: 'closed' });
        } else {
          // Other errors like EHOSTUNREACH, ETIMEDOUT usually mean filtered
          resolve({ port, status: 'filtered' });
        }
      });
    });
  }
  
  /**
   * Parse port ranges into an array of port numbers
   */
  private parsePortRange(ports: string): number[] {
    const result: number[] = [];
    
    // Handle comma-separated list
    const segments = ports.split(',');
    
    for (const segment of segments) {
      // Handle ranges, e.g., "80-100"
      if (segment.includes('-')) {
        const [start, end] = segment.split('-').map(Number);
        
        if (!isNaN(start) && !isNaN(end) && start <= end) {
          for (let i = start; i <= end && i <= 65535; i++) {
            result.push(i);
          }
        }
      } 
      // Handle single port
      else {
        const port = Number(segment.trim());
        if (!isNaN(port) && port > 0 && port <= 65535) {
          result.push(port);
        }
      }
    }
    
    // Remove duplicates and sort
    return [...new Set(result)].sort((a, b) => a - b);
  }
}

/**
 * Main port scanning function that creates and runs a scanner
 * Backward compatibility wrapper for the PortScanner class
 */
export async function portScan(options: PortScannerOptions, progressCallback?: (progress: PortScanProgress) => void): Promise<PortScanResult[]> {
  const scanner = new PortScanner(options);
  
  // If a progress callback is provided, hook it up to the progress events
  if (progressCallback) {
    scanner.on('progress', progressCallback);
  }
  
  return scanner.start();
}