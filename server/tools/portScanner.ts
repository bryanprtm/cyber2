import { createConnection, Socket } from 'net';

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

const COMMON_SERVICES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  465: 'SMTPS',
  587: 'SMTP (submission)',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  8080: 'HTTP Proxy',
  8443: 'HTTPS Alternate',
};

const DEFAULT_TIMEOUT = 3000; // 3 seconds
const DEFAULT_CONCURRENT = 50; // 50 concurrent connections

export async function portScan(options: PortScannerOptions): Promise<PortScanResult[]> {
  const portsToScan = parsePortRange(options.ports);
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const concurrent = options.concurrent || DEFAULT_CONCURRENT;
  const results: PortScanResult[] = [];
  
  // Process ports in batches to limit concurrent connections
  for (let i = 0; i < portsToScan.length; i += concurrent) {
    const batch = portsToScan.slice(i, i + concurrent);
    const batchPromises = batch.map(port => scanPort(options.target, port, timeout));
    
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
  }
  
  return results;
}

async function scanPort(host: string, port: number, timeout: number): Promise<PortScanResult> {
  return new Promise((resolve) => {
    const socket = createConnection({
      host: host,
      port: port,
      timeout: timeout
    });
    
    socket.on('connect', () => {
      const service = COMMON_SERVICES[port];
      socket.destroy();
      resolve({ port, status: 'open', service });
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, status: 'filtered' });
    });
    
    socket.on('error', (error) => {
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

function parsePortRange(ports: string): number[] {
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
  
  // Remove duplicates by using filter instead of Set for compatibility
  return result.filter((value, index, self) => self.indexOf(value) === index);
}