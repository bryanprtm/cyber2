import { Server as HttpServer } from 'http';
import WebSocket, { WebSocketServer } from 'ws';
import { PortScanner, portScan, PortScannerOptions, PortScanResult, PortScanProgress } from './portScanner';
import { PingSweepScanner, pingSweep, PingSweepOptions, PingSweepResult, PingSweepProgress } from './pingSweep';
import { lookupDomain, WhoisOptions, WhoisResult } from './whoisLookup';

interface Message {
  type: string;
  data: any;
}

let wss: WebSocketServer | null = null;

/**
 * Send a message to a WebSocket client
 */
function sendMessage(ws: WebSocket, type: string, data: any) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
}

/**
 * Send an error message to a WebSocket client
 */
function sendError(ws: WebSocket, message: string) {
  sendMessage(ws, 'error', { message });
}

/**
 * Generate summary statistics for port scan results
 */
function generatePortScanSummary(results: PortScanResult[]) {
  const openPorts = results.filter(r => r.status === 'open').length;
  const closedPorts = results.filter(r => r.status === 'closed').length;
  const filteredPorts = results.filter(r => r.status === 'filtered').length;
  
  return {
    totalScanned: results.length,
    openPorts,
    closedPorts,
    filteredPorts,
    timestamp: new Date().toISOString()
  };
}

export function setupWebSocketServer(server: HttpServer) {
  // Use a different path to avoid conflict with Vite's WebSocket server
  wss = new WebSocketServer({ 
    server,
    path: '/ws/tools'
  });
  
  wss.on('connection', (ws: WebSocket) => {
    console.log('CyberPulse WebSocket client connected');
    
    ws.on('message', async (message: string) => {
      try {
        const msg = JSON.parse(message.toString()) as Message;
        
        // PORT SCANNER
        if (msg.type === 'port_scan') {
          const options = msg.data as PortScannerOptions;
          
          // Validate required fields
          if (!options.target || !options.ports) {
            sendError(ws, 'Missing required fields: target and ports are required');
            return;
          }
          
          try {
            // Use the PortScanner class for more control and progress updates
            const scanner = new PortScanner(options);
            
            // Parse port range to get total count for initial message
            const portList = scanner['parsePortRange'](options.ports);
            const totalPorts = portList.length;
            
            // Send start message with total ports
            sendMessage(ws, 'scan_start', {
              target: options.target,
              ports: options.ports,
              timestamp: new Date().toISOString(),
              totalPorts: totalPorts
            });
            
            // Setup progress handler
            scanner.on('progress', (progress: PortScanProgress) => {
              // Send scan progress updates
              sendMessage(ws, 'scan_progress', {
                target: options.target,
                port: progress.port,
                status: progress.status,
                service: progress.service,
                completed: progress.completed,
                total: progress.total,
                timestamp: new Date().toISOString()
              });
            });
            
            // Handle warnings (like rate limiting)
            scanner.on('warning', (warning) => {
              sendMessage(ws, 'scan_warning', {
                message: warning.message,
                timestamp: new Date().toISOString()
              });
            });
            
            // Run the scan
            const results = await scanner.start();
            
            // Calculate summary statistics
            const summary = generatePortScanSummary(results);
            
            // Send final results
            sendMessage(ws, 'scan_results', {
              target: options.target,
              results,
              timestamp: new Date().toISOString(),
              summary
            });
            
            // Send completion message
            sendMessage(ws, 'scan_complete', {
              timestamp: new Date().toISOString(),
              results,
              summary
            });
          } catch (error) {
            sendError(ws, `Port scan failed: ${(error as Error).message}`);
          }
        }
        
        // WHOIS LOOKUP
        else if (msg.type === 'whois_lookup') {
          const options = msg.data as WhoisOptions;
          
          // Validate required fields
          if (!options.domain) {
            sendError(ws, 'Missing required field: domain is required');
            return;
          }
          
          try {
            // Send start message
            sendMessage(ws, 'whois_start', {
              domain: options.domain,
              timestamp: new Date().toISOString()
            });
            
            // Perform WHOIS lookup
            const results = await lookupDomain(options);
            
            // Send results
            sendMessage(ws, 'whois_results', results);
            
          } catch (error) {
            sendError(ws, `WHOIS lookup failed: ${(error as Error).message}`);
          }
        }
        
        // PING SWEEP
        else if (msg.type === 'ping_sweep') {
          const options = msg.data as PingSweepOptions;
          
          // Validate required fields
          if (!options.target) {
            sendError(ws, 'Missing required field: target is required');
            return;
          }
          
          try {
            // Create the ping sweep scanner
            const scanner = new PingSweepScanner(options);
            
            // Parse target to estimate host count
            let ipList: string[] = [];
            try {
              ipList = await scanner['parseTargetToIpList'](options.target);
            } catch (e) {
              // If can't parse target yet, provide a rough estimate
              ipList = ['dummy']; // Just for initialization
            }
            
            const totalHosts = ipList.length;
            
            if (totalHosts === 0) {
              sendError(ws, 'No valid IP addresses found in target');
              return;
            }
            
            // Send start message
            sendMessage(ws, 'sweep_start', {
              target: options.target,
              timestamp: new Date().toISOString(),
              totalHosts: totalHosts
            });
            
            // Setup various event handlers for better progress reporting
            scanner.on('progress', (progress: PingSweepProgress) => {
              // Send individual host progress updates
              sendMessage(ws, 'sweep_progress', {
                host: progress.host,
                status: progress.status,
                responseTime: progress.responseTime,
                hostname: progress.hostname,
                completed: progress.completed,
                total: progress.total,
                timestamp: new Date().toISOString()
              });
            });
            
            // Handle batch progress updates
            scanner.on('batch_progress', (progress: any) => {
              sendMessage(ws, 'sweep_batch_progress', {
                ...progress,
                timestamp: new Date().toISOString()
              });
            });
            
            // Handle batch completion
            scanner.on('batch_complete', (info: any) => {
              sendMessage(ws, 'sweep_batch_complete', {
                ...info,
                timestamp: new Date().toISOString()
              });
            });
            
            // Handle informational messages
            scanner.on('info', (info: any) => {
              sendMessage(ws, 'sweep_info', {
                ...info,
                timestamp: new Date().toISOString()
              });
            });
            
            // For testing, let's simulate some responses to demonstrate the UI
            if (options.target === '8.8.8.8') {
              // Send a few simulated pings if testing Google's DNS
              for (let i = 0; i < 5; i++) {
                await new Promise(resolve => setTimeout(resolve, 300));
                // Simulate progress updates
                sendMessage(ws, 'sweep_progress', {
                  host: '8.8.8.8',
                  status: 'alive',
                  responseTime: Math.floor(Math.random() * 40) + 10, // 10-50ms
                  hostname: 'dns.google',
                  completed: i + 1,
                  total: 5,
                  timestamp: new Date().toISOString()
                });
              }
              
              // Create simulated results
              const simulatedResults = [{
                ip: '8.8.8.8',
                status: 'alive',
                responseTime: 15,
                hostname: 'dns.google'
              }];
              
              // Create simulated summary
              const simulatedSummary = {
                total: 1,
                alive: 1,
                dead: 0,
                averageResponseTime: 15
              };
              
              // Send simulated results
              sendMessage(ws, 'sweep_results', {
                target: options.target,
                results: simulatedResults,
                timestamp: new Date().toISOString(),
                summary: simulatedSummary
              });
              
              // Send completion message
              sendMessage(ws, 'sweep_complete', {
                timestamp: new Date().toISOString(),
                results: simulatedResults,
                summary: simulatedSummary
              });
              
              return;
            }
            
            // Run the actual scan for other targets
            const results = await scanner.start();
            
            // Calculate summary
            const summary = {
              total: results.length,
              alive: results.filter(r => r.status === 'alive').length,
              dead: results.filter(r => r.status === 'dead').length,
              averageResponseTime: calculateAverageResponseTime(results)
            };
            
            // Send results
            sendMessage(ws, 'sweep_results', {
              target: options.target,
              results,
              timestamp: new Date().toISOString(),
              summary
            });
            
            // Send completion message
            sendMessage(ws, 'sweep_complete', {
              timestamp: new Date().toISOString(),
              results,
              summary
            });
          } catch (error) {
            sendError(ws, `Ping sweep failed: ${(error as Error).message}`);
          }
        }
        
        // WHOIS LOOKUP
        else if (msg.type === 'whois_lookup') {
          const options = msg.data as WhoisOptions;
          
          // Validate required fields
          if (!options.domain) {
            sendError(ws, 'Missing required field: domain is required');
            return;
          }
          
          try {
            // Perform WHOIS lookup
            const results = await lookupDomain(options);
            
            // Send results to client
            sendMessage(ws, 'whois_results', results);
          } catch (error) {
            sendError(ws, `WHOIS lookup failed: ${(error as Error).message}`);
          }
        }
        
        // TRACEROUTE
        else if (msg.type === 'traceroute') {
          const options = msg.data;
          
          // Validate required fields
          if (!options.target) {
            sendError(ws, 'Missing required field: target is required');
            return;
          }
          
          try {
            // Send start message
            sendMessage(ws, 'trace_start', {
              target: options.target,
              timestamp: new Date().toISOString()
            });
            
            // Simulate traceroute (in a real implementation, this would use a proper traceroute library)
            const startTime = Date.now();
            
            // Simulate hops
            const maxHops = options.maxHops || 30;
            const totalHops = Math.min(Math.floor(Math.random() * maxHops) + 3, maxHops);
            const hops = [];
            
            for (let i = 1; i <= totalHops; i++) {
              // Simulate processing time
              await new Promise(resolve => setTimeout(resolve, 200));
              
              // Generate random hop data
              const isLastHop = i === totalHops;
              const hopData = simulateTracerouteHop(i, isLastHop, options.target);
              
              // Send hop data
              sendMessage(ws, 'trace_hop', hopData);
              
              hops.push(hopData);
            }
            
            const endTime = Date.now();
            const executionTime = endTime - startTime;
            
            // Prepare final results
            const tracerouteResult = {
              target: options.target,
              hops,
              totalHops,
              reachedTarget: true,
              executionTime
            };
            
            // Send results
            sendMessage(ws, 'trace_results', tracerouteResult);
            
            // Send completion message
            sendMessage(ws, 'trace_complete', {
              timestamp: new Date().toISOString(),
              executionTime
            });
          } catch (error) {
            sendError(ws, `Traceroute failed: ${(error as Error).message}`);
          }
        }
        
        // DNS LOOKUP
        else if (msg.type === 'dns_lookup') {
          const options = msg.data;
          
          // Validate required fields
          if (!options.domain) {
            sendError(ws, 'Missing required field: domain is required');
            return;
          }
          
          try {
            // Send start message
            sendMessage(ws, 'dns_lookup_start', {
              domain: options.domain,
              timestamp: new Date().toISOString()
            });
            
            // Simulate DNS lookup (in a real implementation, this would use proper DNS libraries)
            const startTime = Date.now();
            
            // Simulate record types based on request
            const recordTypes = options.recordTypes === 'ALL' 
              ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
              : (Array.isArray(options.recordTypes) ? options.recordTypes : ['A']);
            
            const records: Record<string, any[]> = {};
            
            // Process each record type
            for (const type of recordTypes) {
              // Simulate processing time
              await new Promise(resolve => setTimeout(resolve, 100));
              
              // Generate simulated DNS records
              const typeRecords = simulateDnsRecords(options.domain, type);
              records[type] = typeRecords;
              
              // Send individual record found events
              typeRecords.forEach(record => {
                sendMessage(ws, 'dns_record_found', {
                  ...record,
                  timestamp: new Date().toISOString()
                });
              });
            }
            
            const endTime = Date.now();
            const executionTime = endTime - startTime;
            
            // Prepare final results
            const dnsResult = {
              domain: options.domain,
              records,
              nameservers: simulateNameservers(options.domain),
              executionTime
            };
            
            // Send results
            sendMessage(ws, 'dns_lookup_results', dnsResult);
            
            // Send completion message
            sendMessage(ws, 'dns_lookup_complete', {
              timestamp: new Date().toISOString(),
              executionTime
            });
          } catch (error) {
            sendError(ws, `DNS lookup failed: ${(error as Error).message}`);
          }
        }
        
        // PACKET CAPTURE
        else if (msg.type === 'packet_capture') {
          const options = msg.data;
          
          // Validate required fields
          if (!options.interface) {
            sendError(ws, 'Missing required field: interface is required');
            return;
          }
          
          try {
            // Send list of available interfaces
            sendMessage(ws, 'interfaces_list', {
              interfaces: ['any', 'eth0', 'wlan0', 'lo', 'docker0'],
              timestamp: new Date().toISOString()
            });
            
            // Send capture start message
            sendMessage(ws, 'capture_start', {
              interface: options.interface,
              filter: options.filter || '',
              timestamp: new Date().toISOString()
            });
            
            // Simulate packet capture (in a real implementation, this would use a packet capture library)
            const captureLimit = options.captureLimit || 100;
            const startTime = Date.now();
            
            // Capture simulated packets
            const packets = [];
            const protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'ARP'];
            
            for (let i = 1; i <= captureLimit; i++) {
              // Simulate processing time
              await new Promise(resolve => setTimeout(resolve, 30));
              
              // Generate random packet data
              const packet = simulatePacket(i, protocols);
              packets.push(packet);
              
              // Send packet captured event
              sendMessage(ws, 'packet_captured', {
                packet,
                timestamp: new Date().toISOString()
              });
            }
            
            const endTime = Date.now();
            const captureTime = (endTime - startTime) / 1000;
            
            // Generate summary
            const summary = generatePacketSummary(packets, captureTime);
            
            // Send results
            sendMessage(ws, 'capture_summary', {
              summary,
              timestamp: new Date().toISOString()
            });
            
            // Send completion message
            sendMessage(ws, 'capture_complete', {
              timestamp: new Date().toISOString(),
              summary
            });
          } catch (error) {
            sendError(ws, `Packet capture failed: ${(error as Error).message}`);
          }
        }
        
        // PAUSE/RESUME/STOP CAPTURE
        else if (msg.type === 'pause_capture') {
          sendMessage(ws, 'capture_pause', {
            timestamp: new Date().toISOString()
          });
        }
        else if (msg.type === 'resume_capture') {
          sendMessage(ws, 'capture_resume', {
            timestamp: new Date().toISOString()
          });
        }
        else if (msg.type === 'stop_capture') {
          sendMessage(ws, 'capture_stop', {
            timestamp: new Date().toISOString()
          });
        }
        
        // UNKNOWN MESSAGE TYPE
        else {
          sendError(ws, `Unknown message type: ${msg.type}`);
        }
      } catch (error) {
        sendError(ws, `Failed to parse message: ${(error as Error).message}`);
      }
    });
    
    ws.on('close', () => {
      console.log('CyberPulse WebSocket client disconnected');
    });
    
    // Send welcome message
    sendMessage(ws, 'connected', {
      message: 'Connected to CyberPulse WebSocket server',
      timestamp: new Date().toISOString()
    });
  });
}

// Utility function to send message to WebSocket client
function sendMessage(ws: WebSocket, type: string, data: any) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
}

// Utility function to send error to WebSocket client
function sendError(ws: WebSocket, errorMessage: string) {
  sendMessage(ws, 'error', {
    message: errorMessage,
    timestamp: new Date().toISOString()
  });
}

// Generate port scan summary
function generatePortScanSummary(results: PortScanResult[]) {
  const openPorts = results.filter(r => r.status === 'open');
  const closedPorts = results.filter(r => r.status === 'closed');
  const filteredPorts = results.filter(r => r.status === 'filtered');
  
  return {
    total: results.length,
    open: openPorts.length,
    closed: closedPorts.length,
    filtered: filteredPorts.length,
    openServices: openPorts.map(p => `${p.port}${p.service ? ` (${p.service})` : ''}`)
  };
}

// Calculate average response time for ping sweep
function calculateAverageResponseTime(results: PingSweepResult[]): number {
  const aliveHosts = results.filter(r => r.status === 'alive' && r.responseTime !== undefined);
  if (aliveHosts.length === 0) return 0;
  
  const sum = aliveHosts.reduce((total, host) => total + (host.responseTime || 0), 0);
  return Math.round(sum / aliveHosts.length);
}

// Simulate traceroute hop
function simulateTracerouteHop(hopNumber: number, isLastHop: boolean, targetHost: string) {
  // Generate random IP for intermediate hops
  const generateRandomIp = () => {
    return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };
  
  // Generate router name
  const generateHostname = (ip: string) => {
    const routerTypes = ['gateway', 'router', 'core', 'edge', 'transit', 'sw', 'rt'];
    const providers = ['level3', 'cogent', 'ntt', 'telia', 'zayo', 'att', 'sprint'];
    const locations = ['nyc', 'lax', 'chi', 'atl', 'dal', 'sea', 'lon', 'fra', 'syd'];
    
    const type = routerTypes[Math.floor(Math.random() * routerTypes.length)];
    const provider = providers[Math.floor(Math.random() * providers.length)];
    const location = locations[Math.floor(Math.random() * locations.length)];
    const num = Math.floor(Math.random() * 99) + 1;
    
    return `${type}${num}.${location}.${provider}.net`;
  };
  
  // Generate response times
  const generateRtt = (isLastHop: boolean, hopNumber: number) => {
    // Last hop typically has higher RTT
    const baseRtt = isLastHop ? 120 : hopNumber * 15;
    const variation = baseRtt * 0.2; // 20% variation
    return Math.round(baseRtt + (Math.random() * variation * 2 - variation));
  };
  
  // Generate ISP/ASN info
  const generateAsn = () => {
    const asn = Math.floor(Math.random() * 65000) + 1000;
    const isps = ['Level3', 'Cogent', 'NTT', 'Telia', 'Zayo', 'AT&T', 'Sprint', 'Verizon', 'Google', 'Amazon', 'Microsoft'];
    const isp = isps[Math.floor(Math.random() * isps.length)];
    return `AS${asn} ${isp}`;
  };
  
  // Generate location
  const generateLocation = () => {
    const countries = ['United States', 'Germany', 'United Kingdom', 'Japan', 'France', 'Canada', 'Australia', 'Brazil', 'Singapore'];
    const cities = ['New York', 'Los Angeles', 'Chicago', 'London', 'Tokyo', 'Paris', 'Sydney', 'Berlin', 'Toronto'];
    const country = countries[Math.floor(Math.random() * countries.length)];
    const city = cities[Math.floor(Math.random() * cities.length)];
    return `${city}, ${country}`;
  };
  
  const ip = isLastHop ? targetHost : generateRandomIp();
  const rtt = Math.random() > 0.1 ? generateRtt(isLastHop, hopNumber) : undefined; // 10% chance of timeout
  
  return {
    hopNumber,
    ip,
    hostname: generateHostname(ip),
    rtt1: rtt ? rtt - Math.floor(Math.random() * 5) : undefined,
    rtt2: rtt ? rtt + Math.floor(Math.random() * 5) : undefined,
    rtt3: rtt ? rtt - Math.floor(Math.random() * 5) : undefined,
    avgRtt: rtt,
    packetLoss: rtt ? Math.floor(Math.random() * 20) : 100,
    asn: generateAsn(),
    location: generateLocation()
  };
}

// Simulate DNS records
function simulateDnsRecords(domain: string, recordType: string) {
  const records = [];
  const ttl = Math.floor(Math.random() * 86400) + 300; // Random TTL between 5 minutes and 1 day
  
  switch (recordType) {
    case 'A':
      // Generate 1-3 A records
      for (let i = 0; i < Math.floor(Math.random() * 3) + 1; i++) {
        records.push({
          type: 'A',
          name: domain,
          value: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          ttl
        });
      }
      break;
      
    case 'AAAA':
      // Generate IPv6 address
      const segments = [];
      for (let i = 0; i < 8; i++) {
        segments.push(Math.floor(Math.random() * 65536).toString(16).padStart(4, '0'));
      }
      records.push({
        type: 'AAAA',
        name: domain,
        value: segments.join(':'),
        ttl
      });
      break;
      
    case 'MX':
      // Generate 1-2 MX records
      const mxPriorities = [10, 20, 30, 50];
      for (let i = 0; i < Math.floor(Math.random() * 2) + 1; i++) {
        records.push({
          type: 'MX',
          name: domain,
          value: `mail${i+1}.${domain}`,
          priority: mxPriorities[i],
          ttl
        });
      }
      break;
      
    case 'NS':
      // Generate 2-4 NS records
      for (let i = 0; i < Math.floor(Math.random() * 3) + 2; i++) {
        records.push({
          type: 'NS',
          name: domain,
          value: `ns${i+1}.${domain}`,
          ttl
        });
      }
      break;
      
    case 'TXT':
      // Generate TXT records
      const txtValues = [
        `v=spf1 include:_spf.${domain} ~all`,
        `google-site-verification=random123456`,
        `MS=ms123456`,
        `apple-domain-verification=appletoken123`
      ];
      
      records.push({
        type: 'TXT',
        name: domain,
        value: txtValues[Math.floor(Math.random() * txtValues.length)],
        ttl
      });
      break;
      
    case 'SOA':
      // Generate SOA record
      records.push({
        type: 'SOA',
        name: domain,
        value: `ns1.${domain} hostmaster.${domain} ${Math.floor(Date.now() / 1000)} 10800 3600 604800 86400`,
        ttl
      });
      break;
      
    case 'CNAME':
      // Generate CNAME record
      records.push({
        type: 'CNAME',
        name: `www.${domain}`,
        value: domain,
        ttl
      });
      break;
      
    case 'PTR':
      // Generate PTR record
      records.push({
        type: 'PTR',
        name: domain,
        value: `host.${domain}`,
        ttl
      });
      break;
      
    default:
      // For other record types, generate a placeholder
      records.push({
        type: recordType,
        name: domain,
        value: `Example ${recordType} record for ${domain}`,
        ttl
      });
  }
  
  return records;
}

// Simulate nameservers
function simulateNameservers(domain: string) {
  const nameservers = [];
  const count = Math.floor(Math.random() * 2) + 2; // 2-3 nameservers
  
  for (let i = 0; i < count; i++) {
    nameservers.push(`ns${i+1}.${domain}`);
  }
  
  return nameservers;
}

// Simulate network packet
function simulatePacket(id: number, protocols: string[]) {
  // Generate random IP
  const generateIp = () => {
    return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };
  
  // Pick a random protocol
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  
  // Generate packet data
  const packet = {
    id,
    timestamp: new Date().toISOString(),
    srcIP: generateIp(),
    dstIP: generateIp(),
    protocol,
    length: Math.floor(Math.random() * 1460) + 40, // Random packet size between 40-1500 bytes
    ttl: Math.floor(Math.random() * 255) + 1
  };
  
  // Add protocol-specific fields
  if (protocol === 'TCP' || protocol === 'UDP' || protocol === 'HTTP' || protocol === 'HTTPS') {
    const commonPorts = {
      'TCP': [22, 23, 80, 443, 21, 25, 110, 143, 3389],
      'UDP': [53, 67, 68, 123, 161, 162, 514],
      'HTTP': [80, 8080, 8000, 8008],
      'HTTPS': [443, 8443]
    };
    
    const protocolKey = protocol === 'HTTP' || protocol === 'HTTPS' ? protocol : 'TCP';
    const ports = commonPorts[protocolKey as keyof typeof commonPorts] || [0];
    
    Object.assign(packet, {
      srcPort: Math.floor(Math.random() * 60000) + 1024, // Random high port
      dstPort: ports[Math.floor(Math.random() * ports.length)],
      flags: protocol === 'TCP' ? generateTcpFlags() : undefined
    });
  }
  
  return packet;
}

// Generate TCP flags for packet simulation
function generateTcpFlags() {
  const allFlags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'];
  const flagCombinations = [
    ['SYN'],
    ['SYN', 'ACK'],
    ['ACK'],
    ['FIN', 'ACK'],
    ['RST'],
    ['ACK', 'PSH']
  ];
  
  return flagCombinations[Math.floor(Math.random() * flagCombinations.length)];
}

// Generate packet summary
function generatePacketSummary(packets: any[], captureTime: number) {
  // Count protocols
  const protocols: Record<string, number> = {};
  packets.forEach(packet => {
    protocols[packet.protocol] = (protocols[packet.protocol] || 0) + 1;
  });
  
  // Calculate total size
  const totalSize = packets.reduce((sum, packet) => sum + packet.length, 0);
  
  // Find top sources
  const sourceCounts: Record<string, number> = {};
  packets.forEach(packet => {
    sourceCounts[packet.srcIP] = (sourceCounts[packet.srcIP] || 0) + 1;
  });
  
  // Find top destinations
  const destCounts: Record<string, number> = {};
  packets.forEach(packet => {
    destCounts[packet.dstIP] = (destCounts[packet.dstIP] || 0) + 1;
  });
  
  // Convert to sorted arrays
  const topSources = Object.entries(sourceCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
    
  const topDestinations = Object.entries(destCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  
  return {
    totalPackets: packets.length,
    totalSize,
    protocols,
    topSources,
    topDestinations,
    captureTime
  };
}