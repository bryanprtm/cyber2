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
            // Create a scanner instance for event-based progress reporting
            const scanner = new PingSweepScanner(options);
            
            // Send start message
            sendMessage(ws, 'sweep_start', {
              target: options.target,
              timestamp: new Date().toISOString()
            });
            
            // Setup progress handler
            scanner.on('progress', (progress: PingSweepProgress) => {
              // Send progress updates
              sendMessage(ws, 'sweep_progress', {
                ...progress,
                timestamp: new Date().toISOString()
              });
            });
            
            // Run the scan
            const results = await scanner.start();
            
            // Send final results
            sendMessage(ws, 'sweep_results', {
              target: options.target,
              results,
              timestamp: new Date().toISOString(),
              summary: {
                total: results.length,
                alive: results.filter(r => r.status === 'alive').length,
                dead: results.filter(r => r.status === 'dead').length
              }
            });
            
          } catch (error) {
            sendError(ws, `Ping sweep failed: ${(error as Error).message}`);
          }
        }
        
        // Handle unknown message types
        else {
          console.warn(`Unknown message type: ${msg.type}`);
          sendError(ws, `Unknown message type: ${msg.type}`);
        }
        
      } catch (error) {
        console.error('Error processing WebSocket message:', error);
        sendError(ws, `Failed to process message: ${(error as Error).message}`);
      }
    });
    
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
    
    ws.on('close', () => {
      console.log('CyberPulse WebSocket client disconnected');
    });
  });
}