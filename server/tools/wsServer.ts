import { Server as HttpServer } from 'http';
import WebSocket, { WebSocketServer } from 'ws';
import { PortScanner, portScan, PortScannerOptions, PortScanResult, PortScanProgress } from './portScanner';
import { PingSweepScanner, pingSweep, PingSweepOptions, PingSweepResult, PingSweepProgress } from './pingSweep';

interface Message {
  type: string;
  data: any;
}

let wss: WebSocketServer | null = null;

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
        
        if (msg.type === 'port_scan') {
          const options = msg.data as PortScannerOptions;
          
          // Validate required fields
          if (!options.target || !options.ports) {
            sendError(ws, 'Missing required fields: target and ports are required');
            return;
          }
          
          // Send initial message
          sendMessage(ws, 'scan_start', {
            target: options.target,
            ports: options.ports,
            timestamp: new Date().toISOString()
          });
          
          try {
            // Use the PortScanner class for more control and progress updates
            const scanner = new PortScanner(options);
            
            // Parse port range to get total count for initial message
            const portList = scanner['parsePortRange'](options.ports);
            const totalPorts = portList.length;
            
            // Add total ports to the scan_start message
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
            const summary = generateSummary(results);
            
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
        } else {
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

function sendMessage(ws: WebSocket, type: string, data: any) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type, data }));
  }
}

function sendError(ws: WebSocket, errorMessage: string) {
  sendMessage(ws, 'error', {
    message: errorMessage,
    timestamp: new Date().toISOString()
  });
}

function generateSummary(results: PortScanResult[]) {
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