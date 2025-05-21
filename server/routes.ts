import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { portScan, PortScannerOptions } from "./tools/portScanner";
import { setupWebSocketServer } from "./tools/wsServer";

export async function registerRoutes(app: Express): Promise<Server> {
  // API Routes - all prefixed with /api
  
  // Get available tools
  app.get("/api/tools", (req, res) => {
    res.json({
      success: true,
      tools: [
        { id: "port-scanner", name: "Port Scanner", category: "vulnerability" },
        { id: "sql-injector", name: "SQL Injector", category: "vulnerability" },
        { id: "xss-detector", name: "XSS Detector", category: "vulnerability" },
        { id: "dns-lookup", name: "DNS Lookup", category: "network" },
        { id: "whois-lookup", name: "WHOIS Lookup", category: "info" }
      ]
    });
  });
  
  // Port Scanner API - Real implementation
  app.post("/api/scan/port", async (req, res) => {
    const { target, ports, timeout, concurrent } = req.body;
    
    if (!target) {
      return res.status(400).json({ success: false, message: "Target is required" });
    }
    
    if (!ports) {
      return res.status(400).json({ success: false, message: "Ports range is required" });
    }
    
    try {
      const startTime = Date.now();
      
      const options: PortScannerOptions = {
        target,
        ports,
        timeout: timeout || 3000,
        concurrent: concurrent || 50
      };
      
      const results = await portScan(options);
      const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);
      
      const openPorts = results.filter(r => r.status === 'open');
      
      res.json({
        success: true,
        results: {
          target,
          scannedPorts: ports,
          openPorts: openPorts.map(p => ({ port: p.port, service: p.service })),
          closedPorts: results.filter(r => r.status === 'closed').length,
          filteredPorts: results.filter(r => r.status === 'filtered').length,
          totalPorts: results.length,
          scanDuration: `${scanDuration}s`
        }
      });
    } catch (error) {
      console.error('Port scan error:', error);
      res.status(500).json({ 
        success: false, 
        message: `Port scan failed: ${(error as Error).message}` 
      });
    }
  });
  
  // HTTP Header Analyzer API
  app.post("/api/analyze/headers", (req, res) => {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ success: false, message: "URL is required" });
    }
    
    // In a real implementation, this would analyze the headers of the specified URL
    res.json({
      success: true,
      results: {
        url,
        headers: {
          "Server": "nginx/1.18.0",
          "Content-Type": "text/html; charset=UTF-8",
          "X-Frame-Options": "SAMEORIGIN",
          "X-XSS-Protection": "1; mode=block"
        },
        securityIssues: [
          "Missing HSTS header",
          "Missing Content-Security-Policy header"
        ]
      }
    });
  });
  
  // WHOIS Lookup API
  app.post("/api/lookup/whois", (req, res) => {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ success: false, message: "Domain is required" });
    }
    
    res.json({
      success: true,
      results: {
        domain,
        registrar: "Example Registrar, LLC",
        registeredOn: "2005-08-03",
        expiresOn: "2023-08-03",
        nameServers: ["ns1.example.com", "ns2.example.com"]
      }
    });
  });
  
  // DNS Lookup API
  app.post("/api/lookup/dns", (req, res) => {
    const { domain, recordType } = req.body;
    
    if (!domain) {
      return res.status(400).json({ success: false, message: "Domain is required" });
    }
    
    res.json({
      success: true,
      results: {
        domain,
        recordType: recordType || "A",
        records: ["192.168.1.1"]
      }
    });
  });

  const httpServer = createServer(app);
  
  // Setup WebSocket server for real-time communication
  setupWebSocketServer(httpServer);
  
  return httpServer;
}
