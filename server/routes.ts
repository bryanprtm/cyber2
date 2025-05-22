import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupWebSocketServer } from "./tools/wsServer";
import { handlePortScan, handlePingSweep, getScanHistory } from "./controllers/scanController";
import { handleWhoisLookup } from "./controllers/whoisController";

export async function registerRoutes(app: Express): Promise<Server> {
  // API Routes - all prefixed with /api
  
  // Get available tools
  app.get("/api/tools", async (req, res) => {
    try {
      // Get tools from database
      const toolsFromDb = await storage.getAllTools();
      
      // If no tools in database, return default set
      if (toolsFromDb.length === 0) {
        return res.json({
          success: true,
          tools: [
            { 
              toolId: "port-scanner", 
              name: "Port Scanner", 
              description: "Scan for open ports on a target host",
              category: "network", 
              categoryLabel: "Network"
            },
            { 
              toolId: "sql-injector", 
              name: "SQL Injection Tester", 
              description: "Test for SQL injection vulnerabilities",
              category: "vulnerability", 
              categoryLabel: "Vulnerability"
            },
            { 
              toolId: "xss-detector", 
              name: "XSS Detector", 
              description: "Detect cross-site scripting vulnerabilities",
              category: "vulnerability", 
              categoryLabel: "Vulnerability"
            },
            { 
              toolId: "dns-lookup", 
              name: "DNS Lookup", 
              description: "Look up DNS records for a domain",
              category: "information", 
              categoryLabel: "Information"
            },
            { 
              toolId: "whois-lookup", 
              name: "WHOIS Lookup", 
              description: "Look up domain registration information",
              category: "information", 
              categoryLabel: "Information"
            }
          ]
        });
      }
      
      // Return tools from database
      res.json({
        success: true,
        tools: toolsFromDb
      });
    } catch (error) {
      console.error('Error fetching tools:', error);
      res.status(500).json({ 
        success: false, 
        message: `Failed to fetch tools: ${(error as Error).message}`
      });
    }
  });
  
  // Port Scanner API - Using controller with database integration
  app.post("/api/scan/port", handlePortScan);
  
  // Ping Sweep API - Using controller with database integration
  app.post("/api/scan/ping-sweep", handlePingSweep);
  
  // WHOIS Lookup API - Using controller with database integration
  app.post("/api/lookup/whois", handleWhoisLookup);
  
  // Get scan history for a user
  app.get("/api/scan/history/:userId", getScanHistory);
  
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
  
  // Note: WHOIS Lookup API is now handled by the controller at line 82
  
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
