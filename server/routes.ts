import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupWebSocketServer } from "./tools/wsServer";
import { handlePortScan, handlePingSweep, getScanHistory } from "./controllers/scanController";
import { handleHeaderAnalysis } from "./controllers/headerAnalyzerController";

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
  
  // Header Analyzer API - Using controller with database integration
  app.post("/api/analyze/headers", handleHeaderAnalysis);
  
  // Get scan history for a user
  app.get("/api/scan/history/:userId", getScanHistory);
  
  // Header Analyzer API is now handled by the controller at line 82
  
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
