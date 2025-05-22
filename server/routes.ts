import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupWebSocketServer } from "./tools/wsServer";
import { handlePortScan, handlePingSweep, getScanHistory } from "./controllers/scanController";
import { handleHeaderAnalysis } from "./controllers/headerAnalyzerController";
import { handleEmailHunting } from "./controllers/emailHunterController";
import { handleShellUploaderAnalysis } from "./controllers/shellUploaderController";
import { handleTechDetection } from "./controllers/techDetectorController";
import { handlePasswordCheck } from "./controllers/passwordCheckerController";
import { handleFileScanning } from "./controllers/fileScannerController";
import { handleUrlScanning } from "./controllers/urlScannerController";
import { getAllTools, addTool, updateTool } from "./controllers/toolsController";
import multer from "multer";

export async function registerRoutes(app: Express): Promise<Server> {
  // API Routes - all prefixed with /api
  
  // Get available tools
  // Get all tools
  app.get("/api/tools", getAllTools);
  
  // Add a new tool
  app.post("/api/tools", addTool);
  
  // Update a tool
  app.put("/api/tools/:toolId", updateTool);
  
  // Port Scanner API - Using controller with database integration
  app.post("/api/scan/port", handlePortScan);
  
  // Ping Sweep API - Using controller with database integration
  app.post("/api/scan/ping-sweep", handlePingSweep);
  
  // Header Analyzer API - Using controller with database integration
  app.post("/api/analyze/headers", handleHeaderAnalysis);
  
  // Get scan history for a user
  app.get("/api/scan/history/:userId", getScanHistory);
  
  // Header Analyzer API is now handled by the controller at line 82
  
  // Email Hunter API 
  app.post("/api/scan/email-hunter", handleEmailHunting);
  
  // Shell Uploader API
  app.post("/api/scan/shell-uploader", handleShellUploaderAnalysis);
  
  // Tech Detector API
  app.post("/api/scan/tech-detector", handleTechDetection);
  
  // Password Checker API
  app.post("/api/security/password-checker", handlePasswordCheck);
  
  // File Scanner API - Uses multer for file upload handling
  const upload = multer({ storage: multer.memoryStorage() });
  app.post("/api/security/file-scanner", upload.single('file'), handleFileScanning);
  
  // URL Scanner API
  app.post("/api/security/url-scanner", handleUrlScanning);
  
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
