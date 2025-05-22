import { Request, Response } from 'express';
import { storage } from '../storage';
import { lookupDomain } from '../tools/whoisLookup';
import { InsertScanResult } from '@shared/schema';

// Controller for handling WHOIS lookup requests
export async function handleWhoisLookup(req: Request, res: Response) {
  const { domain, followIcannReferral, timeout, userId, results } = req.body;
  
  try {
    // If results are already provided (from WebSocket scan), just save them
    if (results && userId) {
      try {
        const scanResultData: InsertScanResult = {
          userId,
          toolId: 'whois-lookup',
          target: domain,
          results,
          status: 'completed',
          duration: '0s'
        };
        
        const savedResult = await storage.createScanResult(scanResultData);
        
        // Log tool execution
        await storage.createToolExecutionLog({
          userId,
          toolId: 'whois-lookup',
          parameters: {
            domain,
            followIcannReferral,
            timeout
          },
          sourceIp: req.ip,
          userAgent: req.headers['user-agent']
        });
        
        return res.json({
          success: true,
          message: 'WHOIS lookup results saved to database',
          scanId: savedResult.id
        });
      } catch (dbError) {
        console.error('Failed to save WHOIS lookup result to database:', dbError);
        return res.status(500).json({
          success: false, 
          message: `Failed to save scan result: ${(dbError as Error).message}`
        });
      }
    } else {
      // If no domain or userId provided, return error
      if (!domain) {
        return res.status(400).json({ 
          success: false, 
          message: "Domain is required" 
        });
      }
      
      if (!userId) {
        return res.status(400).json({ 
          success: false, 
          message: "userId is required to save results" 
        });
      }
      
      // Execute a WHOIS lookup directly
      const whoisOptions = {
        domain,
        followIcannReferral: followIcannReferral !== false,
        timeout: timeout || 10000
      };
      
      const lookupResults = await lookupDomain(whoisOptions);
      
      // Save to database
      const scanResultData: InsertScanResult = {
        userId,
        toolId: 'whois-lookup',
        target: domain,
        results: lookupResults,
        status: 'completed',
        duration: '1s' // Sample duration
      };
      
      const savedResult = await storage.createScanResult(scanResultData);
      
      // Return results
      return res.json({
        success: true,
        results: lookupResults,
        scanId: savedResult.id
      });
    }
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    res.status(500).json({ 
      success: false, 
      message: `WHOIS lookup failed: ${(error as Error).message}` 
    });
  }
}