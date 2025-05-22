import { Request, Response } from 'express';
import { lookupDomain, WhoisOptions } from '../tools/whoisLookup';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle WHOIS lookup requests via the API
 */
export async function handleWhoisLookup(req: Request, res: Response) {
  const { domain, userId = 1, saveResults = true } = req.body;
  
  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      message: 'Domain is required' 
    });
  }
  
  try {
    // Configure WHOIS lookup options
    const options: WhoisOptions = {
      domain,
      followIcannReferral: req.body.followIcannReferral || true,
      timeout: req.body.timeout || 10000
    };
    
    // Perform WHOIS lookup
    console.log(`Performing WHOIS lookup for domain: ${domain}`);
    const results = await lookupDomain(options);
    
    // Save results to database if requested
    let scanResultId;
    if (saveResults) {
      try {
        // Prepare data for database
        const scanResultData: InsertScanResult = {
          userId: userId,
          toolId: 'whois-lookup',
          target: domain,
          results: JSON.stringify(results),
          status: 'completed'
        };
        
        // Save to database
        const scanResult = await storage.createScanResult(scanResultData);
        scanResultId = scanResult.id;
        console.log(`WHOIS lookup results saved with ID: ${scanResultId}`);
      } catch (dbError) {
        console.error('Failed to save WHOIS results to database:', dbError);
        // Continue even if database save fails
      }
    }
    
    // Return results
    res.json({
      success: true,
      results,
      scanResultId
    });
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    res.status(500).json({ 
      success: false, 
      message: `WHOIS lookup failed: ${(error as Error).message}`
    });
  }
}