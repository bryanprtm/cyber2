import { Request, Response } from 'express';
import { scanUrl, UrlScannerOptions } from '../tools/urlScanner';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle URL scanning requests via the API
 */
export async function handleUrlScanning(req: Request, res: Response) {
  try {
    const { 
      url, 
      checkPhishing, 
      checkMalware, 
      checkReputation 
    } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting URL scan for: ${url}`);
    
    // Configure scan options
    const options: UrlScannerOptions = {
      url,
      checkPhishing: checkPhishing === 'true' || checkPhishing === true,
      checkMalware: checkMalware === 'true' || checkMalware === true,
      checkReputation: checkReputation === 'true' || checkReputation === true
    };
    
    // Perform URL scan
    const result = await scanUrl(options);
    
    // Store scan result in the database if user is logged in
    // Note: Using a fixed userId (1) for demo purposes
    const userId = 1;
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'url-scanner',
        target: url,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] URL scan saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('URL scanning error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'URL scanning failed'
    });
  }
}