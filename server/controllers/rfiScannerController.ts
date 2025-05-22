import { Request, Response } from 'express';
import { scanForRfi, RfiScannerOptions } from '../tools/rfiScanner';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle RFI scanning requests via the API
 */
export async function handleRfiScanning(req: Request, res: Response) {
  try {
    const { 
      url, 
      paramName, 
      customPayloads,
      deepScan,
      scanRemoteHosts 
    } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting RFI scan for: ${url}`);
    
    // Configure scan options
    const options: RfiScannerOptions = {
      url,
      paramName: paramName || undefined,
      customPayloads: customPayloads ? customPayloads.split('\n').filter(Boolean) : undefined,
      deepScan: deepScan === 'true' || deepScan === true,
      scanRemoteHosts: scanRemoteHosts === 'true' || scanRemoteHosts === true
    };
    
    // Perform RFI scan
    const result = await scanForRfi(options);
    
    // Store scan result in the database
    // Note: Using a fixed userId (1) for demo purposes
    const userId = 1;
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'rfi-scanner',
        target: url,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] RFI scan saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('RFI scanning error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'RFI scanning failed'
    });
  }
}