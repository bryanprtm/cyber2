import { Request, Response } from 'express';
import { scanForLfi, LfiScannerOptions } from '../tools/lfiScanner';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle LFI scanning requests via the API
 */
export async function handleLfiScanning(req: Request, res: Response) {
  try {
    const { 
      url, 
      paramName, 
      customPayloads,
      deepScan,
      scanCommonLocations 
    } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting LFI scan for: ${url}`);
    
    // Configure scan options
    const options: LfiScannerOptions = {
      url,
      paramName: paramName || undefined,
      customPayloads: customPayloads ? customPayloads.split('\n').filter(Boolean) : undefined,
      deepScan: deepScan === 'true' || deepScan === true,
      scanCommonLocations: scanCommonLocations === 'true' || scanCommonLocations === true
    };
    
    // Perform LFI scan
    const result = await scanForLfi(options);
    
    // Store scan result in the database
    // Note: Using a fixed userId (1) for demo purposes
    const userId = 1;
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'lfi-scanner',
        target: url,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] LFI scan saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('LFI scanning error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'LFI scanning failed'
    });
  }
}