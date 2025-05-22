import { Request, Response } from 'express';
import { scanFile, FileScannerOptions } from '../tools/fileScanner';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle file scanning requests via the API
 */
export async function handleFileScanning(req: any, res: Response) {
  try {
    // req.file is populated by multer middleware
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'No file uploaded' 
      });
    }
    
    const { 
      scanMalware = true, 
      scanVulnerabilities = true, 
      scanMetadata = true, 
      scanSensitiveData = true 
    } = req.body;
    
    console.log(`[*] Starting file scan for: ${req.file.originalname}`);
    
    const fileBuffer = req.file.buffer;
    const fileName = req.file.originalname;
    
    // Configure scan options
    const options: FileScannerOptions = {
      fileBuffer,
      fileName,
      scanMalware: scanMalware === 'true' || scanMalware === true,
      scanVulnerabilities: scanVulnerabilities === 'true' || scanVulnerabilities === true,
      scanMetadata: scanMetadata === 'true' || scanMetadata === true,
      scanSensitiveData: scanSensitiveData === 'true' || scanSensitiveData === true
    };
    
    // Perform file scan
    const result = await scanFile(options);
    
    // Store scan result in the database if user is logged in
    // Note: Using a fixed userId (1) for demo purposes
    const userId = 1;
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'file-scanner',
        target: fileName,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] File scan saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('File scanning error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'File scanning failed'
    });
  }
}