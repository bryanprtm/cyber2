import { Request, Response } from 'express';
import { analyzeShellUpload, ShellUploaderOptions } from '../tools/shellUploader';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle shell uploader analysis requests via the API
 */
export async function handleShellUploaderAnalysis(req: any, res: Response) {
  try {
    const { url, shellType, bypassWaf } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting shell uploader analysis for: ${url}`);
    
    const options: ShellUploaderOptions = {
      url,
      shellType: shellType || 'php',
      timeout: 15000,
      bypassWaf: bypassWaf || false
    };
    
    const result = await analyzeShellUpload(options);
    
    // Store scan result in the database
    if (req.session?.userId) {
      try {
        const scanResultData: InsertScanResult = {
          userId: req.session.userId,
          toolId: 'shell-uploader',
          target: url,
          results: result,
          status: 'completed',
          tags: ['security', 'vulnerability']
        };
        
        const savedScan = await storage.createScanResult(scanResultData);
        result.scanId = savedScan.id;
        
        console.log(`[+] Shell uploader scan saved with ID: ${savedScan.id}`);
      } catch (dbError) {
        console.error('Failed to save scan result:', dbError);
      }
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    console.error('Shell uploader analysis error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Shell uploader analysis failed'
    });
  }
}