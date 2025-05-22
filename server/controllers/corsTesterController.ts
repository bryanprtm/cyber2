import { Request, Response } from 'express';
import { testCors, CorsTesterOptions } from '../tools/corsTester';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle CORS testing requests via the API
 */
export async function handleCorsTesting(req: Request, res: Response) {
  try {
    const { 
      url, 
      methods, 
      headers,
      withCredentials 
    } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting CORS test for: ${url}`);
    
    // Configure test options
    const options: CorsTesterOptions = {
      url,
      methods: methods ? methods.split(',').map((m: string) => m.trim()) : undefined,
      headers: headers ? JSON.parse(headers) : undefined,
      withCredentials: withCredentials === 'true' || withCredentials === true
    };
    
    // Perform CORS test
    const result = await testCors(options);
    
    // Store scan result in the database
    // Note: Using a fixed userId (1) for demo purposes
    const userId = 1;
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'cors-tester',
        target: url,
        results: result,
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] CORS test saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('CORS testing error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'CORS testing failed'
    });
  }
}