import { Request, Response } from 'express';
import { analyzeHeaders, HeaderAnalyzerOptions } from '../tools/headerAnalyzer';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle HTTP header analysis requests via the API
 */
export async function handleHeaderAnalysis(req: Request, res: Response) {
  try {
    const { url, followRedirects, userAgent, timeout } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL is required'
      });
    }
    
    console.log(`[HeaderAnalyzer] Analyzing headers for: ${url}`);
    
    const options: HeaderAnalyzerOptions = {
      url,
      followRedirects: followRedirects || false,
      userAgent: userAgent || undefined,
      timeout: timeout || 10000
    };
    
    const results = await analyzeHeaders(options);
    
    // Create a scan result record
    try {
      const scanResultData: InsertScanResult = {
        userId: null, // We'll implement user auth later
        toolId: 'header-analyzer',
        target: url,
        results: results,
        status: 'completed'
      };
      
      const savedResult = await storage.createScanResult(scanResultData);
      
      // Add scan ID to results
      const responseData = {
        ...results,
        scanId: savedResult.id
      };
      
      return res.json({ 
        success: true, 
        data: responseData
      });
    } catch (dbError) {
      console.error('[HeaderAnalyzer] Error saving scan results:', dbError);
      // Still return the results even if saving to DB fails
      return res.json({ 
        success: true, 
        data: results,
        message: 'Results generated but not saved to database'
      });
    }
  } catch (error) {
    console.error('Header analysis error:', error);
    res.status(500).json({ 
      success: false, 
      message: `Header analysis failed: ${(error as Error).message}`
    });
  }
}