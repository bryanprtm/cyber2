import { Request, Response } from 'express';
import { fuzzForms, FormFuzzerOptions } from '../tools/formFuzzer';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle form fuzzing requests via the API
 */
export async function handleFormFuzzing(req: Request, res: Response) {
  try {
    const { 
      url, 
      depth, 
      fuzzerTypes,
      timeoutMs,
      maxForms,
      followRedirects,
      userId
    } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting form fuzzing for: ${url}`);
    
    // Configure fuzzer options
    const options: FormFuzzerOptions = {
      url,
      depth: depth ? parseInt(depth) : 1,
      fuzzerTypes: fuzzerTypes ? (Array.isArray(fuzzerTypes) ? fuzzerTypes : [fuzzerTypes]) : undefined,
      timeoutMs: timeoutMs ? parseInt(timeoutMs) : undefined,
      maxForms: maxForms ? parseInt(maxForms) : undefined,
      followRedirects: followRedirects === 'true' || followRedirects === true
    };
    
    // Perform form fuzzing
    const result = await fuzzForms(options);
    
    // Store scan result in the database
    const scanUserId = userId || 1; // Use provided ID or fallback to demo ID
    try {
      const scanResultData: InsertScanResult = {
        userId: Number(scanUserId),
        toolId: 'form-fuzzer',
        target: url,
        results: JSON.stringify(result),
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] Form fuzzing scan saved with ID: ${savedScan.id}`);
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('Form fuzzing error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Form fuzzing failed'
    });
  }
}