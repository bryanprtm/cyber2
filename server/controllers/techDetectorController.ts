import { Request, Response } from 'express';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle technology detection requests via the API
 */
export async function handleTechDetection(req: Request, res: Response) {
  try {
    const { url, timeout, userAgent, checkScripts, deepScan } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL parameter is required' 
      });
    }
    
    console.log(`[*] Starting tech detection for: ${url}`);
    
    const options: TechDetectorOptions = {
      url,
      timeout: timeout || 15000,
      userAgent: userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      checkScripts: checkScripts || true,
      deepScan: deepScan || false
    };
    
    const result = await detectTechnologies(options);
    
    // Store scan result in the database
    if (req.session?.userId) {
      try {
        const scanResultData: InsertScanResult = {
          userId: req.session.userId,
          toolId: 'tech-detector',
          target: url,
          results: result,
          status: 'completed',
          duration: `${result.scanTime}ms`
        };
        
        const savedScan = await storage.createScanResult(scanResultData);
        
        console.log(`[+] Tech detection scan saved with ID: ${savedScan.id}`);
      } catch (dbError) {
        console.error('Failed to save scan result:', dbError);
      }
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('Tech detection error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Tech detection failed'
    });
  }
}