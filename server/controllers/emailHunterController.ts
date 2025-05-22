import { Request, Response } from 'express';
import { findEmails, EmailHunterOptions } from '../tools/emailHunter';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle email hunting requests via the API
 */
export async function handleEmailHunting(req: Request, res: Response) {
  try {
    const { url, maxDepth, timeout, followLinks } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL is required'
      });
    }
    
    console.log(`[EmailHunter] Scanning for emails on: ${url}`);
    
    const options: EmailHunterOptions = {
      url,
      maxDepth: maxDepth || 1,
      timeout: timeout || 10000,
      followLinks: followLinks !== false
    };
    
    const results = await findEmails(options);
    
    // Create a scan result record
    try {
      const scanResultData: InsertScanResult = {
        userId: null, // We'll implement user auth later
        toolId: 'email-hunter',
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
      console.error('[EmailHunter] Error saving scan results:', dbError);
      // Still return the results even if saving to DB fails
      return res.json({ 
        success: true, 
        data: results,
        message: 'Results generated but not saved to database'
      });
    }
  } catch (error) {
    console.error('Email hunting error:', error);
    res.status(500).json({ 
      success: false, 
      message: `Email hunting failed: ${(error as Error).message}`
    });
  }
}