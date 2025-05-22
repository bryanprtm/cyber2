import { Request, Response } from 'express';
import { checkPassword, PasswordCheckerOptions } from '../tools/passwordChecker';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle password check requests via the API
 */
export async function handlePasswordCheck(req: Request, res: Response) {
  try {
    const { password, checkLeaked } = req.body;
    
    if (!password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password parameter is required' 
      });
    }
    
    console.log(`[*] Starting password check analysis`);
    
    const options: PasswordCheckerOptions = {
      password,
      checkLeaked: checkLeaked || false
    };
    
    const result = await checkPassword(options);
    
    // Store scan result in the database if user is logged in
    const userId = 1; // Default for demo purposes
    try {
      const scanResultData: InsertScanResult = {
        userId: userId,
        toolId: 'password-checker',
        target: 'Password analysis',
        results: result,
        status: 'completed',
        duration: '100ms' // Placeholder
      };
      
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] Password check scan saved with ID: ${savedScan.id}`);
      
      // Add scanId to result
      result['scanId'] = savedScan.id;
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
    }
    
    return res.json({
      success: true,
      data: result
    });
    
  } catch (error: any) {
    console.error('Password check error:', error);
    
    return res.status(500).json({
      success: false,
      message: error.message || 'Password check failed'
    });
  }
}