import { Request, Response } from 'express';
import { generateBeefHook, BeefXssOptions, BeefXssResult } from '../tools/beefXss';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle BeEF XSS hook generation requests via the API
 */
export async function handleBeefXss(req: Request, res: Response) {
  try {
    // Extract and validate options from request body
    const options: BeefXssOptions = {
      target: req.body.target,
      hookUrl: req.body.hookUrl,
      customHook: req.body.customHook,
      payloadType: req.body.payloadType,
      includeJquery: req.body.includeJquery,
      autorun: req.body.autorun,
      modules: req.body.modules
    };

    // Validate required parameters
    if (!options.target) {
      return res.status(400).json({
        error: 'Target URL is required'
      });
    }

    try {
      // Run the beef XSS hook generator
      const result = await generateBeefHook(options);
      
      // If user is authenticated, store the result
      const userId = req.body.userId || 1; // Default to user ID 1 if not authenticated
      if (userId) {
        const scanResultData: InsertScanResult = {
          userId,
          toolId: 'beef-xss',
          target: options.target,
          results: result,
          status: result.status,
          duration: `${result.scanTime}ms`
        };
        
        // Save scan result to database
        await storage.createScanResult(scanResultData);
        
        // Log tool execution
        await storage.createToolExecutionLog({
          userId,
          toolId: 'beef-xss',
          parameters: options,
          sourceIp: req.ip,
          userAgent: req.headers['user-agent']
        });
      }
      
      // Return the results
      return res.json(result);
    } catch (error) {
      console.error('BeEF XSS hook generation error:', error);
      return res.status(500).json({
        error: 'Error generating BeEF XSS hook',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  } catch (error) {
    console.error('BeEF XSS controller error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}