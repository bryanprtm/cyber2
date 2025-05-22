import { Request, Response } from 'express';
import { testSqlInjection, getAllPayloads, SqlInjectorOptions } from '../tools/sqlInjector';
import { storage } from '../storage';
import { v4 as uuidv4 } from 'uuid';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle SQL injection testing requests via the API
 */
export async function handleSqlInjectionTesting(req: Request, res: Response) {
  try {
    const {
      url,
      method,
      paramName,
      payloadType,
      customPayload,
      dbType,
      testAllParams,
      timeDelay,
      userId
    } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Create options object for the testing
    const options: SqlInjectorOptions = {
      url,
      method: method || 'GET',
      paramName: paramName || undefined,
      payloadType: payloadType || 'error-based',
      customPayload: customPayload || undefined,
      dbType: dbType || 'generic',
      testAllParams: testAllParams !== undefined ? testAllParams : true,
      timeDelay: timeDelay || 300
    };

    // Run the test
    const result = await testSqlInjection(options);

    // Save scan result to database if userId is provided
    if (userId) {
      try {
        const toolId = 'sql-injector';
        
        // Prepare scan result data
        const scanResultData: InsertScanResult = {
          userId: Number(userId),
          toolId,
          target: url,
          results: JSON.stringify(result),
          status: 'completed'
        };
        
        // Save to database
        await storage.createScanResult(scanResultData);
        
        // Log tool execution
        await storage.createToolExecutionLog({
          userId: Number(userId),
          toolId,
          parameters: JSON.stringify({ url, method, payloadType }),
          sourceIp: req.ip || '',
          userAgent: req.headers['user-agent'] || ''
        });
      } catch (dbError) {
        console.error('Failed to save scan result:', dbError);
        // Continue with response even if database save fails
      }
    }

    // Return success response with result
    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (error: any) {
    console.error('SQL Injection Testing error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error during SQL injection testing: ' + error.message
    });
  }
}

/**
 * Get all available SQL injection payloads
 */
export async function getSqlInjectionPayloads(req: Request, res: Response) {
  try {
    const payloads = getAllPayloads();
    
    return res.status(200).json({
      success: true,
      data: payloads
    });
  } catch (error: any) {
    console.error('Error getting SQL injection payloads:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error retrieving SQL injection payloads: ' + error.message
    });
  }
}