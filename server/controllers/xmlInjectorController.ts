import { Request, Response } from 'express';
import { testXmlInjection, XmlInjectorOptions } from '../tools/xmlInjector';
import { storage } from '../storage';
import { InsertScanResult } from '@shared/schema';

/**
 * Handle XML injection testing requests via the API
 */
export async function handleXmlInjectionTesting(req: Request, res: Response) {
  try {
    const {
      url,
      method,
      paramName,
      payloadType,
      customPayload,
      testAllParams,
      requestContentType,
      timeout,
      soapEndpoint,
      userId
    } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Create options object for the testing
    const options: XmlInjectorOptions = {
      url,
      method: method || 'POST',
      paramName: paramName || undefined,
      payloadType: payloadType || 'xxe',
      customPayload: customPayload || undefined,
      testAllParams: testAllParams !== undefined ? testAllParams : true,
      requestContentType: requestContentType || 'application/xml',
      timeout: timeout ? parseInt(timeout) : 5000,
      soapEndpoint: soapEndpoint === 'true' || soapEndpoint === true
    };

    // Run the test
    const result = await testXmlInjection(options);

    // Save scan result to database if userId is provided
    const scanUserId = userId || 1; // Use provided ID or fallback to demo ID
    try {
      const toolId = 'xml-injector';
      
      // Prepare scan result data
      const scanResultData: InsertScanResult = {
        userId: Number(scanUserId),
        toolId,
        target: url,
        results: JSON.stringify(result),
        status: 'completed',
        duration: `${result.scanTime}ms`
      };
      
      // Save to database
      const savedScan = await storage.createScanResult(scanResultData);
      console.log(`[+] XML injection scan saved with ID: ${savedScan.id}`);
      
      // Log tool execution
      await storage.createToolExecutionLog({
        userId: Number(scanUserId),
        toolId,
        parameters: JSON.stringify({ url, method, payloadType }),
        sourceIp: req.ip || '',
        userAgent: req.headers['user-agent'] || ''
      });
    } catch (dbError) {
      console.error('Failed to save scan result:', dbError);
      // Continue with response even if database save fails
    }

    // Return success response with result
    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (error: any) {
    console.error('XML Injection Testing error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error during XML injection testing: ' + error.message
    });
  }
}