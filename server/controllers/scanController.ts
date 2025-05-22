import { Request, Response } from 'express';
import { storage } from '../storage';
import { portScan, PortScannerOptions } from '../tools/portScanner';
import { pingSweep, PingSweepOptions } from '../tools/pingSweep';
import { InsertScanResult } from '@shared/schema';

// Controller for handling port scan requests
export async function handlePortScan(req: Request, res: Response) {
  const { target, ports, timeout, concurrent, userId } = req.body;
  
  if (!target) {
    return res.status(400).json({ 
      success: false, 
      message: "Target is required" 
    });
  }
  
  if (!ports) {
    return res.status(400).json({ 
      success: false, 
      message: "Ports range is required" 
    });
  }
  
  try {
    const startTime = Date.now();
    
    const options: PortScannerOptions = {
      target,
      ports,
      timeout: timeout || 3000,
      concurrent: concurrent || 50
    };
    
    // Perform the port scan
    const scanResults = await portScan(options);
    const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);
    
    // Filter results by status
    const openPorts = scanResults.filter(r => r.status === 'open');
    const closedPorts = scanResults.filter(r => r.status === 'closed');
    const filteredPorts = scanResults.filter(r => r.status === 'filtered');
    
    // Prepare response data
    const responseData = {
      target,
      scannedPorts: ports,
      openPorts: openPorts.map(p => ({ port: p.port, service: p.service })),
      closedPortsCount: closedPorts.length,
      filteredPortsCount: filteredPorts.length,
      totalPortsScanned: scanResults.length,
      scanDuration: `${scanDuration}s`
    };

    // Save scan result to database if userId is provided
    if (userId) {
      try {
        const scanResultData: InsertScanResult = {
          userId,
          toolId: 'port-scanner',
          target,
          results: scanResults,
          status: 'completed',
          duration: scanDuration
        };
        
        await storage.createScanResult(scanResultData);
        
        // Log tool execution
        await storage.createToolExecutionLog({
          userId,
          toolId: 'port-scanner',
          parameters: {
            target,
            ports,
            timeout,
            concurrent
          },
          sourceIp: req.ip,
          userAgent: req.headers['user-agent']
        });
      } catch (dbError) {
        console.error('Failed to save scan result to database:', dbError);
        // Continue with the response even if saving to DB fails
      }
    }

    // Return the scan results
    res.json({
      success: true,
      results: responseData
    });
  } catch (error) {
    console.error('Port scan error:', error);
    res.status(500).json({ 
      success: false, 
      message: `Port scan failed: ${(error as Error).message}` 
    });
  }
}

// Controller for handling ping sweep requests and saving results
export async function handlePingSweep(req: Request, res: Response) {
  const { target, timeout, parallel, retries, resolveHostnames, userId, toolId, results, duration } = req.body;
  
  try {
    // If results are already provided (from WebSocket scan), just save them
    if (results && userId) {
      try {
        const scanResultData: InsertScanResult = {
          userId,
          toolId: toolId || 'ping-sweep',
          target,
          results,
          status: 'completed',
          duration: duration || '0s'
        };
        
        const savedResult = await storage.createScanResult(scanResultData);
        
        // Log tool execution
        await storage.createToolExecutionLog({
          userId,
          toolId: toolId || 'ping-sweep',
          parameters: {
            target,
            timeout,
            parallel,
            retries,
            resolveHostnames
          },
          sourceIp: req.ip,
          userAgent: req.headers['user-agent']
        });
        
        return res.json({
          success: true,
          message: 'Ping sweep results saved to database',
          scanId: savedResult.id
        });
      } catch (dbError) {
        console.error('Failed to save ping sweep result to database:', dbError);
        return res.status(500).json({
          success: false, 
          message: `Failed to save scan result: ${(dbError as Error).message}`
        });
      }
    } else {
      // If no target or userId provided
      if (!target) {
        return res.status(400).json({ 
          success: false, 
          message: "Target is required" 
        });
      }
      
      if (!userId) {
        return res.status(400).json({ 
          success: false, 
          message: "userId is required to save results" 
        });
      }
      
      // Execute a new ping sweep (fallback if not coming from WebSocket)
      const options: PingSweepOptions = {
        target,
        timeout: timeout || 1000,
        parallel: parallel || 20,
        retries: retries || 1,
        resolveHostnames: resolveHostnames !== false
      };
      
      const startTime = Date.now();
      const scanResults = await pingSweep(options);
      const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2) + 's';
      
      // Save to database
      const scanResultData: InsertScanResult = {
        userId,
        toolId: 'ping-sweep',
        target,
        results: scanResults,
        status: 'completed',
        duration: scanDuration
      };
      
      const savedResult = await storage.createScanResult(scanResultData);
      
      // Return results
      return res.json({
        success: true,
        results: {
          aliveHosts: scanResults.filter(r => r.status === 'alive').length,
          totalHosts: scanResults.length,
          scanDuration
        },
        scanId: savedResult.id
      });
    }
  } catch (error) {
    console.error('Ping sweep error:', error);
    res.status(500).json({ 
      success: false, 
      message: `Ping sweep failed: ${(error as Error).message}` 
    });
  }
}

// Controller for retrieving scan history
export async function getScanHistory(req: Request, res: Response) {
  const { userId } = req.params;
  
  if (!userId || isNaN(parseInt(userId))) {
    return res.status(400).json({
      success: false,
      message: "Valid userId is required"
    });
  }
  
  try {
    const userIdNum = parseInt(userId);
    const results = await storage.getScanResultsByUser(userIdNum);
    
    res.json({
      success: true,
      count: results.length,
      results: results.map(result => ({
        id: result.id,
        target: result.target,
        toolId: result.toolId,
        scanTime: result.scanTime,
        status: result.status,
        duration: result.duration,
        openPortsCount: Array.isArray(result.results) 
          ? result.results.filter((r: any) => r.status === 'open').length 
          : 0
      }))
    });
  } catch (error) {
    console.error('Error retrieving scan history:', error);
    res.status(500).json({
      success: false,
      message: `Failed to retrieve scan history: ${(error as Error).message}`
    });
  }
}