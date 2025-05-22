import { Request, Response } from 'express';
import { storage } from '../storage';
import { InsertTool } from '@shared/schema';

/**
 * Get all available tools
 */
export async function getAllTools(req: Request, res: Response) {
  try {
    // Get tools from database
    const toolsFromDb = await storage.getAllTools();
    
    // Return tools from database
    res.json({
      success: true,
      tools: toolsFromDb
    });
  } catch (error: any) {
    console.error('Error fetching tools:', error);
    res.status(500).json({ 
      success: false, 
      message: `Failed to fetch tools: ${error.message}`
    });
  }
}

/**
 * Add a new tool to the database
 */
export async function addTool(req: Request, res: Response) {
  try {
    const toolData: InsertTool = req.body;
    
    if (!toolData.toolId || !toolData.name || !toolData.category) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields: toolId, name, category' 
      });
    }
    
    // Check if tool already exists
    const existingTool = await storage.getTool(toolData.toolId);
    if (existingTool) {
      return res.status(409).json({
        success: false,
        message: `Tool with ID '${toolData.toolId}' already exists`
      });
    }
    
    // Add new tool
    const newTool = await storage.createTool(toolData);
    
    res.status(201).json({
      success: true,
      tool: newTool
    });
  } catch (error: any) {
    console.error('Error adding tool:', error);
    res.status(500).json({ 
      success: false, 
      message: `Failed to add tool: ${error.message}`
    });
  }
}

/**
 * Update an existing tool
 */
export async function updateTool(req: Request, res: Response) {
  try {
    const { toolId } = req.params;
    const toolData = req.body;
    
    if (!toolId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tool ID is required' 
      });
    }
    
    // Check if tool exists
    const existingTool = await storage.getTool(toolId);
    if (!existingTool) {
      return res.status(404).json({
        success: false,
        message: `Tool with ID '${toolId}' not found`
      });
    }
    
    // Update tool
    const updatedTool = await storage.updateTool(toolId, toolData);
    
    res.json({
      success: true,
      tool: updatedTool
    });
  } catch (error: any) {
    console.error('Error updating tool:', error);
    res.status(500).json({ 
      success: false, 
      message: `Failed to update tool: ${error.message}`
    });
  }
}