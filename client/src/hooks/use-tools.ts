import { useState, useCallback, useEffect } from "react";
import { Tool } from "@/data/tool-categories";

const RECENT_TOOLS_KEY = "cyberpulse-recent-tools";
const MAX_RECENT_TOOLS = 5;

export function useTools() {
  const [recentTools, setRecentTools] = useState<Tool[]>([]);
  
  // Load recent tools from local storage on init
  useEffect(() => {
    try {
      const storedTools = localStorage.getItem(RECENT_TOOLS_KEY);
      if (storedTools) {
        setRecentTools(JSON.parse(storedTools));
      }
    } catch (error) {
      console.error("Failed to load recent tools from localStorage:", error);
    }
  }, []);
  
  // Save recent tools to local storage when they change
  useEffect(() => {
    try {
      localStorage.setItem(RECENT_TOOLS_KEY, JSON.stringify(recentTools));
    } catch (error) {
      console.error("Failed to save recent tools to localStorage:", error);
    }
  }, [recentTools]);
  
  const addToolToRecents = useCallback((tool: Tool) => {
    setRecentTools(prev => {
      // Remove the tool if it already exists
      const filtered = prev.filter(t => t.id !== tool.id);
      
      // Add the tool to the beginning
      const updated = [tool, ...filtered];
      
      // Keep only the max number of recent tools
      return updated.slice(0, MAX_RECENT_TOOLS);
    });
  }, []);
  
  const clearRecentTools = useCallback(() => {
    setRecentTools([]);
  }, []);
  
  return {
    recentTools,
    addToolToRecents,
    clearRecentTools
  };
}
