import { useState, useCallback } from 'react';

export interface TerminalLine {
  id: string;
  type: 'command' | 'success' | 'error' | 'info' | 'system';
  content: string;
  timestamp: Date;
}

export function useTerminal() {
  const [lines, setLines] = useState<TerminalLine[]>([]);

  // Add a line to the terminal
  const addLine = useCallback((content: string, type: TerminalLine['type']) => {
    const line: TerminalLine = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      content,
      timestamp: new Date(),
    };
    
    setLines((prevLines) => [...prevLines, line]);
    return line.id;
  }, []);

  // Clear all lines from the terminal
  const clearTerminal = useCallback(() => {
    setLines([]);
  }, []);

  // Shorthand methods for different line types
  const addCommandLine = useCallback((content: string) => addLine(content, 'command'), [addLine]);
  const addSuccessLine = useCallback((content: string) => addLine(content, 'success'), [addLine]);
  const addErrorLine = useCallback((content: string) => addLine(content, 'error'), [addLine]);
  const addInfoLine = useCallback((content: string) => addLine(content, 'info'), [addLine]);
  const addSystemLine = useCallback((content: string) => addLine(content, 'system'), [addLine]);

  return {
    lines,
    addLine,
    clearTerminal,
    addCommandLine,
    addSuccessLine,
    addErrorLine,
    addInfoLine,
    addSystemLine,
  };
}