import { useState, useCallback } from 'react';
import { v4 as uuidv4 } from 'uuid';

export interface TerminalLine {
  id: string;
  type: 'command' | 'success' | 'error' | 'info' | 'system';
  content: string;
  timestamp: Date;
}

export function useTerminal(maxLines: number = 100) {
  const [lines, setLines] = useState<TerminalLine[]>([]);

  const addLine = useCallback((type: TerminalLine['type'], content: string) => {
    const line: TerminalLine = {
      id: uuidv4(),
      type,
      content,
      timestamp: new Date()
    };

    setLines(prevLines => {
      const newLines = [...prevLines, line];
      // Keep only the last maxLines
      return newLines.slice(-maxLines);
    });

    return line.id;
  }, [maxLines]);

  const addCommandLine = useCallback((content: string) => {
    return addLine('command', content);
  }, [addLine]);

  const addSuccessLine = useCallback((content: string) => {
    return addLine('success', content);
  }, [addLine]);

  const addErrorLine = useCallback((content: string) => {
    return addLine('error', content);
  }, [addLine]);

  const addInfoLine = useCallback((content: string) => {
    return addLine('info', content);
  }, [addLine]);

  const addSystemLine = useCallback((content: string) => {
    return addLine('system', content);
  }, [addLine]);

  const clearLines = useCallback(() => {
    setLines([]);
  }, []);

  const removeLine = useCallback((id: string) => {
    setLines(prevLines => prevLines.filter(line => line.id !== id));
  }, []);

  return {
    lines,
    addLine,
    addCommandLine,
    addSuccessLine,
    addErrorLine,
    addInfoLine,
    addSystemLine,
    clearLines,
    removeLine
  };
}