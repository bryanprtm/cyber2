import { useState, useCallback } from "react";
import { useToast } from "@/hooks/use-toast";

export type TerminalLineType = "system" | "info" | "error" | "warning" | "command" | "output";

export interface TerminalLine {
  content: string;
  type: TerminalLineType;
  timestamp: Date;
}

export function useTerminal() {
  const [outputLines, setOutputLines] = useState<TerminalLine[]>([
    {
      content: "[SYSTEM] CyberPulse v1.0.2_alpha initialized",
      type: "system",
      timestamp: new Date()
    },
    {
      content: "[INFO] Loading security modules...",
      type: "info",
      timestamp: new Date()
    },
    {
      content: "[SYSTEM] System ready. Waiting for user input.",
      type: "system",
      timestamp: new Date()
    },
    {
      content: "[WARNING] Tools should only be used on authorized systems",
      type: "warning",
      timestamp: new Date()
    }
  ]);
  
  const { toast } = useToast();
  
  const addLine = useCallback((content: string, type: TerminalLineType) => {
    setOutputLines(prev => [
      ...prev, 
      { content, type, timestamp: new Date() }
    ]);
  }, []);
  
  const addSystemLine = useCallback((content: string) => {
    addLine(`[SYSTEM] ${content}`, "system");
  }, [addLine]);
  
  const addInfoLine = useCallback((content: string) => {
    addLine(`[INFO] ${content}`, "info");
  }, [addLine]);
  
  const addErrorLine = useCallback((content: string) => {
    addLine(`[ERROR] ${content}`, "error");
  }, [addLine]);
  
  const addWarningLine = useCallback((content: string) => {
    addLine(`[WARNING] ${content}`, "warning");
  }, [addLine]);
  
  const addCommandLine = useCallback((command: string) => {
    addLine(`user@cyberpulse:~$ ${command}`, "command");
  }, [addLine]);
  
  const addOutputLine = useCallback((output: string) => {
    addLine(output, "output");
  }, [addLine]);
  
  const clearTerminal = useCallback(() => {
    setOutputLines([
      {
        content: "[SYSTEM] Terminal cleared",
        type: "system",
        timestamp: new Date()
      }
    ]);
  }, []);
  
  const copyTerminalContent = useCallback(() => {
    const content = outputLines
      .map(line => line.content)
      .join('\n');
    
    navigator.clipboard.writeText(content)
      .then(() => {
        toast({
          title: "Copied to clipboard",
          description: "Terminal content has been copied to clipboard",
        });
      })
      .catch(err => {
        toast({
          title: "Copy failed",
          description: "Failed to copy terminal content: " + err.message,
          variant: "destructive"
        });
      });
  }, [outputLines, toast]);
  
  const downloadTerminalContent = useCallback(() => {
    const content = outputLines
      .map(line => `${line.timestamp.toISOString()} ${line.content}`)
      .join('\n');
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = `cyberpulse-terminal-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.log`;
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
    
    toast({
      title: "Log downloaded",
      description: "Terminal log has been downloaded",
    });
  }, [outputLines, toast]);
  
  return {
    outputLines,
    addLine,
    addSystemLine,
    addInfoLine,
    addErrorLine,
    addWarningLine,
    addCommandLine,
    addOutputLine,
    clearTerminal,
    copyTerminalContent,
    downloadTerminalContent
  };
}
