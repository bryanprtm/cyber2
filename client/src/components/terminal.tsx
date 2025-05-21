import { useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { useTerminal } from "@/hooks/use-terminal";
import { Copy, Download, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface TerminalProps {
  className?: string;
}

export default function Terminal({ className }: TerminalProps) {
  const { 
    outputLines, 
    clearTerminal, 
    copyTerminalContent, 
    downloadTerminalContent 
  } = useTerminal();
  
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [outputLines]);

  return (
    <div className={cn("terminal rounded-md", className)}>
      <div className="bg-[hsl(var(--terminal-bg))] p-2 rounded-t flex justify-between items-center border-b border-primary/30">
        <div className="text-primary font-tech text-sm">Terminal Output</div>
        <div className="flex space-x-2">
          <Tooltip content="Copy content">
            <Button 
              variant="ghost" 
              size="icon" 
              className="text-secondary hover:text-primary transition-colors h-6 w-6"
              onClick={copyTerminalContent}
            >
              <Copy className="h-4 w-4" />
              <span className="sr-only">Copy</span>
            </Button>
          </Tooltip>
          <Tooltip content="Download log">
            <Button 
              variant="ghost" 
              size="icon" 
              className="text-secondary hover:text-primary transition-colors h-6 w-6"
              onClick={downloadTerminalContent}
            >
              <Download className="h-4 w-4" />
              <span className="sr-only">Download</span>
            </Button>
          </Tooltip>
          <Tooltip content="Clear terminal">
            <Button 
              variant="ghost" 
              size="icon" 
              className="text-secondary hover:text-primary transition-colors h-6 w-6"
              onClick={clearTerminal}
            >
              <Trash2 className="h-4 w-4" />
              <span className="sr-only">Clear</span>
            </Button>
          </Tooltip>
        </div>
      </div>
      <div 
        ref={terminalRef}
        className="p-4 font-code text-sm text-foreground h-64 overflow-y-auto bg-[hsl(var(--terminal-bg))]"
      >
        {outputLines.map((line, index) => (
          <div 
            key={index} 
            className={cn(
              "mb-2",
              line.type === "system" && "text-primary",
              line.type === "info" && "text-secondary", 
              line.type === "error" && "text-accent",
              line.type === "warning" && "text-accent",
              line.type === "success" && "text-green-500",
              line.type === "command" && "text-primary"
            )}
          >
            {line.content}
          </div>
        ))}
        <div className="text-primary">
          user@cyberpulse:~$ <span className="cursor"></span>
        </div>
      </div>
    </div>
  );
}
