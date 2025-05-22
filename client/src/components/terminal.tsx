import React, { useEffect, useRef } from 'react';
import { TerminalLine } from '@/hooks/use-terminal';
import { 
  AlertCircle, 
  Terminal as TerminalIcon, 
  CheckCircle2, 
  Info, 
  MonitorPlay 
} from 'lucide-react';

interface TerminalProps {
  lines: TerminalLine[];
  maxHeight?: string;
  className?: string;
}

const Terminal: React.FC<TerminalProps> = ({ 
  lines = [], 
  maxHeight = '300px',
  className = '' 
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the bottom when new lines are added
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [lines]);

  // Get icon for line type
  const getLineIcon = (type: TerminalLine['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircle2 className="h-4 w-4 text-green-500 mr-2 shrink-0" />;
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-500 mr-2 shrink-0" />;
      case 'info':
        return <Info className="h-4 w-4 text-blue-500 mr-2 shrink-0" />;
      case 'system':
        return <MonitorPlay className="h-4 w-4 text-purple-500 mr-2 shrink-0" />;
      case 'command':
        return <TerminalIcon className="h-4 w-4 text-amber-500 mr-2 shrink-0" />;
      default:
        return null;
    }
  };

  // Format timestamp
  const formatTimestamp = (date: Date) => {
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit',
      second: '2-digit',
      hour12: false 
    });
  };

  // Get class name for line type
  const getLineClassName = (type: TerminalLine['type']) => {
    switch (type) {
      case 'success':
        return 'text-green-500';
      case 'error':
        return 'text-red-500';
      case 'info':
        return 'text-blue-500';
      case 'system':
        return 'text-purple-500';
      case 'command':
        return 'text-amber-500 font-bold';
      default:
        return '';
    }
  };

  return (
    <div 
      className={`bg-black bg-opacity-80 text-white font-mono text-sm p-3 rounded-md overflow-auto ${className}`}
      style={{ maxHeight }}
      ref={terminalRef}
    >
      {lines && lines.length > 0 ? (
        lines.map((line) => (
          <div key={line.id} className="py-1 flex items-start">
            <span className="text-gray-500 text-xs mr-2 mt-0.5">
              {formatTimestamp(line.timestamp)}
            </span>
            {getLineIcon(line.type)}
            <div className={`break-words ${getLineClassName(line.type)}`}>
              {line.content}
            </div>
          </div>
        ))
      ) : (
        <div className="text-gray-500 italic">No output yet</div>
      )}
    </div>
  );
};

export default Terminal;