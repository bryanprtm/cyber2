import { useEffect, useState } from "react";

interface StatusBarProps {
  className?: string;
}

export default function StatusBar({ className }: StatusBarProps) {
  const [statusText, setStatusText] = useState("System ready. Select a tool to begin.");
  const [displayText, setDisplayText] = useState("");
  const [charIndex, setCharIndex] = useState(0);
  
  const messages = [
    "System ready. Select a tool to begin.",
    "All security modules loaded successfully.",
    "Scanning engines prepared. Awaiting target information.",
    "Remember to use these tools ethically and responsibly."
  ];
  
  // Type out effect
  useEffect(() => {
    if (charIndex < statusText.length) {
      const timer = setTimeout(() => {
        setDisplayText(prev => prev + statusText.charAt(charIndex));
        setCharIndex(prev => prev + 1);
      }, 35);
      
      return () => clearTimeout(timer);
    }
  }, [charIndex, statusText]);
  
  // Rotate messages
  useEffect(() => {
    const messageInterval = setInterval(() => {
      const nextIndex = (messages.indexOf(statusText) + 1) % messages.length;
      setStatusText(messages[nextIndex]);
      setDisplayText("");
      setCharIndex(0);
    }, 6000);
    
    return () => clearInterval(messageInterval);
  }, [statusText, messages]);
  
  return (
    <div className={`flex justify-between items-center bg-card p-3 rounded-t-md border-b border-primary/50 ${className}`}>
      <div className="text-primary font-code text-sm">
        <span id="status-text">{displayText}</span>
        <span className="cursor"></span>
      </div>
      <div className="flex space-x-3">
        <div className="h-3 w-3 rounded-full bg-primary"></div>
        <div className="h-3 w-3 rounded-full bg-secondary"></div>
        <div className="h-3 w-3 rounded-full bg-accent"></div>
      </div>
    </div>
  );
}
