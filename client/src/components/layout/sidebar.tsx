import { useState } from "react";
import { cn } from "@/lib/utils";
import { useTools } from "@/hooks/use-tools";
import { 
  Bug, 
  NetworkIcon, 
  Fingerprint, 
  ShieldAlert, 
  Code, 
  KeyRound, 
  Terminal as TerminalIcon,
  History
} from "lucide-react";

interface SidebarProps {
  onCategorySelect: (category: string) => void;
  selectedCategory: string;
}

export default function Sidebar({ onCategorySelect, selectedCategory }: SidebarProps) {
  const { recentTools } = useTools();

  const categories = [
    { id: "vulnerability", name: "Vulnerability Scanning", icon: <Bug className="w-4 h-4 mr-2" /> },
    { id: "network", name: "Network Tools", icon: <NetworkIcon className="w-4 h-4 mr-2" /> },
    { id: "info", name: "Information Gathering", icon: <Fingerprint className="w-4 h-4 mr-2" /> },
    { id: "security", name: "Security Testing", icon: <ShieldAlert className="w-4 h-4 mr-2" /> },
    { id: "web", name: "Web Exploitation", icon: <Code className="w-4 h-4 mr-2" /> },
    { id: "password", name: "Password Tools", icon: <KeyRound className="w-4 h-4 mr-2" /> },
    { id: "shell", name: "Shell & Command Tools", icon: <TerminalIcon className="w-4 h-4 mr-2" /> },
  ];

  return (
    <div className="lg:w-1/4">
      <div className="bg-card rounded-md border border-primary/30">
        <div className="p-4 border-b border-primary/30">
          <h2 className="text-primary font-tech text-xl">Categories</h2>
        </div>
        <div className="p-2">
          <ul className="font-mono text-sm">
            {categories.map((category) => (
              <li 
                key={category.id}
                onClick={() => onCategorySelect(category.id)}
                className={cn(
                  "p-2 rounded mb-2 cursor-pointer transition-colors flex items-center",
                  selectedCategory === category.id 
                    ? "bg-primary/10 text-primary" 
                    : "hover:bg-secondary/10 hover:text-secondary"
                )}
              >
                {category.icon}
                {category.name}
              </li>
            ))}
          </ul>
        </div>
        <div className="p-4 border-t border-primary/30">
          <h2 className="text-primary font-tech text-xl mb-3">Recent Tools</h2>
          <ul className="text-xs font-code text-muted-foreground">
            {recentTools.length > 0 ? (
              recentTools.map((tool, index) => (
                <li key={index} className="mb-2 hover:text-primary cursor-pointer flex items-center">
                  <History className="w-3 h-3 mr-2" />
                  {tool.name}
                </li>
              ))
            ) : (
              <li className="text-muted-foreground">No recent tools</li>
            )}
          </ul>
        </div>
      </div>
      
      <div className="mt-6 bg-card rounded-md border border-accent/30 p-4">
        <h2 className="text-accent font-tech text-xl mb-3 flex items-center">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5 mr-2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
          Disclaimer
        </h2>
        <p className="text-xs font-mono text-muted-foreground">
          These tools are provided for educational and ethical testing purposes only. 
          Always obtain proper authorization before security testing any system or network.
        </p>
      </div>
    </div>
  );
}
