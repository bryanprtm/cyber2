import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { RotateCw, Settings } from "lucide-react";

interface SearchBarProps {
  onSearch: (searchTerm: string) => void;
  onReset: () => void;
}

export default function SearchBar({ onSearch, onReset }: SearchBarProps) {
  const [searchTerm, setSearchTerm] = useState("");
  
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setSearchTerm(value);
    onSearch(value);
  };
  
  const handleReset = () => {
    setSearchTerm("");
    onReset();
  };
  
  return (
    <div className="bg-card p-4 mb-6 border-b border-secondary/30">
      <div className="flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="relative flex-grow max-w-lg">
          <span className="absolute left-3 top-3 text-primary">&gt;</span>
          <Input
            type="text"
            placeholder="Search tools..."
            value={searchTerm}
            onChange={handleSearch}
            className="w-full bg-[hsl(var(--terminal-bg))] text-foreground py-2 px-8 border border-primary/50 focus:border-primary font-code pl-8"
          />
        </div>
        <div className="flex space-x-4">
          <Button 
            variant="outline" 
            className="bg-primary/10 hover:bg-primary/20 text-primary border-primary/50 font-tech"
            onClick={handleReset}
          >
            <RotateCw className="h-4 w-4 mr-2" />
            Reset
          </Button>
          <Button 
            variant="outline" 
            className="bg-secondary/10 hover:bg-secondary/20 text-secondary border-secondary/50 font-tech"
          >
            <Settings className="h-4 w-4 mr-2" />
            Settings
          </Button>
        </div>
      </div>
    </div>
  );
}
