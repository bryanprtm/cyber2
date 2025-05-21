import { useRef } from "react";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn, applyGlitchEffect } from "@/lib/utils";
import { Play } from "lucide-react";
import { useTerminal } from "@/hooks/use-terminal";

export interface ToolProps {
  id: string;
  name: string;
  description: string;
  category: string;
  categoryLabel: string;
  onUse: () => void;
}

export default function ToolCard({ id, name, description, category, categoryLabel, onUse }: ToolProps) {
  const { addCommandLine } = useTerminal();
  const cardRef = useRef<HTMLDivElement>(null);
  
  const handleRunTool = () => {
    if (Math.random() > 0.7) {
      applyGlitchEffect(cardRef.current);
    }
    
    addCommandLine(`run ${name.toLowerCase().replace(/\s+/g, '-')}`);
    onUse();
  };
  
  return (
    <Card 
      ref={cardRef}
      className="tool-card bg-[hsl(var(--terminal-bg))] border border-primary/30 overflow-hidden hover:border-primary"
    >
      <CardHeader className="p-3 border-b border-primary/30 flex justify-between items-center">
        <h3 className="text-primary font-tech">{name}</h3>
        <Badge variant="outline" className="bg-primary/10 text-primary py-1 px-2 rounded text-xs">
          {categoryLabel}
        </Badge>
      </CardHeader>
      <CardContent className="p-3">
        <p className="text-sm font-mono text-muted-foreground mb-3">{description}</p>
      </CardContent>
      <CardFooter className="p-3 pt-0">
        <a href={`/tools/${id}`} style={{ width: '100%' }}>
          <Button 
            variant="outline" 
            className="w-full bg-primary/10 hover:bg-primary/20 text-primary border-primary/50 font-code text-sm"
            onClick={handleRunTool}
          >
            <Play className="h-4 w-4 mr-2" />
            Run Tool
          </Button>
        </a>
      </CardFooter>
    </Card>
  );
}
