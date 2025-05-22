import React, { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from '@/components/ui/badge';
import { 
  AlertTriangle, 
  Globe, 
  Shield, 
  Wifi, 
  Server, 
  Database,
  Clock,
  Zap,
  ExternalLink
} from 'lucide-react';
import { cn } from '@/lib/utils';

export default function CheckpointThreatMap() {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedView, setSelectedView] = useState<'live' | 'trends'>('live');

  // Set up loading state to provide feedback while iframe loads
  useEffect(() => {
    const iframe = iframeRef.current;
    if (!iframe) return;

    const handleLoad = () => {
      setIsLoading(false);
    };

    iframe.addEventListener('load', handleLoad);
    return () => {
      iframe.removeEventListener('load', handleLoad);
    };
  }, []);

  return (
    <Card className="bg-card border-primary/30 overflow-hidden">
      <div className="p-4 border-b border-primary/30 flex items-center justify-between">
        <h2 className="text-xl font-tech text-primary flex items-center">
          <Globe className="h-5 w-5 mr-2" />
          Live Cyber Threat Map
        </h2>
        <div className="flex items-center space-x-1 text-xs font-mono">
          <Clock className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">Live feed</span>
          <span className="ml-2 h-2 w-2 rounded-full bg-green-500 animate-pulse"></span>
        </div>
      </div>
      
      <Tabs defaultValue="live" className="w-full" onValueChange={(value) => setSelectedView(value as 'live' | 'trends')}>
        <div className="p-2 border-b border-border">
          <TabsList className="grid grid-cols-2">
            <TabsTrigger value="live" className="text-xs font-mono">Live Map</TabsTrigger>
            <TabsTrigger value="trends" className="text-xs font-mono">Trends & Stats</TabsTrigger>
          </TabsList>
        </div>
        
        <TabsContent value="live" className="p-0">
          <div className="relative w-full overflow-hidden bg-black" style={{ height: '500px' }}>
            {isLoading && (
              <div className="absolute inset-0 flex items-center justify-center bg-background/80 z-10">
                <div className="flex flex-col items-center">
                  <div className="loading-dots">
                    <div className="loading-dots--dot"></div>
                    <div className="loading-dots--dot"></div>
                    <div className="loading-dots--dot"></div>
                  </div>
                  <div className="mt-4 text-primary font-tech animate-pulse">
                    Loading Threat Intelligence...
                  </div>
                </div>
              </div>
            )}
            
            <iframe 
              ref={iframeRef}
              src="https://threatmap.checkpoint.com/"
              title="Check Point Live Cyber Threat Map"
              className="w-full h-full border-0"
              style={{ 
                height: '500px',
                width: '100%',
                backgroundColor: 'black',
                border: 'none'
              }}
              allowFullScreen
            />

            <div className="absolute bottom-4 right-4 flex gap-2">
              <a 
                href="https://threatmap.checkpoint.com/" 
                target="_blank" 
                rel="noopener noreferrer"
                className="bg-black/80 text-primary hover:bg-black p-2 rounded-md text-xs font-mono flex items-center"
              >
                <ExternalLink className="h-3 w-3 mr-1" />
                Open in new tab
              </a>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="trends" className="p-0">
          <div className="relative w-full overflow-hidden" style={{ height: '500px' }}>
            {isLoading && (
              <div className="absolute inset-0 flex items-center justify-center bg-background/80 z-10">
                <div className="flex flex-col items-center">
                  <div className="loading-dots">
                    <div className="loading-dots--dot"></div>
                    <div className="loading-dots--dot"></div>
                    <div className="loading-dots--dot"></div>
                  </div>
                  <div className="mt-4 text-primary font-tech animate-pulse">
                    Loading Threat Intelligence...
                  </div>
                </div>
              </div>
            )}
            
            <iframe 
              src="https://threatmap.checkpoint.com/ThreatPortal/livemap"
              title="Check Point Threat Portal Live Map"
              className="w-full h-full border-0"
              style={{ 
                height: '500px',
                width: '100%',
                backgroundColor: 'black',
                border: 'none'
              }}
              allowFullScreen
            />
          </div>
        </TabsContent>
      </Tabs>
      
      <div className="p-3 border-t border-border bg-black/20">
        <div className="flex items-center justify-between">
          <p className="text-xs font-mono text-muted-foreground">
            Powered by Check Point Research Threat Intelligence
          </p>
          <div className="flex items-center">
            <a 
              href="https://research.checkpoint.com/" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-xs font-mono text-primary hover:text-primary/80 flex items-center"
            >
              <Shield className="h-3 w-3 mr-1" />
              Check Point Research
            </a>
          </div>
        </div>
      </div>
      
      <style dangerouslySetInnerHTML={{
        __html: `
        .loading-dots {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
        }
        
        .loading-dots--dot {
          background-color: rgb(0, 255, 163);
          border-radius: 50%;
          width: 10px;
          height: 10px;
          animation: pulse 1.5s infinite ease-in-out;
        }
        
        .loading-dots--dot:nth-child(2) {
          animation-delay: 0.5s;
        }
        
        .loading-dots--dot:nth-child(3) {
          animation-delay: 1s;
        }
        
        @keyframes pulse {
          0%, 100% {
            opacity: 0.3;
            transform: scale(0.8);
          }
          50% {
            opacity: 1;
            transform: scale(1.2);
          }
        }
        `
      }} />
    </Card>
  );
}