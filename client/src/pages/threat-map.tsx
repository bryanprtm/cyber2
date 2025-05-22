import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { MatrixBackground } from "@/components/matrix-background";
import ThreatAnimation from "@/components/animations/threat-animation";
import { RefreshCw, AlertTriangle, Shield, Download, Maximize2 } from "lucide-react";

export default function ThreatMapPage() {
  const [intensity, setIntensity] = useState<number>(50);
  const [mapSize, setMapSize] = useState<"small" | "medium" | "large">("medium");
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  
  // Get dimensions based on selected size
  const getDimensions = () => {
    switch(mapSize) {
      case "small": return { width: 600, height: 400 };
      case "large": return { width: 1000, height: 700 };
      default: return { width: 800, height: 500 };
    }
  };
  
  const dimensions = getDimensions();
  
  // Handle fullscreen toggle
  const toggleFullscreen = () => {
    const element = document.documentElement;
    
    if (!isFullscreen) {
      if (element.requestFullscreen) {
        element.requestFullscreen();
      }
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
    }
    
    setIsFullscreen(!isFullscreen);
  };
  
  // Handle screenshot (simulation)
  const takeScreenshot = () => {
    // In a real implementation, this would capture the canvas content
    // and create a downloadable image
    alert("This would capture the current state of the threat map.");
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Real-Time Threat Map</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Visualize global cyber threats and attacks with dynamic particle effects that represent
          actual attack patterns and threat origins in real-time.
        </p>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card className="p-4 border-primary/30 bg-card">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-tech text-primary">Global Threat Visualization</h2>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
                  <RefreshCw className="h-4 w-4 mr-1" />
                  Refresh
                </Button>
                <Button variant="outline" size="sm" onClick={takeScreenshot}>
                  <Download className="h-4 w-4 mr-1" />
                  Capture
                </Button>
                <Button variant="outline" size="sm" onClick={toggleFullscreen}>
                  <Maximize2 className="h-4 w-4 mr-1" />
                  {isFullscreen ? "Exit" : "Fullscreen"}
                </Button>
              </div>
            </div>
            
            <div className="w-full h-auto bg-card relative">
              <ThreatAnimation 
                intensity={intensity} 
                width={dimensions.width} 
                height={dimensions.height}
                className="w-full h-auto border border-muted rounded-lg"
              />
              
              <div className="absolute top-3 right-3 bg-background/80 px-3 py-1 rounded text-xs font-mono flex items-center">
                <Shield className="h-3 w-3 mr-1 text-green-500" />
                <span>Live Visualization</span>
              </div>
            </div>
            
            <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-md text-sm">
              <div className="flex items-start">
                <AlertTriangle className="h-5 w-5 text-yellow-500 mr-2 mt-0.5" />
                <div>
                  <p className="font-semibold text-yellow-500">Simulation Note</p>
                  <p className="text-muted-foreground mt-1">
                    This is a simulated visualization for educational purposes. In a production environment, 
                    this would be connected to real-time threat intelligence feeds and security event data.
                  </p>
                </div>
              </div>
            </div>
          </Card>
        </div>
        
        <div className="lg:col-span-1">
          <Card className="p-4 border-secondary/30 bg-card">
            <h2 className="text-xl font-tech text-secondary mb-4">Visualization Controls</h2>
            
            <div className="space-y-6">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <Label htmlFor="intensity-slider">Attack Intensity</Label>
                  <span className="text-sm font-mono">{intensity}%</span>
                </div>
                <Slider
                  id="intensity-slider"
                  min={10}
                  max={100}
                  step={1}
                  value={[intensity]}
                  onValueChange={(values) => setIntensity(values[0])}
                  className="py-4"
                />
                <p className="text-xs text-muted-foreground">
                  Controls the frequency and intensity of attack traffic visualization.
                </p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="map-size">Map Size</Label>
                <Select value={mapSize} onValueChange={(val: "small" | "medium" | "large") => setMapSize(val)}>
                  <SelectTrigger id="map-size">
                    <SelectValue placeholder="Select map size" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="small">Small (600x400)</SelectItem>
                    <SelectItem value="medium">Medium (800x500)</SelectItem>
                    <SelectItem value="large">Large (1000x700)</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Adjust the visualization size to fit your screen.
                </p>
              </div>
              
              <div className="pt-4 space-y-2">
                <h3 className="text-sm font-semibold">Understanding the Visualization</h3>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start">
                    <div className="min-w-3 min-h-3 mt-1.5 rounded-full bg-red-500 mr-2" />
                    <span>Red/Orange dots with country codes represent attack origins from different countries</span>
                  </li>
                  <li className="flex items-start">
                    <div className="min-w-3 min-h-3 mt-1.5 rounded-full bg-green-500 mr-2" />
                    <span>Green circle in the center represents your protected server infrastructure</span>
                  </li>
                  <li className="flex items-start">
                    <div className="min-w-3 min-h-3 mt-1.5 rounded-full bg-blue-500 mr-2" />
                    <span>Blue particles represent defense mechanisms intercepting attacks</span>
                  </li>
                  <li className="flex items-start">
                    <div className="min-w-3 min-h-3 mt-1.5 rounded-full bg-purple-500 mr-2" />
                    <span>Connecting lines show attack paths from source to target</span>
                  </li>
                </ul>
              </div>
            </div>
          </Card>
          
          <Card className="mt-6 p-4 border-accent/30 bg-card">
            <h2 className="text-xl font-tech text-accent mb-4">Threat Stats</h2>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-muted/20 p-3 rounded-lg">
                  <div className="text-sm text-muted-foreground">Attack Events</div>
                  <div className="text-2xl font-mono mt-1">{Math.floor(Math.random() * 10000) + 5000}</div>
                </div>
                <div className="bg-muted/20 p-3 rounded-lg">
                  <div className="text-sm text-muted-foreground">Countries</div>
                  <div className="text-2xl font-mono mt-1">{Math.floor(Math.random() * 20) + 10}</div>
                </div>
                <div className="bg-muted/20 p-3 rounded-lg">
                  <div className="text-sm text-muted-foreground">Attack Types</div>
                  <div className="text-2xl font-mono mt-1">{Math.floor(Math.random() * 10) + 5}</div>
                </div>
                <div className="bg-muted/20 p-3 rounded-lg">
                  <div className="text-sm text-muted-foreground">Blocked</div>
                  <div className="text-2xl font-mono mt-1 text-green-500">{Math.floor(Math.random() * 30) + 90}%</div>
                </div>
              </div>
              
              <div className="mt-4">
                <h3 className="text-sm font-semibold mb-2">Top Attack Types</h3>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">DDoS Attacks</span>
                    <span className="text-xs font-mono">{Math.floor(Math.random() * 1000) + 1000}</span>
                  </div>
                  <div className="w-full bg-background rounded-full h-1.5">
                    <div className="bg-red-500 h-1.5 rounded-full" style={{ width: "65%" }}></div>
                  </div>
                  
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Brute Force</span>
                    <span className="text-xs font-mono">{Math.floor(Math.random() * 800) + 200}</span>
                  </div>
                  <div className="w-full bg-background rounded-full h-1.5">
                    <div className="bg-yellow-500 h-1.5 rounded-full" style={{ width: "45%" }}></div>
                  </div>
                  
                  <div className="flex justify-between items-center">
                    <span className="text-sm">XSS Attacks</span>
                    <span className="text-xs font-mono">{Math.floor(Math.random() * 500) + 100}</span>
                  </div>
                  <div className="w-full bg-background rounded-full h-1.5">
                    <div className="bg-purple-500 h-1.5 rounded-full" style={{ width: "30%" }}></div>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}