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
  Zap
} from 'lucide-react';
import { cn } from '@/lib/utils';

// Interface for attack data
interface Attack {
  id: string;
  source: {
    country: string;
    ip: string;
    latitude: number;
    longitude: number;
  };
  destination: {
    country: string;
    ip: string;
    latitude: number;
    longitude: number;
  };
  type: 'malware' | 'ddos' | 'intrusion' | 'phishing' | 'ransomware';
  timestamp: Date;
}

// Simulate a constant stream of cyber attacks
const generateAttacks = (): Attack[] => {
  // Common attack sources
  const sources = [
    { country: 'Russia', latitude: 55.7558, longitude: 37.6173 },
    { country: 'China', latitude: 39.9042, longitude: 116.4074 },
    { country: 'North Korea', latitude: 39.0392, longitude: 125.7625 },
    { country: 'Iran', latitude: 35.6892, longitude: 51.3890 },
    { country: 'Brazil', latitude: -15.7801, longitude: -47.9292 },
    { country: 'Nigeria', latitude: 9.0765, longitude: 7.3986 },
    { country: 'Ukraine', latitude: 50.4501, longitude: 30.5234 },
    { country: 'India', latitude: 28.6139, longitude: 77.2090 },
    { country: 'USA', latitude: 37.7749, longitude: -122.4194 },
    { country: 'Romania', latitude: 44.4268, longitude: 26.1025 },
  ];
  
  // Common attack destinations
  const destinations = [
    { country: 'USA', latitude: 38.9072, longitude: -77.0369 },
    { country: 'UK', latitude: 51.5074, longitude: -0.1278 },
    { country: 'Germany', latitude: 52.5200, longitude: 13.4050 },
    { country: 'France', latitude: 48.8566, longitude: 2.3522 },
    { country: 'Japan', latitude: 35.6762, longitude: 139.6503 },
    { country: 'South Korea', latitude: 37.5665, longitude: 126.9780 },
    { country: 'Australia', latitude: -35.2809, longitude: 149.1300 },
    { country: 'Canada', latitude: 45.4215, longitude: -75.6972 },
    { country: 'Netherlands', latitude: 52.3676, longitude: 4.9041 },
    { country: 'Sweden', latitude: 59.3293, longitude: 18.0686 },
  ];
  
  // Attack types
  const attackTypes: ('malware' | 'ddos' | 'intrusion' | 'phishing' | 'ransomware')[] = 
    ['malware', 'ddos', 'intrusion', 'phishing', 'ransomware'];
  
  // Generate random attacks
  const attacks: Attack[] = [];
  
  for (let i = 0; i < 20; i++) {
    const sourceIndex = Math.floor(Math.random() * sources.length);
    const destIndex = Math.floor(Math.random() * destinations.length);
    const typeIndex = Math.floor(Math.random() * attackTypes.length);
    
    // Generate random IPs
    const sourceIp = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const destIp = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    
    // Generate random timestamp within the last hour
    const timestamp = new Date();
    timestamp.setMinutes(timestamp.getMinutes() - Math.floor(Math.random() * 60));
    
    attacks.push({
      id: `attack-${i}-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      source: {
        country: sources[sourceIndex].country,
        ip: sourceIp,
        latitude: sources[sourceIndex].latitude + (Math.random() * 2 - 1),
        longitude: sources[sourceIndex].longitude + (Math.random() * 2 - 1),
      },
      destination: {
        country: destinations[destIndex].country,
        ip: destIp,
        latitude: destinations[destIndex].latitude + (Math.random() * 2 - 1),
        longitude: destinations[destIndex].longitude + (Math.random() * 2 - 1),
      },
      type: attackTypes[typeIndex],
      timestamp,
    });
  }
  
  return attacks.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
};

// World map dimensions
const MAP_WIDTH = 800;
const MAP_HEIGHT = 400;

// Convert latitude and longitude to x, y coordinates on the map
const convertToXY = (lat: number, lon: number): [number, number] => {
  // Simple approximation for demo purposes
  const x = (lon + 180) * (MAP_WIDTH / 360);
  const y = (90 - lat) * (MAP_HEIGHT / 180);
  return [x, y];
};

export default function ThreatMap() {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [filteredAttacks, setFilteredAttacks] = useState<Attack[]>([]);
  const [filter, setFilter] = useState<string>('all');
  const [activeAttacks, setActiveAttacks] = useState<string[]>([]);
  const [stats, setStats] = useState({
    malware: 0,
    ddos: 0,
    intrusion: 0,
    phishing: 0,
    ransomware: 0,
    total: 0
  });
  
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>();
  
  // Initialize attacks
  useEffect(() => {
    const initialAttacks = generateAttacks();
    setAttacks(initialAttacks);
    setFilteredAttacks(initialAttacks);
    
    // Calculate stats
    const newStats = {
      malware: initialAttacks.filter(a => a.type === 'malware').length,
      ddos: initialAttacks.filter(a => a.type === 'ddos').length,
      intrusion: initialAttacks.filter(a => a.type === 'intrusion').length,
      phishing: initialAttacks.filter(a => a.type === 'phishing').length,
      ransomware: initialAttacks.filter(a => a.type === 'ransomware').length,
      total: initialAttacks.length
    };
    setStats(newStats);
    
    // Continuously add new attacks
    const interval = setInterval(() => {
      const newAttack = generateAttacks()[0]; // Get one new attack
      
      setAttacks(prev => {
        const updated = [newAttack, ...prev.slice(0, 19)]; // Keep only the 20 most recent
        
        // Update stats
        const updatedStats = {
          malware: updated.filter(a => a.type === 'malware').length,
          ddos: updated.filter(a => a.type === 'ddos').length,
          intrusion: updated.filter(a => a.type === 'intrusion').length,
          phishing: updated.filter(a => a.type === 'phishing').length,
          ransomware: updated.filter(a => a.type === 'ransomware').length,
          total: updated.length
        };
        setStats(updatedStats);
        
        // Update filtered attacks if needed
        if (filter === 'all' || filter === newAttack.type) {
          setFilteredAttacks(prev => [newAttack, ...prev.slice(0, 19)]);
        }
        
        return updated;
      });
      
      // Create unique ID for new attack
      const uniqueId = `${newAttack.id}-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
      newAttack.id = uniqueId;
      
      // Add to active attacks for animation
      setActiveAttacks(prev => [...prev, uniqueId]);
      
      // Remove from active attacks after animation completes
      setTimeout(() => {
        setActiveAttacks(prev => prev.filter(id => id !== uniqueId));
      }, 3000);
      
    }, 3000); // New attack every 3 seconds
    
    return () => clearInterval(interval);
  }, []);
  
  // Handle filter changes
  useEffect(() => {
    if (filter === 'all') {
      setFilteredAttacks(attacks);
    } else {
      setFilteredAttacks(attacks.filter(attack => attack.type === filter));
    }
  }, [filter, attacks]);
  
  // Draw the map and attack paths
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Set canvas size
    canvas.width = MAP_WIDTH;
    canvas.height = MAP_HEIGHT;
    
    const drawMap = () => {
      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Draw world map background
      ctx.fillStyle = 'rgba(25, 25, 35, 0.6)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Draw grid lines
      ctx.strokeStyle = 'rgba(0, 255, 180, 0.1)';
      ctx.lineWidth = 0.5;
      
      // Vertical grid lines
      for (let i = 0; i <= canvas.width; i += 50) {
        ctx.beginPath();
        ctx.moveTo(i, 0);
        ctx.lineTo(i, canvas.height);
        ctx.stroke();
      }
      
      // Horizontal grid lines
      for (let i = 0; i <= canvas.height; i += 50) {
        ctx.beginPath();
        ctx.moveTo(0, i);
        ctx.lineTo(canvas.width, i);
        ctx.stroke();
      }
      
      // Draw continents (simplified)
      ctx.fillStyle = 'rgba(55, 65, 81, 0.5)';
      
      // North America
      ctx.beginPath();
      ctx.arc(150, 120, 50, 0, Math.PI * 2);
      ctx.fill();
      
      // South America
      ctx.beginPath();
      ctx.arc(200, 250, 40, 0, Math.PI * 2);
      ctx.fill();
      
      // Europe
      ctx.beginPath();
      ctx.arc(400, 100, 30, 0, Math.PI * 2);
      ctx.fill();
      
      // Africa
      ctx.beginPath();
      ctx.arc(400, 200, 45, 0, Math.PI * 2);
      ctx.fill();
      
      // Asia
      ctx.beginPath();
      ctx.arc(550, 150, 70, 0, Math.PI * 2);
      ctx.fill();
      
      // Australia
      ctx.beginPath();
      ctx.arc(650, 280, 25, 0, Math.PI * 2);
      ctx.fill();
      
      // Draw attack paths
      filteredAttacks.forEach(attack => {
        const isActive = activeAttacks.includes(attack.id);
        const [sourceX, sourceY] = convertToXY(attack.source.latitude, attack.source.longitude);
        const [destX, destY] = convertToXY(attack.destination.latitude, attack.destination.longitude);
        
        // Draw path
        ctx.beginPath();
        ctx.moveTo(sourceX, sourceY);
        ctx.lineTo(destX, destY);
        
        // Set path style based on attack type and activity
        let pathColor;
        switch(attack.type) {
          case 'malware':
            pathColor = isActive ? 'rgba(220, 38, 38, 0.8)' : 'rgba(220, 38, 38, 0.3)';
            break;
          case 'ddos':
            pathColor = isActive ? 'rgba(234, 179, 8, 0.8)' : 'rgba(234, 179, 8, 0.3)';
            break;
          case 'intrusion':
            pathColor = isActive ? 'rgba(59, 130, 246, 0.8)' : 'rgba(59, 130, 246, 0.3)';
            break;
          case 'phishing':
            pathColor = isActive ? 'rgba(139, 92, 246, 0.8)' : 'rgba(139, 92, 246, 0.3)';
            break;
          case 'ransomware':
            pathColor = isActive ? 'rgba(16, 185, 129, 0.8)' : 'rgba(16, 185, 129, 0.3)';
            break;
          default:
            pathColor = isActive ? 'rgba(255, 255, 255, 0.8)' : 'rgba(255, 255, 255, 0.3)';
        }
        
        ctx.strokeStyle = pathColor;
        ctx.lineWidth = isActive ? 2 : 1;
        ctx.stroke();
        
        // Draw source point
        ctx.beginPath();
        ctx.arc(sourceX, sourceY, isActive ? 4 : 3, 0, Math.PI * 2);
        ctx.fillStyle = pathColor.replace('0.3', '0.7');
        ctx.fill();
        
        // Draw destination point
        ctx.beginPath();
        ctx.arc(destX, destY, isActive ? 5 : 3, 0, Math.PI * 2);
        ctx.fillStyle = pathColor.replace('0.3', '0.7');
        ctx.fill();
        
        // Animated pulse for active attacks
        if (isActive) {
          ctx.beginPath();
          ctx.arc(destX, destY, 8 + Math.sin(Date.now() / 200) * 3, 0, Math.PI * 2);
          ctx.strokeStyle = pathColor;
          ctx.stroke();
        }
      });
    };
    
    // Animation loop
    const animate = () => {
      drawMap();
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animate();
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [filteredAttacks, activeAttacks]);
  
  // Format timestamp
  const formatTime = (date: Date): string => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    
    if (diffMin === 0) {
      return `${diffSec}s ago`;
    } else {
      return `${diffMin}m ${diffSec % 60}s ago`;
    }
  };
  
  // Get attack type badge color
  const getAttackTypeColor = (type: string): string => {
    switch(type) {
      case 'malware':
        return 'bg-red-500/10 text-red-500';
      case 'ddos':
        return 'bg-yellow-500/10 text-yellow-500';
      case 'intrusion':
        return 'bg-blue-500/10 text-blue-500';
      case 'phishing':
        return 'bg-purple-500/10 text-purple-500';
      case 'ransomware':
        return 'bg-emerald-500/10 text-emerald-500';
      default:
        return 'bg-gray-500/10 text-gray-500';
    }
  };
  
  // Get attack type icon
  const getAttackTypeIcon = (type: string) => {
    switch(type) {
      case 'malware':
        return <AlertTriangle className="h-3.5 w-3.5 text-red-500" />;
      case 'ddos':
        return <Wifi className="h-3.5 w-3.5 text-yellow-500" />;
      case 'intrusion':
        return <Shield className="h-3.5 w-3.5 text-blue-500" />;
      case 'phishing':
        return <Globe className="h-3.5 w-3.5 text-purple-500" />;
      case 'ransomware':
        return <Database className="h-3.5 w-3.5 text-emerald-500" />;
      default:
        return <Server className="h-3.5 w-3.5 text-gray-500" />;
    }
  };
  
  return (
    <Card className="bg-card border-primary/30">
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
      
      <Tabs defaultValue="map" className="w-full">
        <div className="p-2 border-b border-border">
          <TabsList className="grid grid-cols-2">
            <TabsTrigger value="map" className="text-xs font-mono">Map View</TabsTrigger>
            <TabsTrigger value="list" className="text-xs font-mono">Attack Log</TabsTrigger>
          </TabsList>
        </div>
        
        <TabsContent value="map" className="p-0">
          <div className="p-2 border-b border-border bg-background/40 flex flex-wrap gap-2">
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'all' ? "bg-primary/10 text-primary" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('all')}
            >
              All ({stats.total})
            </Badge>
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'malware' ? "bg-red-500/10 text-red-500" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('malware')}
            >
              Malware ({stats.malware})
            </Badge>
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'ddos' ? "bg-yellow-500/10 text-yellow-500" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('ddos')}
            >
              DDoS ({stats.ddos})
            </Badge>
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'intrusion' ? "bg-blue-500/10 text-blue-500" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('intrusion')}
            >
              Intrusion ({stats.intrusion})
            </Badge>
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'phishing' ? "bg-purple-500/10 text-purple-500" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('phishing')}
            >
              Phishing ({stats.phishing})
            </Badge>
            <Badge 
              variant="outline" 
              className={cn(
                "cursor-pointer text-xs",
                filter === 'ransomware' ? "bg-emerald-500/10 text-emerald-500" : "bg-background text-muted-foreground"
              )}
              onClick={() => setFilter('ransomware')}
            >
              Ransomware ({stats.ransomware})
            </Badge>
          </div>
          
          <div className="relative w-full overflow-hidden">
            <div className="overflow-auto flex items-center justify-center p-4">
              <canvas 
                ref={canvasRef} 
                width={MAP_WIDTH} 
                height={MAP_HEIGHT} 
                className="max-w-full"
              ></canvas>
            </div>
            
            <div className="absolute top-2 right-2 bg-black/60 rounded-sm p-1.5 text-xs font-mono">
              <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-red-500 mr-1"></div>
                  <span className="text-red-400">Malware</span>
                </div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-yellow-500 mr-1"></div>
                  <span className="text-yellow-400">DDoS</span>
                </div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-blue-500 mr-1"></div>
                  <span className="text-blue-400">Intrusion</span>
                </div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-purple-500 mr-1"></div>
                  <span className="text-purple-400">Phishing</span>
                </div>
                <div className="flex items-center">
                  <div className="h-2 w-2 rounded-full bg-emerald-500 mr-1"></div>
                  <span className="text-emerald-400">Ransomware</span>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="list" className="space-y-1 p-0 max-h-[400px] overflow-y-auto">
          <div className="sticky top-0 z-10 bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
            <div className="col-span-2">Time</div>
            <div className="col-span-2">Type</div>
            <div className="col-span-4">Source</div>
            <div className="col-span-4">Destination</div>
          </div>
          
          {filteredAttacks.map((attack, index) => (
            <div 
              key={attack.id}
              className={cn(
                "p-2 grid grid-cols-12 gap-2 font-mono text-xs border-b border-border/20",
                index % 2 === 0 ? "bg-background/50" : "bg-muted/30",
                activeAttacks.includes(attack.id) ? "bg-primary/5 border-l-2 border-l-primary" : ""
              )}
            >
              <div className="col-span-2 flex items-center">
                <Clock className="h-3 w-3 mr-1 text-muted-foreground" />
                {formatTime(attack.timestamp)}
              </div>
              <div className="col-span-2">
                <Badge 
                  variant="outline" 
                  className={cn("px-1 py-0.5 h-5 flex items-center gap-1", getAttackTypeColor(attack.type))}
                >
                  {getAttackTypeIcon(attack.type)}
                  <span className="capitalize">{attack.type}</span>
                </Badge>
              </div>
              <div className="col-span-4">
                <div className="flex items-center">
                  <span className="font-bold">{attack.source.country}</span>
                </div>
                <div className="text-muted-foreground mt-0.5">{attack.source.ip}</div>
              </div>
              <div className="col-span-4">
                <div className="flex items-center">
                  <span className="font-bold">{attack.destination.country}</span>
                  {activeAttacks.includes(attack.id) && (
                    <Zap className="h-3 w-3 ml-1 text-yellow-500 animate-pulse" />
                  )}
                </div>
                <div className="text-muted-foreground mt-0.5">{attack.destination.ip}</div>
              </div>
            </div>
          ))}
          
          {filteredAttacks.length === 0 && (
            <div className="p-8 text-center text-muted-foreground">
              No attacks matching the selected filter.
            </div>
          )}
        </TabsContent>
      </Tabs>
      
      <div className="p-2 border-t border-border bg-black/20">
        <p className="text-xs font-mono text-muted-foreground text-center">
          Note: This is a simulated visualization for educational purposes.
        </p>
      </div>
    </Card>
  );
}