import { useEffect, useRef, useState } from "react";
// Import local theme context instead of next-themes
import { useContext } from "react";

interface ThreatAnimationProps {
  intensity?: number; // 0-100, controls number of particles and speed
  width?: number;
  height?: number;
  className?: string;
}

interface Particle {
  x: number;
  y: number;
  size: number;
  speedX: number;
  speedY: number;
  color: string;
  opacity: number;
  life: number;
  maxLife: number;
  type: 'attacker' | 'defender' | 'packet';
  targetX?: number;
  targetY?: number;
}

interface ThreatSource {
  x: number;
  y: number;
  country: string;
  intensity: number;
  active: boolean;
  interval: number;
  lastAttack: number;
  color: string;
}

export default function ThreatAnimation({
  intensity = 50,
  width = 800,
  height = 500,
  className = ""
}: ThreatAnimationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { theme } = useTheme();
  const [particles, setParticles] = useState<Particle[]>([]);
  const [threats, setThreats] = useState<ThreatSource[]>([]);
  const [frame, setFrame] = useState(0);
  const [serverPosition, setServerPosition] = useState({ x: 0, y: 0 });
  const [isActive, setIsActive] = useState(true);
  
  const frameRef = useRef(frame);
  frameRef.current = frame;
  
  const particlesRef = useRef(particles);
  particlesRef.current = particles;
  
  const threatsRef = useRef(threats);
  threatsRef.current = threats;
  
  const serverPositionRef = useRef(serverPosition);
  serverPositionRef.current = serverPosition;
  
  const isActiveRef = useRef(isActive);
  isActiveRef.current = isActive;
  
  // Generate random threat sources
  useEffect(() => {
    const countries = ['RU', 'CN', 'US', 'KP', 'IR', 'BR', 'IN'];
    const colors = ['#ff4e4e', '#ffae00', '#2a80eb', '#8e44ef', '#00c2a8'];
    
    const generatedThreats: ThreatSource[] = [];
    
    // Create 5-10 threat sources
    const threatCount = Math.floor(Math.random() * 6) + 5;
    
    for (let i = 0; i < threatCount; i++) {
      // Position threats around the borders of the canvas
      let x, y;
      
      if (Math.random() > 0.5) {
        // Position on left or right edge
        x = Math.random() > 0.5 ? 10 : width - 10;
        y = Math.random() * height;
      } else {
        // Position on top or bottom edge
        x = Math.random() * width;
        y = Math.random() > 0.5 ? 10 : height - 10;
      }
      
      generatedThreats.push({
        x,
        y,
        country: countries[Math.floor(Math.random() * countries.length)],
        intensity: Math.random() * 80 + 20, // 20-100
        active: true,
        interval: Math.floor(Math.random() * 2000) + 500, // 500-2500ms between attacks
        lastAttack: 0,
        color: colors[Math.floor(Math.random() * colors.length)]
      });
    }
    
    setThreats(generatedThreats);
    
    // Set server position in the center
    setServerPosition({
      x: width / 2,
      y: height / 2
    });
  }, [width, height]);
  
  // Animation loop
  useEffect(() => {
    if (!canvasRef.current) return;
    
    let frameId: number;
    let lastTimestamp = 0;
    
    const animate = (timestamp: number) => {
      if (!isActiveRef.current) return;
      
      const delta = timestamp - lastTimestamp;
      
      // Only update state every 30ms for better performance
      if (delta > 30) {
        lastTimestamp = timestamp;
        updateParticles(delta);
        generateNewParticles(delta);
        setFrame(prevFrame => prevFrame + 1);
      }
      
      renderFrame();
      frameId = requestAnimationFrame(animate);
    };
    
    const updateParticles = (delta: number) => {
      const updatedParticles = particlesRef.current
        .map(particle => {
          // Update particle position
          let updatedX = particle.x + particle.speedX * (delta / 16);
          let updatedY = particle.y + particle.speedY * (delta / 16);
          
          // If it's a packet with a target, adjust direction toward target
          if (particle.type === 'packet' && particle.targetX !== undefined && particle.targetY !== undefined) {
            const dx = particle.targetX - particle.x;
            const dy = particle.targetY - particle.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            if (distance > 5) {
              const speed = Math.sqrt(particle.speedX * particle.speedX + particle.speedY * particle.speedY);
              particle.speedX = (dx / distance) * speed;
              particle.speedY = (dy / distance) * speed;
            }
          }
          
          // Update life
          const newLife = particle.life - 1;
          
          // Calculate opacity based on remaining life
          const newOpacity = Math.min(1, (newLife / particle.maxLife) * 2);
          
          return {
            ...particle,
            x: updatedX,
            y: updatedY,
            life: newLife,
            opacity: newOpacity
          };
        })
        .filter(particle => particle.life > 0 && 
                             particle.x >= 0 && particle.x <= width && 
                             particle.y >= 0 && particle.y <= height);
      
      setParticles(updatedParticles);
    };
    
    const generateNewParticles = (delta: number) => {
      const currentTime = Date.now();
      const newParticles: Particle[] = [...particlesRef.current];
      const adjustedIntensity = Math.max(10, Math.min(100, intensity));
      
      // Process each threat source
      threatsRef.current.forEach(threat => {
        if (!threat.active) return;
        
        // Check if it's time for this threat to send an attack
        if (currentTime - threat.lastAttack > threat.interval) {
          // Generate 1-3 attack particles based on threat intensity
          const attackCount = Math.floor(Math.random() * 3) + 1;
          
          for (let i = 0; i < attackCount; i++) {
            // Calculate direction to server
            const dx = serverPositionRef.current.x - threat.x;
            const dy = serverPositionRef.current.y - threat.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            // Base speed on threat intensity and global intensity
            const baseSpeed = (threat.intensity / 50) * (adjustedIntensity / 50);
            
            // Create attack packet
            newParticles.push({
              x: threat.x,
              y: threat.y,
              size: Math.random() * 3 + 2,
              speedX: (dx / distance) * baseSpeed,
              speedY: (dy / distance) * baseSpeed,
              color: threat.color,
              opacity: 0.9,
              life: Math.floor(Math.random() * 100) + 100,
              maxLife: 200,
              type: 'packet',
              targetX: serverPositionRef.current.x,
              targetY: serverPositionRef.current.y
            });
          }
          
          // Update threat's last attack time
          const updatedThreats = [...threatsRef.current];
          const threatIndex = updatedThreats.findIndex(t => 
            t.x === threat.x && t.y === threat.y && t.country === threat.country
          );
          
          if (threatIndex !== -1) {
            updatedThreats[threatIndex] = {
              ...threat,
              lastAttack: currentTime
            };
            setThreats(updatedThreats);
          }
        }
      });
      
      // Random particle generation (background effect)
      if (Math.random() < 0.1 * (adjustedIntensity / 50)) {
        for (let i = 0; i < Math.floor(Math.random() * 3) + 1; i++) {
          // Add random background particles around the server
          const angle = Math.random() * Math.PI * 2;
          const distance = Math.random() * 50 + 30;
          
          newParticles.push({
            x: serverPositionRef.current.x + Math.cos(angle) * distance,
            y: serverPositionRef.current.y + Math.sin(angle) * distance,
            size: Math.random() * 2 + 1,
            speedX: Math.cos(angle) * (Math.random() * 0.5 + 0.2),
            speedY: Math.sin(angle) * (Math.random() * 0.5 + 0.2),
            color: theme === 'dark' ? '#3498db' : '#2980b9',
            opacity: 0.6,
            life: Math.floor(Math.random() * 60) + 30,
            maxLife: 90,
            type: 'defender'
          });
        }
      }
      
      setParticles(newParticles);
    };
    
    const renderFrame = () => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      
      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Set canvas dimensions
      canvas.width = width;
      canvas.height = height;
      
      // Draw connection lines between threats and server (subtle background effect)
      ctx.globalAlpha = 0.1;
      threatsRef.current.forEach(threat => {
        ctx.beginPath();
        ctx.moveTo(threat.x, threat.y);
        ctx.lineTo(serverPositionRef.current.x, serverPositionRef.current.y);
        ctx.strokeStyle = theme === 'dark' ? '#aaa' : '#555';
        ctx.lineWidth = 0.5;
        ctx.stroke();
      });
      
      // Draw server/target
      ctx.globalAlpha = 1;
      ctx.beginPath();
      ctx.arc(serverPositionRef.current.x, serverPositionRef.current.y, 15, 0, Math.PI * 2);
      ctx.fillStyle = theme === 'dark' ? '#2ecc71' : '#27ae60';
      ctx.fill();
      
      // Draw inner server circle
      ctx.beginPath();
      ctx.arc(serverPositionRef.current.x, serverPositionRef.current.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = theme === 'dark' ? '#e6e6e6' : '#fff';
      ctx.fill();
      
      // Draw threat sources
      threatsRef.current.forEach(threat => {
        // Draw threat node
        ctx.beginPath();
        ctx.arc(threat.x, threat.y, 8, 0, Math.PI * 2);
        ctx.fillStyle = threat.color;
        ctx.fill();
        
        // Draw country code
        ctx.font = 'bold 10px monospace';
        ctx.fillStyle = theme === 'dark' ? '#fff' : '#000';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(threat.country, threat.x, threat.y);
        
        // Draw blinking effect during attack
        const timeSinceAttack = Date.now() - threat.lastAttack;
        if (timeSinceAttack < 500) {
          const pulseSize = 8 + (timeSinceAttack / 500) * 8;
          ctx.beginPath();
          ctx.arc(threat.x, threat.y, pulseSize, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(255, 255, 255, ' + (0.5 - timeSinceAttack / 1000) + ')';
          ctx.fill();
        }
      });
      
      // Draw particles
      particlesRef.current.forEach(particle => {
        ctx.globalAlpha = particle.opacity;
        
        // Different particle types have different visuals
        if (particle.type === 'packet') {
          // Attack packets - small squares that rotate
          ctx.save();
          ctx.translate(particle.x, particle.y);
          ctx.rotate(frameRef.current * 0.05);
          ctx.fillStyle = particle.color;
          ctx.fillRect(-particle.size / 2, -particle.size / 2, particle.size, particle.size);
          ctx.restore();
          
          // Add glowing trail effect
          if (Math.random() > 0.6) {
            ctx.beginPath();
            ctx.arc(particle.x, particle.y, particle.size / 2, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${parseInt(particle.color.slice(1, 3), 16)}, ${parseInt(particle.color.slice(3, 5), 16)}, ${parseInt(particle.color.slice(5, 7), 16)}, 0.3)`;
            ctx.fill();
          }
        } else if (particle.type === 'defender') {
          // Defense particles - circles with pulsing effect
          const pulseSize = particle.size * (1 + 0.2 * Math.sin(frameRef.current * 0.1));
          ctx.beginPath();
          ctx.arc(particle.x, particle.y, pulseSize, 0, Math.PI * 2);
          ctx.fillStyle = particle.color;
          ctx.fill();
        } else {
          // Default particle
          ctx.beginPath();
          ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
          ctx.fillStyle = particle.color;
          ctx.fill();
        }
      });
      
      // Reset global alpha
      ctx.globalAlpha = 1;
    };
    
    frameId = requestAnimationFrame(animate);
    
    return () => {
      cancelAnimationFrame(frameId);
    };
  }, [width, height, intensity, theme]);
  
  // Pause/resume animation when component is hidden/visible
  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsActive(!document.hidden);
    };
    
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);
  
  return (
    <div className={`relative overflow-hidden rounded-lg ${className}`}>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className="bg-muted/30 w-full h-full"
      />
      
      {/* Legend overlay */}
      <div className="absolute bottom-2 left-2 bg-background/80 text-foreground text-xs p-2 rounded">
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <span>Attack Traffic</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span>Protected Server</span>
          </div>
        </div>
      </div>
    </div>
  );
}