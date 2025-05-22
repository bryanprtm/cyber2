import React, { useEffect, useRef } from 'react';

interface MatrixBackgroundProps {
  speed?: number;
  density?: number;
  color?: string;
}

const MatrixBackground: React.FC<MatrixBackgroundProps> = ({
  speed = 5,
  density = 15,
  color = '#00ff41'
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Set canvas dimensions to match window
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    
    window.addEventListener('resize', resize);
    resize();
    
    // Matrix character set
    const chars = '01αβγδεζηθικλμνξοπρστυφχψωABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');
    
    // Create columns
    const columnCount = Math.floor(canvas.width / 15); // Adjust for character width
    const columns = Array(columnCount).fill(0);
    
    // Calculate actual density (fewer characters for performance)
    const actualDensity = Math.max(5, Math.min(25, density));
    const dropChance = actualDensity / 100;
    
    // Calculate actual speed (slower for better visuals)
    const actualSpeed = Math.max(1, Math.min(10, speed));
    const frameDelay = 120 - (actualSpeed * 10);
    
    let frameCount = 0;
    
    // Animation loop
    const draw = () => {
      // Slight fade effect for trailing effect
      ctx.fillStyle = 'rgba(0, 0, 0, 0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Set text color
      ctx.fillStyle = color;
      ctx.font = '15px monospace';
      
      frameCount++;
      
      // Only update on certain frames based on speed
      if (frameCount % Math.max(1, Math.round(frameDelay / 10)) === 0) {
        // Draw characters
        for (let i = 0; i < columns.length; i++) {
          // Random character
          const charIndex = Math.floor(Math.random() * chars.length);
          const x = i * 15;
          const y = columns[i] * 20;
          
          if (y < canvas.height && columns[i] > 0) {
            ctx.fillText(chars[charIndex], x, y);
          }
          
          // Random chance to create a new falling character
          if (Math.random() < dropChance && columns[i] === 0) {
            columns[i] = 1;
          }
          
          // Move existing characters down
          if (columns[i] > 0) {
            columns[i]++;
            
            // Reset when character goes off screen
            if (columns[i] * 20 > canvas.height && Math.random() > 0.975) {
              columns[i] = 0;
            }
          }
        }
      }
      
      animationFrame = requestAnimationFrame(draw);
    };
    
    let animationFrame = requestAnimationFrame(draw);
    
    // Cleanup
    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrame);
    };
  }, [speed, density, color]);
  
  return (
    <canvas 
      ref={canvasRef}
      className="absolute inset-0 w-full h-full z-0"
      style={{ pointerEvents: 'none' }}
    />
  );
};

export default MatrixBackground;