import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import Terminal from "@/components/terminal";
import { MatrixBackground } from "@/components/matrix-background";
import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";

export default function Home() {
  const { addSystemLine, addInfoLine } = useTerminal();
  
  useEffect(() => {
    // Simulate terminal initialization
    addSystemLine("CyberPulse v1.0.2_alpha initialized");
    addInfoLine("Loading system components...");
    
    const timer1 = setTimeout(() => {
      addInfoLine("Security modules configured and ready");
    }, 800);
    
    const timer2 = setTimeout(() => {
      addSystemLine("System ready. Type 'help' for a list of commands.");
    }, 1500);
    
    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, [addSystemLine, addInfoLine]);
  
  return (
    <div className="container mx-auto px-4 py-10">
      <div className="relative">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 mb-16">
          <div className="flex flex-col justify-center">
            <h2 className="text-3xl font-tech mb-4 text-glitch" data-text="Cybersecurity Tools">
              Cybersecurity Tools
            </h2>
            <p className="mb-6 text-muted-foreground font-mono">
              Access a comprehensive collection of security tools designed for penetration testing, 
              vulnerability scanning, and network analysis. All tools are web-based and require no installation.
            </p>
            <Link href="/tools">
              <Button className="w-full md:w-auto bg-primary text-primary-foreground hover:bg-primary/90 font-tech">
                Explore Tools
              </Button>
            </Link>
          </div>
          
          <div className="relative">
            <MatrixBackground />
            <Card className="border border-primary/50 bg-card/80 backdrop-blur-sm p-6 h-full">
              <h3 className="text-xl font-tech mb-4 text-primary">Features</h3>
              <ul className="space-y-3 font-mono text-sm">
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Web-based vulnerability scanning</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Network reconnaissance tools</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Information gathering utilities</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Password and encryption tools</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Web exploitation framework</span>
                </li>
              </ul>
            </Card>
          </div>
        </div>
        
        <div className="relative">
          <h2 className="text-2xl font-tech mb-6 text-center">Interactive Terminal</h2>
          <Terminal />
        </div>
      </div>
      
      <div className="mt-16">
        <h2 className="text-2xl font-tech mb-6 text-center">Getting Started</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">1. Select a Tool</h3>
            <p className="text-sm font-mono text-muted-foreground">Browse through our categorized collection of cybersecurity tools and select one that matches your needs.</p>
          </Card>
          
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">2. Configure Parameters</h3>
            <p className="text-sm font-mono text-muted-foreground">Set the required parameters for your selected tool, such as target URL, IP address, or input data.</p>
          </Card>
          
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">3. Analyze Results</h3>
            <p className="text-sm font-mono text-muted-foreground">Review the detailed output provided by the tool in the terminal display and take appropriate action.</p>
          </Card>
        </div>
      </div>
      
      <div className="mt-16 text-center">
        <div className="inline-block border border-accent/30 p-6 rounded-md bg-card relative overflow-hidden">
          <MatrixBackground className="opacity-20" />
          <h2 className="text-xl font-tech mb-4 text-accent">Important Disclaimer</h2>
          <p className="text-sm font-mono text-muted-foreground max-w-2xl">
            The tools provided by CyberPulse are intended for educational and ethical purposes only. 
            Always ensure you have proper authorization before testing any system or network. 
            Unauthorized scanning or testing may be illegal in your jurisdiction.
          </p>
        </div>
      </div>
    </div>
  );
}
