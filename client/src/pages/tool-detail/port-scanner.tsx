import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import PortScanner from "@/components/port-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function PortScannerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Port Scanner module initialized");
    addInfoLine("Ready to scan targets. Configure scan parameters below.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Port Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Scan networks for open ports and detect running services. Port scanning is a crucial
          reconnaissance technique in network security assessment.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PortScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Port scanning is the process of checking a network host for open ports. 
                This tool allows you to scan a target for open TCP ports.
              </p>
              <p>
                <span className="text-primary">Open ports</span> indicate services that are actively 
                accepting connections and may provide access points to a system.
              </p>
              <p>
                <span className="text-accent">Filtered ports</span> are blocked by a firewall or 
                other network security device.
              </p>
              <p>
                <span className="text-muted-foreground">Closed ports</span> are reachable but have 
                no service listening on them.
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Legal Warning</h2>
            <p className="text-sm font-mono text-muted-foreground">
              Port scanning without explicit permission is illegal in many jurisdictions. Only scan 
              systems you own or have written permission to test. CyberPulse is not responsible for 
              any misuse of this tool.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mt-6">
        <Terminal className="h-80" />
      </div>
    </div>
  );
}