import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import OpenCTI from "@/components/tools/opencti";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function OpenCTIPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("OpenCTI Platform Interface initialized");
    addInfoLine("Ready to query threat intelligence data");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">OpenCTI Platform</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Access and analyze cyber threat intelligence from the open-source OpenCTI platform. 
          Query information about threat actors, malware, campaigns, and their relationships.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <OpenCTI />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                OpenCTI is an open-source platform that allows organizations to manage their cyber 
                threat intelligence knowledge and observables.
              </p>
              <p>
                <span className="text-primary">Key features:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Structured storage of threat intelligence</li>
                <li>Relationship mapping between entities</li>
                <li>STIX2 compliant data model</li>
                <li>Advanced correlation analysis</li>
                <li>Visualization of threat intelligence data</li>
                <li>Integration with external CTI sources</li>
              </ul>
              <p className="mt-4">
                <span className="text-primary">Supported entity types:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Threat Actors</li>
                <li>Malware</li>
                <li>Campaigns</li>
                <li>Attack Patterns</li>
                <li>Tools</li>
                <li>Vulnerabilities</li>
                <li>Indicators (IOCs)</li>
              </ul>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Terminal Output</h2>
            <Terminal lines={[]} />
          </div>
        </div>
      </div>
    </div>
  );
}