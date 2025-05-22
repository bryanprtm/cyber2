import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import WhoisLookup from "@/components/tools/whois-lookup";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function WhoisLookupPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("WHOIS Lookup Tool initialized");
    addInfoLine("Ready to perform domain WHOIS lookups");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">WHOIS Lookup</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Discover comprehensive domain registration information including registrar, dates, nameservers, 
          and contact information. Analyze domain security and privacy with advanced visual tools.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <WhoisLookup />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                WHOIS is a query and response protocol used for querying databases that store registered users 
                or assignees of internet resources such as domain names and IP address blocks.
              </p>
              <p>
                <span className="text-primary">Key features:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Domain registrant information lookup</li>
                <li>Registration and expiration date checks</li>
                <li>Nameserver and DNS configuration analysis</li>
                <li>Domain security and privacy assessment</li>
                <li>Registrar and technical contact information</li>
                <li>Domain status code interpretation</li>
              </ul>
              <p className="mt-4">
                <span className="text-primary">Security implications:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Verify domain legitimacy and ownership</li>
                <li>Identify potentially suspicious domains</li>
                <li>Assess domain age and ownership patterns</li>
                <li>Evaluate domain security configurations</li>
                <li>Detect privacy protection measures</li>
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