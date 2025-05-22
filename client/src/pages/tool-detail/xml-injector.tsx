import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import XmlInjector from "@/components/tools/xml-injector";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function XmlInjectorPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("XML Injection Testing module initialized");
    terminal.addInfoLine("Ready to test for XML injection vulnerabilities.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">XML Injection Testing Tool</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Detect vulnerabilities in web services that process XML data, including XXE, SOAP injection,
          and XML-based attacks that could compromise your system.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <XmlInjector />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About XML Injection</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                XML Injection allows attackers to manipulate XML processing in web services, potentially 
                leading to unauthorized data access, service disruption, or server compromise.
              </p>
              <p>
                Common vulnerabilities include:
              </p>
              <div className="ml-2 space-y-1">
                <p>• <span className="text-amber-500">XML External Entity (XXE)</span>: Reading local files or making network requests</p>
                <p>• <span className="text-amber-500">Billion Laughs Attack</span>: Causing denial of service through entity expansion</p>
                <p>• <span className="text-amber-500">SOAP Injection</span>: Manipulating web service parameters</p>
                <p>• <span className="text-amber-500">XPath Injection</span>: Extracting data from XML documents</p>
              </div>
              <div className="p-2 rounded-md bg-red-500/10 mt-2 border border-red-500/20">
                <p className="text-xs text-red-500">
                  <span className="font-bold">Warning:</span> Only test systems you own or have explicit permission to test.
                  XML injection testing can cause service disruption or data loss.
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-lg font-tech text-accent mb-4">Terminal Output</h2>
            <Terminal className="h-80 text-xs" lines={terminal.lines} />
          </div>
        </div>
      </div>
    </div>
  );
}