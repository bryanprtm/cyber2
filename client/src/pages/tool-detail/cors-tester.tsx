import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import CorsTester from "@/components/tools/cors-tester";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function CorsTesterPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("CORS Tester module initialized");
    terminal.addInfoLine("Ready to test Cross-Origin Resource Sharing configurations on web servers.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">CORS Configuration Tester</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Analyze Cross-Origin Resource Sharing (CORS) configurations to identify security
          vulnerabilities and potential misconfigurations in web applications.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <CorsTester />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About CORS Testing</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Cross-Origin Resource Sharing (CORS) is a security mechanism that allows or restricts
                web resources from being requested from domains other than the one serving the resource.
              </p>
              <p>
                Common CORS misconfiguration issues include:
              </p>
              <div className="ml-2 space-y-1">
                <p>• Wildcard origins (<span className="text-amber-500">Access-Control-Allow-Origin: *</span>)</p>
                <p>• Missing preflight request support for complex requests</p>
                <p>• Incorrectly configured credentials handling</p>
                <p>• Overly permissive header configurations</p>
              </div>
              <div className="p-2 rounded-md bg-secondary/10 mt-2">
                <p className="text-xs">
                  <span className="text-accent font-bold">Note:</span> This tool sends multiple types of requests
                  to the target URL with various origins and headers to test how the server handles them.
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