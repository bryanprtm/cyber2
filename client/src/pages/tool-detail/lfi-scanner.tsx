import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import LfiScanner from "@/components/tools/lfi-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function LfiScannerPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("LFI Scanner module initialized");
    terminal.addInfoLine("Ready to scan for Local File Inclusion vulnerabilities.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Local File Inclusion Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Detect Local File Inclusion (LFI) vulnerabilities in web applications that could
          allow attackers to access sensitive files on the server.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <LfiScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About LFI Vulnerabilities</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Local File Inclusion (LFI) is a vulnerability that allows attackers to include files on a server
                through the web browser, potentially exposing sensitive data or executing malicious code.
              </p>
              <p>
                Common vulnerable patterns include:
              </p>
              <div className="ml-2 space-y-1">
                <p>• <span className="text-amber-500">file.php?page=../../../etc/passwd</span></p>
                <p>• <span className="text-amber-500">include.php?path=config.php</span></p>
                <p>• <span className="text-amber-500">view.php?file=/var/www/sensitive_file</span></p>
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