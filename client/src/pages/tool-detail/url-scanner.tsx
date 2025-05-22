import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import UrlScanner from "@/components/tools/url-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function UrlScannerPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("URL Scanner module initialized");
    terminal.addInfoLine("Ready to scan URLs for phishing, malware, and security threats.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">URL Security Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Scan websites for phishing attempts, malware, and security vulnerabilities. 
          Analyze URLs to detect potential threats before visiting them.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <UrlScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">How It Works</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                This tool helps identify potential threats by analyzing various aspects of a website:
              </p>
              <div className="ml-2 space-y-1">
                <p>• Detects phishing websites that impersonate legitimate services</p>
                <p>• Scans for malicious code patterns and drive-by downloads</p>
                <p>• Checks site reputation and historical security issues</p>
                <p>• Analyzes URL structure for suspicious patterns</p>
                <p>• Inspects website content for potential security risks</p>
              </div>
              <p className="text-accent mt-2">
                Always practice caution when browsing the web, even if a URL appears safe in our scans.
              </p>
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