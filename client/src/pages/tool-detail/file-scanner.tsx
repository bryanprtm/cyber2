import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import FileScanner from "@/components/tools/file-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function FileScannerPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("File Scanner module initialized");
    terminal.addInfoLine("Upload a file to scan it for malware, vulnerabilities, and sensitive information.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">File Security Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Analyze files for security threats, code vulnerabilities, malicious patterns, 
          and sensitive information to ensure data safety and code integrity.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <FileScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                This tool examines uploaded files to identify security issues such as:
              </p>
              <div className="space-y-2">
                <div className="flex items-start gap-2">
                  <span className="text-red-500">•</span>
                  <p><span className="text-red-500 font-bold">Malware signatures</span> - Patterns that match known malicious code</p>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-orange-500">•</span>
                  <p><span className="text-orange-500 font-bold">Code vulnerabilities</span> - Security flaws in source code files</p>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-amber-500">•</span>
                  <p><span className="text-amber-500 font-bold">Sensitive data</span> - Personal information, credentials, or API keys</p>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-blue-500">•</span>
                  <p><span className="text-blue-500 font-bold">Hidden metadata</span> - Embedded information that could leak sensitive details</p>
                </div>
              </div>
              <p>
                <span className="text-red-500">Note:</span> File uploads are scanned locally on the server
                and are not permanently stored after analysis is complete.
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