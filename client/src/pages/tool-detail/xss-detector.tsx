import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import XssDetector from "@/components/tools/xss-detector";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function XssDetectorPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("XSS Vulnerability Scanner initialized");
    addInfoLine("Ready to scan for Cross-Site Scripting vulnerabilities.");
    addInfoLine("Configure scan parameters below to begin testing.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">XSS Vulnerability Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Scan for Cross-Site Scripting (XSS) vulnerabilities in web applications.
          Identify DOM-based, Reflected, and Stored XSS vulnerabilities with this educational tool.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <XssDetector />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">XSS Attack Types</h2>
            <div className="space-y-3 text-sm font-mono">
              <div>
                <p className="text-primary">Reflected XSS</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Malicious script is reflected off a web server and executed in the victim's browser.
                  Typically delivered via URLs, where the payload is part of the request.
                </p>
              </div>
              
              <div>
                <p className="text-primary">Stored XSS</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Malicious script is stored on the target server (e.g., in a database) and later
                  retrieved and executed when other users access the affected page.
                </p>
              </div>
              
              <div>
                <p className="text-primary">DOM-based XSS</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Vulnerability exists in client-side code rather than server-side code.
                  The payload is executed through modification of the DOM environment.
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Prevention Techniques</h2>
            <div className="space-y-3 text-sm font-mono">
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Input Validation</p>
                <p className="text-xs text-muted-foreground mt-1">Verify that user input contains expected data types and patterns.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Output Encoding</p>
                <p className="text-xs text-muted-foreground mt-1">Context-specific encoding to ensure data is displayed as text, not interpreted as code.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Content Security Policy</p>
                <p className="text-xs text-muted-foreground mt-1">Implement CSP headers to restrict source of executable scripts.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Modern Frameworks</p>
                <p className="text-xs text-muted-foreground mt-1">Use frameworks that automatically escape output (React, Angular, Vue).</p>
              </div>
              
              <div className="mt-4 text-xs">
                <p className="text-accent">Security Note:</p>
                <p className="text-muted-foreground mt-1">XSS vulnerabilities remain prevalent in OWASP Top 10. Regular testing and developer education are critical for prevention.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div className="mt-6">
        <Terminal className="h-80" />
      </div>
    </div>
  );
}