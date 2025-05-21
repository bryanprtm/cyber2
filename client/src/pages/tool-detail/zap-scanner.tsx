import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import ZapScanner from "@/components/tools/zap-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function ZapScannerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("OWASP ZAP Scanner module initialized");
    addInfoLine("Ready to scan web applications for security vulnerabilities.");
    addInfoLine("Note: This is a simulated educational tool that demonstrates ZAP scanner capabilities.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">OWASP ZAP Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Scan web applications for security vulnerabilities using simulated OWASP ZAP integration.
          Identify and understand common web security issues with this educational tool.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ZapScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About OWASP ZAP</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                The OWASP Zed Attack Proxy (ZAP) is one of the world's most popular free security tools,
                actively maintained by a dedicated international team of volunteers.
              </p>
              <p>
                <span className="text-primary">ZAP Features:</span>
              </p>
              <div className="ml-2 space-y-1">
                <p>• Automated scanning for vulnerabilities</p>
                <p>• Intercepting proxy for request inspection</p>
                <p>• Automated and manual penetration testing</p>
                <p>• Dynamic and passive scanning capabilities</p>
                <p>• Open source community-driven project</p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Common Web Vulnerabilities</h2>
            <p className="text-sm font-mono text-muted-foreground mb-4">
              Security scanners like ZAP help identify these common web application security issues:
            </p>
            <div className="space-y-2 text-sm font-mono">
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Cross-Site Scripting (XSS)</p>
                <p className="text-xs text-muted-foreground">Allows attackers to inject client-side scripts</p>
              </div>
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">SQL Injection</p>
                <p className="text-xs text-muted-foreground">Allows database manipulation through malicious queries</p>
              </div>
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Cross-Site Request Forgery</p>
                <p className="text-xs text-muted-foreground">Forces users to perform unwanted actions</p>
              </div>
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Insecure Direct Object References</p>
                <p className="text-xs text-muted-foreground">Allows accessing unauthorized resources</p>
              </div>
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Security Misconfiguration</p>
                <p className="text-xs text-muted-foreground">Insecure default configurations and incomplete setups</p>
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