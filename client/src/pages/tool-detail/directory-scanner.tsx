import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import DirectoryScanner from "@/components/tools/directory-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function DirectoryScannerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Directory Scanner module initialized");
    addInfoLine("Ready to discover hidden directories and files on web servers.");
    addInfoLine("This tool helps identify potentially sensitive resources that might be exposed.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Directory Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Identify hidden directories and files on web servers to discover potential security vulnerabilities
          and sensitive information exposure.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <DirectoryScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">How Directory Scanning Works</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Directory scanning is a reconnaissance technique that attempts to identify non-linked directories
                and files on a web server by testing common names and patterns.
              </p>
              <p>
                <span className="text-primary">Common findings include:</span>
              </p>
              <div className="ml-2 space-y-1">
                <p>• Backup files (.bak, .old, .backup)</p>
                <p>• Configuration files (.env, config.php)</p>
                <p>• Development resources (/dev, /test)</p>
                <p>• Admin interfaces (/admin, /wp-admin)</p>
                <p>• Log files and debug information</p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Security Considerations</h2>
            <p className="text-sm font-mono text-muted-foreground mb-4">
              Directory scanning has important ethical and legal considerations:
            </p>
            <div className="space-y-2 text-sm font-mono">
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Permission Required</p>
                <p className="text-xs text-muted-foreground">Always obtain explicit permission before scanning any website you don't own.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Resource Intensive</p>
                <p className="text-xs text-muted-foreground">Scanning can generate significant traffic and load on the target server.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Prevention Methods</p>
                <p className="text-xs text-muted-foreground">Protect your servers with proper access controls, web application firewalls, and custom 404 pages.</p>
              </div>
              
              <div className="mt-4 p-3 bg-background rounded-md text-xs border border-primary/20">
                <p className="text-primary font-tech">Mitigation Strategies:</p>
                <p className="mt-1 text-muted-foreground">
                  • Use .htaccess or web.config to restrict directory listing<br />
                  • Implement proper access controls on all resources<br />
                  • Monitor logs for scanning attempts<br />
                  • Keep sensitive files outside the web root<br />
                  • Use robots.txt appropriately (but don't rely on it for security)
                </p>
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