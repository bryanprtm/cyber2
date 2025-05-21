import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import SslScanner from "@/components/tools/ssl-scanner";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function SslScannerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("SSL/TLS Scanner module initialized");
    addInfoLine("Ready to analyze SSL/TLS configurations and certificates.");
    addInfoLine("Enter a hostname to begin the security assessment.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">SSL/TLS Scanner</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Analyze SSL/TLS configurations and certificates to identify security vulnerabilities 
          and misconfigurations in web server setups.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SslScanner />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">SSL/TLS Security</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                SSL (Secure Sockets Layer) and its successor TLS (Transport Layer Security) 
                are cryptographic protocols that provide secure communication over networks.
              </p>
              <p>
                <span className="text-primary">Common SSL/TLS issues:</span>
              </p>
              <div className="ml-2 space-y-1">
                <p>• Outdated protocols (SSL 2.0/3.0, TLS 1.0/1.1)</p>
                <p>• Weak cipher suites and encryption algorithms</p>
                <p>• Certificate problems (expiration, mismatches)</p>
                <p>• Known vulnerabilities (Heartbleed, POODLE, etc.)</p>
                <p>• Missing security headers and features</p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Best Practices</h2>
            <div className="space-y-2 text-sm font-mono">
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Modern Protocols</p>
                <p className="text-xs text-muted-foreground">Enable only TLS 1.2 and TLS 1.3. Disable all older protocols like TLS 1.0/1.1 and SSL.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Strong Cipher Suites</p>
                <p className="text-xs text-muted-foreground">Use forward secrecy and AEAD ciphers. Disable weak ciphers like RC4, DES, and MD5.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Certificate Management</p>
                <p className="text-xs text-muted-foreground">Use 2048+ bit RSA keys or ECC keys. Monitor expiration dates and renew certificates well before they expire.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Security Headers</p>
                <p className="text-xs text-muted-foreground">Implement HSTS, CSP, and other security headers to enhance protection against various attacks.</p>
              </div>
              
              <div className="mt-4 text-xs">
                <p className="text-accent">Note:</p>
                <p className="text-muted-foreground mt-1">Regular scanning helps identify security weaknesses before attackers can exploit them. Aim for an A+ rating in industry-standard SSL/TLS tests.</p>
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