import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import HashGenerator from "@/components/tools/hash-generator";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function HashGeneratorPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Hash Generator module initialized");
    addInfoLine("Ready to generate cryptographic hashes. Configure hash parameters below.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Hash Generator</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Generate cryptographic hashes for sensitive data using various algorithms. 
          Hashing is a one-way function used to verify data integrity and securely store passwords.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <HashGenerator />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Cryptographic hashing converts any input into a fixed-length string of characters. 
                Unlike encryption, hashing is a one-way process that cannot be reversed.
              </p>
              <p>
                <span className="text-primary">SHA-256</span> and newer algorithms 
                are recommended for security-sensitive applications.
              </p>
              <p>
                <span className="text-accent">MD5 and SHA-1</span> are considered cryptographically 
                broken and should not be used for security purposes.
              </p>
              <p>
                Common uses for hashing include:
                <ul className="list-disc list-inside mt-2 ml-2 space-y-1">
                  <li>Password storage</li>
                  <li>Data integrity verification</li>
                  <li>Digital signatures</li>
                  <li>File checksums</li>
                </ul>
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Security Notice</h2>
            <p className="text-sm font-mono text-muted-foreground">
              For password storage, always use specialized password hashing functions with salting 
              (like Argon2, bcrypt, or PBKDF2) rather than raw hash functions. These tools resist 
              brute force and rainbow table attacks.
            </p>
          </div>
        </div>
      </div>
      
      <div className="mt-6">
        <Terminal className="h-80" />
      </div>
    </div>
  );
}