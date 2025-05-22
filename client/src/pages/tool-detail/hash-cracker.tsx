import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import HashCracker from "@/components/tools/hash-cracker";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function HashCrackerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Hash Cracker module initialized");
    addInfoLine("Ready to attempt hash cracking. Configure parameters below.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Hash Cracker</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Attempt to recover plaintext values from cryptographic hashes using various methods 
          including dictionary attacks, brute force, and rainbow tables.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <HashCracker />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Hash cracking attempts to reverse a one-way cryptographic hash function to 
                recover the original input. This is useful for password recovery and security research.
              </p>
              <p>
                <span className="text-primary">Cracking methods:</span>
              </p>
              <div className="space-y-2 ml-2">
                <p>
                  <span className="text-secondary">Dictionary Attack</span> - Tests a list of potential 
                  passwords against the hash. Efficient for common passwords.
                </p>
                <p>
                  <span className="text-secondary">Brute Force</span> - Systematically tries all possible 
                  combinations. Effective but time-consuming.
                </p>
                <p>
                  <span className="text-secondary">Rainbow Tables</span> - Uses precomputed tables to trade 
                  storage space for cracking speed.
                </p>
              </div>
              <p>
                <span className="text-accent">Note:</span> Modern password hashing algorithms like bcrypt, 
                Argon2, and scrypt are designed to be resistant to cracking attempts through techniques 
                like salting and key stretching.
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Terminal Output</h2>
            <Terminal lines={[]} />
          </div>
        </div>
      </div>
    </div>
  );
}