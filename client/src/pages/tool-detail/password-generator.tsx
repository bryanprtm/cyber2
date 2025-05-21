import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import PasswordGenerator from "@/components/tools/password-generator";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function PasswordGeneratorPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Password Generator module initialized");
    addInfoLine("Ready to generate secure passwords. Configure password parameters below.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Password Generator</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Generate strong, cryptographically secure passwords with configurable complexity.
          Strong passwords are essential for protecting sensitive information and preventing unauthorized access.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PasswordGenerator />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Password Security Tips</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Using strong, unique passwords for each of your accounts is crucial for maintaining 
                security in the digital world.
              </p>
              <p>
                <span className="text-primary">Strong passwords</span> should be:
                <ul className="list-disc list-inside mt-2 ml-2 space-y-1">
                  <li>At least 12 characters long</li>
                  <li>Mix of upper and lowercase letters</li>
                  <li>Include numbers and special characters</li>
                  <li>Not based on personal information</li>
                  <li>Not using common patterns or words</li>
                </ul>
              </p>
              <p>
                <span className="text-accent">Password managers</span> are recommended 
                to securely store your complex passwords. Never reuse passwords across 
                multiple accounts.
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Multi-Factor Authentication</h2>
            <p className="text-sm font-mono text-muted-foreground">
              For maximum security, always enable multi-factor authentication (MFA) when 
              available. MFA adds an additional layer of security beyond just your password, 
              making it significantly harder for attackers to gain unauthorized access.
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