import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import PasswordChecker from "@/components/tools/password-checker";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function PasswordCheckerPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Password Checker module initialized");
    addInfoLine("Ready to analyze password strength and security. Enter a password to begin.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Password Checker</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Analyze password strength, detect vulnerabilities, and assess resistance to brute force attacks.
          Get detailed feedback and improvement suggestions to create more secure passwords.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PasswordChecker />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                A strong password is your first line of defense against unauthorized access to your accounts and sensitive information.
              </p>
              <p>
                <span className="text-primary">What makes a strong password?</span>
                <ul className="list-disc list-inside mt-2 ml-2 space-y-1">
                  <li>At least 12 characters length</li>
                  <li>Combination of uppercase and lowercase letters</li>
                  <li>Includes numbers and special characters</li>
                  <li>Avoids sequential or repeating patterns</li>
                  <li>Not found in common password dictionaries</li>
                </ul>
              </p>
              <p>
                <span className="text-accent">Password managers</span> can help you create and store 
                strong, unique passwords for all your accounts without having to remember them.
              </p>
              <p>
                Always use <span className="text-green-500">different passwords</span> for different accounts, 
                especially for email, banking, and other sensitive services.
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-lg font-tech text-accent mb-4">Terminal Output</h2>
            <Terminal className="h-80 text-xs" />
          </div>
        </div>
      </div>
    </div>
  );
}