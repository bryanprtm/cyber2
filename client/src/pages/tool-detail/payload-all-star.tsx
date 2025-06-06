import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import PayloadAllStar from "@/components/tools/payload-all-star";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function PayloadAllStarPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Payload All Star initialized");
    addInfoLine("Browse and execute payloads from the PayloadsAllTheThings collection");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Payload All Star</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          A comprehensive collection of payloads for web application security testing.
          Based on the PayloadsAllTheThings GitHub repository.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PayloadAllStar />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                PayloadsAllTheThings is a collection of useful payloads and bypass for Web Application Security
                and Pentest/CTF challenges.
              </p>
              <p>
                <span className="text-primary">Available Categories:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>XSS Injection</li>
                <li>SQL Injection</li>
                <li>XML External Entity (XXE)</li>
                <li>Command Injection</li>
                <li>Server-Side Request Forgery (SSRF)</li>
                <li>Cross-Site Request Forgery (CSRF)</li>
                <li>And many more...</li>
              </ul>
              <p>
                <span className="text-accent">Features:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Browse payloads by category</li>
                <li>Search within payloads</li>
                <li>Generate exploitation code</li>
                <li>Simulate payload execution</li>
              </ul>
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