import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import SqlInjector from "@/components/tools/sql-injector";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function SqlInjectorPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("SQL Injection Testing module initialized");
    terminal.addInfoLine("Ready to test target for SQL injection vulnerabilities.");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">SQL Injection Testing Tool</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Detect SQL injection vulnerabilities in web applications that could allow attackers
          to access, modify, or delete data in your database.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SqlInjector />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About SQL Injection</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                SQL Injection (SQLi) is a code injection technique where an attacker inserts malicious
                SQL statements into input fields for execution by the underlying database.
              </p>
              <p>
                Common attack vectors include:
              </p>
              <div className="ml-2 space-y-1">
                <p>• <span className="text-amber-500">Error-based</span>: Forces the database to generate an error revealing information</p>
                <p>• <span className="text-amber-500">Union-based</span>: Uses UNION operator to combine results with another query</p>
                <p>• <span className="text-amber-500">Blind</span>: Asks the database true/false questions to extract data</p>
                <p>• <span className="text-amber-500">Time-based</span>: Uses time delays to extract information</p>
              </div>
              <div className="p-2 rounded-md bg-red-500/10 mt-2 border border-red-500/20">
                <p className="text-xs text-red-500">
                  <span className="font-bold">Warning:</span> This tool is for educational purposes and authorized security testing only.
                  Always obtain proper authorization before testing applications.
                </p>
              </div>
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