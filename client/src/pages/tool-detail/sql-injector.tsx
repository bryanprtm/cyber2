import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import SqlInjector from "@/components/tools/sql-injector";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function SqlInjectorPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("SQL Injection Test module initialized");
    addInfoLine("Ready to test web applications for SQL injection vulnerabilities.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">SQL Injection Tester</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Test web applications for SQL injection vulnerabilities. This tool is for educational 
          purposes only and demonstrates different SQL injection techniques.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SqlInjector />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">What is SQL Injection?</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                SQL injection is a code injection technique where malicious SQL statements are 
                inserted into entry fields for execution by the database backend.
              </p>
              <p>
                <span className="text-primary">Common vulnerabilities</span> include:
                <ul className="list-disc list-inside mt-2 ml-2 space-y-1">
                  <li>Unsanitized user input</li>
                  <li>Dynamic SQL queries</li>
                  <li>Improper error handling</li>
                  <li>Insufficient input validation</li>
                  <li>Overly privileged database users</li>
                </ul>
              </p>
              <p>
                <span className="text-accent">Prevention methods</span> include using 
                parameterized queries, stored procedures, ORMs, and input validation.
              </p>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Ethical Considerations</h2>
            <p className="text-sm font-mono text-muted-foreground">
              This tool is provided for educational purposes only. SQL injection testing without 
              explicit permission is illegal and unethical. Always obtain proper authorization 
              before testing web applications for security vulnerabilities.
            </p>
            <div className="mt-4 p-3 bg-background/50 rounded-md text-xs font-mono border border-border">
              <code className="text-primary">
                // Proper way to prevent SQL injection in code:<br />
                const query = 'SELECT * FROM users WHERE id = ?';<br />
                db.execute(query, [userId]);<br />
                // Instead of:<br />
                // db.execute('SELECT * FROM users WHERE id = ' + userId);
              </code>
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