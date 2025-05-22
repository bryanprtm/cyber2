import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import FormFuzzer from "@/components/tools/form-fuzzer";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function FormFuzzerPage() {
  const terminal = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    terminal.addSystemLine("Form Fuzzer module initialized");
    terminal.addInfoLine("Ready to scan web forms for vulnerabilities");
  }, [terminal]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Web Form Fuzzer</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Detect vulnerabilities in web forms by testing them with a variety of malicious payloads 
          to identify potential security weaknesses.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <FormFuzzer />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">About Form Fuzzing</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Form fuzzing is a technique used to identify security vulnerabilities in web applications 
                by sending unexpected, malformed, or malicious data to form fields.
              </p>
              <p>
                Common vulnerabilities tested:
              </p>
              <div className="ml-2 space-y-1">
                <p>• <span className="text-amber-500">Cross-Site Scripting (XSS)</span>: Injecting malicious scripts</p>
                <p>• <span className="text-amber-500">SQL Injection</span>: Manipulating database queries</p>
                <p>• <span className="text-amber-500">Command Injection</span>: Executing system commands</p>
                <p>• <span className="text-amber-500">Open Redirect</span>: Forcing redirects to malicious sites</p>
                <p>• <span className="text-amber-500">Cross-Site Request Forgery</span>: Performing unwanted actions</p>
              </div>
              <div className="p-2 rounded-md bg-red-500/10 mt-2 border border-red-500/20">
                <p className="text-xs text-red-500">
                  <span className="font-bold">Warning:</span> Only use this tool on systems you own or have explicit permission to test.
                  Unauthorized testing may be illegal and unethical.
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