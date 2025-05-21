import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import CsrfTester from "@/components/tools/csrf-tester";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function CsrfTesterPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("CSRF Vulnerability Tester initialized");
    addInfoLine("Ready to test web applications for Cross-Site Request Forgery vulnerabilities.");
    addInfoLine("Configure the target and test parameters below.");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">CSRF Vulnerability Tester</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Test web applications for Cross-Site Request Forgery vulnerabilities that could allow attackers
          to trick users into performing unwanted actions without their consent.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <CsrfTester />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Understanding CSRF Attacks</h2>
            <div className="space-y-3 text-sm font-mono">
              <p>
                Cross-Site Request Forgery (CSRF) attacks allow malicious websites to perform
                actions on behalf of authenticated users without their knowledge or consent.
              </p>
              <p>
                <span className="text-primary">Attack Scenario:</span>
              </p>
              <div className="ml-2 space-y-1 text-xs">
                <p>1. User logs into a legitimate website (e.g., a banking site)</p>
                <p>2. Without logging out, the user visits a malicious website</p>
                <p>3. The malicious site contains code that submits a request to the banking site</p>
                <p>4. The browser automatically includes the user's cookies in the request</p>
                <p>5. The banking site processes the request as if it came from the legitimate user</p>
              </div>
            </div>
          </div>
          
          <div className="bg-card border border-accent/30 rounded-md p-4">
            <h2 className="text-xl font-tech text-accent mb-4">Prevention Techniques</h2>
            <div className="space-y-2 text-sm font-mono">
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Anti-CSRF Tokens</p>
                <p className="text-xs text-muted-foreground">Include a unique, unpredictable token with each request that the server validates.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">SameSite Cookies</p>
                <p className="text-xs text-muted-foreground">Set cookies with the SameSite attribute to prevent them from being sent in cross-site requests.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Custom Request Headers</p>
                <p className="text-xs text-muted-foreground">Check for custom headers that can only be set by your own JavaScript.</p>
              </div>
              
              <div className="p-2 bg-background/50 rounded-md">
                <p className="text-primary">Referer Validation</p>
                <p className="text-xs text-muted-foreground">Verify that the request's Referer header matches your own domain.</p>
              </div>
              
              <div className="mt-4 p-3 bg-background rounded-md text-xs border border-primary/20">
                <p className="text-primary font-tech">Common Implementation:</p>
                <pre className="mt-2 text-muted-foreground overflow-x-auto">
                  <code>
{`// Server-side example (Node.js/Express)
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Client-side
<form action="/submit" method="post">
  <input type="hidden" name="_csrf" 
         value="{{csrfToken}}">
  <!-- form fields -->
  <button type="submit">Submit</button>
</form>`}
                  </code>
                </pre>
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