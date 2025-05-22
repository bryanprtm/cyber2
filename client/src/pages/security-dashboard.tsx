import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import SecurityMonitor from "@/components/dashboard/security-monitor";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function SecurityDashboardPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Security Operation Center Dashboard initialized");
    addInfoLine("Ready to run comprehensive security analysis");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Security Dashboard</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Comprehensive security assessment platform. Enter a target URL or IP address to automatically run
          all security checks and generate a detailed vulnerability report.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <SecurityMonitor />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Dashboard Features</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                The Security Dashboard provides comprehensive security analysis by automatically running 
                all available security modules against a target and generating a consolidated report.
              </p>
              <p>
                <span className="text-primary">Capabilities:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Comprehensive vulnerability scanning</li>
                <li>Automated risk analysis and scoring</li>
                <li>Detailed technical findings</li>
                <li>Prioritized security recommendations</li>
                <li>Exportable security reports</li>
              </ul>
              <p>
                <span className="text-accent">Instructions:</span>
              </p>
              <ol className="list-decimal ml-5 space-y-1">
                <li>Enter a target URL or IP address</li>
                <li>Click "Scan Target" to begin assessment</li>
                <li>Wait for the scan to complete</li>
                <li>Review findings across the dashboard tabs</li>
              </ol>
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