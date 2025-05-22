import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import PhoneDoxing from "@/components/tools/phone-doxing";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function PhoneDoxingPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Phone Doxing Tool initialized");
    addInfoLine("Ready to gather information about phone numbers and potential owners");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Phone Doxing Tool</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Gather information about phone numbers, including carrier data, location, and potential owner information.
          This tool helps identify details associated with phone numbers for OSINT purposes.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <PhoneDoxing />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Phone number doxing involves gathering metadata and publicly available information associated with 
                phone numbers, including carrier information, geographic location, and potential owner details.
              </p>
              <p>
                <span className="text-primary">Capabilities:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Carrier identification and line type detection</li>
                <li>Number validation and formatting</li>
                <li>Geolocation based on number prefix</li>
                <li>Spam number detection</li>
                <li>Owner information discovery (when available)</li>
                <li>Social profile correlation</li>
              </ul>
              <p className="mt-4 text-yellow-500">
                <span className="font-semibold">Important Note:</span> This tool is for educational purposes only.
                Always respect privacy laws and use responsibly.
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