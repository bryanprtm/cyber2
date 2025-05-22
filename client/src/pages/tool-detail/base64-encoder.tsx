import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import Base64Encoder from "@/components/tools/base64-encoder";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function Base64EncoderPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("Base64 Encoder/Decoder initialized");
    addInfoLine("Ready to encode or decode data using Base64 format");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">Base64 Encoder/Decoder</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Convert text and binary data to and from Base64 encoding format.
          Base64 encoding is commonly used to transmit binary data over systems designed for text.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Base64Encoder />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                Base64 is an encoding scheme that represents binary data in an ASCII string format by
                translating it into a radix-64 representation.
              </p>
              <p>
                Each Base64 digit represents exactly 6 bits of data, so three 8-bit bytes (a total of 24 bits)
                can be represented by four 6-bit Base64 digits.
              </p>
              <p>
                <span className="text-primary">Use cases:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Encoding binary data in JSON</li>
                <li>Email attachments (MIME)</li>
                <li>Data URIs in HTML and CSS</li>
                <li>Cookie values</li>
                <li>Basic Authentication headers</li>
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