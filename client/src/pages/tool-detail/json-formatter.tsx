import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import JsonFormatter from "@/components/tools/json-formatter";
import { MatrixBackground } from "@/components/matrix-background";
import Terminal from "@/components/terminal";

export default function JsonFormatterPage() {
  const { addSystemLine, addInfoLine } = useTerminal();

  useEffect(() => {
    // Add some initial terminal messages when the page loads
    addSystemLine("JSON Formatter initialized");
    addInfoLine("Ready to format, minify, and validate JSON data");
  }, [addSystemLine, addInfoLine]);

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="relative mb-8 p-6 rounded-lg overflow-hidden">
        <MatrixBackground />
        <h1 className="text-3xl font-tech mb-4 text-center text-primary">JSON Formatter</h1>
        <p className="text-center font-mono text-muted-foreground max-w-2xl mx-auto">
          Format, validate, minify, and search through JSON data with ease.
          Essential for working with APIs, configurations, and data files.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <JsonFormatter />
        </div>
        
        <div className="lg:col-span-1">
          <div className="bg-card border border-secondary/30 rounded-md p-4 mb-6">
            <h2 className="text-xl font-tech text-secondary mb-4">Information</h2>
            <div className="space-y-4 text-sm font-mono">
              <p>
                JSON (JavaScript Object Notation) is a lightweight data-interchange format that is easy for
                humans to read and write and easy for machines to parse and generate.
              </p>
              <p>
                <span className="text-primary">Key Features:</span>
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>Formatting with custom indentation</li>
                <li>Minification to reduce file size</li>
                <li>Validation to check for syntax errors</li>
                <li>Key sorting for consistent presentation</li>
                <li>Search within complex JSON structures</li>
              </ul>
              <p>
                <span className="text-accent">Tip:</span> When working with large JSON files, minifying can
                significantly reduce file size for transport, while formatting with proper indentation
                improves readability for development.
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