import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { useTerminal } from "@/hooks/use-terminal";
import { Check, Copy, FileUp, RefreshCw, Trash, Code, Search } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";

export default function JsonFormatter() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine } = useTerminal();
  
  const [jsonInput, setJsonInput] = useState("");
  const [formattedOutput, setFormattedOutput] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [indentSize, setIndentSize] = useState(2);
  const [sortKeys, setSortKeys] = useState(false);
  const [activeTab, setActiveTab] = useState("format");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<Array<{ path: string, value: any }>>([]);
  const [minified, setMinified] = useState(false);
  
  // Format JSON input
  const formatJson = () => {
    try {
      if (!jsonInput.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter JSON data to format"
        });
        return;
      }
      
      // Parse the JSON to validate it
      const parsedJson = JSON.parse(jsonInput);
      
      // Format the JSON with the specified indent
      const formatted = JSON.stringify(
        parsedJson, 
        sortKeys ? function(key, value) {
          // Sort object keys if enabled
          if (value && typeof value === 'object' && !Array.isArray(value)) {
            return Object.keys(value).sort().reduce((result: any, key) => {
              result[key] = value[key];
              return result;
            }, {});
          }
          return value;
        } : undefined, 
        indentSize
      );
      
      setFormattedOutput(formatted);
      setValidationError(null);
      
      addSystemLine("JSON Formatting Operation");
      addInfoLine(`Input size: ${jsonInput.length} characters`);
      addInfoLine(`Formatted size: ${formatted.length} characters`);
      addInfoLine(`Indentation: ${indentSize} spaces${sortKeys ? ', keys sorted' : ''}`);
    } catch (error) {
      console.error("JSON formatting error:", error);
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      setValidationError(errorMessage);
      addErrorLine(`JSON validation error: ${errorMessage}`);
      toast({
        variant: "destructive",
        title: "Invalid JSON",
        description: errorMessage
      });
    }
  };
  
  // Minify JSON
  const minifyJson = () => {
    try {
      if (!jsonInput.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter JSON data to minify"
        });
        return;
      }
      
      // Parse the JSON to validate it
      const parsedJson = JSON.parse(jsonInput);
      
      // Output as a single line without whitespace
      const minified = JSON.stringify(parsedJson);
      
      setFormattedOutput(minified);
      setMinified(true);
      setValidationError(null);
      
      addSystemLine("JSON Minification Operation");
      addInfoLine(`Input size: ${jsonInput.length} characters`);
      addInfoLine(`Minified size: ${minified.length} characters`);
      addInfoLine(`Size reduction: ${Math.round((1 - minified.length / jsonInput.length) * 100)}%`);
    } catch (error) {
      console.error("JSON minification error:", error);
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      setValidationError(errorMessage);
      addErrorLine(`JSON validation error: ${errorMessage}`);
      toast({
        variant: "destructive",
        title: "Invalid JSON",
        description: errorMessage
      });
    }
  };
  
  // Search in JSON
  const searchInJson = () => {
    try {
      if (!jsonInput.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter JSON data to search in"
        });
        return;
      }
      
      if (!searchQuery.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter a search query"
        });
        return;
      }
      
      // Parse the JSON to validate it
      const parsedJson = JSON.parse(jsonInput);
      
      // Perform the search
      const results: Array<{ path: string, value: any }> = [];
      
      const search = (obj: any, path: string = '') => {
        if (obj === null || obj === undefined) return;
        
        // Check if current value matches
        if (typeof obj === 'string' && obj.includes(searchQuery)) {
          results.push({ path, value: obj });
        } else if (typeof obj === 'number' || typeof obj === 'boolean') {
          const strValue = String(obj);
          if (strValue.includes(searchQuery)) {
            results.push({ path, value: obj });
          }
        }
        
        // Recursively search in objects and arrays
        if (typeof obj === 'object') {
          for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
              // Check if the key matches the query
              if (key.includes(searchQuery)) {
                results.push({ path: path ? `${path}.${key}` : key, value: obj[key] });
              }
              
              // Continue searching in nested objects
              const newPath = path ? `${path}.${key}` : key;
              search(obj[key], newPath);
            }
          }
        }
      };
      
      search(parsedJson);
      setSearchResults(results);
      
      addSystemLine("JSON Search Operation");
      addInfoLine(`Search query: "${searchQuery}"`);
      addInfoLine(`Found ${results.length} matches`);
      
      if (results.length === 0) {
        toast({
          title: "Search Complete",
          description: "No matches found for your query"
        });
      }
    } catch (error) {
      console.error("JSON search error:", error);
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      setValidationError(errorMessage);
      addErrorLine(`JSON validation error: ${errorMessage}`);
      toast({
        variant: "destructive",
        title: "Invalid JSON",
        description: errorMessage
      });
    }
  };
  
  // Copy output to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Text copied to clipboard"
    });
  };
  
  // Clear input and output fields
  const clearFields = () => {
    setJsonInput("");
    setFormattedOutput("");
    setValidationError(null);
    setSearchResults([]);
  };
  
  // Handle file selection for JSON input
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setJsonInput(content);
      addSystemLine("File loaded for JSON formatting");
      addInfoLine(`File: ${file.name} (${formatFileSize(file.size)})`);
    };
    
    reader.readAsText(file);
    
    // Reset file input
    event.target.value = "";
  };
  
  // Format file size
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + " bytes";
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    else return (bytes / 1048576).toFixed(1) + " MB";
  };
  
  // Generate sample JSON
  const generateSampleJson = () => {
    const sample = {
      "user": {
        "id": 1,
        "name": "John Doe",
        "email": "john@example.com",
        "isActive": true,
        "roles": ["admin", "user"],
        "address": {
          "street": "123 Main St",
          "city": "Boston",
          "state": "MA",
          "zipCode": "02101"
        }
      },
      "orders": [
        {
          "id": "ORD-001",
          "date": "2023-05-15T14:30:00Z",
          "items": [
            {
              "productId": "P-100",
              "name": "Laptop",
              "price": 1299.99,
              "quantity": 1
            },
            {
              "productId": "P-200",
              "name": "Mouse",
              "price": 25.99,
              "quantity": 2
            }
          ],
          "total": 1351.97
        },
        {
          "id": "ORD-002",
          "date": "2023-06-20T10:15:00Z",
          "items": [
            {
              "productId": "P-300",
              "name": "Keyboard",
              "price": 85.50,
              "quantity": 1
            }
          ],
          "total": 85.50
        }
      ],
      "stats": {
        "totalOrders": 2,
        "totalSpent": 1437.47,
        "averageOrderValue": 718.74,
        "firstPurchaseDate": "2023-05-15T14:30:00Z"
      }
    };
    
    setJsonInput(JSON.stringify(sample, null, 2));
    toast({
      title: "Sample Generated",
      description: "A sample JSON structure has been loaded"
    });
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">JSON Formatter</h2>
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-3 mb-4">
            <TabsTrigger value="format" className="font-tech">Format / Minify</TabsTrigger>
            <TabsTrigger value="search" className="font-tech">Search</TabsTrigger>
            <TabsTrigger value="validate" className="font-tech">Validate</TabsTrigger>
          </TabsList>
          
          <TabsContent value="format" className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label htmlFor="json-input" className="text-sm font-tech">JSON Input</Label>
                <div className="flex space-x-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={clearFields}
                  >
                    <Trash className="h-3 w-3 mr-1" />
                    Clear
                  </Button>
                  <div className="relative">
                    <input
                      type="file"
                      id="json-file"
                      accept=".json,application/json"
                      className="absolute inset-0 opacity-0 w-full cursor-pointer"
                      onChange={handleFileSelect}
                    />
                    <Button 
                      variant="outline" 
                      size="sm"
                      className="h-7 px-2 text-xs"
                    >
                      <FileUp className="h-3 w-3 mr-1" />
                      File
                    </Button>
                  </div>
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={generateSampleJson}
                  >
                    <Code className="h-3 w-3 mr-1" />
                    Sample
                  </Button>
                </div>
              </div>
              <Textarea
                id="json-input"
                placeholder='Enter JSON to format, e.g., {"name":"John","age":30,"city":"New York"}'
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-32"
              />
            </div>
            
            <div className="flex flex-wrap gap-4 items-center">
              <div className="flex items-center space-x-2">
                <Label htmlFor="indent-size" className="text-sm whitespace-nowrap">Indent Size:</Label>
                <Input
                  id="indent-size"
                  type="number"
                  min="0"
                  max="8"
                  value={indentSize}
                  onChange={(e) => setIndentSize(Number(e.target.value))}
                  className="w-16 h-8 font-mono"
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="sort-keys"
                  checked={sortKeys}
                  onCheckedChange={(checked) => setSortKeys(!!checked)}
                />
                <Label htmlFor="sort-keys" className="text-sm cursor-pointer">Sort Keys</Label>
              </div>
              
              <div className="flex-grow"></div>
              
              <Button
                onClick={formatJson}
                className="ml-auto"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Format
              </Button>
              
              <Button
                onClick={minifyJson}
                variant="outline"
              >
                <Code className="h-4 w-4 mr-2" />
                Minify
              </Button>
            </div>
            
            {validationError && (
              <div className="bg-destructive/10 border border-destructive rounded p-3 text-sm">
                <span className="font-semibold">Error:</span> {validationError}
              </div>
            )}
            
            {formattedOutput && !validationError && (
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="json-output" className="text-sm font-tech">
                    {minified ? "Minified JSON" : "Formatted JSON"}
                  </Label>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    className="h-7"
                    onClick={() => copyToClipboard(formattedOutput)}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </Button>
                </div>
                <div className="relative">
                  <Textarea
                    id="json-output"
                    readOnly
                    value={formattedOutput}
                    className="font-mono bg-background/50 border-secondary/50 min-h-32"
                  />
                </div>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="search" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="json-input-search" className="text-sm font-tech">JSON Input</Label>
              <Textarea
                id="json-input-search"
                placeholder='Enter JSON to search in...'
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-20"
              />
            </div>
            
            <div className="flex space-x-2 items-center">
              <div className="flex-grow">
                <Input
                  placeholder="Enter search term..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="font-mono w-full"
                />
              </div>
              <Button onClick={searchInJson}>
                <Search className="h-4 w-4 mr-2" />
                Search
              </Button>
            </div>
            
            {searchResults.length > 0 && (
              <div className="space-y-2">
                <Label className="text-sm font-tech">Search Results ({searchResults.length})</Label>
                <div className="border border-secondary/30 rounded-md p-2 bg-background/50 max-h-80 overflow-y-auto">
                  {searchResults.map((result, index) => (
                    <div key={index} className="border-b border-secondary/20 last:border-0 py-2">
                      <div className="font-mono text-xs text-primary">{result.path}</div>
                      <div className="font-mono text-sm mt-1 break-all">
                        {typeof result.value === 'object' 
                          ? JSON.stringify(result.value) 
                          : String(result.value)
                        }
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="validate" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="json-input-validate" className="text-sm font-tech">JSON Input</Label>
              <Textarea
                id="json-input-validate"
                placeholder='Enter JSON to validate...'
                value={jsonInput}
                onChange={(e) => setJsonInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-32"
              />
            </div>
            
            <Button onClick={formatJson} className="w-full">
              <Check className="h-4 w-4 mr-2" />
              Validate JSON
            </Button>
            
            {validationError ? (
              <div className="bg-destructive/10 border border-destructive rounded p-4">
                <h3 className="text-destructive font-semibold mb-2">Invalid JSON</h3>
                <p className="text-sm">{validationError}</p>
              </div>
            ) : jsonInput ? (
              <div className="bg-green-500/10 border border-green-500 rounded p-4">
                <h3 className="text-green-500 font-semibold mb-2">Valid JSON</h3>
                <p className="text-sm">The JSON is valid and correctly formatted.</p>
              </div>
            ) : null}
          </TabsContent>
        </Tabs>
      </Card>
      
      <Card className="p-4 border-secondary/30 bg-card/80">
        <h3 className="text-lg font-tech text-secondary mb-2">About JSON Formatting</h3>
        <div className="space-y-3 text-sm">
          <p>
            JSON (JavaScript Object Notation) is a lightweight data interchange format that is easy for humans to read 
            and write and easy for machines to parse and generate.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div className="space-y-2">
              <h4 className="font-semibold text-primary">Key Features:</h4>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>Language independent data format</li>
                <li>Self-describing and easy to understand</li>
                <li>Hierarchical (values within values)</li>
                <li>Can represent complex data structures</li>
                <li>Easily parsed and generated by machines</li>
              </ul>
            </div>
            <div className="space-y-2">
              <h4 className="font-semibold text-primary">Common Uses:</h4>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>API responses and requests</li>
                <li>Configuration files</li>
                <li>Data storage and transfer</li>
                <li>Database serialization</li>
                <li>Cross-origin resource sharing</li>
              </ul>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}