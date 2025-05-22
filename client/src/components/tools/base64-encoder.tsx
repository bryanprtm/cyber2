import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useTerminal } from "@/hooks/use-terminal";
import { Copy, Clipboard, FileUp } from "lucide-react";

export default function Base64Encoder() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine } = useTerminal();
  
  const [encodeInput, setEncodeInput] = useState("");
  const [encodeOutput, setEncodeOutput] = useState("");
  const [decodeInput, setDecodeInput] = useState("");
  const [decodeOutput, setDecodeOutput] = useState("");
  const [activeTab, setActiveTab] = useState("encode");
  
  // Handle encoding text to Base64
  const handleEncode = () => {
    try {
      if (!encodeInput.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter some text to encode"
        });
        return;
      }
      
      const encoded = btoa(encodeInput);
      setEncodeOutput(encoded);
      
      addSystemLine("Base64 Encoding Operation");
      addInfoLine(`Input: ${encodeInput.slice(0, 50)}${encodeInput.length > 50 ? '...' : ''}`);
      addInfoLine(`Output: ${encoded.slice(0, 50)}${encoded.length > 50 ? '...' : ''}`);
    } catch (error) {
      console.error("Encoding error:", error);
      addErrorLine("Error encoding to Base64. Make sure you're using valid text.");
      toast({
        variant: "destructive",
        title: "Encoding Error",
        description: "Failed to encode the input. Some characters may not be supported."
      });
    }
  };
  
  // Handle decoding Base64 to text
  const handleDecode = () => {
    try {
      if (!decodeInput.trim()) {
        toast({
          variant: "destructive",
          title: "Error",
          description: "Please enter some Base64 to decode"
        });
        return;
      }
      
      const decoded = atob(decodeInput);
      setDecodeOutput(decoded);
      
      addSystemLine("Base64 Decoding Operation");
      addInfoLine(`Input: ${decodeInput.slice(0, 50)}${decodeInput.length > 50 ? '...' : ''}`);
      addInfoLine(`Output: ${decoded.slice(0, 50)}${decoded.length > 50 ? '...' : ''}`);
    } catch (error) {
      console.error("Decoding error:", error);
      addErrorLine("Error decoding from Base64. Make sure you're using valid Base64 input.");
      toast({
        variant: "destructive",
        title: "Decoding Error",
        description: "Invalid Base64 string. Please check your input."
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
  const clearFields = (mode: "encode" | "decode") => {
    if (mode === "encode") {
      setEncodeInput("");
      setEncodeOutput("");
    } else {
      setDecodeInput("");
      setDecodeOutput("");
    }
  };
  
  // Handle file selection for encoding
  const handleFileSelect = (mode: "encode" | "decode", event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    
    reader.onload = (e) => {
      const result = e.target?.result as string;
      if (mode === "encode") {
        // For file encoding, we read as DataURL and extract the base64 part
        const base64Content = result.split(",")[1]; // Remove the data URL prefix
        setEncodeInput(result);
        addSystemLine("File loaded for encoding");
        addInfoLine(`File: ${file.name} (${formatFileSize(file.size)})`);
      } else {
        // For file decoding, we read as text
        setDecodeInput(result);
        addSystemLine("File loaded for decoding");
        addInfoLine(`File: ${file.name} (${formatFileSize(file.size)})`);
      }
    };
    
    if (mode === "encode") {
      reader.readAsDataURL(file);
    } else {
      reader.readAsText(file);
    }
    
    // Reset file input
    event.target.value = "";
  };
  
  // Format file size
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + " bytes";
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    else return (bytes / 1048576).toFixed(1) + " MB";
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Base64 Encoder/Decoder</h2>
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-2 mb-4">
            <TabsTrigger value="encode" className="font-tech">Encode</TabsTrigger>
            <TabsTrigger value="decode" className="font-tech">Decode</TabsTrigger>
          </TabsList>
          
          <TabsContent value="encode" className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label htmlFor="encode-input" className="text-sm font-tech">Input Text</Label>
                <div className="flex space-x-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={() => clearFields("encode")}
                  >
                    Clear
                  </Button>
                  <div className="relative">
                    <input
                      type="file"
                      id="encode-file"
                      className="absolute inset-0 opacity-0 w-full cursor-pointer"
                      onChange={(e) => handleFileSelect("encode", e)}
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
                </div>
              </div>
              <Textarea
                id="encode-input"
                placeholder="Enter text to encode to Base64..."
                value={encodeInput}
                onChange={(e) => setEncodeInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-32"
              />
            </div>
            
            <Button onClick={handleEncode}>Encode to Base64</Button>
            
            {encodeOutput && (
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="encode-output" className="text-sm font-tech">Base64 Output</Label>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    className="h-7"
                    onClick={() => copyToClipboard(encodeOutput)}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </Button>
                </div>
                <Textarea
                  id="encode-output"
                  readOnly
                  value={encodeOutput}
                  className="font-mono bg-background/50 border-secondary/50 min-h-20"
                />
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="decode" className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label htmlFor="decode-input" className="text-sm font-tech">Base64 Input</Label>
                <div className="flex space-x-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="h-7 px-2 text-xs"
                    onClick={() => clearFields("decode")}
                  >
                    Clear
                  </Button>
                  <div className="relative">
                    <input
                      type="file"
                      id="decode-file"
                      className="absolute inset-0 opacity-0 w-full cursor-pointer"
                      onChange={(e) => handleFileSelect("decode", e)}
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
                </div>
              </div>
              <Textarea
                id="decode-input"
                placeholder="Enter Base64 to decode..."
                value={decodeInput}
                onChange={(e) => setDecodeInput(e.target.value)}
                className="font-mono bg-background border-secondary/50 min-h-32"
              />
            </div>
            
            <Button onClick={handleDecode}>Decode from Base64</Button>
            
            {decodeOutput && (
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="decode-output" className="text-sm font-tech">Decoded Output</Label>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    className="h-7"
                    onClick={() => copyToClipboard(decodeOutput)}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </Button>
                </div>
                <Textarea
                  id="decode-output"
                  readOnly
                  value={decodeOutput}
                  className="font-mono bg-background/50 border-secondary/50 min-h-20"
                />
              </div>
            )}
          </TabsContent>
        </Tabs>
      </Card>
      
      <Card className="p-4 border-secondary/30 bg-card/80">
        <h3 className="text-lg font-tech text-secondary mb-2">About Base64</h3>
        <div className="space-y-3 text-sm">
          <p>
            Base64 is a binary-to-text encoding scheme that represents binary data in an ASCII string format.
            It is commonly used when there is a need to encode binary data that needs to be stored and transferred 
            over media that are designed to deal with text.
          </p>
          <p>
            <span className="font-semibold">Common uses of Base64:</span>
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Encoding email attachments (MIME)</li>
            <li>Encoding binary data in JSON or XML</li>
            <li>Representing small images and files in HTML and CSS</li>
            <li>Encoding data in URLs</li>
            <li>Transmitting binary data securely</li>
          </ul>
        </div>
      </Card>
    </div>
  );
}