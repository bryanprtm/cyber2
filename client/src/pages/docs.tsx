import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { MatrixBackground } from "@/components/matrix-background";

export default function Docs() {
  return (
    <div className="container mx-auto px-4 py-10">
      <div className="max-w-4xl mx-auto">
        <div className="relative mb-10 p-8 rounded-lg overflow-hidden">
          <MatrixBackground />
          <h1 className="text-4xl font-tech mb-4 text-center text-primary">Documentation</h1>
          <p className="text-center font-mono text-muted-foreground">
            Learn how to effectively use CyberPulse tools
          </p>
        </div>
        
        <Tabs defaultValue="getting-started">
          <TabsList className="grid w-full grid-cols-3 mb-8">
            <TabsTrigger value="getting-started" className="font-tech">
              Getting Started
            </TabsTrigger>
            <TabsTrigger value="tools" className="font-tech">
              Tools Guide
            </TabsTrigger>
            <TabsTrigger value="api" className="font-tech">
              API Reference
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="getting-started">
            <Card className="border-primary/30">
              <CardHeader>
                <CardTitle className="text-2xl font-tech text-primary">Getting Started with CyberPulse</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Introduction</h3>
                  <p className="font-mono text-muted-foreground">
                    CyberPulse provides a collection of web-based security tools designed for penetration testing, 
                    vulnerability scanning, and network analysis. This guide will help you get started with using 
                    the platform efficiently.
                  </p>
                </div>
                
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Basic Usage</h3>
                  <ol className="list-decimal pl-5 font-mono text-muted-foreground space-y-4">
                    <li>
                      <strong className="text-foreground">Navigation</strong> - Use the main menu to navigate 
                      between Home, Tools, Documentation, and About pages.
                    </li>
                    <li>
                      <strong className="text-foreground">Tool Selection</strong> - On the Tools page, browse 
                      through the categories in the sidebar to find the tool you need.
                    </li>
                    <li>
                      <strong className="text-foreground">Search Functionality</strong> - Use the search bar to 
                      quickly find tools by name, description, or category.
                    </li>
                    <li>
                      <strong className="text-foreground">Running Tools</strong> - Click the "Run Tool" button to 
                      execute a tool. The output will appear in the terminal below.
                    </li>
                  </ol>
                </div>
                
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Terminal Usage</h3>
                  <p className="mb-2 font-mono text-muted-foreground">
                    The terminal interface allows you to interact with tools directly:
                  </p>
                  <ul className="list-disc pl-5 font-mono text-sm text-muted-foreground space-y-2">
                    <li>View real-time output from tools</li>
                    <li>Copy terminal content with the copy button</li>
                    <li>Download terminal logs for record-keeping</li>
                    <li>Clear the terminal with the trash icon</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="tools">
            <Card className="border-primary/30">
              <CardHeader>
                <CardTitle className="text-2xl font-tech text-primary">Tools Guide</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Tool Categories</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">Vulnerability Scanning</h4>
                      <p className="text-sm font-mono text-muted-foreground">
                        Tools for discovering security flaws in web applications and networks
                      </p>
                    </div>
                    
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">Network Tools</h4>
                      <p className="text-sm font-mono text-muted-foreground">
                        Utilities for network analysis, port scanning, and traffic monitoring
                      </p>
                    </div>
                    
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">Information Gathering</h4>
                      <p className="text-sm font-mono text-muted-foreground">
                        Tools for reconnaissance and information collection
                      </p>
                    </div>
                    
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">Web Exploitation</h4>
                      <p className="text-sm font-mono text-muted-foreground">
                        Tools for testing and exploiting web application vulnerabilities
                      </p>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Using Specific Tools</h3>
                  <div className="p-4 border border-secondary/30 rounded-md">
                    <h4 className="font-tech text-secondary mb-2">Port Scanner</h4>
                    <p className="mb-2 font-mono text-sm text-muted-foreground">
                      The Port Scanner tool allows you to discover open ports on a target system:
                    </p>
                    <ol className="list-decimal pl-5 font-mono text-sm text-muted-foreground space-y-1">
                      <li>Select the Port Scanner tool from the Vulnerability Scanning category</li>
                      <li>Enter the target IP address or hostname</li>
                      <li>Select the port range to scan</li>
                      <li>Click "Start Scan" to begin the scanning process</li>
                      <li>View results in the terminal output</li>
                    </ol>
                  </div>
                </div>
                
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Interpreting Results</h3>
                  <p className="font-mono text-muted-foreground">
                    Each tool provides output in the terminal with color-coded information:
                  </p>
                  <ul className="list-disc pl-5 font-mono text-sm text-muted-foreground space-y-2 mt-2">
                    <li><span className="text-primary">Green text</span> - System messages and successful operations</li>
                    <li><span className="text-secondary">Blue text</span> - Informational messages and status updates</li>
                    <li><span className="text-accent">Red text</span> - Errors, warnings, and critical information</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="api">
            <Card className="border-primary/30">
              <CardHeader>
                <CardTitle className="text-2xl font-tech text-primary">API Reference</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">API Overview</h3>
                  <p className="font-mono text-muted-foreground">
                    CyberPulse provides a RESTful API that allows you to programmatically access the platform's 
                    security tools. This reference documents the available endpoints and how to use them.
                  </p>
                </div>
                
                <div className="p-4 border border-secondary/30 rounded-md">
                  <h3 className="text-xl font-tech mb-2 text-secondary">Authentication</h3>
                  <p className="mb-4 font-mono text-sm text-muted-foreground">
                    All API requests require authentication using an API key that should be passed in the 
                    Authorization header.
                  </p>
                  <div className="bg-[hsl(var(--terminal-bg))] p-3 rounded font-code text-xs text-primary mt-2">
                    <code>
                      Authorization: Bearer YOUR_API_KEY
                    </code>
                  </div>
                </div>
                
                <div>
                  <h3 className="text-xl font-tech mb-2 text-secondary">Endpoints</h3>
                  <div className="space-y-4">
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">GET /api/tools</h4>
                      <p className="text-sm font-mono text-muted-foreground mb-2">
                        Retrieves a list of all available tools
                      </p>
                      <div className="bg-[hsl(var(--terminal-bg))] p-2 rounded font-code text-xs">
                        <code className="text-secondary">
                          GET /api/tools
                        </code>
                      </div>
                    </div>
                    
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">POST /api/scan/port</h4>
                      <p className="text-sm font-mono text-muted-foreground mb-2">
                        Performs a port scan on the specified target
                      </p>
                      <div className="bg-[hsl(var(--terminal-bg))] p-2 rounded font-code text-xs">
                        <code className="text-secondary">
                          POST /api/scan/port<br />
                          {`{`}<br />
                          &nbsp;&nbsp;"target": "example.com",<br />
                          &nbsp;&nbsp;"ports": "1-1000",<br />
                          &nbsp;&nbsp;"timeout": 5000<br />
                          {`}`}
                        </code>
                      </div>
                    </div>
                    
                    <div className="p-3 border border-primary/20 rounded bg-card/50">
                      <h4 className="font-tech text-primary">POST /api/analyze/headers</h4>
                      <p className="text-sm font-mono text-muted-foreground mb-2">
                        Analyzes HTTP headers of a target website
                      </p>
                      <div className="bg-[hsl(var(--terminal-bg))] p-2 rounded font-code text-xs">
                        <code className="text-secondary">
                          POST /api/analyze/headers<br />
                          {`{`}<br />
                          &nbsp;&nbsp;"url": "https://example.com"<br />
                          {`}`}
                        </code>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
