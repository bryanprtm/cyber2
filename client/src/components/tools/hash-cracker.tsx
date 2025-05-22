import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { useTerminal } from "@/hooks/use-terminal";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Loader2, CheckCircle, AlertCircle, Copy } from "lucide-react";
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

// Form validation schema
const formSchema = z.object({
  hash: z.string().min(1, { message: "Hash is required" }),
  algorithm: z.enum(['md5', 'sha1', 'sha256', 'bcrypt']),
  method: z.enum(['dictionary', 'bruteforce', 'rainbow']),
  dictionary: z.string().optional(),
  usePredefined: z.boolean().default(true),
  charset: z.enum(['numeric', 'alphabetic', 'alphanumeric', 'special']).optional(),
  maxLength: z.string().optional(),
});

type FormValues = z.infer<typeof formSchema>;

// Common password dictionaries
const dictionaries = [
  { value: 'common', label: 'Common Passwords (10k)' },
  { value: 'rockyou', label: 'RockYou (sample)' },
  { value: 'english', label: 'English Words' },
  { value: 'names', label: 'Common Names' },
  { value: 'custom', label: 'Custom Wordlist' }
];

// Hash algorithms
const hashAlgorithms = [
  { value: 'md5', label: 'MD5' },
  { value: 'sha1', label: 'SHA-1' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'bcrypt', label: 'bcrypt (slow)' }
];

// Character sets for brute force
const charsets = [
  { value: 'numeric', label: 'Numeric (0-9)' },
  { value: 'alphabetic', label: 'Alphabetic (a-z, A-Z)' },
  { value: 'alphanumeric', label: 'Alphanumeric (0-9, a-z, A-Z)' },
  { value: 'special', label: 'All Characters (includes special chars)' }
];

// Common passwords for simulation
const commonPasswords = [
  '123456', 'password', '12345678', 'qwerty', 'abc123',
  'monkey', 'letmein', 'dragon', '111111', 'baseball',
  'iloveyou', 'trustno1', 'sunshine', 'master', 'welcome',
  'shadow', 'ashley', 'football', 'jesus', 'michael',
  'ninja', 'mustang', 'password1', 'admin', 'password123'
];

export default function HashCracker() {
  const { toast } = useToast();
  const { addSystemLine, addErrorLine, addInfoLine, clearLines } = useTerminal();
  
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [crackResult, setCrackResult] = useState<{
    found: boolean;
    plaintext?: string;
    timeTaken?: number;
    attempts?: number;
  } | null>(null);
  const [activeTab, setActiveTab] = useState("dictionary");
  const [customDictionary, setCustomDictionary] = useState("");
  
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      hash: "",
      algorithm: "md5",
      method: "dictionary",
      usePredefined: true,
      charset: "alphanumeric",
      maxLength: "8"
    }
  });
  
  // Effect to update the tab when method changes
  useEffect(() => {
    const method = form.watch("method");
    setActiveTab(method);
  }, [form.watch("method")]);
  
  // Generate a mock hash for demo purposes
  const generateMockHash = (text: string, algorithm: string): string => {
    // This is a simulation function only - in a real app this would use crypto libraries
    const hashLength = 
      algorithm === 'md5' ? 32 : 
      algorithm === 'sha1' ? 40 : 
      algorithm === 'sha256' ? 64 : 
      algorithm === 'bcrypt' ? 60 : 32;
    
    // Simple fake hash generation - NOT secure, just for UI demo
    let hash = '';
    const chars = '0123456789abcdef';
    
    if (algorithm === 'bcrypt') {
      hash = '$2a$10$';
      for (let i = 0; i < 53; i++) {
        hash += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    } else {
      for (let i = 0; i < hashLength; i++) {
        hash += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    }
    
    return hash;
  };
  
  // Simulate password cracking
  const simulateCracking = (hash: string, method: string, options: any): Promise<any> => {
    return new Promise((resolve, reject) => {
      // For demo, we'll just check against common passwords after a delay
      let foundPassword: string | null = null;
      let attempts = 0;
      
      // Calculate expected attempts based on method
      const totalAttempts = 
        method === 'dictionary' ? (options.usePredefined ? 1000 : 10000) : 
        method === 'bruteforce' ? 10000 : 
        method === 'rainbow' ? 500 : 1000;
      
      // Update progress periodically
      const startTime = Date.now();
      const interval = setInterval(() => {
        attempts += Math.floor(Math.random() * 100) + 50;
        const newProgress = Math.min(Math.floor((attempts / totalAttempts) * 100), 99);
        setProgress(newProgress);
        
        // For demo purposes, let's pretend we found the password sometimes
        if (Math.random() < 0.05 && !foundPassword) {
          // 5% chance of finding per interval
          foundPassword = commonPasswords[Math.floor(Math.random() * commonPasswords.length)];
        }
        
        // Simulate completion
        if (attempts >= totalAttempts || foundPassword) {
          clearInterval(interval);
          setProgress(100);
          
          // In a real app, we'd actually try to crack the hash
          // For this demo, we'll randomly succeed or fail
          const timeTaken = (Date.now() - startTime) / 1000;
          
          if (foundPassword) {
            resolve({
              found: true,
              plaintext: foundPassword,
              timeTaken,
              attempts
            });
          } else {
            resolve({
              found: false,
              timeTaken,
              attempts
            });
          }
        }
      }, 200);
    });
  };
  
  const onSubmit = async (data: FormValues) => {
    try {
      setLoading(true);
      setCrackResult(null);
      setProgress(0);
      clearLines();
      
      addSystemLine("Hash Cracker initialized");
      addInfoLine(`Target hash: ${data.hash}`);
      addInfoLine(`Algorithm: ${data.algorithm}`);
      addInfoLine(`Method: ${data.method}`);
      
      if (data.method === 'dictionary') {
        addInfoLine(`Dictionary: ${data.usePredefined ? (
          dictionaries.find(d => d.value === data.dictionary)?.label || 'Common Passwords'
        ) : 'Custom Dictionary'}`);
      } else if (data.method === 'bruteforce') {
        addInfoLine(`Character set: ${charsets.find(c => c.value === data.charset)?.label}`);
        addInfoLine(`Max length: ${data.maxLength}`);
      }
      
      addSystemLine("Starting hash cracking attempt...");
      
      // Simulate the cracking process
      const result = await simulateCracking(data.hash, data.method, {
        algorithm: data.algorithm,
        usePredefined: data.usePredefined,
        dictionary: data.dictionary,
        charset: data.charset,
        maxLength: data.maxLength
      });
      
      // Update the terminal with results
      if (result.found) {
        addSystemLine(`Hash successfully cracked!`);
        addInfoLine(`Plaintext: ${result.plaintext}`);
      } else {
        addErrorLine("Failed to crack the hash with the current settings");
      }
      
      addInfoLine(`Time taken: ${result.timeTaken.toFixed(2)} seconds`);
      addInfoLine(`Attempts: ${result.attempts.toLocaleString()}`);
      
      setCrackResult(result);
    } catch (error) {
      console.error("Hash cracking error:", error);
      addErrorLine("An error occurred during the hash cracking process");
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to process the hash cracking request"
      });
    } finally {
      setLoading(false);
    }
  };
  
  const handleMethodChange = (method: string) => {
    form.setValue('method', method as any);
    setActiveTab(method);
  };
  
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "The text has been copied to your clipboard."
    });
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Hash Cracker</h2>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="hash"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Hash to Crack</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Enter the hash value..."
                        className="font-mono bg-background border-secondary/50 min-h-[80px]"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="algorithm"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Hash Algorithm</FormLabel>
                    <Select 
                      onValueChange={field.onChange} 
                      defaultValue={field.value}
                    >
                      <FormControl>
                        <SelectTrigger className="font-mono bg-background border-secondary/50">
                          <SelectValue placeholder="Select algorithm" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {hashAlgorithms.map((algo) => (
                          <SelectItem key={algo.value} value={algo.value}>
                            {algo.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            
            <Separator className="my-4" />
            
            <div className="space-y-4">
              <FormLabel>Cracking Method</FormLabel>
              <Tabs 
                value={activeTab} 
                onValueChange={handleMethodChange}
                className="w-full"
              >
                <TabsList className="grid grid-cols-3 mb-4">
                  <TabsTrigger value="dictionary" className="font-tech">Dictionary</TabsTrigger>
                  <TabsTrigger value="bruteforce" className="font-tech">Brute Force</TabsTrigger>
                  <TabsTrigger value="rainbow" className="font-tech">Rainbow Tables</TabsTrigger>
                </TabsList>
                
                <TabsContent value="dictionary" className="space-y-4">
                  <FormField
                    control={form.control}
                    name="usePredefined"
                    render={({ field }) => (
                      <FormItem className="flex items-center space-x-2">
                        <FormControl>
                          <Checkbox 
                            checked={field.value}
                            onCheckedChange={field.onChange}
                          />
                        </FormControl>
                        <FormLabel className="cursor-pointer font-normal">Use predefined dictionary</FormLabel>
                      </FormItem>
                    )}
                  />
                  
                  {form.watch("usePredefined") ? (
                    <FormField
                      control={form.control}
                      name="dictionary"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Dictionary</FormLabel>
                          <Select 
                            onValueChange={field.onChange} 
                            defaultValue={field.value || "common"}
                          >
                            <FormControl>
                              <SelectTrigger className="font-mono bg-background border-secondary/50">
                                <SelectValue placeholder="Select dictionary" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {dictionaries.map((dict) => (
                                <SelectItem key={dict.value} value={dict.value}>
                                  {dict.label}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ) : (
                    <div className="space-y-2">
                      <Label htmlFor="custom-dictionary">Custom Dictionary</Label>
                      <Textarea
                        id="custom-dictionary"
                        placeholder="Enter words, one per line..."
                        className="font-mono bg-background border-secondary/50 min-h-[150px]"
                        value={customDictionary}
                        onChange={(e) => setCustomDictionary(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">
                        Enter potential passwords, one per line. The tool will try each word in order.
                      </p>
                    </div>
                  )}
                </TabsContent>
                
                <TabsContent value="bruteforce" className="space-y-4">
                  <FormField
                    control={form.control}
                    name="charset"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Character Set</FormLabel>
                        <Select 
                          onValueChange={field.onChange} 
                          defaultValue={field.value}
                        >
                          <FormControl>
                            <SelectTrigger className="font-mono bg-background border-secondary/50">
                              <SelectValue placeholder="Select character set" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {charsets.map((charset) => (
                              <SelectItem key={charset.value} value={charset.value}>
                                {charset.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="maxLength"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Maximum Length</FormLabel>
                        <FormControl>
                          <Input
                            type="number"
                            min="1"
                            max="12"
                            className="font-mono bg-background border-secondary/50"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                        <p className="text-xs text-muted-foreground">
                          Warning: Higher values will exponentially increase cracking time.
                        </p>
                      </FormItem>
                    )}
                  />
                </TabsContent>
                
                <TabsContent value="rainbow" className="space-y-4">
                  <div className="p-4 border border-secondary/30 rounded-md bg-secondary/5">
                    <h3 className="font-tech text-secondary text-sm mb-2">Rainbow Tables</h3>
                    <p className="text-sm text-muted-foreground">
                      Rainbow tables are precomputed tables for reversing cryptographic hash functions,
                      useful for cracking password hashes. They sacrifice storage space to reduce computation time.
                    </p>
                    <ul className="mt-2 space-y-1 text-sm">
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span>Much faster than brute force for supported hashes</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span>Effective against unsalted hashes</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <AlertCircle className="h-4 w-4 text-destructive" />
                        <span>Not effective against modern salted hashes (bcrypt, Argon2)</span>
                      </li>
                    </ul>
                  </div>
                  
                  <div className="bg-card border border-accent/20 p-3 rounded-md">
                    <p className="text-xs text-muted-foreground">
                      This demo will simulate rainbow table cracking. In a real scenario, this would use
                      large precomputed tables which are not included in this web application.
                    </p>
                  </div>
                </TabsContent>
              </Tabs>
            </div>
            
            {loading && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Progress:</span>
                  <span className="text-sm">{progress}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
            )}
            
            {crackResult && (
              <div className={`p-4 border rounded-md ${
                crackResult.found ? 'border-green-500/50 bg-green-500/10' : 'border-destructive/50 bg-destructive/10'
              }`}>
                <div className="flex items-start gap-2">
                  {crackResult.found ? (
                    <CheckCircle className="h-5 w-5 text-green-500 mt-0.5" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-destructive mt-0.5" />
                  )}
                  <div>
                    <h3 className="font-tech mb-1">
                      {crackResult.found ? 'Hash Cracked Successfully!' : 'Failed to Crack Hash'}
                    </h3>
                    {crackResult.found && (
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-mono text-sm">Plaintext:</span>
                        <div className="relative flex items-center bg-background px-2 py-1 rounded">
                          <code className="font-mono text-sm">{crackResult.plaintext}</code>
                          <Button 
                            size="sm" 
                            variant="ghost" 
                            className="h-6 w-6 p-0 ml-2"
                            onClick={() => copyToClipboard(crackResult.plaintext!)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>Time taken: {crackResult.timeTaken?.toFixed(2)}s</div>
                      <div>Attempts: {crackResult.attempts?.toLocaleString()}</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            <Button type="submit" disabled={loading} className="w-full">
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Cracking Hash...
                </>
              ) : (
                "Crack Hash"
              )}
            </Button>
          </form>
        </Form>
      </Card>
      
      <div className="bg-secondary/10 p-4 rounded-md text-sm">
        <h3 className="font-semibold mb-2">⚠️ Security Notice</h3>
        <p>
          This hash cracking tool is provided for educational purposes only. The tool 
          simulates hash cracking techniques but does not perform actual intensive cracking operations
          in the browser. For security research, consider dedicated tools like Hashcat or John the Ripper.
        </p>
      </div>
    </div>
  );
}