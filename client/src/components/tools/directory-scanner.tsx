import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { 
  AlertCircle, 
  Play, 
  FolderSearch, 
  FileSearch, 
  Shield, 
  FileLock2, 
  FileWarning,
  Loader2,
  Clock,
  Check,
  X,
  ArrowUpDown
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface DirectoryScannerProps {
  onScanComplete?: (result: any) => void;
}

interface DirectoryEntry {
  path: string;
  type: 'directory' | 'file';
  status: number;
  interesting: boolean;
  size?: string;
  lastModified?: string;
  requiresAuth?: boolean;
  contentType?: string;
}

interface DirectoryScanResult {
  target: string;
  timestamp: Date;
  entries: DirectoryEntry[];
  totalScanned: number;
  found: number;
  interesting: number;
  scanDuration: string;
  wordlist: string;
}

export default function DirectoryScanner({ onScanComplete }: DirectoryScannerProps) {
  const [target, setTarget] = useState<string>('');
  const [wordlist, setWordlist] = useState<string>('common');
  const [extensions, setExtensions] = useState<string>('php,html,txt,bak,old,xml,json');
  const [recursive, setRecursive] = useState<boolean>(false);
  const [followRedirects, setFollowRedirects] = useState<boolean>(true);
  const [customWordlist, setCustomWordlist] = useState<string>('');
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<DirectoryScanResult | null>(null);
  const [sorting, setSorting] = useState<{field: string, direction: 'asc' | 'desc'}>({field: 'path', direction: 'asc'});
  const [filter, setFilter] = useState<string>('all');
  const [error, setError] = useState<string | null>(null);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Common wordlists
  const wordlists = {
    common: 'admin,wp-admin,backup,backups,data,files,images,img,private,old,test,dev,api,login,config,dashboard,tmp,temp,upload,uploads,assets,css,js,vendor,log,logs',
    medium: 'admin,administrator,backup,backups,beta,cache,cgi-bin,conf,config,data,dev,doc,docs,download,files,html,images,img,install,login,logs,old,passwords,private,robots,secret,secrets,secure,server-status,temp,test,tmp,upload,uploads,user,users,webadmin,wp-admin,wp-content,wp-login',
    large: 'admin,administrator,backup,backups,beta,bin,cache,cgi-bin,conf,config,core,data,database,db,debug,dev,development,docs,download,error,files,hidden,home,img,images,inc,include,includes,install,internal,js,lib,library,license,local,login,logs,old,panel,passwords,php,private,robots,root,scripts,secret,secrets,secure,server-status,setup,site,sql,staging,storage,temp,test,tmp,upload,uploads,user,users,util,utilities,webadmin,wp-admin,wp-content,wp-login'
  };
  
  // Reset error when inputs change
  useEffect(() => {
    setError(null);
  }, [target, wordlist, extensions, recursive, followRedirects, customWordlist]);
  
  // Simulated scan progress
  useEffect(() => {
    let progressInterval: NodeJS.Timeout;
    
    if (isScanning && scanProgress < 100) {
      progressInterval = setInterval(() => {
        setScanProgress(prev => {
          // Faster progress for shorter wordlists
          const increment = wordlist === 'common' ? 5 : wordlist === 'medium' ? 3 : 2;
          const newProgress = Math.min(prev + increment, 100);
          
          // Complete scan when reaching 100%
          if (newProgress === 100) {
            setTimeout(() => completeScan(), 500);
          }
          
          return newProgress;
        });
      }, 300);
    }
    
    return () => {
      if (progressInterval) clearInterval(progressInterval);
    };
  }, [isScanning, scanProgress, wordlist]);
  
  // Start the directory scan
  const startScan = () => {
    if (!target) {
      setError('Target URL is required');
      addErrorLine('Target URL is required');
      return;
    }
    
    // Validate URL format
    try {
      const url = new URL(target);
      if (!url.protocol.startsWith('http')) {
        throw new Error('URL must use HTTP or HTTPS protocol');
      }
    } catch (e) {
      setError('Invalid URL format. Please include http:// or https://');
      addErrorLine('Invalid URL format. Please include http:// or https://');
      return;
    }
    
    setIsScanning(true);
    setScanProgress(0);
    setScanResults(null);
    setError(null);
    
    // Log scan settings in terminal
    const commandArgs = [
      `--target ${target}`,
      `--wordlist ${wordlist}`,
      `--extensions ${extensions}`,
      recursive ? '--recursive' : '',
      followRedirects ? '--follow-redirects' : '',
      wordlist === 'custom' && customWordlist ? '--custom-wordlist "..."' : ''
    ].filter(Boolean).join(' ');
    
    addCommandLine(`directory-scan ${commandArgs}`);
    addInfoLine(`Starting directory scan on ${target}`);
    addInfoLine(`Wordlist: ${wordlist}${wordlist === 'custom' ? ' (custom)' : ''}, Extensions: ${extensions}`);
    
    if (recursive) {
      addLine("Recursive scanning enabled - this may take longer", "warning");
    }
  };
  
  // Complete the scan with simulated results
  const completeScan = () => {
    setIsScanning(false);
    
    // Generate a wordlist string representation
    let wordlistUsed = '';
    if (wordlist === 'custom' && customWordlist.trim()) {
      wordlistUsed = 'Custom wordlist';
    } else {
      const wordlistMap = { common: 'Common', medium: 'Medium', large: 'Large' };
      wordlistUsed = wordlistMap[wordlist as keyof typeof wordlistMap] || 'Common';
    }
    
    // Generate simulated results based on scan parameters
    const simulatedResults = generateSimulatedResults(wordlistUsed);
    setScanResults(simulatedResults);
    
    // Log summary in terminal
    addLine(`[COMPLETE] Directory scan completed in ${simulatedResults.scanDuration}`, "success");
    addInfoLine(`Scanned ${simulatedResults.totalScanned} paths, found ${simulatedResults.found} entries`);
    
    if (simulatedResults.interesting > 0) {
      addLine(`[ALERT] Found ${simulatedResults.interesting} potentially interesting paths!`, "warning");
      
      // Log a few of the interesting findings
      const interestingEntries = simulatedResults.entries.filter(e => e.interesting);
      interestingEntries.slice(0, 3).forEach(entry => {
        addLine(`Found: ${entry.path} (${entry.status})`, "warning");
      });
      
      if (interestingEntries.length > 3) {
        addLine(`... and ${interestingEntries.length - 3} more interesting findings.`, "info");
      }
    }
    
    // Show toast notification
    toast({
      title: "Scan Complete",
      description: `Found ${simulatedResults.found} directories and files`,
      variant: "default",
    });
    
    // Call completion callback if provided
    if (onScanComplete) {
      onScanComplete(simulatedResults);
    }
  };
  
  // Generate simulated scan results
  const generateSimulatedResults = (wordlistName: string): DirectoryScanResult => {
    // Selected extensions array
    const extensionArray = extensions.split(',').map(ext => ext.trim()).filter(Boolean);
    
    // Get the appropriate wordlist based on selection
    let words: string[] = [];
    if (wordlist === 'custom' && customWordlist.trim()) {
      words = customWordlist.split('\n').map(w => w.trim()).filter(Boolean);
    } else {
      words = (wordlists[wordlist as keyof typeof wordlists] || wordlists.common).split(',');
    }
    
    // Number of directories/files to find (varies by wordlist size and recursion)
    const baseCount = wordlist === 'common' ? 15 : wordlist === 'medium' ? 25 : 40;
    const foundCount = Math.floor(baseCount * (recursive ? 1.5 : 1) * (Math.random() * 0.5 + 0.75));
    
    // Generate simulated entries
    const entries: DirectoryEntry[] = [];
    const basePaths = [
      '', 'admin/', 'wp-content/', 'images/', 'assets/', 'data/', 'backup/', 
      'test/', 'dev/', 'old/', 'config/', 'api/', 'js/', 'css/'
    ];
    
    // Common interesting files to potentially discover
    const interestingFiles = [
      'config.php', 'wp-config.php', 'database.sql', 'users.db', '.env', 
      'passwords.txt', 'backup.zip', 'admin.php', 'phpinfo.php', '.git/HEAD',
      'credentials.xml', 'config.bak', '.htpasswd', 'secret.key', 'sitemap.xml',
      'robots.txt', 'login.php', 'test.php', 'debug.log', 'error_log'
    ];
    
    // Generate directory entries
    for (let i = 0; i < foundCount; i++) {
      let path: string;
      let type: 'directory' | 'file';
      let status: number;
      let interesting = false;
      
      // Randomly determine if this is a special "interesting" path
      const isInterestingEntry = Math.random() < 0.2; // 20% chance
      
      if (isInterestingEntry && interestingFiles.length > 0) {
        // Use one of the predefined interesting files
        const randomIndex = Math.floor(Math.random() * interestingFiles.length);
        path = interestingFiles.splice(randomIndex, 1)[0];
        type = 'file';
        interesting = true;
        
        // Sensitive files often return 403, 401, or 200
        const statusOptions = [200, 401, 403];
        status = statusOptions[Math.floor(Math.random() * statusOptions.length)];
      } else {
        // Generate a more typical entry
        const basePathIndex = Math.floor(Math.random() * basePaths.length);
        const basePath = basePaths[basePathIndex];
        
        if (Math.random() < 0.4) { // 40% chance of being a directory
          let dirName;
          // Use a word from wordlist
          if (words.length > 0 && Math.random() < 0.8) {
            const wordIndex = Math.floor(Math.random() * words.length);
            dirName = words[wordIndex];
          } else {
            // Or use a common directory name
            const commonDirs = ['images', 'admin', 'include', 'data', 'backup', 'uploads', 'public', 'private'];
            dirName = commonDirs[Math.floor(Math.random() * commonDirs.length)];
          }
          path = `${basePath}${dirName}/`;
          type = 'directory';
          status = Math.random() < 0.8 ? 200 : Math.random() < 0.5 ? 403 : 401;
          interesting = status !== 200; // 403/401 directories are interesting
        } else {
          // File
          let fileName;
          if (words.length > 0 && Math.random() < 0.7) {
            // Use a word from wordlist
            const wordIndex = Math.floor(Math.random() * words.length);
            fileName = words[wordIndex];
          } else {
            // Or use a common file name
            const commonFiles = ['index', 'admin', 'login', 'main', 'file', 'data', 'test', 'backup'];
            fileName = commonFiles[Math.floor(Math.random() * commonFiles.length)];
          }
          
          // Add extension
          const ext = extensionArray.length > 0 
            ? extensionArray[Math.floor(Math.random() * extensionArray.length)] 
            : 'html';
            
          path = `${basePath}${fileName}.${ext}`;
          type = 'file';
          status = Math.random() < 0.9 ? 200 : Math.random() < 0.5 ? 404 : 403;
          interesting = ext === 'bak' || ext === 'old' || ext === 'sql' || fileName.includes('admin');
        }
      }
      
      // Create entry object with additional metadata
      const entry: DirectoryEntry = {
        path,
        type,
        status,
        interesting,
        size: type === 'file' ? `${Math.floor(Math.random() * 1000) + 1}KB` : undefined,
        lastModified: new Date(Date.now() - Math.floor(Math.random() * 30 * 24 * 60 * 60 * 1000)).toISOString().split('T')[0],
        requiresAuth: status === 401,
        contentType: type === 'file' 
          ? path.endsWith('.php') ? 'application/php' 
            : path.endsWith('.html') ? 'text/html' 
              : path.endsWith('.js') ? 'application/javascript'
                : path.endsWith('.css') ? 'text/css'
                  : path.endsWith('.xml') ? 'application/xml'
                    : path.endsWith('.json') ? 'application/json'
                      : 'text/plain'
          : undefined
      };
      
      entries.push(entry);
    }
    
    // Remove any duplicates by path
    const uniqueEntries = Array.from(new Map(entries.map(entry => [entry.path, entry])).values());
    
    // Calculate total and interesting count
    const totalFound = uniqueEntries.length;
    const interestingCount = uniqueEntries.filter(e => e.interesting).length;
    
    // Generate scan duration
    const scanDuration = `${Math.floor(Math.random() * 2)}m ${Math.floor(Math.random() * 50) + 10}s`;
    
    // Return result object
    return {
      target,
      timestamp: new Date(),
      entries: uniqueEntries,
      totalScanned: words.length * (extensionArray.length + 1),
      found: totalFound,
      interesting: interestingCount,
      scanDuration,
      wordlist: wordlistName
    };
  };
  
  // Sort scan results based on current sorting state
  const getSortedEntries = (): DirectoryEntry[] => {
    if (!scanResults) return [];
    
    // Filter entries first
    let filteredEntries = [...scanResults.entries];
    if (filter === 'interesting') {
      filteredEntries = filteredEntries.filter(e => e.interesting);
    } else if (filter === 'directories') {
      filteredEntries = filteredEntries.filter(e => e.type === 'directory');
    } else if (filter === 'files') {
      filteredEntries = filteredEntries.filter(e => e.type === 'file');
    } else if (filter === '200') {
      filteredEntries = filteredEntries.filter(e => e.status === 200);
    } else if (filter === '403') {
      filteredEntries = filteredEntries.filter(e => e.status === 403);
    } else if (filter === '401') {
      filteredEntries = filteredEntries.filter(e => e.status === 401);
    }
    
    // Then sort
    return filteredEntries.sort((a, b) => {
      let comparison = 0;
      
      if (sorting.field === 'path') {
        comparison = a.path.localeCompare(b.path);
      } else if (sorting.field === 'type') {
        comparison = a.type.localeCompare(b.type);
      } else if (sorting.field === 'status') {
        comparison = a.status - b.status;
      } else if (sorting.field === 'interesting') {
        comparison = (a.interesting === b.interesting) ? 0 : a.interesting ? -1 : 1;
      }
      
      return sorting.direction === 'asc' ? comparison : -comparison;
    });
  };
  
  // Toggle sorting by field
  const toggleSort = (field: string) => {
    if (sorting.field === field) {
      setSorting({ ...sorting, direction: sorting.direction === 'asc' ? 'desc' : 'asc' });
    } else {
      setSorting({ field, direction: 'asc' });
    }
  };
  
  // Get status badge color
  const getStatusColor = (status: number): string => {
    if (status === 200) return 'text-green-500';
    if (status === 401) return 'text-orange-500';
    if (status === 403) return 'text-yellow-500';
    if (status === 404) return 'text-muted-foreground';
    return 'text-muted-foreground';
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Directory Scanner</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-url" className="text-sm font-tech">
              Target URL
            </Label>
            <Input
              id="target-url"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="font-mono"
              disabled={isScanning}
            />
            <p className="text-xs font-mono text-muted-foreground mt-1">
              Enter the full URL of the site to scan, including http:// or https://
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="wordlist" className="text-sm font-tech">
                Wordlist
              </Label>
              <Select 
                defaultValue={wordlist} 
                onValueChange={setWordlist}
                disabled={isScanning}
              >
                <SelectTrigger id="wordlist" className="font-mono">
                  <SelectValue placeholder="Select wordlist" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="common">Common (Fast)</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="large">Large (Comprehensive)</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="extensions" className="text-sm font-tech">
                File Extensions
              </Label>
              <Input
                id="extensions"
                placeholder="php,html,txt,bak,old,xml,json"
                value={extensions}
                onChange={(e) => setExtensions(e.target.value)}
                className="font-mono"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Comma-separated list of extensions to check
              </p>
            </div>
          </div>
          
          {wordlist === 'custom' && (
            <div className="space-y-2">
              <Label htmlFor="custom-wordlist" className="text-sm font-tech">
                Custom Wordlist
              </Label>
              <Textarea
                id="custom-wordlist"
                placeholder="Enter one word per line..."
                value={customWordlist}
                onChange={(e) => setCustomWordlist(e.target.value)}
                className="font-mono h-20"
                disabled={isScanning}
              />
              <p className="text-xs font-mono text-muted-foreground mt-1">
                Enter one directory/file name per line (without extensions)
              </p>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 space-x-0 sm:space-x-4">
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="recursive" 
                checked={recursive}
                onCheckedChange={(checked) => setRecursive(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="recursive" 
                className="text-sm font-tech cursor-pointer"
              >
                Recursive Scan
              </Label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="follow-redirects" 
                checked={followRedirects}
                onCheckedChange={(checked) => setFollowRedirects(!!checked)}
                disabled={isScanning}
              />
              <Label 
                htmlFor="follow-redirects" 
                className="text-sm font-tech cursor-pointer"
              >
                Follow Redirects
              </Label>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={startScan}
              disabled={isScanning}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isScanning ? (
                <span className="flex items-center">
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning...
                </span>
              ) : (
                <span className="flex items-center">
                  <FolderSearch className="h-4 w-4 mr-2" />
                  Start Scan
                </span>
              )}
            </Button>
          </div>
          
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Scan in progress...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="h-2" />
              <p className="text-xs font-mono text-muted-foreground animate-pulse">
                {scanProgress < 25 ? "Scanning directories..." : 
                 scanProgress < 50 ? "Testing files with extensions..." :
                 scanProgress < 75 ? "Analyzing responses..." :
                 "Finalizing results..."}
              </p>
            </div>
          )}
        </div>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-tech text-secondary">Scan Results</h2>
            <div className="flex items-center text-sm font-mono text-muted-foreground">
              <Clock className="h-3.5 w-3.5 mr-1" />
              {scanResults.scanDuration}
            </div>
          </div>
          
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Total Scanned</div>
                <div className="text-xl font-tech">{scanResults.totalScanned}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Found</div>
                <div className="text-xl font-tech">{scanResults.found}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-border">
                <div className="text-xs font-mono text-muted-foreground">Wordlist</div>
                <div className="text-md font-tech">{scanResults.wordlist}</div>
              </div>
              
              <div className="bg-background p-3 rounded-md border border-yellow-500/30">
                <div className="text-xs font-mono text-muted-foreground">Interesting</div>
                <div className="text-xl font-tech text-yellow-500">{scanResults.interesting}</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <div className="text-sm font-tech">Directory Listings</div>
                
                <Select 
                  defaultValue="all" 
                  onValueChange={setFilter}
                >
                  <SelectTrigger className="w-[150px] h-8 text-xs font-mono">
                    <SelectValue placeholder="Filter results" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="interesting">Interesting</SelectItem>
                    <SelectItem value="directories">Directories</SelectItem>
                    <SelectItem value="files">Files</SelectItem>
                    <SelectItem value="200">Status 200</SelectItem>
                    <SelectItem value="403">Status 403</SelectItem>
                    <SelectItem value="401">Status 401</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="border border-border rounded-md overflow-hidden">
                <div className="bg-muted p-2 grid grid-cols-12 gap-2 font-tech text-xs border-b border-border">
                  <div className="col-span-6 flex items-center cursor-pointer hover:text-primary" onClick={() => toggleSort('path')}>
                    Path
                    {sorting.field === 'path' && (
                      <ArrowUpDown className="h-3 w-3 ml-1" />
                    )}
                  </div>
                  <div className="col-span-2 flex items-center cursor-pointer hover:text-primary" onClick={() => toggleSort('type')}>
                    Type
                    {sorting.field === 'type' && (
                      <ArrowUpDown className="h-3 w-3 ml-1" />
                    )}
                  </div>
                  <div className="col-span-2 flex items-center cursor-pointer hover:text-primary" onClick={() => toggleSort('status')}>
                    Status
                    {sorting.field === 'status' && (
                      <ArrowUpDown className="h-3 w-3 ml-1" />
                    )}
                  </div>
                  <div className="col-span-2 flex items-center cursor-pointer hover:text-primary" onClick={() => toggleSort('interesting')}>
                    Interesting
                    {sorting.field === 'interesting' && (
                      <ArrowUpDown className="h-3 w-3 ml-1" />
                    )}
                  </div>
                </div>
                
                <div className="max-h-64 overflow-y-auto">
                  {getSortedEntries().length === 0 ? (
                    <div className="p-4 text-center text-muted-foreground text-sm">
                      No matching entries found with current filter.
                    </div>
                  ) : (
                    getSortedEntries().map((entry, index) => (
                      <div 
                        key={index}
                        className={cn(
                          "p-2 grid grid-cols-12 gap-2 font-mono text-xs",
                          index % 2 === 0 ? "bg-background" : "bg-muted",
                          entry.interesting ? "border-l-2 border-l-yellow-500" : ""
                        )}
                      >
                        <div className="col-span-6 flex items-center">
                          {entry.type === 'directory' ? (
                            <FolderSearch className="h-3.5 w-3.5 mr-1 text-primary" />
                          ) : (
                            <FileSearch className="h-3.5 w-3.5 mr-1 text-secondary" />
                          )}
                          <span className="truncate" title={entry.path}>
                            {entry.path}
                          </span>
                        </div>
                        <div className="col-span-2">
                          {entry.type === 'directory' ? 'Directory' : 'File'}
                        </div>
                        <div className={cn("col-span-2", getStatusColor(entry.status))}>
                          {entry.status}
                          {entry.requiresAuth && (
                            <FileLock2 className="h-3 w-3 ml-1 inline-block" />
                          )}
                        </div>
                        <div className="col-span-2">
                          {entry.interesting ? (
                            <span className="text-yellow-500 flex items-center">
                              <Check className="h-3.5 w-3.5 mr-1" />
                              Yes
                            </span>
                          ) : (
                            <span className="text-muted-foreground flex items-center">
                              <X className="h-3.5 w-3.5 mr-1" />
                              No
                            </span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
              
              <div className="p-3 bg-primary/5 border border-primary/20 rounded-md mt-3">
                <div className="flex items-start text-xs">
                  <Shield className="h-3.5 w-3.5 mt-0.5 mr-2 text-primary" />
                  <div>
                    <p className="text-primary font-tech">Security Note:</p>
                    <p className="mt-1 text-muted-foreground">
                      Directory scanning is used to identify hidden or sensitive files and directories
                      on web servers. Always ensure you have permission before scanning any website.
                      This tool is for educational purposes only.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}