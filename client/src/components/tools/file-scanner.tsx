import React, { useState, useRef } from 'react';
import axios from 'axios';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  AlertCircle, 
  Upload, 
  FileUp, 
  FileWarning, 
  Shield, 
  FileLock2, 
  FileX,
  AlertTriangle,
  CheckCircle2,
  File,
  Info,
  RefreshCw
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface FileScannerProps {
  onScanComplete?: (result: any) => void;
}

export default function FileScanner({ onScanComplete }: FileScannerProps) {
  const [file, setFile] = useState<File | null>(null);
  const [scanMalware, setScanMalware] = useState<boolean>(true);
  const [scanVulnerabilities, setScanVulnerabilities] = useState<boolean>(true);
  const [scanMetadata, setScanMetadata] = useState<boolean>(true);
  const [scanSensitiveData, setScanSensitiveData] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<any>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addSuccessLine } = useTerminal();
  const { toast } = useToast();
  
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0] || null;
    setFile(selectedFile);
    setScanResults(null);
    
    if (selectedFile) {
      addInfoLine(`File selected: ${selectedFile.name} (${formatFileSize(selectedFile.size)})`);
    }
  };
  
  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
  };
  
  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    
    const droppedFile = event.dataTransfer.files?.[0] || null;
    if (droppedFile) {
      setFile(droppedFile);
      setScanResults(null);
      addInfoLine(`File dropped: ${droppedFile.name} (${formatFileSize(droppedFile.size)})`);
    }
  };
  
  const handleScan = async () => {
    if (!file) {
      setError('Please select a file to scan');
      return;
    }
    
    setIsScanning(true);
    setError(null);
    setScanResults(null);
    setUploadProgress(0);
    
    addCommandLine(`Scanning file: ${file.name}`);
    addInfoLine('Uploading file and analyzing...');
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('scanMalware', scanMalware.toString());
    formData.append('scanVulnerabilities', scanVulnerabilities.toString());
    formData.append('scanMetadata', scanMetadata.toString());
    formData.append('scanSensitiveData', scanSensitiveData.toString());
    
    try {
      const response = await axios.post('/api/security/file-scanner', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1));
          setUploadProgress(percentCompleted);
        }
      });
      
      if (response.data.success) {
        const data = response.data.data;
        setScanResults(data);
        
        addSuccessLine(`File scan completed - ${data.fileName}`);
        
        // Log different findings based on scan results
        if (data.malwareDetection?.detected) {
          addErrorLine(`[ALERT] Potential malware detected! Risk level: ${data.malwareDetection.riskLevel}`);
        } else if (data.malwareDetection) {
          addInfoLine('No malware detected');
        }
        
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          addErrorLine(`[ALERT] Found ${data.vulnerabilities.length} vulnerabilities in file`);
        }
        
        if (data.sensitiveData?.detected) {
          addErrorLine(`[ALERT] Sensitive data found in file (${data.sensitiveData.patterns.length} types)`);
        }
        
        if (onScanComplete) {
          onScanComplete(data);
        }
        
        toast({
          title: 'Scan completed successfully',
          description: `Analyzed file: ${file.name}`,
          variant: 'default'
        });
      } else {
        setError(response.data.message || 'Failed to scan file');
        addErrorLine(`Error: ${response.data.message}`);
      }
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred';
      setError(errorMessage);
      addErrorLine(`Error: ${errorMessage}`);
      
      toast({
        title: 'Scan failed',
        description: errorMessage,
        variant: 'destructive'
      });
    } finally {
      setIsScanning(false);
    }
  };
  
  const handleReset = () => {
    setFile(null);
    setScanResults(null);
    setError(null);
    setUploadProgress(0);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    addCommandLine('Reset file scanner');
  };
  
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };
  
  const getRiskColor = (risk: string): string => {
    switch (risk.toLowerCase()) {
      case 'critical':
        return 'text-red-600';
      case 'high':
        return 'text-red-500';
      case 'medium':
        return 'text-orange-500';
      case 'low':
        return 'text-yellow-500';
      default:
        return 'text-green-500';
    }
  };
  
  const getRiskIcon = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical':
      case 'high':
        return <FileX className="h-4 w-4 text-red-500" />;
      case 'medium':
        return <FileWarning className="h-4 w-4 text-orange-500" />;
      case 'low':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default:
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">File Security Scanner</h2>
        
        <div 
          className={cn(
            "border-2 border-dashed rounded-md p-8 mb-4 text-center",
            "hover:border-primary/50 transition-colors cursor-pointer",
            "bg-background/50 flex flex-col items-center justify-center"
          )}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input 
            type="file" 
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
          />
          
          <FileUp className="h-12 w-12 text-muted-foreground mb-2" />
          <p className="font-tech text-lg mb-1">Drop file here</p>
          <p className="text-sm text-muted-foreground mb-3">or click to browse</p>
          
          {file && (
            <div className="bg-secondary/10 py-2 px-4 rounded-full flex items-center gap-2 mt-2">
              <File className="h-4 w-4 text-secondary" />
              <span className="font-mono text-sm">{file.name} ({formatFileSize(file.size)})</span>
            </div>
          )}
        </div>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="scan-malware" 
                  checked={scanMalware}
                  onCheckedChange={(checked) => setScanMalware(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="scan-malware" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Scan for malware
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="scan-vulnerabilities" 
                  checked={scanVulnerabilities}
                  onCheckedChange={(checked) => setScanVulnerabilities(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="scan-vulnerabilities" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Detect vulnerabilities
                </Label>
              </div>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="scan-metadata" 
                  checked={scanMetadata}
                  onCheckedChange={(checked) => setScanMetadata(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="scan-metadata" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Extract metadata
                </Label>
              </div>
              
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="scan-sensitive" 
                  checked={scanSensitiveData}
                  onCheckedChange={(checked) => setScanSensitiveData(!!checked)}
                  disabled={isScanning}
                />
                <Label 
                  htmlFor="scan-sensitive" 
                  className="text-sm font-tech cursor-pointer"
                >
                  Check for sensitive data
                </Label>
              </div>
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <AlertCircle className="h-4 w-4 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          
          {isScanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span>Uploading and analyzing...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="h-1.5 w-full bg-secondary/20 rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={handleScan}
              disabled={isScanning || !file}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isScanning ? 'Scanning...' : 'Scan File'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isScanning}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {scanResults && (
        <Card className="p-4 border-secondary/30 bg-card">
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid grid-cols-5 mb-4">
              <TabsTrigger value="summary" className="font-tech">Summary</TabsTrigger>
              <TabsTrigger value="malware" className="font-tech">Malware</TabsTrigger>
              <TabsTrigger value="vulnerabilities" className="font-tech">Vulns</TabsTrigger>
              <TabsTrigger value="metadata" className="font-tech">Metadata</TabsTrigger>
              <TabsTrigger value="sensitive" className="font-tech">Sensitive</TabsTrigger>
            </TabsList>
            
            <TabsContent value="summary" className="space-y-4">
              <div className="p-4 bg-background/70 rounded-md border border-secondary/20">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-lg font-tech text-secondary">Scan Results</h3>
                    <p className="text-sm font-mono text-muted-foreground">
                      {scanResults.fileName} ({formatFileSize(scanResults.fileSize)})
                    </p>
                    <p className="text-xs font-mono text-muted-foreground mt-1">
                      {scanResults.fileType} • {scanResults.mimeType}
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    {scanResults.malwareDetection?.detected ? (
                      <span className={cn("text-xs font-mono flex items-center", getRiskColor(scanResults.malwareDetection.riskLevel))}>
                        {getRiskIcon(scanResults.malwareDetection.riskLevel)}
                        <span className="ml-1">Risk: {scanResults.malwareDetection.riskLevel}</span>
                      </span>
                    ) : (
                      <span className="text-xs font-mono text-green-500 flex items-center">
                        <Shield className="h-3 w-3 mr-1" />
                        No Threats
                      </span>
                    )}
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4">
                  <div className="bg-card p-3 rounded border border-secondary/20 flex items-center justify-center flex-col">
                    <span className="text-xs font-mono text-muted-foreground mb-1">File Hash (MD5)</span>
                    <span className="text-xs font-mono break-all">{scanResults.hash.md5}</span>
                  </div>
                  
                  <div className="bg-card p-3 rounded border border-secondary/20 flex flex-col items-center">
                    <span className="text-xs font-mono text-muted-foreground mb-1">Malware</span>
                    <span className={cn("text-xs font-mono", scanResults.malwareDetection?.detected ? "text-red-500" : "text-green-500")}>
                      {scanResults.malwareDetection?.detected ? "Detected" : "Clean"}
                    </span>
                  </div>
                  
                  <div className="bg-card p-3 rounded border border-secondary/20 flex flex-col items-center">
                    <span className="text-xs font-mono text-muted-foreground mb-1">Vulnerabilities</span>
                    <span className={cn("text-xs font-mono", (scanResults.vulnerabilities?.length > 0) ? "text-amber-500" : "text-green-500")}>
                      {scanResults.vulnerabilities?.length || 0} Found
                    </span>
                  </div>
                  
                  <div className="bg-card p-3 rounded border border-secondary/20 flex flex-col items-center">
                    <span className="text-xs font-mono text-muted-foreground mb-1">Sensitive Data</span>
                    <span className={cn("text-xs font-mono", scanResults.sensitiveData?.detected ? "text-amber-500" : "text-green-500")}>
                      {scanResults.sensitiveData?.detected ? 
                        `${scanResults.sensitiveData.patterns.reduce((total: number, p: any) => total + p.matches, 0)} Matches` : 
                        "None Found"}
                    </span>
                  </div>
                </div>
              </div>
              
              {scanResults.malwareDetection?.detected && (
                <div className="p-3 rounded-md bg-red-500/10 border border-red-500/30">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-tech text-red-500">Malware Alert</h4>
                      <p className="text-xs font-mono mt-1">
                        {scanResults.malwareDetection.signatures?.join(', ')}
                      </p>
                    </div>
                  </div>
                </div>
              )}
              
              {scanResults.sensitiveData?.detected && (
                <div className="p-3 rounded-md bg-amber-500/10 border border-amber-500/30">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-tech text-amber-500">Sensitive Data Found</h4>
                      <p className="text-xs font-mono mt-1">
                        {scanResults.sensitiveData.patterns.map((p: any) => `${p.type} (${p.matches})`).join(', ')}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="malware">
              <div className="p-4 bg-background/70 rounded-md border border-secondary/20">
                <h3 className="text-lg font-tech text-secondary mb-4">Malware Analysis</h3>
                
                {scanResults.malwareDetection ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        {scanResults.malwareDetection.detected ? (
                          <span className={cn("font-tech", getRiskColor(scanResults.malwareDetection.riskLevel))}>
                            {scanResults.malwareDetection.riskLevel} Risk
                          </span>
                        ) : (
                          <span className="font-tech text-green-500">Clean</span>
                        )}
                      </div>
                      <div className="text-sm font-mono">
                        Score: {scanResults.malwareDetection.score}/100
                      </div>
                    </div>
                    
                    {scanResults.malwareDetection.detected && (
                      <>
                        <div className="space-y-2">
                          <h4 className="text-sm font-tech">Threat Type</h4>
                          <p className="font-mono text-xs bg-background p-2 rounded border border-secondary/20">
                            {scanResults.malwareDetection.threatType || 'Unknown'}
                          </p>
                        </div>
                        
                        <div className="space-y-2">
                          <h4 className="text-sm font-tech">Detected Signatures</h4>
                          <ul className="font-mono text-xs space-y-1">
                            {scanResults.malwareDetection.signatures?.map((sig: string, i: number) => (
                              <li key={i} className="bg-background p-2 rounded border border-secondary/20 flex items-start gap-2">
                                <AlertCircle className="h-3 w-3 mt-0.5 flex-shrink-0 text-red-500" />
                                {sig}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </>
                    )}
                    
                    {!scanResults.malwareDetection.detected && (
                      <div className="bg-green-500/10 p-3 rounded-md border border-green-500/30 flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-500" />
                        <p className="font-mono text-xs text-green-500">No malware or suspicious patterns detected in this file.</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <p className="text-muted-foreground">Malware scanning was not performed on this file.</p>
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="vulnerabilities">
              <div className="p-4 bg-background/70 rounded-md border border-secondary/20">
                <h3 className="text-lg font-tech text-secondary mb-4">Vulnerability Analysis</h3>
                
                {scanResults.vulnerabilities ? (
                  scanResults.vulnerabilities.length > 0 ? (
                    <ul className="space-y-3">
                      {scanResults.vulnerabilities.map((vuln: any, i: number) => (
                        <li key={i} className="bg-background p-3 rounded border border-secondary/20">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-2">
                              <div className={cn("mt-0.5", getRiskColor(vuln.severity))}>
                                {getRiskIcon(vuln.severity)}
                              </div>
                              <div>
                                <h4 className="text-sm font-tech">{vuln.name}</h4>
                                <span className="text-xs font-mono text-muted-foreground">{vuln.id}</span>
                              </div>
                            </div>
                            <span className={cn("text-xs font-mono px-2 py-0.5 rounded", 
                              vuln.severity === 'Critical' && "bg-red-500/10 text-red-500",
                              vuln.severity === 'High' && "bg-red-400/10 text-red-400",
                              vuln.severity === 'Medium' && "bg-orange-500/10 text-orange-500",
                              vuln.severity === 'Low' && "bg-yellow-500/10 text-yellow-500"
                            )}>
                              {vuln.severity}
                            </span>
                          </div>
                          
                          <p className="mt-2 text-xs font-mono">{vuln.description}</p>
                          
                          {vuln.remediation && (
                            <div className="mt-2 bg-primary/5 p-2 rounded text-xs font-mono">
                              <span className="font-tech text-primary">Remediation: </span>
                              {vuln.remediation}
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="bg-green-500/10 p-3 rounded-md border border-green-500/30 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-green-500" />
                      <p className="font-mono text-xs text-green-500">No vulnerabilities detected in this file.</p>
                    </div>
                  )
                ) : (
                  <div className="text-center py-6">
                    <p className="text-muted-foreground">Vulnerability scanning was not performed on this file.</p>
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="metadata">
              <div className="p-4 bg-background/70 rounded-md border border-secondary/20">
                <h3 className="text-lg font-tech text-secondary mb-4">File Metadata</h3>
                
                {scanResults.metadata ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div className="bg-background p-3 rounded border border-secondary/20">
                        <h4 className="text-sm font-tech mb-1">File Information</h4>
                        <div className="space-y-1 font-mono text-xs">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Name:</span>
                            <span>{scanResults.fileName}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Size:</span>
                            <span>{formatFileSize(scanResults.fileSize)}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Type:</span>
                            <span>{scanResults.fileType}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">MIME:</span>
                            <span>{scanResults.mimeType}</span>
                          </div>
                        </div>
                      </div>
                      
                      <div className="bg-background p-3 rounded border border-secondary/20">
                        <h4 className="text-sm font-tech mb-1">Timestamps</h4>
                        <div className="space-y-1 font-mono text-xs">
                          {scanResults.metadata.fileCreated && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Created:</span>
                              <span>{new Date(scanResults.metadata.fileCreated).toLocaleString()}</span>
                            </div>
                          )}
                          {scanResults.metadata.fileModified && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Modified:</span>
                              <span>{new Date(scanResults.metadata.fileModified).toLocaleString()}</span>
                            </div>
                          )}
                          {scanResults.metadata.fileLastAccessed && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Accessed:</span>
                              <span>{new Date(scanResults.metadata.fileLastAccessed).toLocaleString()}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div className="bg-background p-3 rounded border border-secondary/20">
                        <h4 className="text-sm font-tech mb-1">Origin</h4>
                        <div className="space-y-1 font-mono text-xs">
                          {scanResults.metadata.creator && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Creator:</span>
                              <span>{scanResults.metadata.creator}</span>
                            </div>
                          )}
                          {scanResults.metadata.application && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Application:</span>
                              <span>{scanResults.metadata.application}</span>
                            </div>
                          )}
                          {scanResults.metadata.os && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">OS:</span>
                              <span>{scanResults.metadata.os}</span>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="bg-background p-3 rounded border border-secondary/20">
                        <h4 className="text-sm font-tech mb-1">Embedded Content</h4>
                        {scanResults.metadata.embedded?.hasEmbeddedFiles ? (
                          <div className="space-y-1 font-mono text-xs">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Embedded Files:</span>
                              <span>{scanResults.metadata.embedded.embeddedFileCount}</span>
                            </div>
                            
                            {scanResults.metadata.embedded.embeddedFiles && (
                              <div className="mt-2">
                                <span className="text-muted-foreground">Files:</span>
                                <ul className="mt-1 ml-2 space-y-1">
                                  {scanResults.metadata.embedded.embeddedFiles.map((file: string, i: number) => (
                                    <li key={i} className="flex items-center">
                                      <File className="h-3 w-3 mr-1" />
                                      {file}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="font-mono text-xs">
                            <span>No embedded files detected</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <p className="text-muted-foreground">Metadata extraction was not performed on this file.</p>
                  </div>
                )}
              </div>
            </TabsContent>
            
            <TabsContent value="sensitive">
              <div className="p-4 bg-background/70 rounded-md border border-secondary/20">
                <h3 className="text-lg font-tech text-secondary mb-4">Sensitive Data Analysis</h3>
                
                {scanResults.sensitiveData ? (
                  scanResults.sensitiveData.detected ? (
                    <div className="space-y-4">
                      <div className="bg-amber-500/10 p-3 rounded-md border border-amber-500/30">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5" />
                          <div>
                            <h4 className="text-sm font-tech text-amber-500">Sensitive Information Found</h4>
                            <p className="font-mono text-xs mt-1">
                              This file contains data that could be sensitive or personally identifiable.
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      <div className="space-y-3">
                        {scanResults.sensitiveData.patterns.map((pattern: any, i: number) => (
                          <div key={i} className="bg-background p-3 rounded border border-secondary/20">
                            <div className="flex items-start justify-between">
                              <div className="flex items-center gap-2">
                                <FileLock2 className="h-4 w-4 text-amber-500" />
                                <h4 className="text-sm font-tech">{pattern.type}</h4>
                              </div>
                              <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-500">
                                {pattern.matches} {pattern.matches === 1 ? 'Match' : 'Matches'}
                              </span>
                            </div>
                            
                            {pattern.examples && pattern.examples.length > 0 && (
                              <div className="mt-2">
                                <h5 className="text-xs font-tech mb-1">Examples (Masked):</h5>
                                <ul className="space-y-1">
                                  {pattern.examples.map((example: string, j: number) => (
                                    <li key={j} className="text-xs font-mono bg-amber-500/5 p-1 rounded">
                                      {example}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="bg-green-500/10 p-3 rounded-md border border-green-500/30 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-green-500" />
                      <p className="font-mono text-xs text-green-500">No sensitive data patterns were detected in this file.</p>
                    </div>
                  )
                ) : (
                  <div className="text-center py-6">
                    <p className="text-muted-foreground">Sensitive data scanning was not performed on this file.</p>
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </Card>
      )}
    </div>
  );
}