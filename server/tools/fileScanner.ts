import * as crypto from 'crypto';

export interface FileScannerOptions {
  fileBuffer: Buffer;
  fileName?: string;
  scanMalware?: boolean;
  scanVulnerabilities?: boolean;
  scanMetadata?: boolean;
  scanSensitiveData?: boolean;
}

export interface FileScanResult {
  fileName: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  hash: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  scanTime: number;
  malwareDetection?: {
    detected: boolean;
    score: number;
    threatType?: string;
    signatures?: string[];
    riskLevel: 'Clean' | 'Low' | 'Medium' | 'High' | 'Critical';
  };
  vulnerabilities?: Array<{
    id: string;
    name: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    description: string;
    remediation?: string;
    location?: {
      line?: number;
      column?: number;
    };
  }>;
  metadata?: {
    fileCreated?: Date;
    fileModified?: Date;
    fileLastAccessed?: Date;
    creator?: string;
    application?: string;
    os?: string;
    embedded?: {
      hasEmbeddedFiles: boolean;
      embeddedFileCount: number;
      embeddedFiles?: string[];
    };
  };
  sensitiveData?: {
    detected: boolean;
    patterns: Array<{
      type: string;
      matches: number;
      examples?: string[];
    }>;
  };
}

/**
 * Scan a file for malware, vulnerabilities, and sensitive information
 * @param options File scanner options
 * @returns File scan results
 */
export async function scanFile(options: FileScannerOptions): Promise<FileScanResult> {
  const { fileBuffer, fileName = 'unknown_file', scanMalware = true, scanVulnerabilities = true, 
          scanMetadata = true, scanSensitiveData = true } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Get basic file info
  const fileSize = fileBuffer.length;
  const mimeType = detectMimeType(fileBuffer);
  const fileType = getFileType(mimeType, fileName);
  
  // Calculate file hashes
  const md5Hash = crypto.createHash('md5').update(fileBuffer).digest('hex');
  const sha1Hash = crypto.createHash('sha1').update(fileBuffer).digest('hex');
  const sha256Hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  
  // Create base result
  const result: FileScanResult = {
    fileName,
    fileSize,
    fileType,
    mimeType,
    hash: {
      md5: md5Hash,
      sha1: sha1Hash,
      sha256: sha256Hash
    },
    scanTime: 0 // Will update at the end
  };
  
  // Perform malware scan if requested
  if (scanMalware) {
    result.malwareDetection = scanForMalware(fileBuffer, mimeType, fileType);
  }
  
  // Perform vulnerability scan if requested
  if (scanVulnerabilities) {
    result.vulnerabilities = scanForVulnerabilities(fileBuffer, mimeType, fileType);
  }
  
  // Extract metadata if requested
  if (scanMetadata) {
    result.metadata = extractMetadata(fileBuffer, mimeType, fileName);
  }
  
  // Scan for sensitive data if requested
  if (scanSensitiveData) {
    result.sensitiveData = scanForSensitiveData(fileBuffer, mimeType, fileType);
  }
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Attempt to detect the MIME type of a file from its buffer
 */
function detectMimeType(buffer: Buffer): string {
  // Very simplified MIME type detection
  const signatureMap: Record<string, string> = {
    '89504E47': 'image/png',
    'FFD8FF': 'image/jpeg',
    '47494638': 'image/gif',
    '25504446': 'application/pdf',
    '504B0304': 'application/zip',
    '7B5C727466': 'application/rtf',
    '3C3F786D6C': 'application/xml',
    '68746D6C3E': 'text/html',
    '1F8B08': 'application/gzip',
    '#!/': 'text/x-script',
    '<?php': 'application/x-php',
    'import': 'text/javascript',
    'function': 'text/javascript',
    'class': 'text/javascript',
    'package': 'text/java',
    '#include': 'text/x-c'
  };
  
  // Check for text files
  const isTextFile = buffer.slice(0, 512).toString().trim().length > 0;
  
  if (isTextFile) {
    const content = buffer.slice(0, 512).toString();
    
    if (content.includes('<?php')) return 'application/x-php';
    if (content.includes('<!DOCTYPE html') || content.includes('<html')) return 'text/html';
    if (content.includes('import') && content.includes('from')) return 'text/javascript';
    if (content.includes('function') && content.includes('var')) return 'text/javascript';
    if (content.includes('class') && content.includes('extends')) return 'text/javascript';
    if (content.includes('package') && content.includes('import')) return 'text/java';
    if (content.includes('#include')) return 'text/x-c';
    
    // Default to plain text
    return 'text/plain';
  }
  
  // Get first bytes as hex
  const hex = buffer.slice(0, 8).toString('hex').toUpperCase();
  
  // Check signature
  for (const [signature, mimeType] of Object.entries(signatureMap)) {
    if (hex.startsWith(signature)) {
      return mimeType;
    }
  }
  
  // Default
  return 'application/octet-stream';
}

/**
 * Get a user-friendly file type from MIME type and filename
 */
function getFileType(mimeType: string, fileName: string): string {
  const extension = fileName.split('.').pop()?.toLowerCase() || '';
  
  // Common file types
  const mimeTypeMap: Record<string, string> = {
    'image/png': 'PNG Image',
    'image/jpeg': 'JPEG Image',
    'image/gif': 'GIF Image',
    'application/pdf': 'PDF Document',
    'application/zip': 'ZIP Archive',
    'application/x-rar-compressed': 'RAR Archive',
    'application/x-gzip': 'GZIP Archive',
    'application/x-7z-compressed': '7Z Archive',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel Spreadsheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'PowerPoint Presentation',
    'text/plain': 'Text File',
    'text/html': 'HTML File',
    'text/css': 'CSS File',
    'text/javascript': 'JavaScript File',
    'application/json': 'JSON File',
    'application/xml': 'XML File',
    'application/x-php': 'PHP File',
    'application/x-executable': 'Executable File',
    'application/x-dosexec': 'Windows Executable',
    'application/java-archive': 'Java JAR File',
    'application/x-msdownload': 'Windows Executable'
  };
  
  // Extensions that might be suspicious
  const suspiciousExtensions = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'sh', 'py'];
  
  if (mimeType in mimeTypeMap) {
    return mimeTypeMap[mimeType];
  }
  
  // Handle specific extensions
  if (extension) {
    if (suspiciousExtensions.includes(extension)) {
      return `Executable File (${extension.toUpperCase()})`;
    }
    
    return `${extension.toUpperCase()} File`;
  }
  
  return 'Unknown File Type';
}

/**
 * Scan file for malware signatures
 * Note: This is a simplified demonstration. Real implementation would use malware signature databases.
 */
function scanForMalware(buffer: Buffer, mimeType: string, fileType: string): FileScanResult['malwareDetection'] {
  // Simplified malware detection - looking for basic suspicious patterns
  const content = buffer.toString('utf8', 0, Math.min(buffer.length, 10240));
  const signatures: string[] = [];
  let score = 0;
  let threatType: string | undefined;

  // Check for executable files
  if (
    mimeType === 'application/x-executable' || 
    mimeType === 'application/x-dosexec' || 
    mimeType === 'application/x-msdownload'
  ) {
    signatures.push('Executable file detected');
    score += 30;
  }

  // Check for common malware patterns - these are simplified examples
  const patterns = [
    { pattern: /(eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate)/i, name: 'PHP Obfuscation', score: 60 },
    { pattern: /WScript\.Shell|Shell\.Application|ShellExecute|CreateObject/i, name: 'Suspicious Script Activity', score: 50 },
    { pattern: /document\.write\s*\(\s*unescape\s*\(/i, name: 'JavaScript Obfuscation', score: 40 },
    { pattern: /powershell\.exe|cmd\.exe|rundll32\.exe/i, name: 'System Command Execution', score: 50 },
    { pattern: /CreateProcess|VirtualAlloc|WriteProcessMemory/i, name: 'Memory Manipulation', score: 70 },
    { pattern: /wget|curl|bitsadmin.*transfer/i, name: 'Suspicious Download Activity', score: 40 },
    { pattern: /net\s+user\s+add|net\s+localgroup\s+administrators/i, name: 'User Account Creation', score: 60 },
    { pattern: /system32.*drivers.*etc.*hosts/i, name: 'Hosts File Modification', score: 50 },
    { pattern: /certutil.*decode|certutil.*urlcache/i, name: 'Certificate Utility Abuse', score: 50 },
    { pattern: /schtasks.*create|at\s+\d{2}:\d{2}/i, name: 'Scheduled Task Creation', score: 40 }
  ];
  
  // Search for patterns
  for (const { pattern, name, score: patternScore } of patterns) {
    if (pattern.test(content)) {
      signatures.push(name);
      score += patternScore;
      
      if (!threatType) {
        threatType = name;
      }
    }
  }
  
  // Assess risk level based on score
  let riskLevel: 'Clean' | 'Low' | 'Medium' | 'High' | 'Critical' = 'Clean';
  
  if (score > 100) {
    riskLevel = 'Critical';
  } else if (score > 80) {
    riskLevel = 'High';
  } else if (score > 50) {
    riskLevel = 'Medium';
  } else if (score > 20) {
    riskLevel = 'Low';
  }
  
  return {
    detected: signatures.length > 0,
    score,
    threatType,
    signatures: signatures.length > 0 ? signatures : undefined,
    riskLevel
  };
}

/**
 * Scan for vulnerabilities in code files
 * Note: This is a simplified demonstration. Real implementation would use static analysis tools.
 */
function scanForVulnerabilities(buffer: Buffer, mimeType: string, fileType: string): FileScanResult['vulnerabilities'] {
  // Only scan certain file types
  const vulnerableFileTypes = [
    'text/javascript', 
    'application/x-php', 
    'text/html', 
    'text/x-python', 
    'text/x-java',
    'text/x-c'
  ];
  
  if (!vulnerableFileTypes.includes(mimeType)) {
    return [];
  }
  
  const content = buffer.toString('utf8');
  const vulnerabilities: FileScanResult['vulnerabilities'] = [];
  
  // Check for common vulnerabilities - these are simplified examples
  const patterns = [
    {
      pattern: /eval\s*\(.*\$_/i,
      id: 'PHP-EVAL-01',
      name: 'PHP Remote Code Execution',
      severity: 'Critical' as const,
      description: 'Unfiltered user input used in eval() function'
    },
    {
      pattern: /\$_GET|\$_POST|\$_REQUEST.*include/i,
      id: 'PHP-LFI-01',
      name: 'PHP Local File Inclusion',
      severity: 'High' as const,
      description: 'User input used in include/require statements'
    },
    {
      pattern: /mysqli_query\s*\(.*\$_/i,
      id: 'PHP-SQLI-01',
      name: 'SQL Injection Vulnerability',
      severity: 'High' as const,
      description: 'Unfiltered user input used in SQL query'
    },
    {
      pattern: /echo\s+.*\$_/i,
      id: 'PHP-XSS-01',
      name: 'Cross-Site Scripting',
      severity: 'Medium' as const,
      description: 'Unfiltered user input echoed to page'
    },
    {
      pattern: /document\.write\s*\(.*location/i,
      id: 'JS-XSS-01',
      name: 'JavaScript XSS',
      severity: 'Medium' as const,
      description: 'User-controlled data written to document'
    },
    {
      pattern: /document\.cookie|localStorage|sessionStorage/i,
      id: 'JS-STORAGE-01',
      name: 'Insecure Data Storage',
      severity: 'Low' as const,
      description: 'Sensitive data may be stored in client-side storage'
    },
    {
      pattern: /password.*['"][^'"]{1,20}['"]|api[_-]?key.*['"][^'"]{1,30}['"]|secret.*['"][^'"]{1,30}['"]|token.*['"][^'"]{1,30}['"]/i,
      id: 'GEN-SECRET-01',
      name: 'Hardcoded Credentials',
      severity: 'High' as const,
      description: 'Potential hardcoded credentials found'
    }
  ];
  
  // Check for each vulnerability pattern
  for (const { pattern, id, name, severity, description } of patterns) {
    if (pattern.test(content)) {
      vulnerabilities.push({
        id,
        name,
        severity,
        description,
        remediation: 'Review the code and implement proper input validation and output encoding.'
      });
    }
  }
  
  return vulnerabilities;
}

/**
 * Extract basic metadata from file
 * Note: This is a simplified version. A real implementation would use more sophisticated tools.
 */
function extractMetadata(buffer: Buffer, mimeType: string, fileName: string): FileScanResult['metadata'] {
  const now = new Date();
  
  // Basic metadata that would normally be extracted from file
  const metadata: FileScanResult['metadata'] = {
    fileCreated: new Date(now.getTime() - 1000 * 60 * 60 * 24 * 7), // 1 week ago (example)
    fileModified: new Date(now.getTime() - 1000 * 60 * 60), // 1 hour ago (example)
    fileLastAccessed: now,
    embedded: {
      hasEmbeddedFiles: false,
      embeddedFileCount: 0
    }
  };
  
  // Check for file type specific metadata
  if (mimeType.startsWith('image/')) {
    metadata.creator = 'Camera/Image Software';
    metadata.application = 'Image Editor';
  } else if (mimeType === 'application/pdf') {
    metadata.creator = 'PDF Creator';
    metadata.application = 'PDF Software';
    
    // Check for embedded content in PDFs
    if (buffer.includes(Buffer.from('stream', 'utf8'))) {
      metadata.embedded = {
        hasEmbeddedFiles: true,
        embeddedFileCount: 1,
        embeddedFiles: ['embedded_content.unknown']
      };
    }
  } else if (mimeType.includes('officedocument')) {
    metadata.creator = 'Document Author';
    metadata.application = 'Microsoft Office';
    metadata.os = 'Windows';
  } else if (mimeType === 'application/zip' || mimeType === 'application/x-7z-compressed') {
    // Archive files often contain embedded files
    metadata.embedded = {
      hasEmbeddedFiles: true,
      embeddedFileCount: 3,
      embeddedFiles: ['file1.txt', 'file2.jpg', 'file3.doc']
    };
  }
  
  return metadata;
}

/**
 * Scan for sensitive data patterns
 * Note: This is a simplified implementation. Real scanners use more sophisticated pattern matching.
 */
function scanForSensitiveData(buffer: Buffer, mimeType: string, fileType: string): FileScanResult['sensitiveData'] {
  // Only scan text-based files
  if (!mimeType.startsWith('text/') && 
      mimeType !== 'application/json' && 
      mimeType !== 'application/xml' && 
      mimeType !== 'application/x-php') {
    return {
      detected: false,
      patterns: []
    };
  }
  
  const content = buffer.toString('utf8');
  const patterns: Array<{type: string, matches: number, examples?: string[]}> = [];
  
  // Define regex patterns for sensitive data
  const dataPatterns = [
    {
      type: 'Credit Card',
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g
    },
    {
      type: 'Email Address',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
    },
    {
      type: 'IP Address',
      regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
    },
    {
      type: 'US Social Security Number',
      regex: /\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))[-]?(?!00)\d{2}[-]?(?!0000)\d{4}\b/g
    },
    {
      type: 'API Key/Token',
      regex: /\b(?:api[_-]?key|access[_-]?token|secret|password)[_-]?[=:][_-]?["']?[A-Za-z0-9+\/=]{16,}["']?/gi
    }
  ];
  
  // Check for each pattern
  for (const { type, regex } of dataPatterns) {
    const matches = content.match(regex);
    if (matches && matches.length > 0) {
      // Mask the examples for privacy
      const maskedExamples = matches.slice(0, 2).map(match => {
        if (type === 'Credit Card') {
          return match.substring(0, 4) + '********' + match.substring(match.length - 4);
        } else if (type === 'Email Address') {
          const [username, domain] = match.split('@');
          return username.substring(0, 2) + '***@' + domain;
        } else if (type === 'US Social Security Number') {
          return '***-**-' + match.substring(match.length - 4);
        } else {
          return match.substring(0, 3) + '****************';
        }
      });
      
      patterns.push({
        type,
        matches: matches.length,
        examples: maskedExamples
      });
    }
  }
  
  return {
    detected: patterns.length > 0,
    patterns
  };
}