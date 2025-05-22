export interface Tool {
  id: string;
  name: string;
  description: string;
  category: string;
  categoryLabel: string;
}

export const tools: Tool[] = [
  // Vulnerability Scanning Tools
  {
    id: "port-scanner",
    name: "Port Scanner",
    description: "Scan target systems for open ports and running services.",
    category: "vulnerability",
    categoryLabel: "Network"
  },
  {
    id: "sql-injector",
    name: "SQL Injector",
    description: "Test websites for SQL injection vulnerabilities.",
    category: "vulnerability",
    categoryLabel: "WebApp"
  },
  {
    id: "xss-detector",
    name: "XSS Detector",
    description: "Scan for cross-site scripting vulnerabilities in web apps.",
    category: "vulnerability",
    categoryLabel: "WebApp"
  },
  {
    id: "directory-scanner",
    name: "Directory Scanner",
    description: "Discover hidden directories and files on web servers.",
    category: "vulnerability",
    categoryLabel: "WebApp"
  },
  {
    id: "ssl-scanner",
    name: "SSL Scanner",
    description: "Analyze SSL/TLS configurations and certificates.",
    category: "vulnerability",
    categoryLabel: "Security"
  },
  {
    id: "csrf-tester",
    name: "CSRF Tester",
    description: "Test web applications for CSRF vulnerabilities.",
    category: "vulnerability",
    categoryLabel: "WebApp"
  },
  
  // Network Tools
  {
    id: "ping-sweep",
    name: "Ping Sweep",
    description: "Discover live hosts on a network using ICMP requests.",
    category: "network",
    categoryLabel: "Network"
  },
  {
    id: "traceroute",
    name: "Traceroute",
    description: "Trace the path of packets to a destination host.",
    category: "network",
    categoryLabel: "Network"
  },
  {
    id: "dns-lookup",
    name: "DNS Lookup",
    description: "Query DNS records for a domain name.",
    category: "network",
    categoryLabel: "DNS"
  },
  {
    id: "subnet-calculator",
    name: "Subnet Calculator",
    description: "Calculate subnet masks, network addresses, and more.",
    category: "network",
    categoryLabel: "Network"
  },
  {
    id: "packet-analyzer",
    name: "Packet Analyzer",
    description: "Analyze network traffic and packet contents.",
    category: "network",
    categoryLabel: "Traffic"
  },
  
  // Information Gathering Tools
  {
    id: "header-analyzer",
    name: "Header Analyzer",
    description: "Analyze HTTP headers for security issues.",
    category: "info",
    categoryLabel: "WebApp"
  },
  {
    id: "email-hunter",
    name: "Email Hunter",
    description: "Find email addresses associated with a domain.",
    category: "info",
    categoryLabel: "Recon"
  },
  {
    id: "tech-detector",
    name: "Tech Detector",
    description: "Identify technologies used by websites.",
    category: "info",
    categoryLabel: "WebApp"
  },
  {
    id: "metadata-extractor",
    name: "Metadata Extractor",
    description: "Extract metadata from documents and images.",
    category: "info",
    categoryLabel: "Files"
  },
  {
    id: "phone-doxing",
    name: "Phone Doxing Tool",
    description: "Gather information about phone numbers, carriers, and potential owners.",
    category: "info",
    categoryLabel: "OSINT"
  },
  
  // Security Testing Tools
  {
    id: "zap-scanner",
    name: "OWASP ZAP Scanner",
    description: "Comprehensive web application vulnerability scanner based on OWASP tools.",
    category: "security",
    categoryLabel: "Scanner"
  },
  {
    id: "password-checker",
    name: "Password Checker",
    description: "Test password strength and detect common vulnerabilities.",
    category: "security",
    categoryLabel: "Security"
  },
  {
    id: "file-scanner",
    name: "File Scanner",
    description: "Scan files for malware and suspicious content.",
    category: "security",
    categoryLabel: "Security"
  },
  {
    id: "url-scanner",
    name: "URL Scanner",
    description: "Check URLs for phishing, malware, and reputation.",
    category: "security",
    categoryLabel: "WebApp"
  },
  {
    id: "cors-tester",
    name: "CORS Tester",
    description: "Test Cross-Origin Resource Sharing configurations.",
    category: "security",
    categoryLabel: "WebApp"
  },
  
  // Web Exploitation Tools
  {
    id: "lfi-scanner",
    name: "LFI Scanner",
    description: "Detect Local File Inclusion vulnerabilities.",
    category: "web",
    categoryLabel: "WebApp"
  },
  {
    id: "rfi-scanner",
    name: "RFI Scanner",
    description: "Detect Remote File Inclusion vulnerabilities.",
    category: "web",
    categoryLabel: "WebApp"
  },
  {
    id: "form-fuzzer",
    name: "Form Fuzzer",
    description: "Test web forms for input validation flaws.",
    category: "web",
    categoryLabel: "WebApp"
  },
  {
    id: "xml-injector",
    name: "XML Injector",
    description: "Test for XML External Entity (XXE) vulnerabilities.",
    category: "web",
    categoryLabel: "WebApp"
  },
  {
    id: "beef-xss",
    name: "BeEF XSS Framework",
    description: "Browser Exploitation Framework for XSS testing and payload generation.",
    category: "web",
    categoryLabel: "WebApp"
  },
  {
    id: "payload-all-star",
    name: "Payload All Star",
    description: "Comprehensive collection of payloads for web exploitation from PayloadsAllTheThings.",
    category: "web",
    categoryLabel: "WebApp"
  },
  
  // Password Tools
  {
    id: "hash-generator",
    name: "Hash Generator",
    description: "Generate hashes using various algorithms.",
    category: "password",
    categoryLabel: "Crypto"
  },
  {
    id: "hash-cracker",
    name: "Hash Cracker",
    description: "Crack password hashes using dictionary, brute force, and rainbow table methods.",
    category: "password",
    categoryLabel: "Crypto"
  },
  {
    id: "password-generator",
    name: "Password Generator",
    description: "Generate strong, random passwords.",
    category: "password",
    categoryLabel: "Security"
  },
  
  // Shell & Command Tools
  {
    id: "shell-uploader",
    name: "Adaptive Shell Uploader",
    description: "Analyze websites for shell upload vulnerabilities, detecting potential security weaknesses.",
    category: "shell",
    categoryLabel: "Shell & Command Tools"
  },
  {
    id: "base64-encoder",
    name: "Base64 Encoder/Decoder",
    description: "Encode or decode data using Base64.",
    category: "shell",
    categoryLabel: "Utility"
  },
  {
    id: "hex-converter",
    name: "Hex Converter",
    description: "Convert between hexadecimal and other formats.",
    category: "shell",
    categoryLabel: "Utility"
  },
  {
    id: "json-formatter",
    name: "JSON Formatter",
    description: "Format and validate JSON data.",
    category: "shell",
    categoryLabel: "Utility"
  }
];
