import { useState } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { useToast } from "@/hooks/use-toast";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import {
  AlertCircle,
  CheckCircle,
  Copy,
  Download,
  Loader2,
  Play,
  Globe,
  ShieldAlert,
  User,
  Building,
  FileText,
  AlertTriangle,
  Search,
  RefreshCw,
  Database,
  Shield,
  Terminal,
  Network,
  ExternalLink,
  Minimize2,
  Maximize2,
  ChevronRight,
  File,
  Folder,
  Link,
  Target,
  Lock,
  ExclamationTriangle,
  Key,
  Server,
  BriefcaseBusiness,
  Hash,
  Code,
  Flag,
  Flame,
  Map
} from "lucide-react";

// Types
interface Indicator {
  id: string;
  type: string;
  value: string;
  created: string;
  modified?: string;
  createdBy?: string;
  score?: number;
  description?: string;
  labels?: string[];
  pattern?: string;
  validFrom?: string;
  validUntil?: string;
}

interface Relationship {
  id: string;
  type: string;
  source: string;
  target: string;
  created: string;
  modified?: string;
  description?: string;
  relationship_type: string;
}

interface Entity {
  id: string;
  type: string;
  name: string;
  description?: string;
  created: string;
  modified?: string;
  createdBy?: string;
  labels?: string[];
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
  primary_motivation?: string;
  resource_level?: string;
  threat_actor_type?: string[];
  tool_type?: string[];
  malware_type?: string[];
}

interface ThreatIntelData {
  indicators: Indicator[];
  entities: Entity[];
  relationships: Relationship[];
}

interface QueryOptions {
  keyword?: string;
  types?: string[];
  from?: string;
  to?: string;
  confidence?: number;
  limit?: number;
  includeIndicators?: boolean;
  includeEntities?: boolean;
  includeRelationships?: boolean;
}

export default function OpenCTI() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine, addSuccessLine, clearLines } = useTerminal();
  
  const [activeTab, setActiveTab] = useState<string>("search");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [searchKeyword, setSearchKeyword] = useState<string>("");
  const [searchResults, setSearchResults] = useState<ThreatIntelData | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [selectedIndicator, setSelectedIndicator] = useState<Indicator | null>(null);
  const [queryOptions, setQueryOptions] = useState<QueryOptions>({
    types: ["malware", "threat-actor", "campaign", "attack-pattern"],
    limit: 20,
    confidence: 70,
    includeIndicators: true,
    includeEntities: true,
    includeRelationships: true
  });
  
  // Handle form submission
  const handleSearch = async () => {
    if (!searchKeyword && (!queryOptions.types || queryOptions.types.length === 0)) {
      toast({
        variant: "destructive",
        title: "Invalid Search",
        description: "Please enter a keyword or select at least one entity type"
      });
      return;
    }
    
    try {
      setIsLoading(true);
      clearLines();
      setSearchResults(null);
      
      addSystemLine(`Starting OpenCTI query for '${searchKeyword || "all recent entities"}'`);
      addInfoLine("Initializing connection to OpenCTI platform...");
      
      // Simulate API calls with different timings
      await new Promise(resolve => setTimeout(resolve, 800));
      addInfoLine("Connected to OpenCTI. Building query...");
      
      const typeString = queryOptions.types?.join(", ") || "all types";
      addInfoLine(`Searching for ${typeString} with confidence >= ${queryOptions.confidence}%`);
      
      if (queryOptions.includeIndicators) {
        await new Promise(resolve => setTimeout(resolve, 600));
        addInfoLine("Retrieving related indicators...");
      }
      
      if (queryOptions.includeRelationships) {
        await new Promise(resolve => setTimeout(resolve, 700));
        addInfoLine("Mapping entity relationships...");
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      addInfoLine("Processing and analyzing results...");
      
      // Generate simulated results
      const results = generateMockResults(searchKeyword, queryOptions);
      setSearchResults(results);
      
      const totalResults = (results.entities.length + results.indicators.length + results.relationships.length);
      
      addSuccessLine(`Query completed: Found ${totalResults} items`);
      addInfoLine(`Retrieved ${results.entities.length} entities, ${results.indicators.length} indicators, and ${results.relationships.length} relationships`);
      
      toast({
        title: "Search Complete",
        description: `Found ${totalResults} threat intelligence items`
      });
      
    } catch (error) {
      addErrorLine(`Error during OpenCTI query: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      toast({
        variant: "destructive",
        title: "Query Failed",
        description: "An error occurred while searching OpenCTI platform"
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Function to generate mock results based on search keyword and options
  const generateMockResults = (keyword: string, options: QueryOptions): ThreatIntelData => {
    // Common CTI entity types
    const entityTypes = options.types || ["malware", "threat-actor", "campaign", "attack-pattern"];
    
    // Mock entity names by type
    const entityNamesByType: Record<string, string[]> = {
      "malware": [
        "WannaCry", "NotPetya", "Emotet", "TrickBot", "Ryuk", "Maze", "Conti", "Lokibot", 
        "QakBot", "Dridex", "GandCrab", "Sodinokibi", "DarkSide", "REvil", "BlackMatter"
      ],
      "threat-actor": [
        "APT28", "APT29", "APT33", "APT40", "Lazarus Group", "FIN7", "FIN8", "Cobalt Group", 
        "OceanLotus", "PLATINUM", "Sandworm Team", "TA505", "Wizard Spider", "NOBELIUM"
      ],
      "campaign": [
        "Operation Aurora", "Operation Ghost", "Operation ShadowHammer", "Cloud Hopper", 
        "Operation Soft Cell", "Operation WildPressure", "Operation PowerFall", "Sunburst Campaign"
      ],
      "attack-pattern": [
        "Spear Phishing", "Drive-by Compromise", "Supply Chain Compromise", "Trusted Relationship", 
        "Valid Accounts", "Brute Force", "Credential Dumping", "Pass the Hash", "Lateral Movement"
      ],
      "tool": [
        "Mimikatz", "Cobalt Strike", "Powershell Empire", "Metasploit", "PsExec", 
        "BloodHound", "Impacket", "Responder", "Rubeus", "PoshC2"
      ],
      "vulnerability": [
        "CVE-2021-44228", "CVE-2021-26855", "CVE-2020-0601", "CVE-2019-19781", 
        "CVE-2018-13379", "CVE-2017-11882", "CVE-2017-0199"
      ]
    };
    
    // Common indicator types and patterns
    const indicatorTypes = [
      { type: "ipv4-addr", pattern: "IP addresses" },
      { type: "domain-name", pattern: "Domain names" },
      { type: "url", pattern: "URLs" },
      { type: "file", pattern: "File hashes" },
      { type: "email-addr", pattern: "Email addresses" }
    ];
    
    // Generate entity descriptions by type
    const entityDescriptionsByType: Record<string, string[]> = {
      "malware": [
        "A ransomware that encrypts files and demands payment for decryption",
        "A banking trojan that steals financial information",
        "A remote access trojan (RAT) providing backdoor access to infected systems",
        "An information stealer targeting credentials and sensitive data",
        "A sophisticated malware used in targeted attacks against specific organizations"
      ],
      "threat-actor": [
        "A state-sponsored APT group targeting government and defense sectors",
        "A financially motivated threat actor focusing on banking and financial institutions",
        "A cyber espionage group targeting intellectual property in specific industries",
        "A threat actor known for deploying ransomware through sophisticated attacks",
        "A nation-state affiliated group conducting intelligence gathering operations"
      ],
      "campaign": [
        "A series of coordinated attacks targeting multiple organizations in the financial sector",
        "A long-running cyber espionage campaign targeting government entities",
        "A supply chain attack affecting thousands of organizations worldwide",
        "A targeted campaign against critical infrastructure in specific regions",
        "A multi-phase attack campaign involving various malware families and techniques"
      ],
      "attack-pattern": [
        "A technique used to gain initial access to target networks",
        "A privilege escalation method exploiting system vulnerabilities",
        "A lateral movement technique used to expand access within compromised networks",
        "A data exfiltration method designed to evade detection",
        "A persistence mechanism ensuring continued access to compromised systems"
      ]
    };
    
    // Generate mock entities
    const entities: Entity[] = [];
    let entityCount = Math.floor(Math.random() * 10) + 5; // 5-15 entities
    
    // If keyword is provided, try to make some results match it
    if (keyword) {
      // Add some entities that match the keyword
      entityTypes.forEach(type => {
        if (Math.random() > 0.5) { // 50% chance for each entity type
          const matchingEntity: Entity = {
            id: generateRandomId(),
            type: type,
            name: keyword.includes(" ") ? keyword : `${keyword} ${getRandomItem(entityNamesByType[type] || ["Group"])}`,
            description: getRandomItem(entityDescriptionsByType[type] || ["A cyber threat entity"]) + 
                        ` associated with ${keyword} activities.`,
            created: getRandomDate(365 * 2), // Within last 2 years
            modified: getRandomDate(30), // Within last month
            createdBy: "OpenCTI Platform",
            labels: generateRandomLabels(type),
            aliases: [keyword, `${keyword}-variant`, `${type}-${keyword.toLowerCase()}`]
          };
          
          // Add type-specific fields
          if (type === "threat-actor") {
            matchingEntity.primary_motivation = getRandomItem(["financial", "espionage", "ideology", "destruction"]);
            matchingEntity.resource_level = getRandomItem(["individual", "club", "team", "organization", "government"]);
            matchingEntity.threat_actor_type = [getRandomItem(["nation-state", "criminal", "hacktivist", "terrorist"])];
          } else if (type === "malware") {
            matchingEntity.malware_type = [getRandomItem(["ransomware", "trojan", "backdoor", "spyware", "worm"])];
            matchingEntity.first_seen = getRandomDate(365 * 3); // Within last 3 years
            matchingEntity.last_seen = getRandomDate(90); // Within last 3 months
          } else if (type === "tool") {
            matchingEntity.tool_type = [getRandomItem(["credential-exploitation", "penetration-testing", "exploit-kit", "rat"])];
          }
          
          entities.push(matchingEntity);
        }
      });
    }
    
    // Fill in with random entities
    while (entities.length < entityCount) {
      const type = getRandomItem(entityTypes);
      const name = getRandomItem(entityNamesByType[type] || ["Unknown Entity"]);
      
      const entity: Entity = {
        id: generateRandomId(),
        type: type,
        name: name,
        description: getRandomItem(entityDescriptionsByType[type] || ["A cyber threat entity"]),
        created: getRandomDate(365 * 2), // Within last 2 years
        modified: getRandomDate(30), // Within last month
        createdBy: "OpenCTI Platform",
        labels: generateRandomLabels(type),
        aliases: generateRandomAliases(name)
      };
      
      // Add type-specific fields
      if (type === "threat-actor") {
        entity.primary_motivation = getRandomItem(["financial", "espionage", "ideology", "destruction"]);
        entity.resource_level = getRandomItem(["individual", "club", "team", "organization", "government"]);
        entity.threat_actor_type = [getRandomItem(["nation-state", "criminal", "hacktivist", "terrorist"])];
      } else if (type === "malware") {
        entity.malware_type = [getRandomItem(["ransomware", "trojan", "backdoor", "spyware", "worm"])];
        entity.first_seen = getRandomDate(365 * 3); // Within last 3 years
        entity.last_seen = getRandomDate(90); // Within last 3 months
      } else if (type === "tool") {
        entity.tool_type = [getRandomItem(["credential-exploitation", "penetration-testing", "exploit-kit", "rat"])];
      }
      
      entities.push(entity);
    }
    
    // Generate mock indicators
    const indicators: Indicator[] = [];
    let indicatorCount = options.includeIndicators ? Math.floor(Math.random() * 15) + 5 : 0; // 5-20 indicators if included
    
    for (let i = 0; i < indicatorCount; i++) {
      const indicatorTypeInfo = getRandomItem(indicatorTypes);
      const indicator: Indicator = {
        id: generateRandomId(),
        type: indicatorTypeInfo.type,
        value: generateMockIndicatorValue(indicatorTypeInfo.type, keyword),
        created: getRandomDate(365), // Within last year
        modified: getRandomDate(30), // Within last month
        createdBy: "OpenCTI Platform",
        score: Math.floor(Math.random() * 40) + 60, // Score between 60-100
        description: `Indicator associated with ${getRandomItem(entities).name}`,
        labels: ["indicator", indicatorTypeInfo.type, getRandomItem(["malicious", "suspicious", "benign"])],
        pattern: `[${indicatorTypeInfo.type}:value = '${generateMockIndicatorValue(indicatorTypeInfo.type, keyword)}']`,
        validFrom: getRandomDate(365 * 2), // Within last 2 years
        validUntil: getRandomFutureDate(365) // Up to 1 year in the future
      };
      
      indicators.push(indicator);
    }
    
    // Generate mock relationships
    const relationships: Relationship[] = [];
    let relationshipCount = options.includeRelationships ? Math.floor(Math.random() * 25) + 10 : 0; // 10-35 relationships if included
    
    const relationshipTypes = [
      "uses", "targets", "mitigates", "indicates", "attributed-to", 
      "delivered-by", "communicates-with", "exfiltrates-to", "related-to"
    ];
    
    for (let i = 0; i < relationshipCount; i++) {
      const sourceEntity = getRandomItem(entities);
      const targetEntity = getRandomItem([...entities, ...indicators]);
      
      const relationship: Relationship = {
        id: generateRandomId(),
        type: "relationship",
        source: sourceEntity.id,
        target: targetEntity.id,
        created: getRandomDate(365), // Within last year
        relationship_type: getRandomItem(relationshipTypes),
        description: `${sourceEntity.name} ${getRandomItem(relationshipTypes)} ${targetEntity.type === "relationship" ? "this entity" : targetEntity.name || targetEntity.value}`
      };
      
      relationships.push(relationship);
    }
    
    return {
      entities,
      indicators,
      relationships
    };
  };
  
  // Helper function to generate a random ID
  const generateRandomId = (): string => {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  };
  
  // Helper function to get a random item from an array
  const getRandomItem = <T,>(array: T[]): T => {
    return array[Math.floor(Math.random() * array.length)];
  };
  
  // Helper function to generate a random date within the past X days
  const getRandomDate = (days: number): string => {
    const date = new Date();
    date.setDate(date.getDate() - Math.floor(Math.random() * days));
    return date.toISOString().split('T')[0];
  };
  
  // Helper function to generate a random date in the future (up to X days)
  const getRandomFutureDate = (days: number): string => {
    const date = new Date();
    date.setDate(date.getDate() + Math.floor(Math.random() * days));
    return date.toISOString().split('T')[0];
  };
  
  // Helper function to generate random labels for an entity
  const generateRandomLabels = (type: string): string[] => {
    const commonLabels = ["malicious", "apt", "ransomware", "targeted", "espionage"];
    const labels = [type];
    
    // Add 1-3 random labels
    const labelCount = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < labelCount; i++) {
      const label = getRandomItem(commonLabels);
      if (!labels.includes(label)) {
        labels.push(label);
      }
    }
    
    return labels;
  };
  
  // Helper function to generate random aliases for an entity
  const generateRandomAliases = (name: string): string[] => {
    const aliases = [];
    const aliasCount = Math.floor(Math.random() * 3); // 0-2 aliases
    
    if (aliasCount > 0) {
      aliases.push(`${name} Group`);
    }
    
    if (aliasCount > 1) {
      aliases.push(`${name.substring(0, 3)}-${Math.floor(Math.random() * 100)}`);
    }
    
    return aliases;
  };
  
  // Helper function to generate mock indicator values
  const generateMockIndicatorValue = (type: string, keyword: string): string => {
    const keywordSafe = keyword ? keyword.replace(/[^a-zA-Z0-9]/g, '') : '';
    
    switch (type) {
      case "ipv4-addr":
        return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
      case "domain-name":
        return keywordSafe 
          ? `${keywordSafe.toLowerCase()}-${Math.floor(Math.random() * 1000)}.com`
          : `malicious-${Math.floor(Math.random() * 1000)}.com`;
      case "url":
        return keywordSafe
          ? `https://${keywordSafe.toLowerCase()}-${Math.floor(Math.random() * 1000)}.com/malicious.php`
          : `https://malicious-${Math.floor(Math.random() * 1000)}.com/payload.php`;
      case "file":
        return `${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;
      case "email-addr":
        return keywordSafe
          ? `${keywordSafe.toLowerCase()}-${Math.floor(Math.random() * 1000)}@malicious.com`
          : `threat-actor-${Math.floor(Math.random() * 1000)}@malicious.com`;
      default:
        return `indicator-${Math.floor(Math.random() * 10000)}`;
    }
  };
  
  // Function to view entity details
  const viewEntityDetails = (entity: Entity) => {
    setSelectedEntity(entity);
    setSelectedIndicator(null);
    setActiveTab("details");
  };
  
  // Function to view indicator details
  const viewIndicatorDetails = (indicator: Indicator) => {
    setSelectedIndicator(indicator);
    setSelectedEntity(null);
    setActiveTab("details");
  };
  
  // Function to get the color for a specific entity type
  const getEntityTypeColor = (type: string): string => {
    const colors: Record<string, string> = {
      "malware": "text-red-500",
      "threat-actor": "text-purple-500",
      "campaign": "text-amber-500",
      "attack-pattern": "text-green-500",
      "tool": "text-blue-500",
      "vulnerability": "text-pink-500"
    };
    
    return colors[type] || "text-gray-500";
  };
  
  // Function to get the icon for a specific entity type
  const getEntityTypeIcon = (type: string) => {
    switch (type) {
      case "malware":
        return <Bug className="h-4 w-4 text-red-500" />;
      case "threat-actor":
        return <User className="h-4 w-4 text-purple-500" />;
      case "campaign":
        return <Target className="h-4 w-4 text-amber-500" />;
      case "attack-pattern":
        return <Target className="h-4 w-4 text-green-500" />;
      case "tool":
        return <Terminal className="h-4 w-4 text-blue-500" />;
      case "vulnerability":
        return <ShieldAlert className="h-4 w-4 text-pink-500" />;
      default:
        return <FileText className="h-4 w-4 text-gray-500" />;
    }
  };
  
  // Function to get the icon for a specific indicator type
  const getIndicatorTypeIcon = (type: string) => {
    switch (type) {
      case "ipv4-addr":
        return <Network className="h-4 w-4 text-blue-500" />;
      case "domain-name":
        return <Globe className="h-4 w-4 text-green-500" />;
      case "url":
        return <Link className="h-4 w-4 text-amber-500" />;
      case "file":
        return <File className="h-4 w-4 text-purple-500" />;
      case "email-addr":
        return <Mail className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  // Mock component for the Bug icon since it's not in lucide-react
  const Bug = ({ className }: { className?: string }) => (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M8 2l1.88 1.88" />
      <path d="M14.12 3.88L16 2" />
      <path d="M9 7.13v-1a3.003 3.003 0 112.995 3.13" />
      <path d="M2.29 9.3a2.66 2.66 0 11.01-2.82" />
      <path d="M18.29 9.3a2.66 2.66 0 10.01-2.82" />
      <path d="M10.83 7.13h2.34a3 3 0 013 3v8.82a3.17 3.17 0 01-3.17 3.17h-2a3.17 3.17 0 01-3.17-3.17v-8.82a3 3 0 013-3z" />
      <path d="M6.83 14.13v-4a2 2 0 00-2-2H2.25" />
      <path d="M17.17 14.13v-4a2 2 0 012-2h2.58" />
      <path d="M19.17 18.13h-14" />
    </svg>
  );

  // Function to get the Mail icon (for compatibility)
  const Mail = ({ className }: { className?: string }) => (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <rect width="20" height="16" x="2" y="4" rx="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
  
  return (
    <div className="space-y-6">
      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <Database className="mr-2 h-5 w-5 text-primary" />
          OpenCTI Platform
        </h2>
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-4">
            <TabsTrigger value="search">Search</TabsTrigger>
            <TabsTrigger value="explore">Explore</TabsTrigger>
            <TabsTrigger value="details" disabled={!selectedEntity && !selectedIndicator}>
              Details
            </TabsTrigger>
            <TabsTrigger value="graph" disabled={!searchResults}>
              Graph
            </TabsTrigger>
          </TabsList>
          
          {/* Search Tab */}
          <TabsContent value="search" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2 space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="keyword">Search Keyword</Label>
                  <div className="flex gap-2">
                    <Input
                      id="keyword"
                      value={searchKeyword}
                      onChange={(e) => setSearchKeyword(e.target.value)}
                      placeholder="APT28, Emotet, CVE-2021-44228..."
                      className="flex-1"
                    />
                    <Button onClick={handleSearch} disabled={isLoading}>
                      {isLoading ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Searching...
                        </>
                      ) : (
                        <>
                          <Search className="mr-2 h-4 w-4" />
                          Search
                        </>
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Enter a threat actor, malware, campaign, CVE, etc. to search the CTI knowledge base
                  </p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Entity Types</Label>
                    <div className="bg-muted rounded-md p-3 space-y-2">
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-malware"
                          checked={queryOptions.types?.includes("malware")}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              types: checked 
                                ? [...(prev.types || []), "malware"] 
                                : prev.types?.filter(t => t !== "malware")
                            }));
                          }}
                        />
                        <Label htmlFor="include-malware" className="flex items-center text-sm cursor-pointer">
                          <span className="inline-block w-3 h-3 bg-red-500 rounded-full mr-2"></span>
                          Malware
                        </Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-threat-actor"
                          checked={queryOptions.types?.includes("threat-actor")}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              types: checked 
                                ? [...(prev.types || []), "threat-actor"] 
                                : prev.types?.filter(t => t !== "threat-actor")
                            }));
                          }}
                        />
                        <Label htmlFor="include-threat-actor" className="flex items-center text-sm cursor-pointer">
                          <span className="inline-block w-3 h-3 bg-purple-500 rounded-full mr-2"></span>
                          Threat Actors
                        </Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-campaign"
                          checked={queryOptions.types?.includes("campaign")}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              types: checked 
                                ? [...(prev.types || []), "campaign"] 
                                : prev.types?.filter(t => t !== "campaign")
                            }));
                          }}
                        />
                        <Label htmlFor="include-campaign" className="flex items-center text-sm cursor-pointer">
                          <span className="inline-block w-3 h-3 bg-amber-500 rounded-full mr-2"></span>
                          Campaigns
                        </Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-attack-pattern"
                          checked={queryOptions.types?.includes("attack-pattern")}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              types: checked 
                                ? [...(prev.types || []), "attack-pattern"] 
                                : prev.types?.filter(t => t !== "attack-pattern")
                            }));
                          }}
                        />
                        <Label htmlFor="include-attack-pattern" className="flex items-center text-sm cursor-pointer">
                          <span className="inline-block w-3 h-3 bg-green-500 rounded-full mr-2"></span>
                          Attack Patterns
                        </Label>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>Include Data Types</Label>
                    <div className="bg-muted rounded-md p-3 space-y-2">
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-indicators"
                          checked={queryOptions.includeIndicators}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              includeIndicators: !!checked
                            }));
                          }}
                        />
                        <Label htmlFor="include-indicators" className="text-sm cursor-pointer">Indicators (IOCs)</Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-entities"
                          checked={queryOptions.includeEntities}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              includeEntities: !!checked
                            }));
                          }}
                        />
                        <Label htmlFor="include-entities" className="text-sm cursor-pointer">Entities</Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Checkbox 
                          id="include-relationships"
                          checked={queryOptions.includeRelationships}
                          onCheckedChange={(checked) => {
                            setQueryOptions(prev => ({
                              ...prev,
                              includeRelationships: !!checked
                            }));
                          }}
                        />
                        <Label htmlFor="include-relationships" className="text-sm cursor-pointer">Relationships</Label>
                      </div>
                      
                      <Separator className="my-2" />
                      
                      <div className="space-y-1">
                        <Label htmlFor="confidence" className="text-sm">Minimum Confidence</Label>
                        <div className="flex items-center gap-2">
                          <Input
                            id="confidence"
                            type="number"
                            min="0"
                            max="100"
                            value={queryOptions.confidence}
                            onChange={(e) => setQueryOptions(prev => ({
                              ...prev,
                              confidence: parseInt(e.target.value) || 0
                            }))}
                            className="w-16"
                          />
                          <span className="text-sm">%</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="bg-muted rounded-md p-4">
                <h3 className="text-sm font-semibold mb-2 flex items-center">
                  <Info className="h-4 w-4 mr-1" />
                  About OpenCTI
                </h3>
                <p className="text-sm mb-4">
                  OpenCTI is an open source platform that allows organizations to manage their cyber 
                  threat intelligence knowledge and observables.
                </p>
                <h4 className="text-xs font-semibold mt-3 mb-1">Supported Entity Types:</h4>
                <div className="grid grid-cols-2 gap-1 text-xs">
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-red-500 rounded-full mr-1"></span>
                    Malware
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-purple-500 rounded-full mr-1"></span>
                    Threat Actors
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-amber-500 rounded-full mr-1"></span>
                    Campaigns
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-green-500 rounded-full mr-1"></span>
                    Attack Patterns
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-blue-500 rounded-full mr-1"></span>
                    Tools
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-2 h-2 bg-pink-500 rounded-full mr-1"></span>
                    Vulnerabilities
                  </div>
                </div>
              </div>
            </div>
            
            {isLoading && (
              <div className="py-8 flex items-center justify-center">
                <div className="text-center">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-2 text-primary" />
                  <p className="text-sm text-muted-foreground">Searching OpenCTI platform...</p>
                </div>
              </div>
            )}
            
            {searchResults && !isLoading && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-semibold">
                    Search Results
                    <Badge variant="outline" className="ml-2">
                      {searchResults.entities.length + searchResults.indicators.length} items
                    </Badge>
                  </h3>
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => setActiveTab("graph")}
                      disabled={!searchResults}
                      className="hidden sm:flex"
                    >
                      <Network className="mr-2 h-4 w-4" />
                      View Graph
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => {
                        const jsonStr = JSON.stringify(searchResults, null, 2);
                        const blob = new Blob([jsonStr], { type: "application/json" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `opencti-export-${new Date().toISOString().split('T')[0]}.json`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                      }}
                      className="hidden sm:flex"
                    >
                      <Download className="mr-2 h-4 w-4" />
                      Export
                    </Button>
                  </div>
                </div>
                
                {searchResults.entities.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2">Entities</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {searchResults.entities.map(entity => (
                        <div 
                          key={entity.id}
                          className="bg-card border border-border/50 rounded-md p-3 hover:border-primary/50 cursor-pointer transition-colors"
                          onClick={() => viewEntityDetails(entity)}
                        >
                          <div className="flex justify-between items-start">
                            <div className="flex items-center">
                              <div className={`mr-2 ${getEntityTypeColor(entity.type)}`}>
                                {getEntityTypeIcon(entity.type)}
                              </div>
                              <div>
                                <h5 className="font-medium text-sm">{entity.name}</h5>
                                <p className="text-xs text-muted-foreground">
                                  {entity.type.replace("-", " ")}
                                </p>
                              </div>
                            </div>
                            <div className="flex flex-col items-end">
                              {entity.labels && entity.labels.length > 0 && (
                                <div className="flex flex-wrap justify-end gap-1 mb-1">
                                  {entity.labels.slice(0, 2).map((label, i) => (
                                    <Badge key={i} variant="outline" className="text-[10px] px-1 py-0 h-auto">
                                      {label}
                                    </Badge>
                                  ))}
                                  {entity.labels.length > 2 && (
                                    <Badge variant="outline" className="text-[10px] px-1 py-0 h-auto">
                                      +{entity.labels.length - 2}
                                    </Badge>
                                  )}
                                </div>
                              )}
                              <p className="text-[10px] text-muted-foreground">
                                {entity.created}
                              </p>
                            </div>
                          </div>
                          {entity.description && (
                            <p className="text-xs mt-2 line-clamp-2 text-muted-foreground">
                              {entity.description}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {searchResults.indicators.length > 0 && (
                  <div className="mt-6">
                    <h4 className="text-sm font-semibold mb-2">Indicators</h4>
                    <div className="overflow-auto">
                      <Table className="w-full">
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[120px]">Type</TableHead>
                            <TableHead>Value</TableHead>
                            <TableHead>Description</TableHead>
                            <TableHead className="w-[80px] text-right">Score</TableHead>
                            <TableHead className="w-[100px] text-right">Valid Until</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {searchResults.indicators.map(indicator => (
                            <TableRow 
                              key={indicator.id}
                              className="cursor-pointer hover:bg-muted/50"
                              onClick={() => viewIndicatorDetails(indicator)}
                            >
                              <TableCell className="font-medium">
                                <div className="flex items-center">
                                  {getIndicatorTypeIcon(indicator.type)}
                                  <span className="ml-2 text-xs">{indicator.type}</span>
                                </div>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{indicator.value}</TableCell>
                              <TableCell className="text-xs text-muted-foreground line-clamp-1">
                                {indicator.description || "No description"}
                              </TableCell>
                              <TableCell className="text-right">
                                <Badge 
                                  variant={indicator.score && indicator.score > 75 ? "destructive" : "outline"}
                                  className="text-xs"
                                >
                                  {indicator.score || "N/A"}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right text-xs">
                                {indicator.validUntil || "N/A"}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}
                
                {searchResults.entities.length === 0 && searchResults.indicators.length === 0 && (
                  <div className="bg-muted rounded-md p-6 text-center">
                    <Search className="h-8 w-8 mx-auto mb-2 opacity-20" />
                    <p className="text-muted-foreground">No results found for your search criteria</p>
                    <p className="text-sm text-muted-foreground mt-1">Try broadening your search terms or including more entity types</p>
                  </div>
                )}
              </div>
            )}
          </TabsContent>
          
          {/* Explore Tab */}
          <TabsContent value="explore" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <Card className="p-4 border-l-4 border-l-red-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <Bug className="h-5 w-5 text-red-500 mr-2" />
                    <h3 className="font-semibold">Malware</h3>
                  </div>
                  <Badge variant="outline">452</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Malicious software designed to infiltrate, damage, or obtain unauthorized access to computer systems.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Malware
                </Button>
              </Card>
              
              <Card className="p-4 border-l-4 border-l-purple-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <User className="h-5 w-5 text-purple-500 mr-2" />
                    <h3 className="font-semibold">Threat Actors</h3>
                  </div>
                  <Badge variant="outline">189</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Individuals, groups, or organizations responsible for cyber attacks or malicious activities.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Threat Actors
                </Button>
              </Card>
              
              <Card className="p-4 border-l-4 border-l-amber-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <Target className="h-5 w-5 text-amber-500 mr-2" />
                    <h3 className="font-semibold">Campaigns</h3>
                  </div>
                  <Badge variant="outline">76</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Sets of malicious activities or attacks targeting specific organizations, sectors, or regions.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Campaigns
                </Button>
              </Card>
              
              <Card className="p-4 border-l-4 border-l-green-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <Target className="h-5 w-5 text-green-500 mr-2" />
                    <h3 className="font-semibold">Attack Patterns</h3>
                  </div>
                  <Badge variant="outline">328</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Types of tactics, techniques, and procedures (TTPs) used by threat actors to achieve their objectives.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Attack Patterns
                </Button>
              </Card>
              
              <Card className="p-4 border-l-4 border-l-blue-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <Terminal className="h-5 w-5 text-blue-500 mr-2" />
                    <h3 className="font-semibold">Tools</h3>
                  </div>
                  <Badge variant="outline">215</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Software that can be used for malicious purposes, including legitimate tools that can be repurposed.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Tools
                </Button>
              </Card>
              
              <Card className="p-4 border-l-4 border-l-pink-500">
                <div className="flex justify-between items-start">
                  <div className="flex items-center">
                    <ShieldAlert className="h-5 w-5 text-pink-500 mr-2" />
                    <h3 className="font-semibold">Vulnerabilities</h3>
                  </div>
                  <Badge variant="outline">873</Badge>
                </div>
                <p className="text-sm mt-2 text-muted-foreground">
                  Weaknesses or flaws in software, hardware, or processes that can be exploited by threat actors.
                </p>
                <Button variant="outline" size="sm" className="mt-4 w-full">
                  <Search className="h-4 w-4 mr-2" />
                  Browse Vulnerabilities
                </Button>
              </Card>
            </div>
            
            <div className="mt-8">
              <h3 className="text-lg font-semibold mb-4">Recent Intelligence</h3>
              <div className="space-y-4">
                <Card className="p-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-red-100 dark:bg-red-900/20 p-2 rounded-full">
                      <Flame className="h-5 w-5 text-red-500" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium">New Ransomware Variant Detected</h4>
                      <p className="text-xs text-muted-foreground">Added 2 hours ago</p>
                    </div>
                    <Badge className="ml-auto">High</Badge>
                  </div>
                  <p className="mt-3 text-sm">
                    A new variant of the BlackCat ransomware has been observed in the wild, with enhanced encryption capabilities and anti-analysis features.
                  </p>
                  <div className="flex gap-2 mt-3">
                    <Badge variant="outline" className="text-xs">Ransomware</Badge>
                    <Badge variant="outline" className="text-xs">BlackCat</Badge>
                    <Badge variant="outline" className="text-xs">Encryption</Badge>
                  </div>
                </Card>
                
                <Card className="p-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-purple-100 dark:bg-purple-900/20 p-2 rounded-full">
                      <User className="h-5 w-5 text-purple-500" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium">APT29 Targeting Healthcare Sector</h4>
                      <p className="text-xs text-muted-foreground">Added 1 day ago</p>
                    </div>
                    <Badge className="ml-auto">Medium</Badge>
                  </div>
                  <p className="mt-3 text-sm">
                    APT29 has been observed conducting spear-phishing campaigns targeting healthcare organizations with COVID-19 themed lures.
                  </p>
                  <div className="flex gap-2 mt-3">
                    <Badge variant="outline" className="text-xs">APT29</Badge>
                    <Badge variant="outline" className="text-xs">Healthcare</Badge>
                    <Badge variant="outline" className="text-xs">Phishing</Badge>
                  </div>
                </Card>
                
                <Card className="p-4">
                  <div className="flex items-center gap-3">
                    <div className="bg-pink-100 dark:bg-pink-900/20 p-2 rounded-full">
                      <ShieldAlert className="h-5 w-5 text-pink-500" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium">Critical Vulnerability in Apache Log4j</h4>
                      <p className="text-xs text-muted-foreground">Added 3 days ago</p>
                    </div>
                    <Badge className="ml-auto">Critical</Badge>
                  </div>
                  <p className="mt-3 text-sm">
                    A critical remote code execution vulnerability (CVE-2021-44228) has been discovered in Apache Log4j. Multiple threat actors are actively exploiting this vulnerability.
                  </p>
                  <div className="flex gap-2 mt-3">
                    <Badge variant="outline" className="text-xs">CVE-2021-44228</Badge>
                    <Badge variant="outline" className="text-xs">Log4j</Badge>
                    <Badge variant="outline" className="text-xs">RCE</Badge>
                  </div>
                </Card>
              </div>
            </div>
          </TabsContent>
          
          {/* Details Tab */}
          <TabsContent value="details" className="space-y-4">
            {selectedEntity && (
              <div className="space-y-6">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-lg font-semibold flex items-center">
                      <span className={`mr-2 ${getEntityTypeColor(selectedEntity.type)}`}>
                        {getEntityTypeIcon(selectedEntity.type)}
                      </span>
                      {selectedEntity.name}
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      {selectedEntity.type.replace("-", " ")} • Created on {selectedEntity.created}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setActiveTab("search")}>
                      <ChevronRight className="h-4 w-4 mr-2" />
                      Back to Results
                    </Button>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="md:col-span-2 space-y-4">
                    <Card className="p-4">
                      <h4 className="text-sm font-semibold mb-2">Description</h4>
                      <p className="text-sm">{selectedEntity.description || "No description available."}</p>
                      
                      {selectedEntity.aliases && selectedEntity.aliases.length > 0 && (
                        <>
                          <h4 className="text-sm font-semibold mt-4 mb-2">Also Known As</h4>
                          <div className="flex flex-wrap gap-2">
                            {selectedEntity.aliases.map((alias, i) => (
                              <Badge key={i} variant="outline">
                                {alias}
                              </Badge>
                            ))}
                          </div>
                        </>
                      )}
                    </Card>
                    
                    {selectedEntity.type === "malware" && (
                      <Card className="p-4">
                        <h4 className="text-sm font-semibold mb-3">Malware Details</h4>
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Malware Type</p>
                            <div className="flex flex-wrap gap-1">
                              {selectedEntity.malware_type?.map((type, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {type}
                                </Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">First Seen</p>
                            <p className="text-sm">{selectedEntity.first_seen || "Unknown"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Last Seen</p>
                            <p className="text-sm">{selectedEntity.last_seen || "Unknown"}</p>
                          </div>
                        </div>
                      </Card>
                    )}
                    
                    {selectedEntity.type === "threat-actor" && (
                      <Card className="p-4">
                        <h4 className="text-sm font-semibold mb-3">Threat Actor Details</h4>
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Motivation</p>
                            <p className="text-sm capitalize">{selectedEntity.primary_motivation || "Unknown"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Resource Level</p>
                            <p className="text-sm capitalize">{selectedEntity.resource_level || "Unknown"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-muted-foreground mb-1">Threat Actor Type</p>
                            <div className="flex flex-wrap gap-1">
                              {selectedEntity.threat_actor_type?.map((type, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {type}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </Card>
                    )}
                    
                    <Card className="p-4">
                      <h4 className="text-sm font-semibold mb-2">Related Entities</h4>
                      <p className="text-sm text-muted-foreground mb-4">
                        Entities that are related to {selectedEntity.name} based on observed relationships.
                      </p>
                      
                      <div className="space-y-2">
                        <div className="flex items-center justify-between p-2 bg-muted rounded-md">
                          <div className="flex items-center">
                            <Bug className="h-4 w-4 text-red-500 mr-2" />
                            <span className="text-sm">TrickBot</span>
                          </div>
                          <Badge variant="outline" className="text-xs">uses</Badge>
                        </div>
                        
                        <div className="flex items-center justify-between p-2 bg-muted rounded-md">
                          <div className="flex items-center">
                            <Shield className="h-4 w-4 text-blue-500 mr-2" />
                            <span className="text-sm">MS-ISAC</span>
                          </div>
                          <Badge variant="outline" className="text-xs">attributed-to</Badge>
                        </div>
                        
                        <div className="flex items-center justify-between p-2 bg-muted rounded-md">
                          <div className="flex items-center">
                            <Target className="h-4 w-4 text-amber-500 mr-2" />
                            <span className="text-sm">Operation Ghost</span>
                          </div>
                          <Badge variant="outline" className="text-xs">part-of</Badge>
                        </div>
                      </div>
                    </Card>
                  </div>
                  
                  <div className="space-y-4">
                    <Card className="p-4">
                      <h4 className="text-sm font-semibold mb-2">Labels</h4>
                      <div className="flex flex-wrap gap-2">
                        {selectedEntity.labels?.map((label, i) => (
                          <Badge key={i} variant="outline">
                            {label}
                          </Badge>
                        ))}
                        {(!selectedEntity.labels || selectedEntity.labels.length === 0) && (
                          <p className="text-sm text-muted-foreground">No labels assigned</p>
                        )}
                      </div>
                    </Card>
                    
                    <Card className="p-4">
                      <h4 className="text-sm font-semibold mb-2">Metadata</h4>
                      <div className="space-y-2">
                        <div>
                          <p className="text-xs text-muted-foreground">Created</p>
                          <p className="text-sm">{selectedEntity.created}</p>
                        </div>
                        
                        {selectedEntity.modified && (
                          <div>
                            <p className="text-xs text-muted-foreground">Last Modified</p>
                            <p className="text-sm">{selectedEntity.modified}</p>
                          </div>
                        )}
                        
                        <div>
                          <p className="text-xs text-muted-foreground">Created By</p>
                          <p className="text-sm">{selectedEntity.createdBy || "Unknown"}</p>
                        </div>
                        
                        <div>
                          <p className="text-xs text-muted-foreground">ID</p>
                          <p className="text-sm font-mono text-xs">{selectedEntity.id}</p>
                        </div>
                      </div>
                    </Card>
                    
                    <Card className="p-4">
                      <h4 className="text-sm font-semibold mb-2">External References</h4>
                      <div className="space-y-2">
                        <div className="flex items-center p-2 bg-muted rounded-md text-sm">
                          <Globe className="h-4 w-4 mr-2 text-primary" />
                          <span className="flex-1 truncate">MITRE ATT&CK</span>
                          <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                        
                        <div className="flex items-center p-2 bg-muted rounded-md text-sm">
                          <Globe className="h-4 w-4 mr-2 text-primary" />
                          <span className="flex-1 truncate">AlienVault OTX</span>
                          <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                        
                        <div className="flex items-center p-2 bg-muted rounded-md text-sm">
                          <Globe className="h-4 w-4 mr-2 text-primary" />
                          <span className="flex-1 truncate">VirusTotal</span>
                          <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </Card>
                  </div>
                </div>
              </div>
            )}
            
            {selectedIndicator && (
              <div className="space-y-6">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-lg font-semibold flex items-center">
                      {getIndicatorTypeIcon(selectedIndicator.type)}
                      <span className="ml-2">
                        {selectedIndicator.type} Indicator
                      </span>
                      {selectedIndicator.score && (
                        <Badge 
                          variant={selectedIndicator.score > 75 ? "destructive" : "outline"}
                          className="ml-2"
                        >
                          Score: {selectedIndicator.score}
                        </Badge>
                      )}
                    </h3>
                    <p className="text-sm font-mono mt-1">{selectedIndicator.value}</p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setActiveTab("search")}>
                      <ChevronRight className="h-4 w-4 mr-2" />
                      Back to Results
                    </Button>
                  </div>
                </div>
                
                <Card className="p-4">
                  <h4 className="text-sm font-semibold mb-2">Indicator Details</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Type</p>
                      <p className="text-sm">{selectedIndicator.type}</p>
                    </div>
                    
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Value</p>
                      <p className="text-sm font-mono">{selectedIndicator.value}</p>
                    </div>
                    
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Created</p>
                      <p className="text-sm">{selectedIndicator.created}</p>
                    </div>
                    
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Modified</p>
                      <p className="text-sm">{selectedIndicator.modified || "Never"}</p>
                    </div>
                    
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Valid From</p>
                      <p className="text-sm">{selectedIndicator.validFrom || "Unknown"}</p>
                    </div>
                    
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Valid Until</p>
                      <p className="text-sm">{selectedIndicator.validUntil || "Unknown"}</p>
                    </div>
                    
                    <div className="md:col-span-2">
                      <p className="text-xs text-muted-foreground mb-1">Description</p>
                      <p className="text-sm">{selectedIndicator.description || "No description available"}</p>
                    </div>
                    
                    <div className="md:col-span-2">
                      <p className="text-xs text-muted-foreground mb-1">Pattern</p>
                      <div className="bg-muted p-2 rounded-md font-mono text-xs overflow-auto">
                        {selectedIndicator.pattern || "No pattern available"}
                      </div>
                    </div>
                  </div>
                </Card>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="p-4">
                    <h4 className="text-sm font-semibold mb-2">Labels</h4>
                    <div className="flex flex-wrap gap-2">
                      {selectedIndicator.labels?.map((label, i) => (
                        <Badge key={i} variant="outline">
                          {label}
                        </Badge>
                      ))}
                      {(!selectedIndicator.labels || selectedIndicator.labels.length === 0) && (
                        <p className="text-sm text-muted-foreground">No labels assigned</p>
                      )}
                    </div>
                  </Card>
                  
                  <Card className="p-4">
                    <h4 className="text-sm font-semibold mb-2">External Analysis</h4>
                    <div className="space-y-2">
                      <Button variant="outline" size="sm" className="w-full justify-start">
                        <Globe className="mr-2 h-4 w-4" />
                        Search in VirusTotal
                      </Button>
                      
                      <Button variant="outline" size="sm" className="w-full justify-start">
                        <Globe className="mr-2 h-4 w-4" />
                        Search in AlienVault OTX
                      </Button>
                      
                      <Button variant="outline" size="sm" className="w-full justify-start">
                        <Globe className="mr-2 h-4 w-4" />
                        Search in Shodan
                      </Button>
                    </div>
                  </Card>
                </div>
                
                <Card className="p-4">
                  <h4 className="text-sm font-semibold mb-3">Related Entities</h4>
                  <p className="text-sm text-muted-foreground mb-4">
                    Entities that are related to this indicator.
                  </p>
                  
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Relationship</TableHead>
                        <TableHead className="text-right">Created</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      <TableRow>
                        <TableCell className="font-medium">
                          <div className="flex items-center">
                            <Bug className="h-4 w-4 text-red-500 mr-2" />
                            TrickBot
                          </div>
                        </TableCell>
                        <TableCell>malware</TableCell>
                        <TableCell>indicates</TableCell>
                        <TableCell className="text-right text-xs">2023-03-15</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">
                          <div className="flex items-center">
                            <User className="h-4 w-4 text-purple-500 mr-2" />
                            APT28
                          </div>
                        </TableCell>
                        <TableCell>threat-actor</TableCell>
                        <TableCell>attributed-to</TableCell>
                        <TableCell className="text-right text-xs">2023-02-28</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">
                          <div className="flex items-center">
                            <Target className="h-4 w-4 text-amber-500 mr-2" />
                            Operation Ghost
                          </div>
                        </TableCell>
                        <TableCell>campaign</TableCell>
                        <TableCell>related-to</TableCell>
                        <TableCell className="text-right text-xs">2023-01-10</TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </Card>
              </div>
            )}
            
            {!selectedEntity && !selectedIndicator && (
              <div className="py-12 text-center">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground opacity-20" />
                <h3 className="text-lg font-semibold mb-2">No Item Selected</h3>
                <p className="text-muted-foreground">
                  Select an entity or indicator from the search results to view details
                </p>
                <Button 
                  variant="outline" 
                  className="mt-4"
                  onClick={() => setActiveTab("search")}
                >
                  Return to Search
                </Button>
              </div>
            )}
          </TabsContent>
          
          {/* Graph Tab */}
          <TabsContent value="graph" className="space-y-4">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Relationship Graph</h3>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="hidden sm:flex">
                  <Download className="mr-2 h-4 w-4" />
                  Export Graph
                </Button>
                <Button variant="outline" size="sm" className="hidden sm:flex">
                  <Maximize2 className="mr-2 h-4 w-4" />
                  Expand
                </Button>
              </div>
            </div>
            
            <div className="aspect-video bg-muted rounded-lg flex items-center justify-center p-4 border">
              <div className="text-center">
                <Network className="h-16 w-16 mx-auto mb-4 text-muted-foreground opacity-20" />
                <p className="text-muted-foreground">Graph visualization placeholder</p>
                <p className="text-sm text-muted-foreground mt-1">
                  In a real implementation, this would show an interactive graph of entity relationships
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <Card className="p-4 col-span-2">
                <h4 className="text-sm font-semibold mb-3">Graph Legend</h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-red-500 rounded-full mr-2"></span>
                    <span className="text-sm">Malware</span>
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-purple-500 rounded-full mr-2"></span>
                    <span className="text-sm">Threat Actor</span>
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-amber-500 rounded-full mr-2"></span>
                    <span className="text-sm">Campaign</span>
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-green-500 rounded-full mr-2"></span>
                    <span className="text-sm">Attack Pattern</span>
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-blue-500 rounded-full mr-2"></span>
                    <span className="text-sm">Tool</span>
                  </div>
                  <div className="flex items-center">
                    <span className="inline-block w-3 h-3 bg-pink-500 rounded-full mr-2"></span>
                    <span className="text-sm">Vulnerability</span>
                  </div>
                </div>
                
                <h4 className="text-sm font-semibold mt-4 mb-2">Relationship Types</h4>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center">
                    <ArrowRight className="h-3 w-3 mr-1" />
                    <span>uses</span>
                  </div>
                  <div className="flex items-center">
                    <ArrowRight className="h-3 w-3 mr-1" />
                    <span>targets</span>
                  </div>
                  <div className="flex items-center">
                    <ArrowRight className="h-3 w-3 mr-1" />
                    <span>attributed-to</span>
                  </div>
                  <div className="flex items-center">
                    <ArrowRight className="h-3 w-3 mr-1" />
                    <span>indicates</span>
                  </div>
                </div>
              </Card>
              
              <Card className="p-4">
                <h4 className="text-sm font-semibold mb-3">Graph Controls</h4>
                <div className="space-y-3">
                  <div>
                    <Label className="text-xs">Layout</Label>
                    <Select defaultValue="force">
                      <SelectTrigger>
                        <SelectValue placeholder="Select layout" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="force">Force-Directed</SelectItem>
                        <SelectItem value="hierarchical">Hierarchical</SelectItem>
                        <SelectItem value="circular">Circular</SelectItem>
                        <SelectItem value="grid">Grid</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div>
                    <Label className="text-xs">Group By</Label>
                    <Select defaultValue="type">
                      <SelectTrigger>
                        <SelectValue placeholder="Select grouping" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="type">Entity Type</SelectItem>
                        <SelectItem value="created">Creation Date</SelectItem>
                        <SelectItem value="label">Labels</SelectItem>
                        <SelectItem value="none">No Grouping</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <Label htmlFor="show-labels" className="text-xs cursor-pointer">
                      Show Labels
                    </Label>
                    <Switch id="show-labels" defaultChecked />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <Label htmlFor="show-relationship-labels" className="text-xs cursor-pointer">
                      Show Relationship Labels
                    </Label>
                    <Switch id="show-relationship-labels" />
                  </div>
                </div>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </Card>
    </div>
  );
}