import { useState } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { useToast } from "@/hooks/use-toast";
import { Card } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
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
  Phone,
  User,
  MapPin,
  Building,
  Globe,
  FileText,
  AlertTriangle,
  Search,
  RefreshCw,
  Database,
  Shield,
  ExternalLink,
  Link,
  Facebook,
  Twitter,
  Instagram,
  Linkedin,
  Youtube,
  Hash,
  Eye,
  Newspaper,
  Image
} from "lucide-react";

// Types
interface PhoneResult {
  phoneNumber: string;
  valid: boolean;
  formatted: string;
  countryCode: string;
  location?: string;
  carrier?: string;
  lineType?: string; // mobile, landline, voip
  owner?: {
    name?: string;
    address?: string;
    socialProfiles?: Array<{
      platform: string;
      url?: string;
    }>
  };
  spam?: boolean;
  spamReports?: number;
  recentActivity?: Array<{
    type: string;
    date: string;
    details?: string;
  }>;
  publicRecords?: Array<{
    source: string;
    recordType: string;
    link?: string;
  }>;
  webResults?: Array<{
    title: string;
    url: string;
    snippet: string;
    source: string; // google, bing, etc.
    type: 'web' | 'social' | 'image' | 'news' | 'forum'; // type of result
    timestamp?: string; // when the content was published/found
  }>;
  imageResults?: Array<{
    title: string;
    url: string;
    thumbnailUrl: string;
    source: string;
  }>;
  socialMediaMentions?: Array<{
    platform: string;
    url: string;
    username?: string;
    content?: string;
    date?: string;
  }>;
  leakedDatabases?: Array<{
    databaseName: string;
    leakDate: string;
    dataTypes: string[];
    confirmed: boolean;
  }>;
}

interface ApiResponse {
  status: string;
  message: string;
  data?: PhoneResult;
}

export default function PhoneDoxing() {
  const { toast } = useToast();
  const { addSystemLine, addInfoLine, addErrorLine, addSuccessLine, clearLines } = useTerminal();
  
  const [phoneNumber, setPhoneNumber] = useState<string>("");
  const [country, setCountry] = useState<string>("US");
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [result, setResult] = useState<PhoneResult | null>(null);
  const [activeTab, setActiveTab] = useState<string>("basic");
  const [selectedDatabases, setSelectedDatabases] = useState<string[]>([
    "carrier", "location", "social", "public"
  ]);
  const [selectedSearchEngines, setSelectedSearchEngines] = useState<string[]>([
    "google", "bing", "socialMedia", "forums"
  ]);
  const [webSearchDepth, setWebSearchDepth] = useState<"basic" | "deep" | "comprehensive">("basic");
  
  // Handle database selection
  const handleDatabaseChange = (database: string, checked: boolean) => {
    if (checked) {
      setSelectedDatabases(prev => [...prev, database]);
    } else {
      setSelectedDatabases(prev => prev.filter(db => db !== database));
    }
  };
  
  // Handle search engine selection
  const handleSearchEngineChange = (engine: string, checked: boolean) => {
    if (checked) {
      setSelectedSearchEngines(prev => [...prev, engine]);
    } else {
      setSelectedSearchEngines(prev => prev.filter(e => e !== engine));
    }
  };
  
  // Handle search depth change
  const handleSearchDepthChange = (depth: "basic" | "deep" | "comprehensive") => {
    setWebSearchDepth(depth);
  };
  
  // Function to search for phone number information
  const searchPhone = async () => {
    if (!phoneNumber) {
      toast({
        variant: "destructive",
        title: "Missing Phone Number",
        description: "Please enter a phone number to search"
      });
      return;
    }
    
    // Validate the phone number format (basic validation)
    const phoneRegex = /^\+?[0-9\s\-()]{8,20}$/;
    if (!phoneRegex.test(phoneNumber)) {
      toast({
        variant: "destructive",
        title: "Invalid Phone Number",
        description: "Please enter a valid phone number"
      });
      return;
    }
    
    try {
      setIsSearching(true);
      clearLines();
      setResult(null);
      
      addSystemLine(`Starting phone number doxing on ${phoneNumber}`);
      addInfoLine("Initializing search engines and databases...");
      
      // Simulate API calls with different timings
      await new Promise(resolve => setTimeout(resolve, 800));
      addInfoLine(`Checking phone number format and validity...`);
      
      // Simulate phone validation
      const isValid = Math.random() > 0.1; // 90% chance of valid
      if (!isValid) {
        addErrorLine("Invalid phone number format or nonexistent number");
        toast({
          variant: "destructive",
          title: "Invalid Phone Number",
          description: "The provided phone number appears to be invalid or nonexistent"
        });
        setIsSearching(false);
        return;
      }
      
      // Display progress based on selected databases
      if (selectedDatabases.includes("carrier")) {
        await new Promise(resolve => setTimeout(resolve, 400));
        addInfoLine("Querying carrier database...");
      }
      
      if (selectedDatabases.includes("location")) {
        await new Promise(resolve => setTimeout(resolve, 600));
        addInfoLine("Performing geolocation lookup...");
      }
      
      if (selectedDatabases.includes("social")) {
        await new Promise(resolve => setTimeout(resolve, 800));
        addInfoLine("Scanning social media platforms...");
      }
      
      if (selectedDatabases.includes("public")) {
        await new Promise(resolve => setTimeout(resolve, 900));
        addInfoLine("Searching public records databases...");
      }
      
      // Process web search options
      if (selectedSearchEngines.length > 0) {
        addInfoLine("Initializing web search across multiple search engines...");
        
        if (selectedSearchEngines.includes("google")) {
          await new Promise(resolve => setTimeout(resolve, 700));
          addInfoLine("Querying Google for phone number references...");
        }
        
        if (selectedSearchEngines.includes("bing")) {
          await new Promise(resolve => setTimeout(resolve, 600));
          addInfoLine("Searching Bing for relevant information...");
        }
        
        if (selectedSearchEngines.includes("socialMedia")) {
          await new Promise(resolve => setTimeout(resolve, 1200));
          addInfoLine("Scanning social media platforms for mentions of the number...");
        }
        
        if (selectedSearchEngines.includes("forums")) {
          await new Promise(resolve => setTimeout(resolve, 800));
          addInfoLine("Searching forums and discussion boards...");
        }
        
        // Additional time for comprehensive search
        if (webSearchDepth === "deep" || webSearchDepth === "comprehensive") {
          await new Promise(resolve => setTimeout(resolve, 1500));
          addInfoLine("Performing deep web search with expanded parameters...");
        }
        
        if (webSearchDepth === "comprehensive") {
          await new Promise(resolve => setTimeout(resolve, 2000));
          addInfoLine("Executing comprehensive search across dark web and leaked databases...");
        }
      }
      
      // Generate a simulated result based on phone number patterns and selected databases
      const generatedResult = generatePhoneResult(phoneNumber, country, selectedDatabases);
      setResult(generatedResult);
      
      // Log the results
      addSuccessLine("Phone number information gathering completed");
      addInfoLine(`Found ${Object.keys(generatedResult).filter(k => generatedResult[k as keyof PhoneResult] && k !== 'phoneNumber').length} data points`);
      
      if (generatedResult.spam) {
        addErrorLine("⚠️ This number has been flagged as potential spam");
      }
      
      toast({
        title: "Search Complete",
        description: "Phone number information has been gathered successfully"
      });
      
    } catch (error) {
      addErrorLine(`Error during phone search: ${error instanceof Error ? error.message : 'Unknown error'}`);
      
      toast({
        variant: "destructive",
        title: "Search Failed",
        description: "An error occurred while searching for phone information"
      });
    } finally {
      setIsSearching(false);
    }
  };
  
  // Function to generate realistic-looking but simulated phone data
  const generatePhoneResult = (phone: string, countryCode: string, selectedDbs: string[]): PhoneResult => {
    const normalizedPhone = phone.replace(/[^0-9+]/g, "");
    
    // Base result
    const result: PhoneResult = {
      phoneNumber: normalizedPhone,
      valid: true,
      formatted: formatPhoneNumber(normalizedPhone, countryCode),
      countryCode: countryCode
    };
    
    // Add carrier info if selected
    if (selectedDbs.includes("carrier")) {
      const carriers = {
        "US": ["AT&T", "Verizon", "T-Mobile", "Sprint", "US Cellular"],
        "UK": ["Vodafone", "EE", "O2", "Three"],
        "CA": ["Rogers", "Bell", "Telus", "Freedom"],
        "AU": ["Telstra", "Optus", "Vodafone AU"],
        // Add more countries as needed
      };
      
      const lineTypes = ["mobile", "landline", "voip"];
      
      result.carrier = carriers[countryCode as keyof typeof carriers]?.[Math.floor(Math.random() * (carriers[countryCode as keyof typeof carriers]?.length || 0))] || "Unknown Carrier";
      result.lineType = lineTypes[Math.floor(Math.random() * lineTypes.length)];
    }
    
    // Add location info if selected
    if (selectedDbs.includes("location")) {
      const locations = {
        "US": ["New York, NY", "Los Angeles, CA", "Chicago, IL", "Houston, TX", "Phoenix, AZ"],
        "UK": ["London", "Manchester", "Birmingham", "Liverpool", "Glasgow"],
        "CA": ["Toronto, ON", "Vancouver, BC", "Montreal, QC", "Calgary, AB"],
        "AU": ["Sydney, NSW", "Melbourne, VIC", "Brisbane, QLD", "Perth, WA"],
        // Add more locations as needed
      };
      
      result.location = locations[countryCode as keyof typeof locations]?.[Math.floor(Math.random() * (locations[countryCode as keyof typeof locations]?.length || 0))] || "Unknown Location";
    }
    
    // Add owner info & social profiles if selected
    if (selectedDbs.includes("social") && Math.random() > 0.4) { // 60% chance of finding owner info
      const firstNames = ["John", "Jane", "Robert", "Mary", "Michael", "Linda", "David", "Sarah"];
      const lastNames = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"];
      
      // Social platforms
      const platforms = ["Facebook", "LinkedIn", "Twitter", "Instagram", "TikTok"];
      const socialProfiles = [];
      
      // Generate 0-3 social profiles
      const profileCount = Math.floor(Math.random() * 4); 
      for (let i = 0; i < profileCount; i++) {
        const platform = platforms[Math.floor(Math.random() * platforms.length)];
        socialProfiles.push({
          platform,
          url: Math.random() > 0.3 ? `https://${platform.toLowerCase()}.com/user${Math.floor(Math.random() * 10000)}` : undefined
        });
      }
      
      // Generate owner info
      result.owner = {
        name: `${firstNames[Math.floor(Math.random() * firstNames.length)]} ${lastNames[Math.floor(Math.random() * lastNames.length)]}`,
        address: Math.random() > 0.6 ? `${Math.floor(Math.random() * 9999) + 1} ${["Main", "Oak", "Pine", "Maple", "Cedar"][Math.floor(Math.random() * 5)]} St` : undefined,
        socialProfiles: socialProfiles.length > 0 ? socialProfiles : undefined
      };
    }
    
    // Add spam info (20% chance of being spam)
    if (Math.random() > 0.8) {
      result.spam = true;
      result.spamReports = Math.floor(Math.random() * 50) + 1;
    } else {
      result.spam = false;
    }
    
    // Add public records if selected
    if (selectedDbs.includes("public") && Math.random() > 0.5) { // 50% chance of finding public records
      const recordTypes = ["Court Record", "Property Record", "Business Registration", "Voter Registration"];
      const sources = ["County Records", "State Database", "Federal Records", "Public Directory"];
      
      const publicRecords = [];
      
      // Generate 0-2 public records
      const recordCount = Math.floor(Math.random() * 3);
      for (let i = 0; i < recordCount; i++) {
        publicRecords.push({
          source: sources[Math.floor(Math.random() * sources.length)],
          recordType: recordTypes[Math.floor(Math.random() * recordTypes.length)],
          link: Math.random() > 0.7 ? `https://records.example.com/ref${Math.floor(Math.random() * 100000)}` : undefined
        });
      }
      
      if (publicRecords.length > 0) {
        result.publicRecords = publicRecords;
      }
    }
    
    // Add recent activity (30% chance)
    if (Math.random() > 0.7) {
      const activityTypes = ["Text message", "Call", "Registration", "Verification"];
      const recentActivity = [];
      
      // Generate 1-3 recent activities
      const activityCount = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < activityCount; i++) {
        const activityType = activityTypes[Math.floor(Math.random() * activityTypes.length)];
        const date = new Date();
        date.setDate(date.getDate() - Math.floor(Math.random() * 30)); // Random date in last 30 days
        
        recentActivity.push({
          type: activityType,
          date: date.toISOString().split('T')[0],
          details: Math.random() > 0.5 ? `${activityType} with ${["service provider", "online platform", "e-commerce site", "app"][Math.floor(Math.random() * 4)]}` : undefined
        });
      }
      
      if (recentActivity.length > 0) {
        result.recentActivity = recentActivity;
      }
    }
    
    // Add web search results if search engines are selected
    if (selectedSearchEngines.includes("google") || selectedSearchEngines.includes("bing")) {
      const webResults = [];
      const ownerName = result.owner?.name || "unknown";
      const formattedPhone = formatPhoneNumber(normalizedPhone, countryCode);
      
      // Common domains for search results
      const domains = [
        "linkedin.com", "facebook.com", "twitter.com", "instagram.com",
        "yelp.com", "yellowpages.com", "whitepages.com", "truecaller.com",
        "indeed.com", "glassdoor.com", "amazon.com", "ebay.com",
        "craigslist.org", "reddit.com", "quora.com", "medium.com"
      ];
      
      // Search result templates
      const resultTemplates = [
        {
          title: `Contact ${ownerName} - Professional Profile`,
          snippet: `... contact information: ${formattedPhone}. Email: ${ownerName.toLowerCase().replace(" ", ".")}@example.com ...`,
          type: "web"
        },
        {
          title: `${result.location} Business Directory`,
          snippet: `... local businesses including ${ownerName}'s service. Contact: ${formattedPhone} ...`,
          type: "web"
        },
        {
          title: `Phone Number Information: ${formattedPhone}`,
          snippet: `This phone number belongs to ${ownerName} from ${result.location}. Carrier: ${result.carrier} ...`,
          type: "web"
        }
      ];
      
      // Generate 2-5 web results depending on search depth
      const resultCount = webSearchDepth === "basic" ? 2 : webSearchDepth === "deep" ? 4 : 5;
      
      for (let i = 0; i < resultCount; i++) {
        const template = resultTemplates[Math.floor(Math.random() * resultTemplates.length)];
        const domain = domains[Math.floor(Math.random() * domains.length)];
        const source = i % 2 === 0 ? "google" : "bing";
        
        // Generate random date within last year
        const date = new Date();
        date.setDate(date.getDate() - Math.floor(Math.random() * 365));
        
        webResults.push({
          title: template.title,
          url: `https://${domain}/profile/${Math.floor(Math.random() * 100000)}`,
          snippet: template.snippet,
          source: source,
          type: template.type as 'web' | 'social' | 'image' | 'news' | 'forum',
          timestamp: date.toISOString().split('T')[0]
        });
      }
      
      if (webResults.length > 0) {
        result.webResults = webResults;
      }
    }
    
    // Add social media mentions if selected
    if (selectedSearchEngines.includes("socialMedia")) {
      const socialMediaMentions = [];
      const platforms = ["Twitter", "Facebook", "Instagram", "LinkedIn", "Reddit"];
      const ownerName = result.owner?.name || "J. Smith";
      
      // Generate 1-3 social media mentions
      const mentionCount = Math.floor(Math.random() * 3) + 1;
      
      for (let i = 0; i < mentionCount; i++) {
        const platform = platforms[Math.floor(Math.random() * platforms.length)];
        const date = new Date();
        date.setDate(date.getDate() - Math.floor(Math.random() * 180)); // Last 6 months
        
        socialMediaMentions.push({
          platform: platform,
          url: `https://${platform.toLowerCase()}.com/post/${Math.floor(Math.random() * 1000000)}`,
          username: `${platform}User${Math.floor(Math.random() * 1000)}`,
          content: Math.random() > 0.5 ? `Contact ${ownerName} at ${formatPhoneNumber(normalizedPhone, countryCode)} for more information.` : undefined,
          date: date.toISOString().split('T')[0]
        });
      }
      
      if (socialMediaMentions.length > 0) {
        result.socialMediaMentions = socialMediaMentions;
      }
    }
    
    // Add image results for comprehensive search
    if (webSearchDepth === "comprehensive") {
      const imageResults = [];
      
      // Generate 1-2 image results
      const imageCount = Math.floor(Math.random() * 2) + 1;
      
      for (let i = 0; i < imageCount; i++) {
        imageResults.push({
          title: `${result.owner?.name || "Profile"} Photo`,
          url: `https://example.com/images/${Math.floor(Math.random() * 10000)}`,
          thumbnailUrl: `https://via.placeholder.com/150?text=Profile`,
          source: i % 2 === 0 ? "google images" : "bing images"
        });
      }
      
      if (imageResults.length > 0) {
        result.imageResults = imageResults;
      }
    }
    
    // Add leaked database information for comprehensive search
    if (webSearchDepth === "comprehensive") {
      const leakedDatabases = [];
      const databaseNames = [
        "SocialConnect 2021 Breach", 
        "EcommerceShop Data Leak", 
        "ForumSite User Database", 
        "MobileApp User Records"
      ];
      
      // Generate 1-2 leaked database entries
      const dbCount = Math.floor(Math.random() * 2) + 1;
      
      for (let i = 0; i < dbCount; i++) {
        const dataTypes = [];
        if (Math.random() > 0.5) dataTypes.push("email");
        if (Math.random() > 0.5) dataTypes.push("phone");
        if (Math.random() > 0.5) dataTypes.push("username");
        if (Math.random() > 0.7) dataTypes.push("password");
        if (dataTypes.length === 0) dataTypes.push("phone"); // Ensure at least one data type
        
        // Generate date in past 1-3 years
        const year = 2021 - Math.floor(Math.random() * 3);
        const month = Math.floor(Math.random() * 12) + 1;
        const day = Math.floor(Math.random() * 28) + 1;
        
        leakedDatabases.push({
          databaseName: databaseNames[Math.floor(Math.random() * databaseNames.length)],
          leakDate: `${year}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`,
          dataTypes: dataTypes,
          confirmed: Math.random() > 0.3 // 70% chance of being confirmed
        });
      }
      
      if (leakedDatabases.length > 0) {
        result.leakedDatabases = leakedDatabases;
      }
    }
    
    return result;
  };
  
  // Format phone number for display
  const formatPhoneNumber = (phone: string, country: string): string => {
    // Simple formatting, in a real app would use a proper phone formatting library
    let formatted = phone.replace(/[^0-9+]/g, "");
    
    if (country === "US") {
      if (formatted.startsWith("+1")) {
        formatted = formatted.substring(2);
      } else if (formatted.startsWith("1")) {
        formatted = formatted.substring(1);
      }
      
      if (formatted.length === 10) {
        return `+1 (${formatted.substring(0, 3)}) ${formatted.substring(3, 6)}-${formatted.substring(6)}`;
      }
    }
    
    // Default formatting for other countries
    return formatted;
  };
  
  // Copy result to clipboard
  const copyToClipboard = () => {
    if (result) {
      const resultText = JSON.stringify(result, null, 2);
      navigator.clipboard.writeText(resultText);
      
      toast({
        title: "Copied to Clipboard",
        description: "Phone information has been copied to clipboard"
      });
    }
  };
  
  // Download result as JSON
  const downloadResult = () => {
    if (result) {
      const resultText = JSON.stringify(result, null, 2);
      const blob = new Blob([resultText], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement("a");
      a.href = url;
      a.download = `phone_lookup_${result.phoneNumber.replace(/[^0-9]/g, "")}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast({
        title: "Download Started",
        description: "The phone information report is being downloaded"
      });
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <div className="flex items-center mb-4">
          <Phone className="w-5 h-5 text-primary mr-2" />
          <h2 className="text-xl font-tech text-primary">Phone Doxing Tool</h2>
        </div>
        
        <div className="space-y-6">
          {/* Input Section */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="col-span-3">
              <Label htmlFor="phone-input">Phone Number (with or without country code)</Label>
              <div className="flex mt-1">
                <Input
                  id="phone-input"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  placeholder="+1 555 123 4567"
                  disabled={isSearching}
                  className="rounded-r-none focus-visible:ring-0 focus-visible:ring-primary/20"
                />
                <Button 
                  onClick={searchPhone} 
                  disabled={isSearching || !phoneNumber}
                  className="rounded-l-none"
                >
                  {isSearching ? (
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
            </div>
            
            <div>
              <Label htmlFor="country-select">Country</Label>
              <select
                id="country-select"
                value={country}
                onChange={(e) => setCountry(e.target.value)}
                disabled={isSearching}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <option value="US">United States (+1)</option>
                <option value="UK">United Kingdom (+44)</option>
                <option value="CA">Canada (+1)</option>
                <option value="AU">Australia (+61)</option>
                <option value="Other">Other</option>
              </select>
            </div>
          </div>
          
          {/* Database Options */}
          <div>
            <Label className="mb-2 block">Search Databases</Label>
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="carrier-db"
                  checked={selectedDatabases.includes("carrier")}
                  onCheckedChange={(checked) => handleDatabaseChange("carrier", !!checked)}
                />
                <Label htmlFor="carrier-db" className="cursor-pointer">Carrier Info</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="location-db"
                  checked={selectedDatabases.includes("location")} 
                  onCheckedChange={(checked) => handleDatabaseChange("location", !!checked)}
                />
                <Label htmlFor="location-db" className="cursor-pointer">Location Data</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="social-db"
                  checked={selectedDatabases.includes("social")}
                  onCheckedChange={(checked) => handleDatabaseChange("social", !!checked)}
                />
                <Label htmlFor="social-db" className="cursor-pointer">Social Media</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="public-db"
                  checked={selectedDatabases.includes("public")}
                  onCheckedChange={(checked) => handleDatabaseChange("public", !!checked)}
                />
                <Label htmlFor="public-db" className="cursor-pointer">Public Records</Label>
              </div>
            </div>
          </div>
          
          {/* Search Engine Options */}
          <div className="mt-4">
            <Label className="mb-2 block">Search Engines</Label>
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="engine-google"
                  checked={selectedSearchEngines.includes("google")}
                  onCheckedChange={(checked) => handleSearchEngineChange("google", !!checked)}
                />
                <Label htmlFor="engine-google" className="cursor-pointer">Google</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="engine-bing"
                  checked={selectedSearchEngines.includes("bing")} 
                  onCheckedChange={(checked) => handleSearchEngineChange("bing", !!checked)}
                />
                <Label htmlFor="engine-bing" className="cursor-pointer">Bing</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="engine-social"
                  checked={selectedSearchEngines.includes("socialMedia")}
                  onCheckedChange={(checked) => handleSearchEngineChange("socialMedia", !!checked)}
                />
                <Label htmlFor="engine-social" className="cursor-pointer">Social Platforms</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox 
                  id="engine-forums"
                  checked={selectedSearchEngines.includes("forums")}
                  onCheckedChange={(checked) => handleSearchEngineChange("forums", !!checked)}
                />
                <Label htmlFor="engine-forums" className="cursor-pointer">Forums & Boards</Label>
              </div>
            </div>
          </div>
          
          {/* Search Depth */}
          <div className="mt-4">
            <Label className="mb-2 block">Search Depth</Label>
            <div className="flex gap-3">
              <Button 
                size="sm" 
                variant={webSearchDepth === "basic" ? "default" : "outline"}
                onClick={() => handleSearchDepthChange("basic")}
              >
                Basic
              </Button>
              <Button 
                size="sm" 
                variant={webSearchDepth === "deep" ? "default" : "outline"}
                onClick={() => handleSearchDepthChange("deep")}
              >
                Deep
              </Button>
              <Button 
                size="sm" 
                variant={webSearchDepth === "comprehensive" ? "default" : "outline"}
                onClick={() => handleSearchDepthChange("comprehensive")}
              >
                Comprehensive
              </Button>
            </div>
          </div>
          
          {/* Disclaimer */}
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-md p-3 text-sm">
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 text-yellow-500 mr-2 mt-0.5" />
              <div>
                <p className="font-semibold text-yellow-500">Educational Purpose Only</p>
                <p className="text-muted-foreground mt-1">
                  This tool is for educational and informational purposes only. Always respect privacy laws and 
                  regulations in your jurisdiction. Do not use this tool for harassment, stalking, or any illegal activities.
                </p>
              </div>
            </div>
          </div>
          
          {/* Results Section */}
          {result && (
            <div className="bg-card/50 border border-border rounded-md p-4 mt-4">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-tech text-primary flex items-center">
                  <Database className="h-5 w-5 mr-2" />
                  Phone Information Results
                </h3>
                <div className="flex space-x-2">
                  <Button variant="outline" size="sm" onClick={copyToClipboard}>
                    <Copy className="h-4 w-4 mr-1" />
                    Copy
                  </Button>
                  <Button variant="outline" size="sm" onClick={downloadResult}>
                    <Download className="h-4 w-4 mr-1" />
                    Download
                  </Button>
                </div>
              </div>
              
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="grid grid-cols-3 mb-4">
                  <TabsTrigger value="basic" className="font-tech">Basic Info</TabsTrigger>
                  <TabsTrigger value="owner" className="font-tech">Owner Data</TabsTrigger>
                  <TabsTrigger value="activity" className="font-tech">Activity & Records</TabsTrigger>
                </TabsList>
                
                {/* Basic Info Tab */}
                <TabsContent value="basic" className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Phone Number:</span>
                        <span className="font-mono">{result.formatted}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Validation:</span>
                        <span className="flex items-center">
                          {result.valid ? (
                            <>
                              <CheckCircle className="h-4 w-4 text-green-500 mr-1" />
                              Valid
                            </>
                          ) : (
                            <>
                              <AlertCircle className="h-4 w-4 text-red-500 mr-1" />
                              Invalid
                            </>
                          )}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Country:</span>
                        <span>{result.countryCode}</span>
                      </div>
                      {result.location && (
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">Location:</span>
                          <span className="flex items-center">
                            <MapPin className="h-3 w-3 text-primary mr-1" />
                            {result.location}
                          </span>
                        </div>
                      )}
                    </div>
                    
                    <div className="space-y-2">
                      {result.carrier && (
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">Carrier:</span>
                          <span className="flex items-center">
                            <Building className="h-3 w-3 text-primary mr-1" />
                            {result.carrier}
                          </span>
                        </div>
                      )}
                      {result.lineType && (
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">Line Type:</span>
                          <span className="capitalize">{result.lineType}</span>
                        </div>
                      )}
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Spam Status:</span>
                        <span className="flex items-center">
                          {result.spam ? (
                            <>
                              <AlertCircle className="h-4 w-4 text-red-500 mr-1" />
                              Flagged as Spam
                            </>
                          ) : (
                            <>
                              <Shield className="h-4 w-4 text-green-500 mr-1" />
                              No Spam Reports
                            </>
                          )}
                        </span>
                      </div>
                      {result.spam && result.spamReports && (
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">Spam Reports:</span>
                          <span className="text-red-500">{result.spamReports} reports</span>
                        </div>
                      )}
                    </div>
                  </div>
                </TabsContent>
                
                {/* Owner Data Tab */}
                <TabsContent value="owner" className="space-y-4">
                  {result.owner ? (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          {result.owner.name && (
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Owner Name:</span>
                              <span className="flex items-center">
                                <User className="h-3 w-3 text-primary mr-1" />
                                {result.owner.name}
                              </span>
                            </div>
                          )}
                          {result.owner.address && (
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Address:</span>
                              <span className="flex items-center">
                                <MapPin className="h-3 w-3 text-primary mr-1" />
                                {result.owner.address}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      {result.owner.socialProfiles && result.owner.socialProfiles.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Social Media Profiles</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {result.owner.socialProfiles.map((profile, index) => (
                              <div key={index} className="flex justify-between items-center border border-border/50 rounded p-2 text-sm">
                                <span className="flex items-center">
                                  <Globe className="h-3 w-3 text-primary mr-1" />
                                  {profile.platform}
                                </span>
                                {profile.url && (
                                  <Button variant="ghost" size="sm" className="h-6 px-2 text-xs">
                                    View
                                  </Button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <User className="h-10 w-10 mx-auto mb-2 opacity-30" />
                      <p>No owner information available</p>
                    </div>
                  )}
                </TabsContent>
                
                {/* Activity & Records Tab */}
                <TabsContent value="activity" className="space-y-4">
                  {/* Recent Activity */}
                  {result.recentActivity && result.recentActivity.length > 0 ? (
                    <div className="mb-6">
                      <h4 className="text-sm font-semibold mb-2">Recent Activity</h4>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Date</TableHead>
                            <TableHead>Activity</TableHead>
                            <TableHead>Details</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {result.recentActivity.map((activity, index) => (
                            <TableRow key={index}>
                              <TableCell className="font-mono">{activity.date}</TableCell>
                              <TableCell>{activity.type}</TableCell>
                              <TableCell className="text-muted-foreground text-xs">{activity.details || "—"}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  ) : (
                    <div className="text-center py-4 text-muted-foreground">
                      <RefreshCw className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p>No recent activity records found</p>
                    </div>
                  )}
                  
                  {/* Public Records */}
                  {result.publicRecords && result.publicRecords.length > 0 ? (
                    <div>
                      <h4 className="text-sm font-semibold mb-2">Public Records</h4>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Record Type</TableHead>
                            <TableHead>Source</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {result.publicRecords.map((record, index) => (
                            <TableRow key={index}>
                              <TableCell>{record.recordType}</TableCell>
                              <TableCell className="text-muted-foreground">{record.source}</TableCell>
                              <TableCell>
                                {record.link ? (
                                  <Button variant="ghost" size="sm" className="h-6 px-2 text-xs">
                                    <FileText className="h-3 w-3 mr-1" />
                                    View Record
                                  </Button>
                                ) : (
                                  <span className="text-xs text-muted-foreground">No link available</span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  ) : (
                    <div className="text-center py-4 text-muted-foreground">
                      <FileText className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p>No public records found</p>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}