import React from 'react';
import { Helmet } from 'react-helmet';
import { Card } from '@/components/ui/card';
import { FileUp, Info, Shield, FileText } from 'lucide-react';

// Import the actual component when available
// import MetadataExtractor from '@/components/tools/metadata-extractor';

const MetadataExtractorPage: React.FC = () => {
  return (
    <div className="container mx-auto px-4 py-8 relative">
      <Helmet>
        <title>Metadata Extractor | CyberPulse Security Toolkit</title>
        <meta name="description" content="Extract and analyze metadata from images, documents, and other files to identify hidden information and potential privacy risks." />
      </Helmet>
      
      <div className="absolute inset-0 opacity-10 pointer-events-none bg-gradient-to-br from-primary/5 to-secondary/5">
        {/* Matrix background effect */}
        <div className="grid grid-cols-12 h-full">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="border-r border-primary/5 h-full"></div>
          ))}
        </div>
        <div className="grid grid-rows-12 w-full absolute top-0">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="border-b border-primary/5 w-full"></div>
          ))}
        </div>
      </div>
      
      <div className="mb-8 text-center">
        <div className="inline-flex items-center justify-center p-2 bg-primary/10 rounded-full mb-4">
          <FileText className="h-8 w-8 text-primary" />
        </div>
        <h1 className="text-3xl font-bold font-tech text-primary mb-2">Metadata Extractor</h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Extract and analyze hidden metadata from files to discover embedded information such as GPS coordinates, 
          device details, creation dates, and more. Identify potential privacy issues in your files.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        {/* Technical Description */}
        <Card className="p-4 border-primary/30 bg-card/30">
          <h3 className="text-lg font-tech mb-3 flex items-center text-primary">
            <FileUp className="h-4 w-4 mr-2" />
            Metadata Analysis Tool
          </h3>
          <p className="text-sm text-muted-foreground">
            Upload files to extract hidden metadata including GPS coordinates, creation timestamps, device information, and other embedded data that may expose sensitive information.
          </p>
        </Card>
        
        {/* Technical Usage */}
        <Card className="p-4 border-primary/30 bg-card/30">
          <h3 className="text-lg font-tech mb-3 flex items-center text-primary">
            <Info className="h-4 w-4 mr-2" />
            How It Works
          </h3>
          <p className="text-sm text-muted-foreground">
            This tool analyzes files using EXIF and other metadata extraction techniques to reveal hidden information that's not visible in standard file viewers.
          </p>
        </Card>
        
        {/* Security Implications */}
        <Card className="p-4 border-primary/30 bg-card/30">
          <h3 className="text-lg font-tech mb-3 flex items-center text-primary">
            <Shield className="h-4 w-4 mr-2" />
            Security Insights
          </h3>
          <p className="text-sm text-muted-foreground">
            Metadata can reveal privacy-sensitive information like exact location, device used, software version, and creation details. This tool helps identify such risks.
          </p>
        </Card>
      </div>

      <Card className="max-w-4xl mx-auto p-6 border-primary/20 bg-background/80 backdrop-blur-sm relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        
        <div className="mb-4 space-y-2">
          <div className="flex items-center space-x-2 text-sm text-muted-foreground">
            <FileUp className="h-4 w-4 text-primary" />
            <span>Upload a file to extract its metadata</span>
          </div>
        </div>
        
        {/* Replace with actual component when available */}
        <div className="py-12 text-center">
          <p className="text-primary text-xl font-tech">Coming Soon</p>
          <p className="text-muted-foreground mt-2">Metadata extraction module is under development.</p>
        </div>
      </Card>
      
      <div className="mt-8 max-w-4xl mx-auto space-y-4 text-sm">
        <h3 className="text-primary font-tech font-medium">About Metadata Extraction</h3>
        <p className="text-muted-foreground">
          Digital files contain hidden information (metadata) that isn't visible when viewing the file normally. 
          This metadata can include GPS coordinates of where photos were taken, device information, software used, 
          creation dates, edit history, and more. This information can potentially reveal sensitive details about you 
          or your organization, creating privacy risks.
        </p>
        
        <p className="text-muted-foreground">
          Our metadata extractor tool allows you to examine this hidden information before sharing files, helping 
          you identify potential privacy risks. It's especially important when sharing images online, as many 
          people don't realize their photos may contain exact location information.
        </p>
      </div>
    </div>
  );
};

export default MetadataExtractorPage;