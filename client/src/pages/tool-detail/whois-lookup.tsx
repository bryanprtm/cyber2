import React from 'react';
import { Helmet } from 'react-helmet';
import BasicWhoisLookup from '@/components/tools/basic-whois';
import { Card } from '@/components/ui/card';
import { Globe, Search, Shield } from 'lucide-react';

const WhoisLookupPage: React.FC = () => {
  return (
    <div className="container mx-auto px-4 py-8 relative">
      <Helmet>
        <title>WHOIS Lookup | CyberPulse Security Toolkit</title>
        <meta name="description" content="Look up comprehensive domain registration information including registrar, creation date, expiry date, and contact details." />
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
          <Globe className="h-8 w-8 text-primary" />
        </div>
        <h1 className="text-3xl font-bold font-tech text-primary mb-2">WHOIS Domain Lookup</h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Discover who owns a domain, when it was registered, and when it expires. 
          Our WHOIS lookup tool provides comprehensive registration data for any domain.
        </p>
      </div>
      
      <Card className="max-w-4xl mx-auto p-6 border-primary/20 bg-background/80 backdrop-blur-sm relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        
        <div className="mb-4 space-y-2">
          <div className="flex items-center space-x-2 text-sm text-muted-foreground">
            <Search className="h-4 w-4 text-primary" />
            <span>Enter a domain name to retrieve its WHOIS information</span>
          </div>
        </div>
        
        <BasicWhoisLookup />
      </Card>
      
      <div className="mt-8 max-w-4xl mx-auto space-y-4 text-sm">
        <h3 className="text-primary font-tech font-medium">About WHOIS Lookup</h3>
        <p className="text-muted-foreground">
          WHOIS (pronounced as "who is") is a query and response protocol that is widely used for querying 
          databases that store the registered users or assignees of an Internet resource, such as a domain name, 
          an IP address block, or an autonomous system. This tool helps you find information about domain names, 
          including the registrar, registration date, and contact information.
        </p>
        
        <p className="text-muted-foreground">
          Please note that some domain registrars may implement privacy protection services that hide the 
          actual owner's details from public WHOIS queries. In such cases, you might see the registrar's 
          information or a privacy service instead of the actual owner's details.
        </p>
      </div>
    </div>
  );
};

export default WhoisLookupPage;