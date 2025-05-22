import React from 'react';
import DnsLookup from '@/components/tools/dns-lookup';
import { Card } from '@/components/ui/card';

export default function DnsLookupPage() {
  return (
    <div className="container mx-auto py-6 px-4">
      <div className="space-y-6">
        <Card className="p-4 border-primary/30 bg-card">
          <h1 className="text-2xl font-tech text-primary mb-2">DNS Lookup Tool</h1>
          <p className="text-muted-foreground">
            Query DNS records for domain names to retrieve information about hosts, mail servers, IP addresses, and more. This tool supports multiple record types including A, AAAA, MX, CNAME, TXT, and others.
          </p>
        </Card>
        
        <DnsLookup />
      </div>
    </div>
  );
}