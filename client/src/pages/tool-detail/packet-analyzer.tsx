import React from 'react';
import PacketAnalyzer from '@/components/tools/packet-analyzer';
import { Card } from '@/components/ui/card';

export default function PacketAnalyzerPage() {
  return (
    <div className="container mx-auto py-6 px-4">
      <div className="space-y-6">
        <Card className="p-4 border-primary/30 bg-card">
          <h1 className="text-2xl font-tech text-primary mb-2">Packet Analyzer</h1>
          <p className="text-muted-foreground">
            Capture and analyze network packets to understand network traffic patterns, troubleshoot connectivity issues, and inspect protocol-specific information. This tool provides detailed insights into your network's data flow.
          </p>
        </Card>
        
        <PacketAnalyzer />
      </div>
    </div>
  );
}