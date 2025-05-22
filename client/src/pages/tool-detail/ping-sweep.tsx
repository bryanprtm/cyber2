import React from 'react';
import PingSweep from '@/components/tools/ping-sweep';
import { Card } from '@/components/ui/card';

export default function PingSweepPage() {
  return (
    <div className="container mx-auto py-6 px-4">
      <div className="space-y-6">
        <Card className="p-4 border-primary/30 bg-card">
          <h1 className="text-2xl font-tech text-primary mb-2">Ping Sweep Tool</h1>
          <p className="text-muted-foreground">
            Discover live hosts on a network using ICMP requests. This tool allows you to scan a single host or a range of IP addresses to determine which hosts are online.
          </p>
        </Card>
        
        <PingSweep />
      </div>
    </div>
  );
}