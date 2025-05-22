import React from 'react';
import Traceroute from '@/components/tools/traceroute';
import { Card } from '@/components/ui/card';

export default function TraceroutePage() {
  return (
    <div className="container mx-auto py-6 px-4">
      <div className="space-y-6">
        <Card className="p-4 border-primary/30 bg-card">
          <h1 className="text-2xl font-tech text-primary mb-2">Traceroute Tool</h1>
          <p className="text-muted-foreground">
            Trace the network path to a destination host by showing each hop along the route. This tool helps identify network bottlenecks, routing issues, and visualize the path your data takes across the internet.
          </p>
        </Card>
        
        <Traceroute />
      </div>
    </div>
  );
}