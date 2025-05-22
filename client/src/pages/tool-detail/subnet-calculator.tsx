import React from 'react';
import SubnetCalculator from '@/components/tools/subnet-calculator';
import { Card } from '@/components/ui/card';

export default function SubnetCalculatorPage() {
  return (
    <div className="container mx-auto py-6 px-4">
      <div className="space-y-6">
        <Card className="p-4 border-primary/30 bg-card">
          <h1 className="text-2xl font-tech text-primary mb-2">Subnet Calculator</h1>
          <p className="text-muted-foreground">
            Calculate subnet information including network address, broadcast address, subnet mask, and IP ranges. This tool helps network administrators plan and manage IP addressing schemes for their networks.
          </p>
        </Card>
        
        <SubnetCalculator />
      </div>
    </div>
  );
}