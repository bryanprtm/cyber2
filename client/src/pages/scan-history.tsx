import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Loader2, Eye, RefreshCw } from "lucide-react";
import { MatrixBackground } from '@/components/matrix-background';
import { formatDate } from '@/lib/utils';
import StatusBar from '@/components/status-bar';

// Mocked user ID until we implement authentication
const MOCK_USER_ID = 1;

interface ScanHistoryItem {
  id: number;
  target: string;
  toolId: string;
  scanTime: string;
  status: string;
  duration: string;
  openPortsCount: number;
}

interface ApiResponse {
  success: boolean;
  count: number;
  results: ScanHistoryItem[];
}

export default function ScanHistory() {
  const [selectedScan, setSelectedScan] = useState<number | null>(null);
  
  // For demo purposes, we're showing mock data since there might not be real scans yet
  const mockData: ScanHistoryItem[] = [
    {
      id: 1,
      target: '192.168.1.1',
      toolId: 'port-scanner',
      scanTime: new Date().toISOString(),
      status: 'completed',
      duration: '3.24s',
      openPortsCount: 3
    },
    {
      id: 2,
      target: 'localhost',
      toolId: 'port-scanner',
      scanTime: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
      status: 'completed',
      duration: '2.15s',
      openPortsCount: 5
    },
    {
      id: 3,
      target: '10.0.0.1',
      toolId: 'port-scanner',
      scanTime: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
      status: 'completed',
      duration: '5.78s',
      openPortsCount: 1
    }
  ];
  
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['/api/scan/history', MOCK_USER_ID],
    // We'll replace this with real API calls once we have scan data in the database
    queryFn: async () => {
      return {
        success: true,
        count: mockData.length,
        results: mockData
      } as ApiResponse;
    }
  });
  
  const scanResults = data?.results || [];
  
  const handleViewDetails = (scanId: number) => {
    setSelectedScan(scanId);
    // In a real implementation, we would navigate to a details page
    // or open a modal with the scan details
    console.log(`View details for scan ${scanId}`);
  };
  
  const getToolDisplayName = (toolId: string) => {
    const toolNames: Record<string, string> = {
      'port-scanner': 'Port Scanner',
      'sql-injection': 'SQL Injection Tester',
      'xss-detector': 'XSS Detector',
      // Add more mappings as needed
    };
    
    return toolNames[toolId] || toolId;
  };
  
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-black text-green-500">
        <MatrixBackground className="opacity-20" />
        <div className="text-red-500 font-mono mb-4">
          <h2 className="text-xl">Error Loading Scan History</h2>
          <p className="mt-2">
            {(error as Error).message || 'An unexpected error occurred'}
          </p>
        </div>
        <Button 
          variant="outline" 
          onClick={() => refetch()} 
          className="border-green-500 text-green-500 hover:bg-green-900/20"
        >
          <RefreshCw className="mr-2 h-4 w-4" /> Retry
        </Button>
      </div>
    );
  }
  
  return (
    <div className="flex flex-col min-h-screen p-4 bg-black text-green-500 relative">
      <MatrixBackground className="opacity-20" />
      
      <div className="container mx-auto p-4 z-10">
        <h1 className="text-3xl font-bold mb-6 font-mono glitch-text">Scan History</h1>
        
        <div className="bg-black/70 border border-green-500/50 rounded-lg overflow-hidden mb-6">
          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <Loader2 className="h-8 w-8 animate-spin mr-2" />
              <span className="font-mono">Accessing secured records...</span>
            </div>
          ) : scanResults.length === 0 ? (
            <div className="p-12 text-center font-mono">
              <p>No scan history found.</p>
              <p className="mt-2 text-green-400/70">
                Complete a scan to see results here.
              </p>
            </div>
          ) : (
            <Table>
              <TableCaption className="font-mono text-green-400/70">
                Security scan history logs
              </TableCaption>
              <TableHeader>
                <TableRow className="border-green-500/30 hover:bg-green-900/20">
                  <TableHead className="font-mono text-green-400">ID</TableHead>
                  <TableHead className="font-mono text-green-400">Target</TableHead>
                  <TableHead className="font-mono text-green-400">Tool</TableHead>
                  <TableHead className="font-mono text-green-400">Date</TableHead>
                  <TableHead className="font-mono text-green-400">Status</TableHead>
                  <TableHead className="font-mono text-green-400">Results</TableHead>
                  <TableHead className="font-mono text-green-400">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scanResults.map((scan: ScanHistoryItem) => (
                  <TableRow 
                    key={scan.id} 
                    className="border-green-500/30 hover:bg-green-900/20 font-mono"
                  >
                    <TableCell className="font-mono">{scan.id}</TableCell>
                    <TableCell className="font-mono">{scan.target}</TableCell>
                    <TableCell className="font-mono">{getToolDisplayName(scan.toolId)}</TableCell>
                    <TableCell className="font-mono">{formatDate(new Date(scan.scanTime))}</TableCell>
                    <TableCell>
                      <Badge 
                        variant="default"
                        className={
                          scan.status === 'completed' 
                            ? "bg-green-500/20 text-green-400 border-green-500" 
                            : "bg-yellow-500/20 text-yellow-400 border-yellow-500"
                        }
                      >
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">
                      {scan.toolId === 'port-scanner' 
                        ? `${scan.openPortsCount} open ports` 
                        : 'View details'}
                    </TableCell>
                    <TableCell>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        className="font-mono text-green-400 hover:text-green-300 hover:bg-green-900/30"
                        onClick={() => handleViewDetails(scan.id)}
                      >
                        <Eye className="h-4 w-4 mr-1" /> View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
        
        <div className="flex justify-end mt-4">
          <Button 
            onClick={() => refetch()} 
            variant="outline" 
            className="border-green-500 text-green-500 hover:bg-green-900/20 font-mono"
          >
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh Logs
          </Button>
        </div>
      </div>
      
      <StatusBar className="mt-auto" />
    </div>
  );
}