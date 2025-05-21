import { useState, useEffect, useCallback, useRef } from 'react';
import { useToast } from './use-toast';

interface WebSocketMessage {
  type: string;
  data: any;
}

export function useWebSocket(path: string = '/ws/tools') {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [messageHistory, setMessageHistory] = useState<WebSocketMessage[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const { toast } = useToast();

  // Get the WebSocket URL based on current window location
  const getWebSocketUrl = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}${path}`;
  }, [path]);

  // Connect to the WebSocket server
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return; // Already connected
    }

    const ws = new WebSocket(getWebSocketUrl());
    
    ws.onopen = () => {
      setIsConnected(true);
      console.log('Connected to WebSocket server');
    };
    
    ws.onclose = () => {
      setIsConnected(false);
      console.log('Disconnected from WebSocket server');
      
      // Try to reconnect after a delay
      setTimeout(() => {
        if (wsRef.current === ws) { // Only reconnect if this is still the current connection
          connect();
        }
      }, 3000);
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      toast({
        title: 'Connection Error',
        description: 'Failed to connect to the tool server',
        variant: 'destructive'
      });
    };
    
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data) as WebSocketMessage;
        setLastMessage(message);
        setMessageHistory(prev => [...prev, message]);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };
    
    wsRef.current = ws;
    
    // Cleanup on unmount
    return () => {
      ws.close();
    };
  }, [getWebSocketUrl, toast]);

  // Send a message through the WebSocket
  const sendMessage = useCallback((type: string, data: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type, data }));
      return true;
    } else {
      console.error('WebSocket is not connected');
      toast({
        title: 'Connection Error',
        description: 'Not connected to the tool server',
        variant: 'destructive'
      });
      return false;
    }
  }, [toast]);

  // Clear message history
  const clearMessages = useCallback(() => {
    setMessageHistory([]);
  }, []);

  // Connect on mount
  useEffect(() => {
    connect();
    
    // Cleanup on unmount
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return {
    isConnected,
    lastMessage,
    messageHistory,
    sendMessage,
    clearMessages
  };
}