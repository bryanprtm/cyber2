import { useState, useEffect, useCallback, useRef } from 'react';

export interface WebSocketMessage {
  type: string;
  data: any;
}

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  // Connect to the WebSocket server
  const connect = useCallback(() => {
    // Close existing socket if any
    if (socketRef.current) {
      socketRef.current.close();
    }

    // Clear any pending reconnection
    if (reconnectTimeoutRef.current) {
      window.clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    try {
      // Determine the WebSocket URL based on the current location
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/tools`;

      // Create a new WebSocket connection
      const socket = new WebSocket(wsUrl);
      socketRef.current = socket;

      // Set up event handlers
      socket.onopen = () => {
        console.log('WebSocket connection established');
        setIsConnected(true);
      };

      socket.onclose = (event) => {
        console.log(`WebSocket connection closed: ${event.code} - ${event.reason}`);
        setIsConnected(false);

        // Attempt to reconnect after a delay
        reconnectTimeoutRef.current = window.setTimeout(() => {
          console.log('Attempting to reconnect to WebSocket...');
          connect();
        }, 3000);
      };

      socket.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
    }
  }, []);

  // Send a message to the WebSocket server
  const sendMessage = useCallback((type: string, data: any): boolean => {
    if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
      console.error('Cannot send message: WebSocket is not connected');
      return false;
    }

    try {
      const message: WebSocketMessage = { type, data };
      socketRef.current.send(JSON.stringify(message));
      return true;
    } catch (error) {
      console.error('Error sending WebSocket message:', error);
      return false;
    }
  }, []);

  // Connect when the component mounts
  useEffect(() => {
    connect();

    // Clean up when the component unmounts
    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }

      if (reconnectTimeoutRef.current) {
        window.clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect]);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    connect,
  };
}