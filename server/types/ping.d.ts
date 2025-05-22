declare module 'ping' {
  export interface PingConfig {
    numeric?: boolean;
    timeout?: number;
    min_reply?: number;
    extra?: string[];
    packetSize?: number;
  }

  export interface PingResponse {
    host: string;
    alive: boolean;
    output: string;
    time: string;
    min?: string;
    max?: string;
    avg?: string;
    stddev?: string;
    packetLoss?: string;
  }

  export namespace promise {
    function probe(target: string, config?: PingConfig): Promise<PingResponse>;
  }

  export namespace sys {
    function probe(target: string, callback: (isAlive: boolean, error: any) => void): void;
  }
}