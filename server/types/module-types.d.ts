declare module 'whois' {
  export function lookup(domain: string, options: object, callback: (error: Error | null, data: string) => void): void;
}

declare module 'whoisjs' {
  interface Parser {
    parse(data: string): any;
  }
  
  export const parsers: {
    getParser(domain: string): Parser | null;
  };
}

declare module 'wappalyzer-core' {
  interface WappalyzerData {
    url: string;
    html: string;
    headers: Record<string, string>;
    scriptSrc?: string[];
    cookies?: Record<string, string>;
    meta?: Record<string, string>;
  }
  
  export function analyze(data: WappalyzerData): Record<string, any>;
}