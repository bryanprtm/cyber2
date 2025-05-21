import { db } from './db';
import { tools, InsertTool } from '@shared/schema';

// Default cybersecurity tools to seed the database
const defaultTools: InsertTool[] = [
  {
    toolId: 'port-scanner',
    name: 'Port Scanner',
    description: 'Scan for open ports on a target host to identify potential security vulnerabilities and exposed services.',
    category: 'network',
    categoryLabel: 'Network',
    active: true
  },
  {
    toolId: 'sql-injection',
    name: 'SQL Injection Tester',
    description: 'Test web applications for SQL injection vulnerabilities that could allow attackers to access or modify database data.',
    category: 'vulnerability',
    categoryLabel: 'Vulnerability',
    active: true
  },
  {
    toolId: 'xss-detector',
    name: 'XSS Detector',
    description: 'Detect cross-site scripting vulnerabilities in web applications that could allow attackers to inject malicious scripts.',
    category: 'vulnerability',
    categoryLabel: 'Vulnerability',
    active: true
  },
  {
    toolId: 'dns-lookup',
    name: 'DNS Lookup',
    description: 'Query DNS records for a domain to gather information about its infrastructure and configuration.',
    category: 'information',
    categoryLabel: 'Information',
    active: true
  },
  {
    toolId: 'whois-lookup',
    name: 'WHOIS Lookup',
    description: 'Look up domain registration information to identify domain owners, registration dates, and contact information.',
    category: 'information',
    categoryLabel: 'Information',
    active: true
  },
  {
    toolId: 'hash-cracker',
    name: 'Password Hash Cracker',
    description: 'Attempt to recover passwords from their hash values using various cracking techniques.',
    category: 'cryptography',
    categoryLabel: 'Cryptography',
    active: true
  },
  {
    toolId: 'network-sniffer',
    name: 'Network Packet Sniffer',
    description: 'Capture and analyze network traffic to identify potential security issues or data leakage.',
    category: 'network',
    categoryLabel: 'Network',
    active: true
  },
  {
    toolId: 'subdomain-finder',
    name: 'Subdomain Finder',
    description: 'Discover subdomains associated with a target domain to map out the attack surface.',
    category: 'reconnaissance',
    categoryLabel: 'Reconnaissance',
    active: true
  }
];

/**
 * Seeds the database with default tool data if no tools exist
 */
export async function seedDatabase() {
  console.log('Checking if database needs seeding...');
  
  try {
    // Check if tools already exist
    const existingTools = await db.select().from(tools);
    
    if (existingTools.length === 0) {
      console.log('No tools found in database. Seeding with default tools...');
      
      // Insert default tools
      const result = await db.insert(tools).values(defaultTools).returning();
      
      console.log(`Successfully seeded database with ${result.length} tools`);
    } else {
      console.log(`Database already contains ${existingTools.length} tools. Skipping seed operation.`);
    }
  } catch (error) {
    console.error('Error seeding database:', error);
  }
}