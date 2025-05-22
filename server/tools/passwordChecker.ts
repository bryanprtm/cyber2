export interface PasswordCheckerOptions {
  password: string;
  checkLeaked?: boolean;
}

export interface PasswordStrengthResult {
  score: number; // 0-4 (very weak to very strong)
  feedback: {
    warning?: string;
    suggestions: string[];
  };
  crackTimeSeconds: {
    offline_slow_hashing_1e4_per_second: number;
    offline_fast_hashing_1e10_per_second: number;
    online_no_throttling_10_per_second: number;
    online_throttling_100_per_hour: number;
  };
  crackTimeDisplay: {
    offline_slow_hashing_1e4_per_second: string;
    offline_fast_hashing_1e10_per_second: string;
    online_no_throttling_10_per_second: string;
    online_throttling_100_per_hour: string;
  };
  guessesLog10: number;
}

export interface PasswordCheckResult {
  password: string; // We should mask this in responses
  strength: PasswordStrengthResult;
  breached: boolean; // Whether the password has been found in data breaches
  commonPassword: boolean; // Whether it's a commonly used password
  hasRepeatingPatterns: boolean;
  hasSequentialPatterns: boolean;
  containsPersonalInfo: boolean;
  issues: string[];
  improvements: string[];
}

/**
 * Check password strength and security issues
 * @param options Password checker options
 * @returns Password check results
 */
export async function checkPassword(options: PasswordCheckerOptions): Promise<PasswordCheckResult> {
  const { password, checkLeaked = false } = options;
  
  // Start timing
  const startTime = Date.now();
  
  // Basic length check
  const length = password.length;
  
  // Check for character diversity
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  
  // Check for sequential patterns
  const hasSequentialChars = 
    /01234|12345|23456|34567|45678|56789|6789|abcde|bcdef|cdefg|defgh|efghi|fghij|ghijk|hijkl|ijklm|jklmn|klmno|lmnop|mnopq|nopqr|opqrs|pqrst|qrstu|rstuv|stuvw|tuvwx|uvwxy|vwxyz/i.test(password);
  
  // Check for repeating patterns
  const hasRepeatingChars = /(.)\1{2,}/i.test(password);
  
  // Check against common passwords (abbreviated list)
  const commonPasswords = [
    "password", "123456", "12345678", "qwerty", "admin", 
    "welcome", "1234567", "12345", "1234567890", "abc123"
  ];
  const isCommonPassword = commonPasswords.includes(password.toLowerCase());
  
  // Generate calculated stats
  // These figures are approximations for demo purposes
  const entropyBits = calculateEntropyBits(password);
  const guessesLog10 = calculateGuessesLog10(entropyBits);
  
  // Calculate crack times
  const offline_slow_hashing_1e4_per_second = Math.pow(10, guessesLog10) / 1e4;
  const offline_fast_hashing_1e10_per_second = Math.pow(10, guessesLog10) / 1e10;
  const online_no_throttling_10_per_second = Math.pow(10, guessesLog10) / 10;
  const online_throttling_100_per_hour = Math.pow(10, guessesLog10) / (100/3600);
  
  // Calculate score from 0-4
  let score = 0;
  if (length >= 8) score += 1;
  if (length >= 12) score += 1;
  if ((hasUppercase && hasLowercase) || hasSpecialChars) score += 1;
  if (hasUppercase && hasLowercase && hasNumbers && hasSpecialChars) score += 1;
  if (isCommonPassword || hasSequentialChars || hasRepeatingChars) score = Math.max(0, score - 2);
  
  // Generate feedback
  const issues: string[] = [];
  const improvements: string[] = [];
  
  if (length < 8) {
    issues.push("Password is too short (minimum 8 characters recommended)");
    improvements.push("Use at least 8 characters, preferably 12 or more");
  }
  
  if (!hasUppercase) {
    issues.push("No uppercase letters");
    improvements.push("Add uppercase letters (A-Z)");
  }
  
  if (!hasLowercase) {
    issues.push("No lowercase letters");
    improvements.push("Add lowercase letters (a-z)");
  }
  
  if (!hasNumbers) {
    issues.push("No numbers");
    improvements.push("Add numbers (0-9)");
  }
  
  if (!hasSpecialChars) {
    issues.push("No special characters");
    improvements.push("Add special characters (e.g., !@#$%^&*)");
  }
  
  if (hasSequentialChars) {
    issues.push("Contains sequential patterns (e.g., '12345', 'abcde')");
    improvements.push("Avoid sequential character patterns");
  }
  
  if (hasRepeatingChars) {
    issues.push("Contains repeating characters (e.g., 'aaa', '111')");
    improvements.push("Avoid repeating the same character");
  }
  
  if (isCommonPassword) {
    issues.push("This is a commonly used password");
    improvements.push("Choose a unique password not found in common password lists");
  }
  
  const warning = issues.length > 0 ? issues[0] : undefined;
  
  // Format crack times
  const formatTime = (seconds: number): string => {
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
    return `${Math.round(seconds / 31536000)} years`;
  };
  
  const strength: PasswordStrengthResult = {
    score,
    feedback: {
      warning,
      suggestions: improvements
    },
    crackTimeSeconds: {
      offline_slow_hashing_1e4_per_second,
      offline_fast_hashing_1e10_per_second,
      online_no_throttling_10_per_second,
      online_throttling_100_per_hour
    },
    crackTimeDisplay: {
      offline_slow_hashing_1e4_per_second: formatTime(offline_slow_hashing_1e4_per_second),
      offline_fast_hashing_1e10_per_second: formatTime(offline_fast_hashing_1e10_per_second),
      online_no_throttling_10_per_second: formatTime(online_no_throttling_10_per_second),
      online_throttling_100_per_hour: formatTime(online_throttling_100_per_hour)
    },
    guessesLog10
  };
  
  return {
    password: maskPassword(password),
    strength,
    breached: false, // In a real implementation, we would check against breach databases
    commonPassword: isCommonPassword,
    hasRepeatingPatterns: hasRepeatingChars,
    hasSequentialPatterns: hasSequentialChars,
    containsPersonalInfo: false, // Would need user data to check
    issues,
    improvements
  };
}

// Helper functions
function calculateEntropyBits(password: string): number {
  // Simplified entropy calculation
  const length = password.length;
  let charsetSize = 0;
  
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/\d/.test(password)) charsetSize += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) charsetSize += 33;
  
  return Math.log2(Math.pow(charsetSize, length));
}

function calculateGuessesLog10(entropyBits: number): number {
  // Convert entropy bits to log10 of guesses
  return entropyBits * Math.log10(2);
}

function maskPassword(password: string): string {
  if (password.length <= 2) return password;
  return password.substring(0, 1) + '*'.repeat(password.length - 2) + password.substring(password.length - 1);
}