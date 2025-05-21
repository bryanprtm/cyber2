import React, { useState, useEffect } from 'react';
import { useTerminal } from '@/hooks/use-terminal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Copy, RefreshCw, ShieldCheck, Eye, EyeOff } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface PasswordGeneratorProps {
  onPasswordGenerated?: (result: any) => void;
}

export default function PasswordGenerator({ onPasswordGenerated }: PasswordGeneratorProps) {
  const [password, setPassword] = useState<string>('');
  const [passwordLength, setPasswordLength] = useState<number>(16);
  const [includeUppercase, setIncludeUppercase] = useState<boolean>(true);
  const [includeLowercase, setIncludeLowercase] = useState<boolean>(true);
  const [includeNumbers, setIncludeNumbers] = useState<boolean>(true);
  const [includeSymbols, setIncludeSymbols] = useState<boolean>(true);
  const [excludeSimilar, setExcludeSimilar] = useState<boolean>(true);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [passwordStrength, setPasswordStrength] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState<boolean>(false);
  
  const { addSystemLine, addInfoLine, addErrorLine, addCommandLine, addLine } = useTerminal();
  const { toast } = useToast();
  
  // Password strength calculation
  useEffect(() => {
    if (!password) {
      setPasswordStrength(0);
      return;
    }
    
    let strength = 0;
    
    // Length contribution (up to 40%)
    strength += Math.min(40, (password.length / 20) * 40);
    
    // Character variety contribution (up to 60%)
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^A-Za-z0-9]/.test(password)) strength += 15;
    
    setPasswordStrength(Math.min(100, strength));
  }, [password]);
  
  // Generate password
  const generatePassword = () => {
    if (!includeLowercase && !includeUppercase && !includeNumbers && !includeSymbols) {
      setError('At least one character type must be selected');
      addErrorLine('At least one character type must be selected');
      return;
    }
    
    setIsGenerating(true);
    setError(null);
    
    try {
      const chars: string[] = [];
      
      // Build character sets
      if (includeUppercase) chars.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
      if (includeLowercase) chars.push('abcdefghijkmnopqrstuvwxyz');
      if (includeNumbers) chars.push('23456789');
      if (includeSymbols) chars.push('!@#$%^&*()_+-=[]{}|;:,.<>?');
      
      // Remove similar looking characters if option is selected
      let charSet = chars.join('');
      if (excludeSimilar) {
        charSet = charSet.replace(/[Il1O0]/g, '');
      }
      
      if (charSet.length === 0) {
        throw new Error('No valid characters available with current settings');
      }
      
      // Generate password using the crypto API for better randomness
      const randomValues = new Uint32Array(passwordLength);
      crypto.getRandomValues(randomValues);
      
      let generatedPassword = '';
      for (let i = 0; i < passwordLength; i++) {
        generatedPassword += charSet[randomValues[i] % charSet.length];
      }
      
      setPassword(generatedPassword);
      
      const command = `password-generate --length ${passwordLength} --upper ${includeUppercase} --lower ${includeLowercase} --numbers ${includeNumbers} --symbols ${includeSymbols}`;
      addCommandLine(command);
      addLine(`[SUCCESS] Generated secure password of length ${passwordLength}`, "success");
      
      if (onPasswordGenerated) {
        onPasswordGenerated({
          password: generatedPassword,
          length: passwordLength,
          strength: passwordStrength,
          settings: {
            uppercase: includeUppercase,
            lowercase: includeLowercase,
            numbers: includeNumbers,
            symbols: includeSymbols,
            excludeSimilar: excludeSimilar
          },
          timestamp: new Date()
        });
      }
    } catch (err) {
      console.error('Password generation error:', err);
      setError(`Failed to generate password: ${(err as Error).message}`);
      addErrorLine(`Failed to generate password: ${(err as Error).message}`);
    } finally {
      setIsGenerating(false);
    }
  };
  
  const getPasswordStrengthColor = () => {
    if (passwordStrength >= 80) return 'bg-green-500';
    if (passwordStrength >= 60) return 'bg-blue-500';
    if (passwordStrength >= 40) return 'bg-yellow-500';
    if (passwordStrength >= 20) return 'bg-orange-500';
    return 'bg-red-500';
  };
  
  const getPasswordStrengthText = () => {
    if (passwordStrength >= 80) return 'Very Strong';
    if (passwordStrength >= 60) return 'Strong';
    if (passwordStrength >= 40) return 'Moderate';
    if (passwordStrength >= 20) return 'Weak';
    return 'Very Weak';
  };
  
  const handleCopyPassword = () => {
    if (!password) return;
    
    navigator.clipboard.writeText(password)
      .then(() => {
        toast({
          title: "Password copied",
          description: "Password has been copied to clipboard",
          variant: "default",
        });
        addInfoLine("Password copied to clipboard");
      })
      .catch(err => {
        toast({
          title: "Copy failed",
          description: `Failed to copy password: ${err.message}`,
          variant: "destructive"
        });
      });
  };
  
  const handleReset = () => {
    setPassword('');
    setPasswordLength(16);
    setIncludeUppercase(true);
    setIncludeLowercase(true);
    setIncludeNumbers(true);
    setIncludeSymbols(true);
    setExcludeSimilar(true);
    setError(null);
    addInfoLine("Password generator reset");
  };
  
  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">Password Generator</h2>
        
        <div className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <Label htmlFor="password-length" className="text-sm font-tech">
                Password Length: {passwordLength}
              </Label>
              <span className="text-xs font-mono text-secondary">
                (8-32 characters)
              </span>
            </div>
            <Slider
              id="password-length"
              min={8}
              max={32}
              step={1}
              value={[passwordLength]}
              onValueChange={(value) => setPasswordLength(value[0])}
              className="my-4"
            />
          </div>
          
          <div className="space-y-3">
            <h3 className="text-sm font-tech">Character Types</h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="flex items-center justify-between space-x-2 bg-background/50 p-2 rounded-md">
                <Label htmlFor="include-uppercase" className="text-sm cursor-pointer font-mono">
                  Uppercase (A-Z)
                </Label>
                <Switch
                  id="include-uppercase"
                  checked={includeUppercase}
                  onCheckedChange={setIncludeUppercase}
                />
              </div>
              
              <div className="flex items-center justify-between space-x-2 bg-background/50 p-2 rounded-md">
                <Label htmlFor="include-lowercase" className="text-sm cursor-pointer font-mono">
                  Lowercase (a-z)
                </Label>
                <Switch
                  id="include-lowercase"
                  checked={includeLowercase}
                  onCheckedChange={setIncludeLowercase}
                />
              </div>
              
              <div className="flex items-center justify-between space-x-2 bg-background/50 p-2 rounded-md">
                <Label htmlFor="include-numbers" className="text-sm cursor-pointer font-mono">
                  Numbers (0-9)
                </Label>
                <Switch
                  id="include-numbers"
                  checked={includeNumbers}
                  onCheckedChange={setIncludeNumbers}
                />
              </div>
              
              <div className="flex items-center justify-between space-x-2 bg-background/50 p-2 rounded-md">
                <Label htmlFor="include-symbols" className="text-sm cursor-pointer font-mono">
                  Symbols (!@#$%...)
                </Label>
                <Switch
                  id="include-symbols"
                  checked={includeSymbols}
                  onCheckedChange={setIncludeSymbols}
                />
              </div>
            </div>
            
            <div className="flex items-center justify-between space-x-2 bg-background/50 p-2 rounded-md mt-2">
              <Label htmlFor="exclude-similar" className="text-sm cursor-pointer font-mono flex items-center">
                <ShieldCheck className="h-3.5 w-3.5 mr-2 text-primary" />
                Exclude similar characters (1, l, I, 0, O)
              </Label>
              <Switch
                id="exclude-similar"
                checked={excludeSimilar}
                onCheckedChange={setExcludeSimilar}
              />
            </div>
          </div>
          
          {error && (
            <div className="bg-destructive/10 p-3 rounded-md border border-destructive/50 text-destructive flex items-start gap-2 text-sm font-mono">
              <span>{error}</span>
            </div>
          )}
          
          <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
            <Button
              onClick={generatePassword}
              disabled={isGenerating}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
            >
              {isGenerating ? 'Generating...' : 'Generate Password'}
            </Button>
            
            <Button
              onClick={handleReset}
              variant="outline"
              disabled={isGenerating}
              className="border-secondary/50 text-secondary font-tech"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </div>
      </Card>
      
      {password && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-lg font-tech text-secondary">Generated Password</h3>
            <div className="text-xs font-mono flex items-center">
              <span className={cn(
                passwordStrength >= 80 ? "text-green-500" : 
                passwordStrength >= 60 ? "text-blue-500" : 
                passwordStrength >= 40 ? "text-yellow-500" : 
                passwordStrength >= 20 ? "text-orange-500" : 
                "text-red-500"
              )}>
                {getPasswordStrengthText()}
              </span>
            </div>
          </div>
          
          <div className="relative">
            <div className="bg-background p-3 rounded-md border border-secondary/30 font-mono text-base break-all">
              {showPassword ? password : password.replace(/./g, '•')}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-2 top-1/2 transform -translate-y-1/2 h-8 w-8 p-0"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
          
          <div className="mt-3">
            <div className="w-full bg-background/50 rounded-full h-2.5 mb-1">
              <div 
                className={`h-2.5 rounded-full ${getPasswordStrengthColor()}`} 
                style={{ width: `${passwordStrength}%` }}
              ></div>
            </div>
            <div className="flex justify-between text-xs font-mono text-muted-foreground">
              <span>Weak</span>
              <span>Strong</span>
            </div>
          </div>
          
          <div className="flex justify-end mt-4 space-x-2">
            <Button
              variant="outline"
              size="sm"
              className="text-primary border-primary/50 font-tech text-xs"
              onClick={handleCopyPassword}
            >
              <Copy className="h-3 w-3 mr-1" />
              Copy Password
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}