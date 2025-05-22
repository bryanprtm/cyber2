import { useState } from "react";
import axios from "axios";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { useTerminal } from "@/hooks/use-terminal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Checkbox } from "@/components/ui/checkbox";
import { 
  CheckCircle2, 
  RefreshCw, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX, 
  AlertCircle, 
  AlertTriangle, 
  Clock
} from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/hooks/use-translation";

const formSchema = z.object({
  password: z.string().min(1, "Password is required"),
  checkLeaked: z.boolean().default(false)
});

interface PasswordCheckerProps {
  onPasswordChecked?: (result: any) => void;
}

export default function PasswordChecker({ onPasswordChecked }: PasswordCheckerProps) {
  const [isChecking, setIsChecking] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const { addCommandLine, addResultLine, addErrorLine, addSuccessLine } = useTerminal();
  const { t } = useTranslation();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      password: "",
      checkLeaked: false
    }
  });

  const handleCheck = async (values: z.infer<typeof formSchema>) => {
    // Reset states
    setIsChecking(true);
    setError(null);
    
    // Add to terminal
    addCommandLine("Analyzing password security...");
    
    try {
      const response = await axios.post("/api/security/password-checker", {
        password: values.password,
        checkLeaked: values.checkLeaked
      });
      
      if (response.data.success) {
        const passwordResult = response.data.data;
        setResult(passwordResult);
        
        // Send score level to terminal
        const scoreLabels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"];
        const score = passwordResult.strength.score;
        
        addSuccessLine("Password analysis completed");
        addResultLine(`Password strength: ${scoreLabels[score]} (${score}/4)`);
        
        if (passwordResult.issues.length > 0) {
          addResultLine("Issues found:");
          passwordResult.issues.forEach((issue: string) => {
            addResultLine(`• ${issue}`);
          });
        }
        
        if (onPasswordChecked) {
          onPasswordChecked(passwordResult);
        }
      } else {
        setError(response.data.message || "Failed to check password");
        addErrorLine(`Error: ${response.data.message}`);
      }
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || "An error occurred";
      setError(errorMessage);
      addErrorLine(`Error: ${errorMessage}`);
    } finally {
      setIsChecking(false);
    }
  };

  const handleReset = () => {
    form.reset();
    setResult(null);
    setError(null);
    addCommandLine("Reset password checker");
  };

  // Helper function to get score color
  const getScoreColor = (score: number) => {
    if (score === 0) return "bg-destructive";
    if (score === 1) return "bg-red-500";
    if (score === 2) return "bg-amber-500";
    if (score === 3) return "bg-green-500";
    return "bg-emerald-500";
  };

  // Helper function to get score icon
  const getScoreIcon = (score: number) => {
    if (score <= 1) return <ShieldX className="h-5 w-5 text-destructive" />;
    if (score === 2) return <ShieldAlert className="h-5 w-5 text-amber-500" />;
    if (score === 3) return <Shield className="h-5 w-5 text-green-500" />;
    return <ShieldCheck className="h-5 w-5 text-emerald-500" />; 
  };

  return (
    <div className="space-y-6">
      <Card className="p-4 border-primary/30 bg-card">
        <h2 className="text-xl font-tech text-primary mb-4">{t('Password Checker')}</h2>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(handleCheck)} className="space-y-4">
            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-tech">{t('Enter Password')}</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="Enter password to check..."
                      className="font-mono bg-background border-secondary/50"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            
            <FormField
              control={form.control}
              name="checkLeaked"
              render={({ field }) => (
                <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border border-secondary/30 p-3">
                  <FormControl>
                    <Checkbox
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <FormLabel className="text-sm font-tech">
                      {t('Check for breached passwords')}
                    </FormLabel>
                    <p className="text-xs text-muted-foreground">
                      {t('Warning: This will send a hash of your password to check against known data breaches')}
                    </p>
                  </div>
                </FormItem>
              )}
            />
            
            {error && (
              <Alert variant="destructive" className="text-sm font-mono">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            
            <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
              <Button
                type="submit"
                disabled={isChecking || form.formState.isSubmitting}
                className="bg-primary text-primary-foreground hover:bg-primary/90 font-tech"
              >
                {isChecking ? t('Analyzing...') : t('Check Password')}
              </Button>
              
              <Button
                type="button"
                onClick={handleReset}
                variant="outline"
                disabled={isChecking}
                className="border-secondary/50 text-secondary font-tech"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                {t('Reset')}
              </Button>
            </div>
          </form>
        </Form>
      </Card>
      
      {result && (
        <Card className="p-4 border-secondary/30 bg-card">
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-tech text-secondary mb-2">{t('Password Analysis')}</h3>
              <div className="flex items-center space-x-2 mb-4">
                <Progress
                  value={(result.strength.score + 1) * 20}
                  className="h-2"
                  indicatorClassName={cn(getScoreColor(result.strength.score))}
                />
                <span className="font-mono text-sm">
                  {result.strength.score}/4
                </span>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-background p-3 rounded-md border border-secondary/30 space-y-2">
                  <h4 className="text-sm font-tech flex items-center gap-1">
                    {getScoreIcon(result.strength.score)}
                    <span>
                      {result.strength.score <= 1 && t('Very Weak')}
                      {result.strength.score === 2 && t('Moderate')} 
                      {result.strength.score === 3 && t('Strong')}
                      {result.strength.score >= 4 && t('Very Strong')}
                    </span>
                  </h4>
                  
                  <div className="space-y-1 font-mono text-xs">
                    {result.issues.length > 0 ? (
                      <ul className="space-y-1 text-destructive">
                        {result.issues.map((issue: string, i: number) => (
                          <li key={i} className="flex items-start gap-1">
                            <AlertTriangle className="h-3 w-3 mt-0.5 flex-shrink-0" />
                            <span>{issue}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-green-500 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        <span>{t('No major issues detected')}</span>
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="bg-background p-3 rounded-md border border-secondary/30 space-y-2">
                  <h4 className="text-sm font-tech flex items-center gap-1">
                    <Clock className="h-4 w-4 text-secondary" />
                    <span>{t('Estimated Crack Time')}</span>
                  </h4>
                  
                  <div className="space-y-1 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span>{t('Fast attack')}:</span>
                      <span className={result.strength.score <= 1 ? "text-destructive" : "text-green-500"}>
                        {result.strength.crackTimeDisplay.offline_fast_hashing_1e10_per_second}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>{t('Slow attack')}:</span>
                      <span className="text-green-500">
                        {result.strength.crackTimeDisplay.offline_slow_hashing_1e4_per_second}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>{t('Online attack')}:</span>
                      <span className="text-green-500">
                        {result.strength.crackTimeDisplay.online_throttling_100_per_hour}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="text-md font-tech text-secondary mb-2">{t('Improvements')}</h3>
              <ul className="font-mono text-xs space-y-1">
                {result.improvements.map((improvement: string, i: number) => (
                  <li key={i} className="flex items-start gap-1 text-green-500">
                    <CheckCircle2 className="h-3 w-3 mt-0.5 flex-shrink-0" />
                    <span>{improvement}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            {result.commonPassword && (
              <Alert variant="destructive" className="text-sm font-mono">
                <ShieldAlert className="h-4 w-4" />
                <AlertTitle>{t('Critical Warning')}</AlertTitle>
                <AlertDescription>
                  {t('This is a commonly used password! It is likely to be included in password dictionaries used by attackers.')}
                </AlertDescription>
              </Alert>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}