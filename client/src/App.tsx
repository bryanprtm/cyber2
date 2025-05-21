import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Home from "@/pages/home";
import Tools from "@/pages/tools";
import About from "@/pages/about";
import Docs from "@/pages/docs";
import PortScannerPage from "@/pages/tool-detail/port-scanner";
import HashGeneratorPage from "@/pages/tool-detail/hash-generator";
import PasswordGeneratorPage from "@/pages/tool-detail/password-generator";
import SqlInjectorPage from "@/pages/tool-detail/sql-injector";
import ZapScannerPage from "@/pages/tool-detail/zap-scanner";
import XssDetectorPage from "@/pages/tool-detail/xss-detector";
import DirectoryScannerPage from "@/pages/tool-detail/directory-scanner";
import SslScannerPage from "@/pages/tool-detail/ssl-scanner";
import CsrfTesterPage from "@/pages/tool-detail/csrf-tester";
import ScanHistory from "@/pages/scan-history";
import Header from "@/components/layout/header";
import Footer from "@/components/layout/footer";

function Router() {
  return (
    <div className="flex flex-col min-h-screen bg-background">
      <Header />
      <main className="flex-grow">
        <Switch>
          <Route path="/" component={Home} />
          <Route path="/tools" component={Tools} />
          <Route path="/docs" component={Docs} />
          <Route path="/about" component={About} />
          <Route path="/tools/port-scanner" component={PortScannerPage} />
          <Route path="/tools/hash-generator" component={HashGeneratorPage} />
          <Route path="/tools/password-generator" component={PasswordGeneratorPage} />
          <Route path="/tools/sql-injector" component={SqlInjectorPage} />
          <Route path="/tools/zap-scanner" component={ZapScannerPage} />
          <Route path="/tools/xss-detector" component={XssDetectorPage} />
          <Route path="/tools/directory-scanner" component={DirectoryScannerPage} />
          <Route path="/tools/ssl-scanner" component={SslScannerPage} />
          <Route path="/tools/csrf-tester" component={CsrfTesterPage} />
          <Route path="/scan-history" component={ScanHistory} />
          <Route component={NotFound} />
        </Switch>
      </main>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
