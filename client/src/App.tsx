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
import HashCrackerPage from "@/pages/tool-detail/hash-cracker";
import ZapScannerPage from "@/pages/tool-detail/zap-scanner";
import XssDetectorPage from "@/pages/tool-detail/xss-detector";
import DirectoryScannerPage from "@/pages/tool-detail/directory-scanner";
import SslScannerPage from "@/pages/tool-detail/ssl-scanner";
import CsrfTesterPage from "@/pages/tool-detail/csrf-tester";
import PingSweepPage from "@/pages/tool-detail/ping-sweep";
import TraceroutePage from "@/pages/tool-detail/traceroute";
import DnsLookupPage from "@/pages/tool-detail/dns-lookup";
import SubnetCalculatorPage from "@/pages/tool-detail/subnet-calculator";
import PacketAnalyzerPage from "@/pages/tool-detail/packet-analyzer";

import MetadataExtractorPage from "@/pages/tool-detail/metadata-extractor";
import HeaderAnalyzerPage from "@/pages/tool-detail/header-analyzer";
import EmailHunterPage from "@/pages/tool-detail/email-hunter";
import ShellUploaderPage from "@/pages/tool-detail/shell-uploader";
import TechDetectorPage from "@/pages/tool-detail/tech-detector";
import PasswordCheckerPage from "@/pages/tool-detail/password-checker";
import FileScannerPage from "@/pages/tool-detail/file-scanner";
import UrlScannerPage from "@/pages/tool-detail/url-scanner";
import CorsTesterPage from "@/pages/tool-detail/cors-tester";
import LfiScannerPage from "@/pages/tool-detail/lfi-scanner";
import RfiScannerPage from "@/pages/tool-detail/rfi-scanner";
import FormFuzzerPage from "@/pages/tool-detail/form-fuzzer";
import XmlInjectorPage from "@/pages/tool-detail/xml-injector";
import BeefXssPage from "@/pages/tool-detail/beef-xss";
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
          <Route path="/tools/hash-cracker" component={HashCrackerPage} />
          <Route path="/tools/password-generator" component={PasswordGeneratorPage} />
          <Route path="/tools/zap-scanner" component={ZapScannerPage} />
          <Route path="/tools/xss-detector" component={XssDetectorPage} />
          <Route path="/tools/directory-scanner" component={DirectoryScannerPage} />
          <Route path="/tools/ssl-scanner" component={SslScannerPage} />
          <Route path="/tools/csrf-tester" component={CsrfTesterPage} />
          <Route path="/tools/ping-sweep" component={PingSweepPage} />
          <Route path="/tools/traceroute" component={TraceroutePage} />
          <Route path="/tools/dns-lookup" component={DnsLookupPage} />
          <Route path="/tools/subnet-calculator" component={SubnetCalculatorPage} />
          <Route path="/tools/packet-analyzer" component={PacketAnalyzerPage} />
          <Route path="/tools/metadata-extractor" component={MetadataExtractorPage} />
          <Route path="/tools/header-analyzer" component={HeaderAnalyzerPage} />
          <Route path="/tools/email-hunter" component={EmailHunterPage} />
          <Route path="/tools/shell-uploader" component={ShellUploaderPage} />
          <Route path="/tools/tech-detector" component={TechDetectorPage} />
          <Route path="/tools/password-checker" component={PasswordCheckerPage} />
          <Route path="/tools/file-scanner" component={FileScannerPage} />
          <Route path="/tools/url-scanner" component={UrlScannerPage} />
          <Route path="/tools/cors-tester" component={CorsTesterPage} />
          <Route path="/tools/lfi-scanner" component={LfiScannerPage} />
          <Route path="/tools/rfi-scanner" component={RfiScannerPage} />
          <Route path="/tools/form-fuzzer" component={FormFuzzerPage} />
          <Route path="/tools/xml-injector" component={XmlInjectorPage} />
          <Route path="/tools/sql-injector" component={SqlInjectorPage} />
          <Route path="/tools/beef-xss" component={BeefXssPage} />
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
