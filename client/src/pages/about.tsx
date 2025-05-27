import { Card, CardContent } from "@/components/ui/card";
import { MatrixBackground } from "@/components/matrix-background";

export default function About() {
  return (
    <div className="container mx-auto px-4 py-10">
      <div className="max-w-4xl mx-auto">
        <div className="relative mb-10 p-8 rounded-lg overflow-hidden">
          <MatrixBackground />
          <h1 className="text-4xl font-tech mb-4 text-center text-primary">About Security Operation Center</h1>
          <p className="text-center font-mono text-muted-foreground">
            An open-source cybersecurity toolkit designed for educational purposes
          </p>
        </div>
        
        <Card className="mb-8 border-primary/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-primary">Our Mission</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              Security Operation Center was created to provide cybersecurity professionals, students, and enthusiasts 
              with a comprehensive set of web-based tools for security testing and education. We believe 
              that knowledge about security vulnerabilities helps build more secure systems.
            </p>
            <p className="font-mono text-muted-foreground">
              Our goal is to make security testing accessible without requiring complex software 
              installations, enabling users to learn about security concepts through practical application.
            </p>
          </CardContent>
        </Card>
        
        <Card className="mb-8 border-secondary/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-secondary">Ethical Use</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              All tools provided by Security Operation Center are meant to be used ethically and legally. Always ensure you have 
              proper authorization before scanning or testing any system, network, or website. Unauthorized 
              security testing may be illegal in your jurisdiction.
            </p>
            <div className="p-4 border border-accent/30 rounded-md bg-card/50">
              <h3 className="text-lg font-tech mb-2 text-accent">Remember:</h3>
              <ul className="list-disc pl-5 font-mono text-sm text-muted-foreground space-y-2">
                <li>Only test systems you own or have explicit permission to test</li>
                <li>Document all testing activities and findings</li>
                <li>Report vulnerabilities responsibly through proper channels</li>
                <li>Never use these tools for malicious purposes</li>
              </ul>
            </div>
          </CardContent>
        </Card>
        
        <Card className="mb-8 border-primary/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-primary">Technology</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              Security Operation Center is built using modern web technologies to provide a responsive, 
              browser-based experience. Our tech stack includes:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div className="p-3 border border-primary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-primary">Frontend</h3>
                <ul className="list-disc pl-5 font-mono text-sm text-muted-foreground">
                  <li>React</li>
                  <li>Tailwind CSS</li>
                  <li>ShadCN UI</li>
                  <li>TypeScript</li>
                </ul>
              </div>
              
              <div className="p-3 border border-secondary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-secondary">Backend</h3>
                <ul className="list-disc pl-5 font-mono text-sm text-muted-foreground">
                  <li>Node.js</li>
                  <li>Express</li>
                  <li>RESTful APIs</li>
                  <li>WebSockets</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="mb-8 border-accent/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-accent">📥 Download & Source Code</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              Get the latest version of Security Operation Center and access the full source code:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <a 
                href="https://github.com/security-operation-center/soc-toolkit/releases/latest" 
                target="_blank" 
                rel="noopener noreferrer"
                className="block p-4 border border-primary/30 rounded-lg bg-card/50 hover:bg-primary/10 transition-colors group"
              >
                <h3 className="text-lg font-tech mb-2 text-primary group-hover:text-primary/80">🚀 Latest Release</h3>
                <p className="font-mono text-sm text-muted-foreground">
                  Download stable release v2.0.0 with all security tools
                </p>
              </a>
              
              <a 
                href="https://github.com/security-operation-center/soc-toolkit" 
                target="_blank" 
                rel="noopener noreferrer"
                className="block p-4 border border-secondary/30 rounded-lg bg-card/50 hover:bg-secondary/10 transition-colors group"
              >
                <h3 className="text-lg font-tech mb-2 text-secondary group-hover:text-secondary/80">📂 GitHub Repository</h3>
                <p className="font-mono text-sm text-muted-foreground">
                  View source code, contribute, and report issues
                </p>
              </a>
              
              <a 
                href="https://github.com/security-operation-center/soc-toolkit/archive/refs/heads/main.zip" 
                target="_blank" 
                rel="noopener noreferrer"
                className="block p-4 border border-accent/30 rounded-lg bg-card/50 hover:bg-accent/10 transition-colors group"
              >
                <h3 className="text-lg font-tech mb-2 text-accent group-hover:text-accent/80">📦 Download ZIP</h3>
                <p className="font-mono text-sm text-muted-foreground">
                  Download source code as ZIP file directly
                </p>
              </a>
            </div>
            
            <div className="p-4 border border-primary/20 rounded-lg bg-primary/5">
              <h3 className="text-lg font-tech mb-3 text-primary">🛠️ Quick Installation</h3>
              <div className="bg-black/50 p-3 rounded font-mono text-sm">
                <div className="text-green-400 mb-2"># Clone repository</div>
                <div className="text-white mb-3">git clone https://github.com/security-operation-center/soc-toolkit.git</div>
                <div className="text-green-400 mb-2"># Install and run</div>
                <div className="text-white mb-1">cd soc-toolkit</div>
                <div className="text-white mb-1">npm install</div>
                <div className="text-white">npm run dev</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-secondary/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-secondary">Contact & Support</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              For questions, feedback, or to report issues, please reach out through the following channels:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 border border-primary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-primary">GitHub Issues</h3>
                <p className="font-mono text-sm text-muted-foreground mb-2">
                  Submit bug reports and feature requests
                </p>
                <a 
                  href="https://github.com/security-operation-center/soc-toolkit/issues" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:text-primary/80 font-mono text-sm underline"
                >
                  Open Issue →
                </a>
              </div>
              
              <div className="p-3 border border-secondary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-secondary">Documentation</h3>
                <p className="font-mono text-sm text-muted-foreground mb-2">
                  Full documentation and API reference
                </p>
                <a 
                  href="https://github.com/security-operation-center/soc-toolkit/wiki" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-secondary hover:text-secondary/80 font-mono text-sm underline"
                >
                  View Docs →
                </a>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
