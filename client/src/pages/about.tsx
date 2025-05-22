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
        
        <Card className="border-secondary/30">
          <CardContent className="p-6">
            <h2 className="text-2xl font-tech mb-4 text-secondary">Contact</h2>
            <p className="mb-4 font-mono text-muted-foreground">
              For questions, feedback, or to report issues, please reach out through the following channels:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 border border-primary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-primary">GitHub</h3>
                <p className="font-mono text-sm text-muted-foreground">
                  Submit issues, contribute to the project, or fork the repository
                </p>
              </div>
              
              <div className="p-3 border border-secondary/20 rounded bg-card/50">
                <h3 className="text-lg font-tech mb-2 text-secondary">Email</h3>
                <p className="font-mono text-sm text-muted-foreground">
                  For private inquiries: contact@securityoperation-example.com
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
