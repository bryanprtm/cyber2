import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { MatrixBackground } from "../matrix-background";

export default function Header() {
  const [location] = useLocation();
  
  const navItems = [
    { name: "Home", path: "/" },
    { name: "Tools", path: "/tools" },
    { name: "Docs", path: "/docs" },
    { name: "About", path: "/about" }
  ];
  
  return (
    <header className="relative border-b border-primary/50 py-6">
      <MatrixBackground />
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center">
            <Link href="/">
              <div 
                className="text-primary text-4xl font-tech text-glitch cursor-pointer" 
                data-text="CyberPulse"
              >
                CyberPulse
              </div>
            </Link>
            <div className="ml-3 text-xs text-secondary font-mono mt-2">v1.0.2_alpha</div>
          </div>
          <nav className="mt-4 md:mt-0">
            <ul className="flex space-x-6 font-tech">
              {navItems.map((item) => (
                <li key={item.path}>
                  <Link href={item.path}>
                    <a 
                      className={cn(
                        "transition-colors duration-300",
                        location === item.path
                          ? "text-primary"
                          : "text-foreground hover:text-primary"
                      )}
                    >
                      {item.name}
                    </a>
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>
        <div className="mt-8 text-center">
          <h1 className="text-3xl md:text-5xl font-tech mb-4">
            Advanced <span className="text-primary">Cybersecurity</span> Toolkit
          </h1>
          <p className="font-mono text-muted-foreground max-w-2xl mx-auto">
            Access powerful security tools for scanning, testing, and hardening digital systems. 
            For educational purposes only.
          </p>
        </div>
      </div>
    </header>
  );
}
