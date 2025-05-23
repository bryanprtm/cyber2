import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { MatrixBackground } from "../matrix-background";
import { BarChart, Database } from "lucide-react";

export default function Header() {
  const [location] = useLocation();
  
  const navItems = [
    { name: "Beranda", path: "/" },
    { name: "Alat", path: "/tools" },
    { name: "Dasbor Keamanan", path: "/security-dashboard" },
    { name: "Riwayat Pemindaian", path: "/scan-history" },
    { name: "Dokumentasi", path: "/docs" },
    { name: "Tentang", path: "/about" }
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
                data-text="Pusat Operasi Keamanan"
              >
                Pusat Operasi Keamanan
              </div>
            </Link>
            <div className="ml-3 text-xs text-secondary font-mono mt-2">v1.0.3_alpha</div>
          </div>
          <nav className="mt-4 md:mt-0">
            <ul className="flex space-x-4 font-tech">
              {navItems.map((item) => (
                <li key={item.path}>
                  <Link
                    href={item.path}
                    className={cn(
                      "transition-colors duration-300 flex items-center",
                      location === item.path
                        ? "text-primary"
                        : "text-foreground hover:text-primary"
                    )}
                  >
                    {item.path === "/scan-history" && <Database className="mr-1 h-3 w-3" />}
                    {item.name}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>
        <div className="mt-8 text-center">
          <h1 className="text-3xl md:text-5xl font-tech mb-4">
            Perangkat <span className="text-primary">Keamanan Cyber</span> Canggih
          </h1>
          <p className="font-mono text-muted-foreground max-w-2xl mx-auto">
            Akses alat keamanan yang kuat untuk memindai, menguji, dan memperkuat sistem digital.
            Hanya untuk tujuan pendidikan.
          </p>
        </div>
      </div>
    </header>
  );
}
