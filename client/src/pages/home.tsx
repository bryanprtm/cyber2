import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import Terminal from "@/components/terminal";
import { MatrixBackground } from "@/components/matrix-background";
import CheckpointThreatMap from "@/components/checkpoint-threat-map";
import { useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";

export default function Home() {
  const { addSystemLine, addInfoLine } = useTerminal();
  
  useEffect(() => {
    // Simulate terminal initialization
    addSystemLine("Pusat Operasi Keamanan v1.0.2_alpha diinisialisasi");
    addInfoLine("Memuat komponen sistem...");
    
    const timer1 = setTimeout(() => {
      addInfoLine("Modul keamanan telah dikonfigurasi dan siap");
    }, 800);
    
    const timer2 = setTimeout(() => {
      addSystemLine("Sistem siap. Ketik 'bantuan' untuk daftar perintah.");
    }, 1500);
    
    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, [addSystemLine, addInfoLine]);
  
  return (
    <div className="container mx-auto px-4 py-10">
      <div className="relative">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 mb-16">
          <div className="flex flex-col justify-center">
            <h2 className="text-3xl font-tech mb-4 text-glitch" data-text="Alat Keamanan Cyber">
              Alat Keamanan Cyber
            </h2>
            <p className="mb-6 text-muted-foreground font-mono">
              Akses koleksi lengkap alat keamanan yang dirancang untuk pengujian penetrasi, 
              pemindaian kerentanan, dan analisis jaringan. Semua alat berbasis web dan tidak memerlukan instalasi.
            </p>
            <Link href="/tools">
              <Button className="w-full md:w-auto bg-primary text-primary-foreground hover:bg-primary/90 font-tech">
                Jelajahi Alat
              </Button>
            </Link>
          </div>
          
          <div className="relative">
            <MatrixBackground />
            <Card className="border border-primary/50 bg-card/80 backdrop-blur-sm p-6 h-full">
              <h3 className="text-xl font-tech mb-4 text-primary">Fitur</h3>
              <ul className="space-y-3 font-mono text-sm">
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Pemindaian kerentanan berbasis web</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Alat pengintaian jaringan</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Utilitas pengumpulan informasi</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Alat kata sandi dan enkripsi</span>
                </li>
                <li className="flex items-start">
                  <span className="text-primary mr-2">✓</span>
                  <span>Kerangka eksploitasi web</span>
                </li>
              </ul>
            </Card>
          </div>
        </div>
        
        <div className="relative mb-16">
          <h2 className="text-2xl font-tech mb-6 text-center">Intelijen Ancaman Cyber Langsung</h2>
          <CheckpointThreatMap />
        </div>
        
        <div className="relative">
          <h2 className="text-2xl font-tech mb-6 text-center">Terminal Interaktif</h2>
          <Terminal lines={[]} />
        </div>
      </div>
      
      <div className="mt-16">
        <h2 className="text-2xl font-tech mb-6 text-center">Cara Memulai</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">1. Pilih Alat</h3>
            <p className="text-sm font-mono text-muted-foreground">Telusuri koleksi alat keamanan cyber kami yang dikategorikan dan pilih yang sesuai dengan kebutuhan Anda.</p>
          </Card>
          
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">2. Konfigurasi Parameter</h3>
            <p className="text-sm font-mono text-muted-foreground">Tetapkan parameter yang diperlukan untuk alat yang Anda pilih, seperti URL target, alamat IP, atau data input.</p>
          </Card>
          
          <Card className="bg-card border border-secondary/30 p-5">
            <h3 className="text-xl font-tech mb-2 text-secondary">3. Analisis Hasil</h3>
            <p className="text-sm font-mono text-muted-foreground">Tinjau output rinci yang disediakan oleh alat di tampilan terminal dan ambil tindakan yang sesuai.</p>
          </Card>
        </div>
      </div>
      
      <div className="mt-16 text-center">
        <div className="inline-block border border-accent/30 p-6 rounded-md bg-card relative overflow-hidden">
          <MatrixBackground className="opacity-20" />
          <h2 className="text-xl font-tech mb-4 text-accent">Penafian Penting</h2>
          <p className="text-sm font-mono text-muted-foreground max-w-2xl">
            Alat yang disediakan oleh Pusat Operasi Keamanan ditujukan hanya untuk tujuan pendidikan dan etis.
            Selalu pastikan Anda memiliki otorisasi yang tepat sebelum menguji sistem atau jaringan apa pun.
            Pemindaian atau pengujian yang tidak sah mungkin ilegal di yurisdiksi Anda.
          </p>
        </div>
      </div>
    </div>
  );
}
