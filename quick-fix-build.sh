#!/bin/bash
# Quick Fix untuk Build Error - Pusat Operasi Keamanan

echo "🔧 Memperbaiki masalah build error..."

# Set environment variables untuk mengatasi masalah crypto
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"
export NODE_ENV=production

# Membuat script build manual yang mengatasi masalah entry module
cat > build-fix.js << 'EOL'
const { build } = require('vite');
const path = require('path');

async function buildApp() {
  try {
    console.log('🚀 Memulai build dengan konfigurasi yang diperbaiki...');
    
    await build({
      root: path.resolve(__dirname, 'client'),
      build: {
        outDir: path.resolve(__dirname, 'dist/public'),
        emptyOutDir: true,
        rollupOptions: {
          input: path.resolve(__dirname, 'client/index.html'),
        },
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, 'client/src'),
          '@shared': path.resolve(__dirname, 'shared'),
        },
      },
      define: {
        global: 'globalThis',
      },
    });
    
    console.log('✅ Build berhasil!');
  } catch (error) {
    console.error('❌ Build gagal:', error.message);
    process.exit(1);
  }
}

buildApp();
EOL

echo "📦 Menjalankan build dengan konfigurasi yang diperbaiki..."
node build-fix.js

if [ $? -eq 0 ]; then
    echo "✅ Build berhasil diselesaikan!"
    echo "📁 File build tersimpan di: dist/public/"
    echo "🚀 Aplikasi siap untuk deployment"
else
    echo "❌ Build masih gagal. Mencoba metode alternatif..."
    
    # Fallback: Build dengan pengaturan minimal
    echo "🔄 Mencoba build dengan pengaturan minimal..."
    npx vite build --outDir dist/public --emptyOutDir
fi

echo "🎉 Selesai!"