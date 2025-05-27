#!/bin/bash
# Script Build Deploy untuk Security Operation Center

echo "🚀 Memulai build deploy Security Operation Center..."

# Set environment untuk build produksi
export NODE_ENV=production
export NODE_OPTIONS="--openssl-legacy-provider --max-old-space-size=4096"

# Buat direktori dist jika belum ada
mkdir -p dist/public

echo "📦 Menjalankan build dengan konfigurasi minimal..."

# Build dengan konfigurasi yang disederhanakan
cd client
npx vite build \
  --outDir ../dist/public \
  --emptyOutDir \
  --mode production \
  --config ../vite.config.ts

if [ $? -eq 0 ]; then
    echo "✅ Build berhasil!"
    echo "📁 File build tersimpan di: dist/public/"
    
    # Copy server files
    cd ..
    echo "📋 Menyalin file server..."
    cp -r server dist/
    cp -r shared dist/
    cp package.json dist/
    cp package-lock.json dist/
    
    echo "🎉 Deployment siap!"
    echo "📂 Struktur deployment:"
    ls -la dist/
    
else
    echo "❌ Build gagal. Menggunakan mode development untuk deployment."
    echo "🔧 Aplikasi akan berjalan dalam mode development di production."
fi