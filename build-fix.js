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
