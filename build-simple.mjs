import { build } from 'vite';
import { resolve } from 'path';

async function buildApp() {
  try {
    console.log('🚀 Memulai build produksi...');
    
    await build({
      configFile: false,
      root: resolve(process.cwd(), 'client'),
      build: {
        outDir: resolve(process.cwd(), 'dist/public'),
        emptyOutDir: true,
      },
      resolve: {
        alias: {
          '@': resolve(process.cwd(), 'client/src'),
          '@shared': resolve(process.cwd(), 'shared'),
        },
      },
      define: {
        global: 'globalThis',
      },
    });
    
    console.log('✅ Build berhasil!');
  } catch (error) {
    console.error('❌ Build error:', error);
    process.exit(1);
  }
}

buildApp();