#!/usr/bin/env node
/**
 * Security Operation Center - Main Entry Point
 * Production-ready Node.js server for cybersecurity tools
 */

const express = require('express');
const path = require('path');
const { createServer } = require('http');

// Initialize Express app
const app = express();
const server = createServer(app);

// Configuration
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    version: '1.0.0'
  });
});

// API Routes untuk cybersecurity tools
app.get('/api/tools', (req, res) => {
  const tools = [
    {
      id: 'port-scanner',
      nama: 'Pemindai Port',
      deskripsi: 'Memindai port terbuka pada target',
      kategori: 'Jaringan',
      aktif: true
    },
    {
      id: 'whois-lookup',
      nama: 'WHOIS Lookup',
      deskripsi: 'Mencari informasi domain dan IP',
      kategori: 'Intelijen',
      aktif: true
    },
    {
      id: 'ping-sweep',
      nama: 'Ping Sweep',
      deskripsi: 'Memindai host aktif dalam jaringan',
      kategori: 'Jaringan',
      aktif: true
    },
    {
      id: 'header-analyzer',
      nama: 'Analisis Header HTTP',
      deskripsi: 'Menganalisis header keamanan HTTP',
      kategori: 'Web',
      aktif: true
    },
    {
      id: 'ssl-scanner',
      nama: 'Pemindai SSL/TLS',
      deskripsi: 'Memeriksa konfigurasi SSL/TLS',
      kategori: 'Keamanan',
      aktif: true
    },
    {
      id: 'tech-detector',
      nama: 'Deteksi Teknologi',
      deskripsi: 'Mendeteksi teknologi website',
      kategori: 'Web',
      aktif: true
    },
    {
      id: 'url-scanner',
      nama: 'Pemindai URL',
      deskripsi: 'Memindai keamanan URL',
      kategori: 'Web',
      aktif: true
    },
    {
      id: 'cors-tester',
      nama: 'Tester CORS',
      deskripsi: 'Menguji konfigurasi CORS',
      kategori: 'Web',
      aktif: true
    },
    {
      id: 'sql-injector',
      nama: 'SQL Injection Tester',
      deskripsi: 'Menguji kerentanan SQL injection',
      kategori: 'Keamanan',
      aktif: true
    },
    {
      id: 'xss-scanner',
      nama: 'XSS Scanner',
      deskripsi: 'Memindai kerentanan XSS',
      kategori: 'Keamanan',
      aktif: true
    },
    {
      id: 'file-scanner',
      nama: 'Pemindai File',
      deskripsi: 'Menganalisis file untuk malware',
      kategori: 'Keamanan',
      aktif: true
    },
    {
      id: 'email-hunter',
      nama: 'Pemburu Email',
      deskripsi: 'Mencari alamat email di website',
      kategori: 'Intelijen',
      aktif: true
    },
    {
      id: 'phone-doxing',
      nama: 'Phone Doxing',
      deskripsi: 'Mencari informasi nomor telepon',
      kategori: 'Intelijen',
      aktif: true
    }
  ];
  
  res.json(tools);
});

// API endpoint untuk dashboard data
app.get('/api/dashboard/stats', (req, res) => {
  res.json({
    totalScans: Math.floor(Math.random() * 1000) + 500,
    activeThreats: Math.floor(Math.random() * 50) + 10,
    securityScore: Math.floor(Math.random() * 30) + 70,
    lastUpdate: new Date().toISOString()
  });
});

// Serve static files
if (NODE_ENV === 'production') {
  // Serve built frontend
  app.use(express.static(path.join(__dirname, 'dist/public')));
  
  // Catch all handler for SPA
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist/public/index.html'));
  });
} else {
  // Development mode
  app.get('/', (req, res) => {
    res.json({
      message: 'Security Operation Center API',
      version: '1.0.0',
      status: 'Development Mode',
      endpoints: [
        'GET /health - Health check',
        'GET /api/tools - List cybersecurity tools',
        'GET /api/dashboard/stats - Dashboard statistics'
      ]
    });
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'Endpoint tidak ditemukan'
  });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Security Operation Center`);
  console.log(`📡 Server running on http://0.0.0.0:${PORT}`);
  console.log(`🔧 Environment: ${NODE_ENV}`);
  console.log(`⚡ Node.js version: ${process.version}`);
  console.log(`🛡️ 13 cybersecurity tools available`);
  console.log(`🌐 Ready to accept connections`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('\nSIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

module.exports = app;