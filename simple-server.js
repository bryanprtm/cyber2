// Simple Security Operation Center Server
// Standalone Express server tanpa bundling
const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(express.static('client'));

// Simple in-memory storage
const tools = [
    { id: 'port-scanner', nama: 'Port Scanner', kategori: 'Network Security', aktif: 1 },
    { id: 'whois-lookup', nama: 'WHOIS Lookup', kategori: 'Information Gathering', aktif: 1 },
    { id: 'ping-sweep', nama: 'Ping Sweep', kategori: 'Network Discovery', aktif: 1 },
    { id: 'header-analyzer', nama: 'Header Analyzer', kategori: 'Web Security', aktif: 1 },
    { id: 'ssl-scanner', nama: 'SSL Scanner', kategori: 'Security Analysis', aktif: 1 },
    { id: 'tech-detector', nama: 'Tech Detector', kategori: 'Web Analysis', aktif: 1 },
    { id: 'url-scanner', nama: 'URL Scanner', kategori: 'Threat Detection', aktif: 1 },
    { id: 'cors-tester', nama: 'CORS Tester', kategori: 'Web Security', aktif: 1 },
    { id: 'sql-injector', nama: 'SQL Injector', kategori: 'Vulnerability Assessment', aktif: 1 },
    { id: 'xss-scanner', nama: 'XSS Scanner', kategori: 'Web Security', aktif: 1 },
    { id: 'file-scanner', nama: 'File Scanner', kategori: 'Malware Detection', aktif: 1 },
    { id: 'email-hunter', nama: 'Email Hunter', kategori: 'OSINT', aktif: 1 },
    { id: 'phone-lookup', nama: 'Phone Lookup', kategori: 'OSINT', aktif: 1 }
];

// API Routes
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        version: '2.0.0-simple',
        server: 'Security Operation Center',
        timestamp: new Date().toISOString(),
        message: 'System running normally'
    });
});

app.get('/api/tools', (req, res) => {
    res.json(tools);
});

app.get('/api/dashboard/stats', (req, res) => {
    res.json({
        totalScans: Math.floor(Math.random() * 1000) + 100,
        scansToday: Math.floor(Math.random() * 50) + 10,
        securityScore: Math.floor(Math.random() * 30) + 70,
        activeThreats: Math.floor(Math.random() * 10) + 2,
        systemStatus: 'Online',
        uptime: process.uptime(),
        lastUpdate: new Date().toISOString()
    });
});

// Simple port scan simulation
app.post('/api/scan/port', (req, res) => {
    const { target, ports } = req.body;
    const portList = ports ? ports.split(',').map(p => parseInt(p.trim())) : [22, 80, 443];
    
    const results = {
        target,
        scanTime: Math.floor(Math.random() * 2000) + 500,
        openPorts: [],
        closedPorts: [],
        totalPorts: portList.length,
        status: 'completed',
        timestamp: new Date().toISOString()
    };
    
    portList.forEach(port => {
        if (Math.random() < 0.2) { // 20% chance port is open
            results.openPorts.push({
                port,
                service: getServiceName(port),
                state: 'open'
            });
        } else {
            results.closedPorts.push(port);
        }
    });
    
    res.json(results);
});

// Fallback untuk SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/index.html'));
});

// Helper function
function getServiceName(port) {
    const services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
    };
    return services[port] || 'Unknown';
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Security Operation Center running on port ${PORT}`);
    console.log(`🌐 Access: http://0.0.0.0:${PORT}`);
    console.log(`📊 API Health: http://0.0.0.0:${PORT}/api/health`);
    console.log(`✅ Simple server mode - no bundling dependencies`);
});
