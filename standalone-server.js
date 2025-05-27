import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(express.static('client'));

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

app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        version: '2.0.0',
        server: 'Security Operation Center',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/tools', (req, res) => {
    res.json(tools);
});

app.get('/api/dashboard/stats', (req, res) => {
    res.json({
        totalScans: Math.floor(Math.random() * 500) + 100,
        scansToday: Math.floor(Math.random() * 50) + 5,
        securityScore: Math.floor(Math.random() * 30) + 70,
        activeThreats: Math.floor(Math.random() * 10) + 1,
        systemStatus: 'Online',
        lastUpdate: new Date().toISOString()
    });
});

app.post('/api/scan/port', (req, res) => {
    const { target, ports = '22,80,443' } = req.body;
    const portList = ports.split(',').map(p => parseInt(p.trim()));
    
    const result = {
        target,
        scanTime: Math.floor(Math.random() * 2000) + 500,
        openPorts: [],
        closedPorts: [],
        totalPorts: portList.length,
        status: 'completed',
        timestamp: new Date().toISOString()
    };
    
    portList.forEach(port => {
        if (Math.random() < 0.2) {
            result.openPorts.push({
                port,
                service: getServiceName(port),
                state: 'open'
            });
        } else {
            result.closedPorts.push(port);
        }
    });
    
    res.json(result);
});

function getServiceName(port) {
    const services = {
        21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
    };
    return services[port] || 'Unknown';
}

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Security Operation Center running on port ${PORT}`);
    console.log(`🌐 Access: http://0.0.0.0:${PORT}`);
    console.log(`📊 Health: http://0.0.0.0:${PORT}/api/health`);
});
