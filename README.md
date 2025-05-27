# 🔐 Security Operation Center

[![GitHub release](https://img.shields.io/github/release/security-operation-center/soc-toolkit.svg)](https://github.com/security-operation-center/soc-toolkit/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node.js-20.x-green.svg)](https://nodejs.org/)

**Advanced Cybersecurity Toolkit for Ethical Security Testing**

A comprehensive web-based cybersecurity platform providing 13+ security tools for ethical hackers, penetration testers, and security professionals.

## 🚀 Quick Start

### Download & Installation

**Option 1: GitHub Release (Recommended)**
```bash
# Download latest release
wget https://github.com/security-operation-center/soc-toolkit/archive/refs/tags/v2.0.0.tar.gz
tar -xzf v2.0.0.tar.gz
cd soc-toolkit-2.0.0

# Install dependencies
npm install

# Start application
npm run dev
```

**Option 2: Clone Repository**
```bash
git clone https://github.com/security-operation-center/soc-toolkit.git
cd soc-toolkit
npm install
npm run dev
```

**Option 3: Direct Download**
- 📥 [Download ZIP](https://github.com/security-operation-center/soc-toolkit/archive/refs/heads/main.zip)
- 📦 [Latest Release](https://github.com/security-operation-center/soc-toolkit/releases/latest)

## 🛡️ Security Tools Available

### Network Security
- **🌐 Port Scanner** - Advanced port scanning with service detection
- **📡 Ping Sweep** - Network host discovery and mapping
- **🔍 WHOIS Lookup** - Domain registration information gathering

### Web Security
- **🛡️ Header Analyzer** - HTTP security headers assessment
- **🔒 SSL Scanner** - Certificate and TLS configuration analysis
- **🔗 CORS Tester** - Cross-Origin Resource Sharing validation
- **🗄️ SQL Injector** - SQL injection vulnerability testing
- **💻 XSS Scanner** - Cross-Site Scripting detection

### Analysis & Detection
- **⚡ Tech Detector** - Website technology stack identification
- **🔗 URL Scanner** - Malicious URL and threat detection
- **📁 File Scanner** - Malware and suspicious file analysis

### OSINT Tools
- **📧 Email Hunter** - Email address discovery and validation
- **📱 Phone Lookup** - Phone number information gathering

## 🏗️ Installation Methods

### Ubuntu 20.04+ / Debian
```bash
# Download installation script
wget https://raw.githubusercontent.com/security-operation-center/soc-toolkit/main/install-ubuntu.sh
chmod +x install-ubuntu.sh
sudo ./install-ubuntu.sh
```

### CentOS / RHEL
```bash
# Download installation script
curl -O https://raw.githubusercontent.com/security-operation-center/soc-toolkit/main/install-centos.sh
chmod +x install-centos.sh
sudo ./install-centos.sh
```

### Docker Container
```bash
# Pull and run Docker image
docker pull securityoc/soc-toolkit:latest
docker run -d -p 5000:5000 --name soc-toolkit securityoc/soc-toolkit:latest
```

### Manual Installation
```bash
# Prerequisites
node --version  # Requires Node.js 18+
npm --version   # Requires npm 8+

# Clone and setup
git clone https://github.com/security-operation-center/soc-toolkit.git
cd soc-toolkit
npm install
npm run build
npm start
```

## 🔧 Configuration

### Environment Variables
```bash
# Server Configuration
PORT=5000
NODE_ENV=production

# Database (Optional)
DATABASE_URL=postgresql://user:pass@localhost:5432/soc_db
PGHOST=localhost
PGUSER=socuser
PGPASSWORD=your_password
PGDATABASE=security_operations_center
```

### Custom Configuration
```javascript
// config/settings.js
module.exports = {
  server: {
    port: process.env.PORT || 5000,
    host: '0.0.0.0'
  },
  security: {
    scanTimeout: 300,
    maxConcurrentScans: 10,
    enableLogging: true
  }
};
```

## 📱 Usage Examples

### API Endpoints
```bash
# Health check
curl http://localhost:5000/api/health

# Get available tools
curl http://localhost:5000/api/tools

# Port scan example
curl -X POST http://localhost:5000/api/scan/port \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","ports":"22,80,443"}'

# WHOIS lookup
curl -X POST http://localhost:5000/api/lookup/whois \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

### Web Interface
1. Open browser: `http://localhost:5000`
2. Select security tool from dashboard
3. Configure scan parameters
4. Review results in terminal interface

## 🔒 Security & Legal Notice

**⚠️ IMPORTANT: For Educational and Authorized Testing Only**

This toolkit is designed for:
- ✅ Educational cybersecurity learning
- ✅ Authorized penetration testing
- ✅ Security assessment of your own systems
- ✅ Bug bounty hunting with proper authorization

**Prohibited Uses:**
- ❌ Unauthorized scanning of systems you don't own
- ❌ Malicious attacks or illegal activities
- ❌ Violation of computer crime laws

**Users are solely responsible for ensuring legal compliance in their jurisdiction.**

## 🏗️ Development

### Build from Source
```bash
# Development mode
npm run dev

# Production build
npm run build
npm start

# Run tests
npm test

# Lint code
npm run lint
```

### Contributing
1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-tool`
3. Commit changes: `git commit -m 'Add amazing security tool'`
4. Push to branch: `git push origin feature/amazing-tool`
5. Submit Pull Request

## 📊 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 18.04+, CentOS 7+, Windows 10, macOS 10.14+
- **Node.js**: 18.0 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 1GB free space
- **Network**: Internet connection for tool updates

### Recommended Setup
- **OS**: Ubuntu 20.04 LTS or newer
- **Node.js**: 20.x LTS
- **RAM**: 8GB or more
- **CPU**: 4+ cores
- **Storage**: SSD with 5GB+ free space

## 🔄 Updates & Releases

### Automatic Updates
```bash
# Enable auto-updates (optional)
npm install -g @security-oc/auto-updater
soc-updater enable
```

### Manual Updates
```bash
# Check for updates
git fetch origin
git pull origin main
npm install
npm run build
```

### Version History
- **v2.0.0** - Complete rebuild with enhanced UI and 13 tools
- **v1.5.0** - Added OSINT tools and improved scanning
- **v1.0.0** - Initial release with core security tools

## 🆘 Support & Documentation

### Getting Help
- 📖 [Full Documentation](https://github.com/security-operation-center/soc-toolkit/wiki)
- 🐛 [Report Issues](https://github.com/security-operation-center/soc-toolkit/issues)
- 💬 [Community Discord](https://discord.gg/security-oc)
- 📧 [Email Support](mailto:support@security-oc.org)

### Troubleshooting
```bash
# Check system status
curl http://localhost:5000/api/health

# View application logs
npm run logs

# Reset application
npm run reset

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Express.js, React, and modern web technologies
- Inspired by industry-standard penetration testing tools
- Special thanks to the cybersecurity community

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=security-operation-center/soc-toolkit&type=Date)](https://star-history.com/#security-operation-center/soc-toolkit&Date)

---

**Made with ❤️ for the cybersecurity community**

[🔗 Website](https://security-oc.org) | [📖 Docs](https://docs.security-oc.org) | [💬 Discord](https://discord.gg/security-oc)