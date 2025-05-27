-- Security Operation Center - MySQL Database Schema
-- Skema database untuk sistem cybersecurity tools

CREATE DATABASE IF NOT EXISTS security_operations_center;
USE security_operations_center;

-- Tabel pengguna
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'user') DEFAULT 'user',
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabel tools cybersecurity
CREATE TABLE tools (
    id VARCHAR(50) PRIMARY KEY,
    nama VARCHAR(100) NOT NULL,
    deskripsi TEXT,
    kategori VARCHAR(50) NOT NULL,
    icon VARCHAR(50),
    aktif BOOLEAN DEFAULT TRUE,
    usage_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabel hasil scan
CREATE TABLE scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    tool_id VARCHAR(50),
    target VARCHAR(255) NOT NULL,
    result_data JSON,
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    scan_duration DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE SET NULL,
    INDEX idx_user_tool (user_id, tool_id),
    INDEX idx_created_at (created_at)
);

-- Insert data tools cybersecurity
INSERT INTO tools (id, nama, deskripsi, kategori, icon, aktif) VALUES
('port-scanner', 'Pemindai Port', 'Memindai port terbuka pada target untuk analisis keamanan', 'Jaringan', 'network', TRUE),
('whois-lookup', 'WHOIS Lookup', 'Mencari informasi registrasi domain dan kepemilikan', 'Intelijen', 'search', TRUE),
('ping-sweep', 'Ping Sweep', 'Memindai host aktif dalam range jaringan tertentu', 'Jaringan', 'radar', TRUE),
('header-analyzer', 'Analisis Header HTTP', 'Menganalisis header keamanan pada website', 'Web', 'file-text', TRUE),
('ssl-scanner', 'Pemindai SSL/TLS', 'Memeriksa konfigurasi dan keamanan SSL/TLS', 'Keamanan', 'shield', TRUE),
('tech-detector', 'Deteksi Teknologi', 'Mendeteksi teknologi yang digunakan website', 'Web', 'cpu', TRUE),
('url-scanner', 'Pemindai URL', 'Memindai keamanan dan reputasi URL', 'Web', 'link', TRUE),
('cors-tester', 'Tester CORS', 'Menguji konfigurasi Cross-Origin Resource Sharing', 'Web', 'globe', TRUE),
('sql-injector', 'SQL Injection Tester', 'Menguji kerentanan SQL injection pada aplikasi web', 'Keamanan', 'database', TRUE),
('xss-scanner', 'XSS Scanner', 'Memindai kerentanan Cross-Site Scripting', 'Keamanan', 'code', TRUE),
('file-scanner', 'Pemindai File', 'Menganalisis file untuk deteksi malware dan ancaman', 'Keamanan', 'file', TRUE),
('email-hunter', 'Pemburu Email', 'Mencari dan mengumpulkan alamat email dari website', 'Intelijen', 'mail', TRUE),
('phone-doxing', 'Phone Doxing', 'Mencari informasi terkait nomor telepon', 'Intelijen', 'phone', TRUE);

-- Create user for application
CREATE USER IF NOT EXISTS 'socuser'@'localhost' IDENTIFIED BY 'SecurePass2024!';
GRANT ALL PRIVILEGES ON security_operations_center.* TO 'socuser'@'localhost';
FLUSH PRIVILEGES;