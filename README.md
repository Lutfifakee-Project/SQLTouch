<div align="center">

# 🚀 SQLTouch

### Advanced SQL Injection Automation Tool

<p>
  <img src="https://img.shields.io/badge/version-2.0.0-blue" />
  <img src="https://img.shields.io/badge/python-3.7+-green" />
  <img src="https://img.shields.io/badge/license-MIT-red" />
  <img src="https://img.shields.io/github/stars/lutfifakeexone/SQLTouch?style=social" />
</p>

<p>
  <b>SQLTouch</b> is a powerful automated SQL Injection tool inspired by SQLMap.<br>
  Designed for security researchers and penetration testers to efficiently detect and exploit SQL injection vulnerabilities.
</p>

</div>

---

## 📖 Table of Contents

- [✨ Features](#-features)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🚀 Usage](#-usage)
- [⚙️ Options](#️-options)
- [🎯 Test Targets](#-test-targets)
- [📁 Project Structure](#-project-structure)
- [🛡️ Security Notice](#️-security-notice)
- [📝 License](#-license)

---

## ✨ Features

### 🧠 Injection Techniques

| Technique | Description |
|----------|-------------|
| **Error-based** | Detects SQL errors in response |
| **Boolean-based Blind** | Compares content differences |
| **Time-based Blind** | Measures response delays |
| **Union-based** | Merges query results |

### 🔍 Smart Detection

- Automatic WAF/IPS detection (Cloudflare, ModSecurity, etc.)
- DBMS fingerprinting (MySQL, MSSQL, PostgreSQL, Oracle)
- Intelligent parameter discovery
- Multi-threaded scanning

### 📤 Data Extraction

- Enumerate databases, tables, and columns
- Dump database contents
- Automatic credential detection

### ⚡ Performance & Flexibility

- Multi-threaded scanning (configurable threads)
- Proxy support (Burp Suite, OWASP ZAP)
- Custom headers & cookies
- Randomized User-Agent
- GET and POST method support

### 📊 Output & Reporting

- JSON output support
- File export
- Verbose debugging mode

---

## ⚡ Quick Start

```bash
# Basic vulnerability scan
python main.py -u "http://example.com/page.php?id=1"

# Verbose mode with all techniques
python main.py -u "http://example.com/page.php?id=1" -v

# Specific techniques only (Boolean, Error, Time)
python main.py -u "http://example.com/page.php?id=1" --techniques BET -v
```

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/Lutfifakee-Project/SQLTouch.git
cd SQLTouch
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
python main.py -u "http://example.com/page.php?id=1"
```

---

## 🚀 Usage

### 🔹 GET Method Scan

```bash
python main.py -u "http://example.com/page.php?id=1"
```

### 🔹 POST Method Scan

```bash
python main.py -u "http://example.com/login.php" --data "user=admin&pass=123"
```

### 🔹 Advanced Scan with Verbose

```bash
python main.py -u "http://example.com/page.php?id=1" --techniques BET -v
```

### 🔹 Mass Target Scan

```bash
python main.py -f targets.txt --threads 10
```

### 🔹 Proxy Integration (Burp Suite)

```bash
python main.py -u "http://example.com/page.php?id=1" \
  --proxy "http://127.0.0.1:8080"
```

### 🔹 Custom Headers & Cookies

```bash
python main.py -u "http://example.com/page.php?id=1" \
  --cookie "PHPSESSID=abc123" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Authorization: Bearer token123"
```

### 🔹 Random User-Agent with Delay

```bash
python main.py -u "http://example.com/page.php?id=1" \
  --random-agent \
  --delay 1
```

### 🔹 Dump Database

```bash
python main.py -u "http://example.com/page.php?id=1" --dump
```

### 🔹 Save Output

```bash
# Save as text
python main.py -u "http://example.com/page.php?id=1" --output results.txt

# Save as JSON
python main.py -u "http://example.com/page.php?id=1" --json --output results.json
```

---

## ⚙️ Options

| Option | Description | Default |
|--------|------------|---------|
| -u, --url | Target URL | - |
| -f, --file | File containing list of URLs | - |
| --data | POST data | - |
| --cookie | HTTP Cookie header | - |
| -H, --header | Custom HTTP headers | - |
| --proxy | Use proxy server | - |
| --threads | Number of threads | 5 |
| --timeout | Request timeout (seconds) | 10 |
| --delay | Delay between requests | 0 |
| --level | Test level (1–5) | 1 |
| --risk | Risk level (1–3) | 1 |
| --techniques | Techniques: B, E, U, T | BETU |
| --random-agent | Use random User-Agent | False |
| --skip-waf | Skip WAF detection | False |
| -v, --verbose | Verbose output | False |
| --dump | Dump database data | False |
| --json | Output JSON | False |
| --output | Save results to file | - |

---

## 📁 Project Structure

```text
SQLTouch/
├── main.py
├── payloads.yml
├── requirements.txt
├── README.md
└── modules/
    ├── __init__.py
    ├── core.py
    ├── detector.py
    ├── extractor.py
    └── utils.py
```

---

## 🛡️ Security Notice

⚠️ **Important**

This tool is intended for:
- Educational purposes  
- Authorized penetration testing  
- Security research  

Do NOT use this tool on systems without explicit permission.  
The author is not responsible for misuse.

---

## 📝 License

MIT License

---

## 📧 Contact

- GitHub: https://github.com/Lutfifakee-Project/  

---

<div align="center">

⭐ If you find this project useful, consider giving it a star!

</div>
