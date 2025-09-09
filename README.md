# NPM Security Scanner

A comprehensive security scanner to detect compromised npm packages and malicious code patterns from the QIX supply chain attack that affected popular packages like `chalk` and `debug-js`.

## 🚨 About the Attack

On September 8, 2025, an attacker compromised all packages published by `qix`, including extremely popular packages such as `chalk` and `debug-js`. Collectively, these packages have over 2 billion downloads per week, making this likely the largest supply chain attack in history.

**Attack Details:**
- **Method**: Phishing email to package maintainer
- **Compromised Packages**: All packages by `qix` author
- **Malware**: Crypto stealer targeting Ethereum and Solana wallets
- **Impact**: Despite the scale, only ~5 cents of ETH and $20 of memecoin were stolen

## 🔍 What This Scanner Detects

### Compromised Packages
- **Version-specific detection**: Only flags packages if their installed version is vulnerable
- All packages published by the `qix` author with vulnerable versions
- Popular packages: `chalk`, `debug-js`, `supports-color`, `has-flag`, etc.
- **NPM Cache vulnerabilities**: Detects vulnerable packages in your npm cache

### Malicious Code Patterns
- `checkethereumw` - Main malicious function that hooks into Ethereum wallets
- Hardcoded malicious addresses (Ethereum: `0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976`)
- Solana address replacement (`19111111111111111111111111111111`)
- WebSocket data exfiltration endpoints
- CDN malware hosting domains
- Fake NPM domains used in phishing
- Network request interception patterns
- **Ethereum function hooking** patterns
- **Levenshtein distance** calculations for address replacement

### Suspicious Addresses
- **280+ crypto addresses** from the attack including:
  - Bitcoin addresses
  - Bitcoin Cash addresses  
  - Ethereum addresses
  - Solana addresses
  - Tron addresses
- **Malicious domains**: `npmjs.help`, `static-mw-host.b-cdn.net`, etc.
- **IP addresses**: `185.7.81.108`

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/npm-security-scanner.git
cd npm-security-scanner

# Install dependencies
npm install

# Make the scan-projects script executable
chmod +x scan-projects
```

### Usage

#### Quick Start - Scan All Projects Recursively

```bash
# Scan all projects in current directory recursively
./scan-projects

# Scan all projects in specific directory recursively
./scan-projects /path/to/your/projects

# Using npm script
npm run scan-projects
npm run scan-projects /path/to/your/projects
```

#### Advanced Usage

```bash
# Scan current directory
npm run scan

# Scan specific directory
node scanner.js --directory /path/to/your/project

# Verbose output
node scanner.js --verbose

# JSON output
node scanner.js --output json

# Help
node scanner.js --help
```

### Programmatic Usage

```javascript
const NPMSecurityScanner = require('./scanner.js');

const scanner = new NPMSecurityScanner({
  directory: '/path/to/your/project',
  verbose: true
});

scanner.scan().then(results => {
  console.log('Scan completed:', results);
});
```

## 📊 Sample Output

```
🔍 Scanning projects in: /path/to/projects

🔍 NPM Security Scanner - QIX Supply Chain Attack Detection
Scanning directory: /path/to/projects
Scanning for compromised packages and malicious code patterns...

⠋ Initializing scan...Found 47 projects to scan
⠙ Scanning project 1/47: my-project

================================================================================
🔒 SECURITY SCAN REPORT
================================================================================

📊 SUMMARY:
Files scanned: 1,247
Packages checked: 15
Issues found: 3

💾 NPM CACHE VULNERABILITIES:
╔═════════════╤═════════╤══════════╗
║ Package     │ Version │ Severity ║
╟─────────────┼─────────┼──────────╢
║ strip-ansi  │ 7.1.1   │ HIGH     ║
╟─────────────┼─────────┼──────────╢
║ ansi-regex  │ 6.2.1   │ HIGH     ║
╟─────────────┼─────────┼──────────╢
║ ansi-styles │ 6.2.2   │ HIGH     ║
╚═════════════╧═════════╧══════════╝

🔧 RECOMMENDED REMEDIATION STEPS:
================================================================================

2. NPM CACHE VULNERABILITIES:
   • IMMEDIATE ACTION: Clear npm cache to remove vulnerable packages
   • Run: npm cache clean --force
   • Verify: npm cache verify
   • For each project: rm -rf node_modules package-lock.json && npm install
   • Check cache location: npm config get cache
   • If issues persist: rm -rf ~/.npm && npm cache verify

📄 Markdown report saved: /path/to/security-scan-report-TIMESTAMP.md
✔ Security scan completed!
```

## 🛠️ Features

- **Comprehensive Scanning**: Checks package.json files, node_modules, and JavaScript files
- **Recursive Project Discovery**: Automatically finds all projects in subdirectories
- **Progress Reporting**: Real-time progress with spinner and detailed status
- **Multiple Output Formats**: Console output with colors and tables, JSON export, **Markdown reports**
- **Detailed Reporting**: Shows exactly what was found and where with project paths
- **NPM Cache Detection**: Scans your npm cache for vulnerable packages
- **Version-Specific Detection**: Only flags packages if their specific version is vulnerable
- **Comprehensive Remediation**: Step-by-step instructions for fixing issues
- **Self-Ignoring**: Automatically ignores the scanner's own directory during scans
- **Deduplication**: Removes duplicate entries in reports
- **Git Integration**: Shows relative paths from git repository root
- **Configurable**: Scan specific directories, verbose mode, custom output
- **Fast**: Uses efficient glob patterns and parallel processing

## 🔧 Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--directory` | Directory to scan | Current directory |
| `--verbose` | Enable verbose output | false |
| `--output` | Output format (console/json) | console |
| `--help` | Show help information | - |

## 📋 Requirements

- Node.js 14.0.0 or higher
- npm or yarn package manager

## 📄 Markdown Reports

The scanner automatically generates detailed markdown reports with:

- **Comprehensive remediation steps** for each issue type
- **Step-by-step NPM cache cleanup** instructions (Quick Fix, Thorough Cleanup, Nuclear option)
- **Project-specific information** with git paths and relative paths
- **Verification steps** to ensure issues are resolved
- **Deduplicated results** to avoid confusion
- **Timestamped files** saved as `security-scan-report-TIMESTAMP.md`

Reports are automatically added to `.gitignore` and can be shared with your team.

## 🧹 NPM Cache Cleanup

If the scanner detects vulnerable packages in your npm cache, follow these steps:

### Quick Fix (Recommended)
```bash
# Clear npm cache completely
npm cache clean --force

# Verify cache is clean
npm cache verify

# For each affected project, clean and reinstall
cd /path/to/your/project
rm -rf node_modules package-lock.json
npm install
```

### Thorough Cleanup (If issues persist)
```bash
# Find your npm cache location
npm config get cache

# Stop any running npm processes
pkill -f npm

# Delete the entire cache directory
rm -rf ~/.npm

# Clear npm configuration cache
npm config delete cache
npm config set cache ~/.npm

# Verify cache is completely clean
npm cache verify
```

### Verification
```bash
# Check if vulnerable packages are still in cache
npm cache ls | grep -E "(strip-ansi|ansi-regex|ansi-styles)"

# Should return empty results
```

## 🧪 Testing

```bash
# Run tests
npm test

# Test with sample malicious code
node test-scanner.js

# Test the scan-projects script
./scan-projects
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 References

- [SEAL Alliance - QIX Supply Chain Attack Report](https://www.securityalliance.org/news/2025-09-npm-supply-chain)
- [JDSTAERK - Malicious Code Analysis](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the)
- [PHXGG - Detection Script](https://gist.github.com/phxgg/737198b6e945aba7046e9f9328576271)
- [AndrewMohawk - Dependency Scanner](https://github.com/AndrewMohawk/RandomScripts/blob/main/scan_for_deps_qix-2025-08-09.sh)

## ⚠️ Disclaimer

This tool is provided for educational and security purposes. While we strive to keep the detection patterns up-to-date, this scanner may not catch all variations of malicious code. Always verify results and consult with security professionals for critical systems.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you find any issues or have questions:

1. Check the [Issues](https://github.com/your-username/npm-security-scanner/issues) page
2. Create a new issue with detailed information
3. For security-related issues, please email security@yourcompany.com

---

**Stay secure! 🔒**
# npm-security-scanner
