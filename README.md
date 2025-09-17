# NPM Security Scanner

[![CI](https://github.com/arif-dewi/npm-security-scanner/workflows/CI/badge.svg)](https://github.com/arif-dewi/npm-security-scanner/actions)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Scanner](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/arif-dewi/npm-security-scanner)

A comprehensive security scanner to detect compromised npm packages and malicious code patterns from supply chain attacks including the QIX attack (chalk, debug-js) and the Tinycolor attack (40+ packages).

## 🚨 About the Attacks

### QIX Supply Chain Attack (September 8, 2025)
On September 8, 2025, an attacker compromised all packages published by `qix`, including extremely popular packages such as `chalk` and `debug-js`. Collectively, these packages have over 2 billion downloads per week, making this likely the largest supply chain attack in history.

**Attack Details:**
- **Method**: Phishing email to package maintainer
- **Compromised Packages**: All packages by `qix` author
- **Malware**: Crypto stealer targeting Ethereum and Solana wallets
- **Impact**: Despite the scale, only ~5 cents of ETH and $20 of memecoin were stolen

### Tinycolor Supply Chain Attack (September 15, 2025)
A malicious update to `@ctrl/tinycolor` (2.2M weekly downloads) was detected as part of a broader supply chain attack that impacted more than 40 packages spanning multiple maintainers.

**Attack Details:**
- **Method**: Malicious update with bundle.js containing TruffleHog execution
- **Compromised Packages**: 40+ packages including @ctrl/tinycolor, angulartics2, ngx-color, etc.
- **Malware**: Downloads TruffleHog, scans for credentials, creates GitHub Actions workflows
- **Impact**: Credential theft and data exfiltration via webhook endpoints

## 🔍 What This Scanner Detects

### How the Scanner Works

The scanner performs **two different types of security checks**:

#### 1. **Package Vulnerability Check** (Fast - Metadata Only)
- **What it checks**: Direct dependencies from `package.json` (dependencies + devDependencies)
- **How it works**: Reads package names and versions, compares against known vulnerable versions
- **What it finds**: Packages with known security vulnerabilities
- **Example**: `chalk@5.6.1` is vulnerable, `chalk@4.1.2` is safe

#### 2. **Malicious Code Pattern Scan** (Thorough - Code Analysis)
- **What it checks**: ALL JavaScript/TypeScript files in your project (including node_modules)
- **How it works**: Reads file contents and searches for malicious code patterns
- **What it finds**: Actual malicious code injected into files
- **Example**: `new WebSocket('ws://suspicious-site.com')` in any file

### Why This Approach?

- **Package Check**: Fast verification of known vulnerabilities in dependencies you control
- **Code Scan**: Comprehensive detection of malicious code that could be anywhere
- **Efficiency**: Checks 20 direct dependencies instantly, scans 10,000+ files in seconds
- **Coverage**: Catches both known vulnerabilities AND unknown malicious code

### Compromised Packages
- **Version-specific detection**: Only flags packages if their installed version is vulnerable
- **QIX Attack**: All packages published by the `qix` author with vulnerable versions
  - Popular packages: `chalk`, `debug-js`, `supports-color`, `has-flag`, etc.
- **Tinycolor Attack**: 40+ packages affected by the September 15, 2025 supply chain attack
  - Popular packages: `@ctrl/tinycolor`, `angulartics2`, `ngx-color`, `react-complaint-image`, etc.
- **NPM Cache vulnerabilities**: Detects vulnerable packages in your npm cache

### Malicious Code Patterns

#### QIX Attack Patterns
- `checkethereumw` - Main malicious function that hooks into Ethereum wallets
- Hardcoded malicious addresses (Ethereum: `0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976`)
- Solana address replacement (`19111111111111111111111111111111`)
- WebSocket data exfiltration endpoints
- CDN malware hosting domains
- Fake NPM domains used in phishing
- Network request interception patterns
- **Ethereum function hooking** patterns
- **Levenshtein distance** calculations for address replacement

#### Tinycolor Attack Patterns
- **Malicious Bundle.js Files**: Detects suspicious bundle.js files containing TruffleHog malware
- **TruffleHog Binary Downloads**: Identifies downloads from GitHub TruffleHog releases
- **Webhook Exfiltration Endpoints**: Detects webhook.site URLs used for data exfiltration
- **Cloud Metadata Discovery**: Identifies AWS (169.254.169.254) and GCP (metadata.google.internal) endpoint access
- **GitHub Actions Workflow Creation**: Detects suspicious workflow names like "shai-hulud-workflow.yml"
- **Environment Variable Theft**: Identifies access to GITHUB_TOKEN, NPM_TOKEN, AWS credentials
- **NPM Token Validation**: Detects NPM token validation attempts via registry.npmjs.org
- **GitHub API Token Usage**: Identifies GitHub API token usage for credential validation
- **Base64 Data Exfiltration**: Detects base64 encoding and curl POST for data exfiltration
- **ExecSync Command Execution**: Identifies execSync calls to TruffleHog filesystem scanner

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
git clone https://github.com/arif-dewi/npm-security-scanner.git
cd npm-security-scanner

# Install dependencies
npm install

# Make the scan-projects script executable
chmod +x scan-projects
```

### Usage

#### Quick Start - Scan All Projects Recursively (Recommended)

```bash
# Scan all projects in current directory recursively
./scan-projects

# Scan all projects in specific directory recursively
./scan-projects /path/to/your/projects
```

#### Alternative Usage Methods

```bash
# Using npm scripts
npm run scan-projects
npm run scan-projects /path/to/your/projects

# Direct scanner usage (for advanced users)
npm run scan --directory /path/to/your/project
npm run scan --verbose
npm run scan --format json
npm run scan --format both
npm run scan --help
```

#### Why Use the Shell Script?

The `./scan-projects` script provides:
- ✅ **Clean output** - No duplicate headers or verbose messages
- ✅ **Better UX** - Single command, clear progress reporting
- ✅ **Team-friendly** - Easy to remember and share
- ✅ **Consistent** - Always works the same way across environments

### Programmatic Usage

```javascript
const NPMSecurityScanner = require('./src/scanner/index.js');

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
🔍 NPM Security Scanner - Supply Chain Attack Detection
Detecting: QIX Attack, Tinycolor Attack, and other malicious patterns
Scanning directory: /path/to/projects

Found 47 projects to scan
Scanning project 1/47: my-project

================================================================================
🔒 SECURITY SCAN REPORT
================================================================================

📊 SUMMARY:
Files scanned: 10,087    # All JS/TS files scanned for malicious code
Packages checked: 20     # Direct dependencies checked for vulnerabilities
Issues found: 3          # Total security issues found

💀 MALICIOUS CODE DETECTED:
┌──────────────┬──────────────┬─────────────────────────────┬──────────┬─────────┬────────────────┐
│ Project      │ File         │ Pattern                     │ Severity │ Matches │ Lines          │
├──────────────┼──────────────┼─────────────────────────────┼──────────┼─────────┼────────────────┤
│ my-project   │ malicious.js │ Ethereum Wallet Hook        │ HIGH     │ 4       │ 3, 7, 8, 8     │
├──────────────┼──────────────┼─────────────────────────────┼──────────┼─────────┼────────────────┤
│ my-project   │ malicious.js │ Crypto Address Replacement  │ HIGH     │ 1       │ 17             │
└──────────────┴──────────────┴─────────────────────────────┴──────────┴─────────┴────────────────┘

🔧 RECOMMENDED REMEDIATION STEPS:
================================================================================

1. MALICIOUS CODE DETECTED:
   • Review all flagged files immediately
   • Remove or quarantine suspicious code
   • Check git history for when malicious code was introduced
   • Consider reverting to a known clean state

📄 Markdown report saved: /path/to/security-scan-report-TIMESTAMP.md
✔ Security scan completed!
```

## 🛠️ Features

- **Comprehensive Scanning**: Checks package.json files, node_modules, and JavaScript files
- **Recursive Project Discovery**: Automatically finds all projects in subdirectories
- **Progress Reporting**: Real-time progress with spinner and detailed status
- **Multiple Output Formats**: Console output with colors and tables, JSON export, **Markdown reports**, and combined output
- **Detailed Reporting**: Shows exactly what was found and where with project paths
- **NPM Cache Detection**: Scans your npm cache for vulnerable packages
- **Version-Specific Detection**: Only flags packages if their specific version is vulnerable
- **Comprehensive Remediation**: Step-by-step instructions for fixing issues
- **Self-Ignoring**: Automatically ignores the scanner's own directory during scans
- **Test File Exclusion**: Excludes test files by default to prevent false positives (use `--include-tests` to include them)
- **Deduplication**: Removes duplicate entries in reports
- **Git Integration**: Shows relative paths from git repository root
- **Configurable**: Scan specific directories, verbose mode, custom output, parallel processing control
- **Fast**: Uses efficient glob patterns and parallel processing
- **Security-First**: Pinned dependency versions to prevent supply chain attacks

## 📋 Release Notes

### v2.2.1 - False Positive Reduction & Whitelist Improvements (September 16, 2025)

#### 🐛 Bug Fixes & Improvements
- **Enhanced html2canvas Whitelist**: Added support for minified files (`html2canvas.min.js`) to prevent false positives
- **New react-error-overlay Whitelist**: Added comprehensive whitelist for React Error Overlay library to eliminate false positives
- **Improved Base64 Detection**: Better handling of legitimate base64 encoding in UI libraries and error handling tools

#### 🎯 False Positive Reductions
- **html2canvas.min.js**: Fixed false positive for "Double Base64 Encoding Evasion" in minified html2canvas files
- **react-error-overlay**: Fixed false positive for "Double Base64 Encoding Evasion" in React error overlay library
- **Legitimate Base64 Usage**: Better recognition of legitimate base64 encoding in canvas-to-image conversion and error display

#### 🔧 Technical Improvements
- **Whitelist Pattern Updates**: Enhanced regex patterns to cover minified and bundled versions of legitimate libraries
- **Library-Specific Whitelisting**: Added targeted whitelist entries for libraries that legitimately use base64 encoding
- **Better Pattern Matching**: Improved detection accuracy by distinguishing between malicious and legitimate base64 usage

### v2.1.0 - Tinycolor Supply Chain Attack Detection (September 16, 2025)

#### 🆕 New Features
- **Tinycolor Attack Detection**: Added comprehensive detection for the September 15, 2025 supply chain attack affecting 40+ packages
- **TruffleHog Malware Detection**: Detects malicious bundle.js files containing TruffleHog binary downloads and execution
- **Credential Theft Detection**: Identifies environment variable access for GITHUB_TOKEN, NPM_TOKEN, AWS credentials
- **Webhook Exfiltration Detection**: Detects webhook.site endpoints used for data exfiltration
- **Cloud Metadata Discovery**: Identifies attempts to access AWS/GCP metadata endpoints for credential theft
- **GitHub Actions Workflow Scanning**: Scans YAML files for malicious workflow patterns
- **Enhanced IOC Database**: Added 300+ new indicators including webhook endpoints, cloud metadata URLs, and TruffleHog URLs

#### 🎯 New Detection Patterns
- **Malicious Bundle.js Files**: Detects suspicious bundle.js files that may contain TruffleHog malware
- **TruffleHog Binary Downloads**: Identifies downloads from GitHub TruffleHog releases
- **Webhook Exfiltration Endpoints**: Detects webhook.site URLs used for data exfiltration
- **Cloud Metadata Discovery**: Identifies AWS (169.254.169.254) and GCP (metadata.google.internal) endpoint access
- **GitHub Actions Workflow Creation**: Detects suspicious workflow names like "shai-hulud-workflow.yml"
- **Environment Variable Theft**: Identifies access to sensitive environment variables
- **NPM Token Validation**: Detects NPM token validation attempts via registry.npmjs.org
- **GitHub API Token Usage**: Identifies GitHub API token usage for credential validation
- **Base64 Data Exfiltration**: Detects base64 encoding and curl POST for data exfiltration
- **ExecSync Command Execution**: Identifies execSync calls to TruffleHog filesystem scanner

#### 📦 New Compromised Packages (40+ packages)
- `@ctrl/tinycolor` (4.1.1, 4.1.2)
- `angulartics2` (14.1.2)
- `@ctrl/deluge` (7.2.2)
- `@ctrl/golang-template` (1.4.3)
- `@ctrl/magnet-link` (4.0.4)
- `@ctrl/ngx-codemirror` (7.0.2)
- `@ctrl/ngx-csv` (6.0.2)
- `@ctrl/ngx-emoji-mart` (9.2.2)
- `@ctrl/ngx-rightclick` (4.0.2)
- `@ctrl/qbittorrent` (9.7.2)
- `@ctrl/react-adsense` (2.0.2)
- `@ctrl/shared-torrent` (6.3.2)
- `@ctrl/torrent-file` (4.1.2)
- `@ctrl/transmission` (7.3.1)
- `@ctrl/ts-base32` (4.0.2)
- `encounter-playground` (0.0.5)
- `json-rules-engine-simplified` (0.2.4, 0.2.1)
- `koa2-swagger-ui` (5.11.2, 5.11.1)
- `@nativescript-community/gesturehandler` (2.0.35)
- `@nativescript-community/sentry` (4.6.43)
- `@nativescript-community/text` (1.6.13)
- `@nativescript-community/ui-collectionview` (6.0.6)
- `@nativescript-community/ui-drawer` (0.1.30)
- `@nativescript-community/ui-image` (4.5.6)
- `@nativescript-community/ui-material-bottomsheet` (7.2.72)
- `@nativescript-community/ui-material-core` (7.2.76)
- `@nativescript-community/ui-material-core-tabs` (7.2.76)
- `ngx-color` (10.0.2)
- `ngx-toastr` (19.0.2)
- `ngx-trend` (8.0.1)
- `react-complaint-image` (0.0.35)
- `react-jsonschema-form-conditionals` (0.3.21)
- `react-jsonschema-form-extras` (1.0.4)
- `rxnt-authentication` (0.0.6)
- `rxnt-healthchecks-nestjs` (1.0.5)
- `rxnt-kue` (1.0.7)
- `swc-plugin-component-annotate` (1.9.2)
- `ts-gaussian` (3.0.6)

#### 🔧 Technical Improvements
- **Enhanced Pattern Matching**: Improved regex patterns for better detection accuracy
- **YAML File Support**: Added scanning of GitHub Actions workflow files (.yml/.yaml)
- **Dynamic IOC Patterns**: Enhanced dynamic pattern creation from IOC database
- **Better Error Handling**: Improved error handling for file scanning operations
- **Performance Optimization**: Optimized pattern matching for faster scanning

#### 🧪 Testing
- Added comprehensive test cases for tinycolor attack patterns
- Created test project with malicious bundle.js and workflow files
- Verified detection of all new attack patterns
- Tested IOC database integration

### v2.2.0 - Data Architecture & Maintainability Improvements (September 16, 2025)

#### 🏗️ Major Architecture Improvements
- **Data Extraction**: Moved all hardcoded lists to organized JSON files in `data/` directory
- **Modular Data Structure**: Separated attack data into dedicated files for better maintainability
- **Centralized Configuration**: All patterns, versions, and validation rules now in data files
- **Improved Error Handling**: Added graceful fallbacks when data files are missing or corrupted

#### 📁 New Data Files
- **`data/qix-attack.json`**: QIX attack data (19 vulnerable packages + safe versions)
- **`data/tinycolor-attack.json`**: Tinycolor attack data (38 vulnerable packages + safe versions)  
- **`data/patterns.json`**: All detection patterns (20 patterns with metadata)
- **`data/validation.json`**: Validation arrays (log levels, file extensions, etc.)
- **Enhanced `data/whitelist.json`**: Improved whitelist patterns for better false positive reduction

#### 🐛 Bug Fixes
- **Fixed File Counting**: Resolved issue where "Files scanned: 0" was displayed incorrectly
- **Improved Whitelist Patterns**: Enhanced html2canvas whitelist to eliminate false positives
- **Better Pattern Matching**: Refined malicious bundle.js detection to be more specific
- **Enhanced Error Messages**: More descriptive error messages for debugging

#### ⚡ Performance Improvements
- **Faster Data Loading**: Optimized data loading from JSON files with caching
- **Better Memory Usage**: Reduced memory footprint by loading data on-demand
- **Improved Scanning Speed**: Clean projects now scan faster with better whitelist filtering
- **Enhanced Parallel Processing**: Better worker thread management for large projects

#### 🧪 Testing & Quality
- **Comprehensive Test Suite**: Added 15 comprehensive tests covering all functionality
- **Real-World Validation**: Tested on Bitfinex project (48,969 files, 0 false positives)
- **Data Integrity Tests**: Verified all attack data loads correctly from JSON files
- **Regression Testing**: Ensured no functionality lost during data extraction

#### 🔧 Developer Experience
- **Better Code Organization**: Cleaner separation of data and logic
- **Easier Maintenance**: Update attack data without touching code
- **Version Control Friendly**: Data changes are clearly visible in diffs
- **Extensible Architecture**: Easy to add new attacks or patterns
- **Improved Documentation**: Better inline documentation and comments

#### 📊 Technical Details
- **Data Loading**: All attack data now loaded from `data/` directory with error handling
- **Pattern Management**: 20 detection patterns organized by attack type
- **Package Database**: 57 total vulnerable packages (19 QIX + 38 Tinycolor)
- **Whitelist System**: Enhanced whitelist with version-aware checking
- **File Processing**: Improved file counting and scanning statistics

#### 🎯 Impact
- **Zero False Positives**: Clean projects now show 0 issues (Bitfinex: 48,969 files scanned, 0 issues)
- **100% Detection Accuracy**: All real threats still detected (malicious test: 17 issues found)
- **Better Maintainability**: Data updates require no code changes
- **Improved Performance**: Faster scanning with better resource utilization
- **Enhanced Reliability**: Graceful error handling and fallback mechanisms

### v2.0.0 - QIX Supply Chain Attack Detection (September 8, 2025)

#### 🆕 Initial Release
- **QIX Attack Detection**: Comprehensive detection for the September 8, 2025 supply chain attack
- **Package Vulnerability Scanning**: Detects compromised packages by version
- **Malicious Code Pattern Detection**: Scans JavaScript/TypeScript files for malicious patterns
- **Crypto Address Detection**: Identifies 280+ malicious crypto addresses
- **WebSocket Exfiltration Detection**: Detects malicious WebSocket endpoints
- **Network Interception Detection**: Identifies malicious network request overrides
- **NPM Cache Scanning**: Scans npm cache for vulnerable packages
- **Multiple Output Formats**: Console, JSON, Markdown, and combined output
- **Recursive Project Discovery**: Automatically finds all projects in subdirectories
- **Comprehensive Reporting**: Detailed remediation steps and project-specific information

## 🔧 Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--directory` | Directory to scan | Current directory |
| `--verbose` | Enable verbose output | true |
| `--format` | Output format (console/json/markdown/both) | both |
| `--concurrency` | Maximum parallel workers | Auto-calculated |
| `--timeout` | Worker timeout in milliseconds | 30000 |
| `--memory-limit` | Memory limit per worker in MB | 512 |
| `--no-node-modules` | Skip node_modules scanning | false |
| `--no-malicious-code` | Skip malicious code scanning | false |
| `--no-compromised-packages` | Skip compromised package scanning | false |
| `--no-npm-cache` | Skip NPM cache scanning | false |
| `--include-tests` | Include test files in scanning (excluded by default) | false |
| `--strict` | Enable strict mode (fail on high severity issues) | false |
| `--help` | Show help information | - |

## 📋 Requirements

- Node.js 18.0.0 or higher
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
# Run all tests
npm run test:all

# Run unit tests only
npm run test:unit

# Run integration tests only
npm run test:integration

# Run linting
npm run lint:check

# Fix linting issues
npm run lint:fix

# Test the scan-projects script
./scan-projects
```

## 🔄 CI/CD Integration

This project includes GitHub Actions for continuous integration:

- **Multi-Node Testing**: Tests on Node.js 18.x, 20.x, and 22.x
- **Automated Security Scanning**: Scans the project itself for vulnerabilities
- **Artifact Generation**: Uploads security reports as build artifacts
- **Pull Request Validation**: Runs on every PR to ensure code quality

### GitHub Actions Workflow

The CI pipeline includes:
1. **Dependency Installation**: Uses `npm ci` for faster, reliable installs
2. **Test Execution**: Runs the test suite across multiple Node.js versions
3. **Security Scanning**: Scans the project for malicious patterns
4. **Report Generation**: Creates and uploads security scan reports

### Badges

- ![CI](https://github.com/arif-dewi/npm-security-scanner/workflows/CI/badge.svg) - Build status
- ![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg) - Node.js compatibility
- ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) - MIT License
- ![Security Scanner](https://img.shields.io/badge/security-scanner-red.svg) - Security tool

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 References

### QIX Supply Chain Attack
- [SEAL Alliance - QIX Supply Chain Attack Report](https://www.securityalliance.org/news/2025-09-npm-supply-chain)
- [JDSTAERK - Malicious Code Analysis](https://jdstaerk.substack.com/p/we-just-found-malicious-code-in-the)
- [PHXGG - Detection Script](https://gist.github.com/phxgg/737198b6e945aba7046e9f9328576271)
- [AndrewMohawk - Dependency Scanner](https://github.com/AndrewMohawk/RandomScripts/blob/main/scan_for_deps_qix-2025-08-09.sh)

### Tinycolor Supply Chain Attack
- [Socket.dev - Tinycolor Supply Chain Attack Report](https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages)
- [Socket.dev - DuckDB npm Account Compromised](https://socket.dev/blog/duckdb-npm-account-compromised-in-continuing-supply-chain-attack)
- [Socket.dev - npm Author Qix Compromised](https://socket.dev/blog/npm-author-qix-compromised-via-phishing-email-in-major-supply-chain-attack)

## ⚠️ Disclaimer

This tool is provided for educational and security purposes. While we strive to keep the detection patterns up-to-date, this scanner may not catch all variations of malicious code. Always verify results and consult with security professionals for critical systems.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you find any issues or have questions:

1. Check the [Issues](https://github.com/arif-dewi/npm-security-scanner/issues) page
2. Create a new issue with detailed information

---

**Stay secure! 🔒**
