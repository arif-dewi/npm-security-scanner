/**
 * Pattern matching utilities for security scanning
 * Handles malicious code pattern detection and validation
 */

const path = require('path');

class PatternMatcher {
  constructor(logger) {
    this.logger = logger;
    this.patterns = this.initializePatterns();
  }

  /**
   * Initialize malicious code patterns
   * @returns {Array} Array of pattern objects
   * @private
   */
  initializePatterns() {
    return [
      {
        name: 'Ethereum Wallet Hook',
        pattern: /checkethereumw|window\.ethereum\.(request|send|sendAsync)/gi,
        severity: 'HIGH',
        description: 'Detects the main malicious function that hooks into Ethereum wallets'
      },
      {
        name: 'Crypto Address Replacement',
        pattern: /0x[a-fA-F0-9]{40}/g,
        severity: 'HIGH',
        description: 'Detects hardcoded malicious Ethereum address used for fund theft'
      },
      {
        name: 'WebSocket Data Exfiltration',
        pattern: /new\s+WebSocket\s*\(\s*['"`][^'"`]*['"`]\s*\)/gi,
        severity: 'HIGH',
        description: 'Detects malicious WebSocket endpoint for data exfiltration'
      },
      {
        name: 'Fake NPM Domain',
        pattern: /npmjs\.help|npmjs\.org\.help/gi,
        severity: 'MEDIUM',
        description: 'Detects fake NPM domain used in phishing attacks'
      },
      {
        name: 'Fetch/XMLHttpRequest Override',
        pattern: /(window\.fetch\s*=|XMLHttpRequest\.prototype\.(open|send)\s*=)/gi,
        severity: 'HIGH',
        description: 'Detects malicious override of network request functions'
      },
      {
        name: 'Malicious Network Interception',
        pattern: /(originalFetch|originalOpen|originalSend).*\.(fetch|XMLHttpRequest).*replace/gi,
        severity: 'HIGH',
        description: 'Detects malicious network request interception patterns'
      },
      {
        name: 'Levenshtein Distance Calculation',
        pattern: /levenshtein.*distance.*address|address.*levenshtein.*distance.*replace/gi,
        severity: 'LOW',
        description: 'Detects potential address similarity calculation for replacement'
      }
    ];
  }

  /**
   * Scan JavaScript files in a project for malicious patterns
   * @param {string} projectPath - Path to the project
   * @param {Object} iocs - Indicators of Compromise
   * @param {string} parentProjectName - Optional parent project name (for node_modules scans)
   * @param {boolean} excludeNodeModules - Whether to exclude node_modules from scanning
   * @param {string} mainProjectPath - Main project path for relative path calculation
   * @returns {Promise<Object>} Object with issues array and filesScanned count
   */
  async scanJavaScriptFiles(projectPath, iocs = {}, parentProjectName = null, excludeNodeModules = false, mainProjectPath = null) {
    const fs = require('fs');
    const path = require('path');
    const { glob } = require('glob');

    const results = [];
    let filesScanned = 0;

    try {
      // Find all JavaScript and TypeScript files
      const ignorePatterns = ['coverage/**', 'dist/**', 'build/**', 'dev-dist/**'];
      if (excludeNodeModules) {
        ignorePatterns.push('node_modules/**');
      }

      const jsFiles = await glob('**/*.{js,ts,tsx,jsx}', {
        cwd: projectPath,
        ignore: ignorePatterns
      });

      this.logger.debug('Found files to scan', { count: jsFiles.length, files: jsFiles.slice(0, 5) });

      for (const file of jsFiles) {
        const filePath = path.join(projectPath, file);
        this.logger.debug('Processing file', { file, filePath });

        try {
          // Check if it's actually a file, not a directory
          if (!fs.statSync(filePath).isFile()) {
            this.logger.debug('Skipping directory', { file: filePath });
          } else {
            const content = fs.readFileSync(filePath, 'utf8');
            this.logger.debug('Read file content', { file, contentLength: content.length });
            const issues = this.scanFileContent(content, filePath, projectPath, iocs, parentProjectName, mainProjectPath);
            this.logger.debug('Found issues in file', { file, issuesCount: issues.length });
            results.push(...issues);
            filesScanned++;
          }
        } catch (error) {
          // Only log EISDIR errors in debug mode, suppress others
          if (error.code === 'EISDIR') {
            this.logger.debug('Skipping directory', { file: filePath });
          } else {
            this.logger.debug('Error reading file', { file: filePath, error: error.message });
          }
        }
      }
    } catch (error) {
      this.logger.error('Error scanning JavaScript files', { projectPath, error: error.message });
    }

    return { issues: results, filesScanned };
  }

  /**
   * Create dynamic patterns from IOC data
   * @param {Object} iocs - Indicators of Compromise
   * @returns {Array} Array of dynamic patterns
   * @private
   */
  createDynamicPatterns(iocs) {
    const patterns = [];

    // Create patterns for malicious domains
    if (iocs.domains && iocs.domains.length > 0) {
      const domainPattern = iocs.domains.map(domain =>
        domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') // Escape regex special chars
      ).join('|');

      patterns.push({
        name: 'CDN Malware Hosting',
        pattern: new RegExp(`(https?://)?(${domainPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects malicious CDN domains used for hosting malware'
      });
    }

    // Create patterns for malicious IP addresses
    if (iocs.ipAddresses && iocs.ipAddresses.length > 0) {
      const ipPattern = iocs.ipAddresses.map(ip =>
        ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'Malicious IP Address',
        pattern: new RegExp(`(https?://)?(${ipPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects malicious IP addresses used for hosting malware'
      });
    }

    return patterns;
  }

  /**
   * Scan file content for malicious patterns
   * @param {string} content - File content
   * @param {string} filePath - File path
   * @param {string} projectName - Project name
   * @param {Object} iocs - Indicators of Compromise
   * @returns {Array} Array of malicious patterns found
   */
  scanFileContent(content, filePath, projectPath, iocs = {}, parentProjectName = null, mainProjectPath = null) {
    const maliciousCode = [];
    const projectName = parentProjectName || path.basename(projectPath);
    const relativePath = path.relative(mainProjectPath || projectPath, filePath);

    // Check against known patterns
    for (const pattern of this.patterns) {
      const matches = content.match(pattern.pattern);
      if (matches) {
        const lines = content.split('\n');
        const matchLines = matches.map(match => {
          const lineIndex = lines.findIndex(line => line.includes(match));
          return lineIndex + 1;
        });

        maliciousCode.push({
          project: projectName,
          file: require('path').basename(filePath),
          relativePath,
          pattern: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          matches: matches.length,
          lines: matchLines
        });
      }
    }

    // Check against dynamic patterns from IOCs
    const dynamicPatterns = this.createDynamicPatterns(iocs);
    for (const pattern of dynamicPatterns) {
      const matches = content.match(pattern.pattern);
      if (matches) {
        const lines = content.split('\n');
        const matchLines = matches.map(match => {
          const lineIndex = lines.findIndex(line => line.includes(match));
          return lineIndex + 1;
        });

        maliciousCode.push({
          project: projectName,
          file: require('path').basename(filePath),
          relativePath,
          pattern: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          matches: matches.length,
          lines: matchLines
        });
      }
    }

    // Check for suspicious addresses
    const addressPattern = /0x[a-fA-F0-9]{40}/g;
    const addresses = content.match(addressPattern);
    if (addresses) {
      for (const address of addresses) {
        if (this.isSuspiciousAddress(address, iocs)) {
          maliciousCode.push({
            project: projectName,
            file: require('path').basename(filePath),
            pattern: 'Suspicious Address',
            severity: 'HIGH',
            description: `Suspicious crypto address found: ${address}`,
            matches: 1,
            lines: [content.split('\n').findIndex(line => line.includes(address)) + 1]
          });
        }
      }
    }

    return maliciousCode;
  }

  /**
   * Check if address is suspicious
   * @param {string} address - Address to check
   * @param {Object} iocs - Indicators of Compromise
   * @returns {boolean} Whether address is suspicious
   * @private
   */
  isSuspiciousAddress(address, iocs) {
    if (!iocs.cryptoAddresses) return false;
    return iocs.cryptoAddresses.includes(address.toLowerCase());
  }

  /**
   * Get all patterns
   * @returns {Array} Array of pattern objects
   */
  getPatterns() {
    return this.patterns;
  }

  /**
   * Add custom pattern
   * @param {Object} pattern - Pattern object
   */
  addPattern(pattern) {
    this.patterns.push(pattern);
    this.logger.debug('Custom pattern added', { name: pattern.name });
  }

  /**
   * Remove pattern by name
   * @param {string} name - Pattern name
   * @returns {boolean} Whether pattern was removed
   */
  removePattern(name) {
    const index = this.patterns.findIndex(p => p.name === name);
    if (index !== -1) {
      this.patterns.splice(index, 1);
      this.logger.debug('Pattern removed', { name });
      return true;
    }
    return false;
  }
}

module.exports = PatternMatcher;
