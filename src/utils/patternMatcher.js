/**
 * Pattern matching utilities for security scanning
 * Handles malicious code pattern detection and validation
 */

const path = require('path');
const fs = require('fs');

class PatternMatcher {
  constructor(logger) {
    this.logger = logger;
    this.patterns = this.initializePatterns();
    this.whitelistData = this.loadWhitelistData();
    this.whitelistPatterns = this.initializeWhitelistPatterns();
  }

  /**
   * Initialize malicious code patterns
   * @returns {Array} Array of pattern objects
   * @private
   */
  initializePatterns() {
    return [
      // QIX Supply Chain Attack Patterns (Sept 2025)
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
      },

      // Tinycolor Supply Chain Attack Patterns (Sept 2025)
      {
        name: 'Malicious Bundle.js Content',
        pattern: /bundle\.js.*?(?:trufflehog|webhook\.site|execSync.*trufflehog|process\.env\.(?:GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)|169\.254\.169\.254|metadata\.google\.internal)/gi,
        severity: 'HIGH',
        description: 'Detects bundle.js files containing malicious content like TruffleHog execution, webhook exfiltration, or credential theft'
      },
      {
        name: 'Tinycolor Attack Bundle.js Structure',
        pattern: /(?:function\s+trufflehogUrl\(\)|function\s+runScanner\(|const\s*imdsV4\s*=\s*['"]http:\/\/169\.254\.169\.254['"]|const\s*webhookUrl\s*=\s*['"]https:\/\/webhook\.site\/|execSync.*trufflehog|trufflehog.*execSync)/gi,
        severity: 'HIGH',
        description: 'Detects the specific malicious bundle.js structure from the tinycolor attack with TruffleHog execution and credential theft'
      },
      {
        name: 'TruffleHog Binary Download',
        pattern: /trufflehog.*\.(zip|tar\.gz)|github\.com\/trufflesecurity\/trufflehog\/releases\/download/gi,
        severity: 'HIGH',
        description: 'Detects TruffleHog binary downloads used for credential scanning'
      },
      {
        name: 'Webhook Exfiltration Endpoint',
        pattern: /webhook\.site\/[a-f0-9-]+|hxxps?:\/\/webhook\[\.\]site/gi,
        severity: 'HIGH',
        description: 'Detects webhook.site endpoints used for data exfiltration'
      },
      {
        name: 'Cloud Metadata Discovery',
        pattern: /169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254/gi,
        severity: 'HIGH',
        description: 'Detects cloud metadata endpoint access for credential theft'
      },
      {
        name: 'GitHub Actions Workflow Creation',
        pattern: /\.github\/workflows\/.*\.yml|shai-hulud-workflow/gi,
        severity: 'HIGH',
        description: 'Detects suspicious GitHub Actions workflow creation'
      },
      {
        name: 'Environment Variable Theft',
        pattern: /process\.env\.(GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)/gi,
        severity: 'HIGH',
        description: 'Detects access to sensitive environment variables'
      },
      {
        name: 'NPM Token Validation',
        pattern: /registry\.npmjs\.org\/-\/whoami|Authorization.*Bearer.*NPM_TOKEN/gi,
        severity: 'HIGH',
        description: 'Detects NPM token validation attempts'
      },
      {
        name: 'GitHub API Token Usage',
        pattern: /api\.github\.com\/user.*Authorization.*token.*GITHUB_TOKEN/gi,
        severity: 'HIGH',
        description: 'Detects GitHub API token usage for credential validation'
      },
      {
        name: 'Base64 Data Exfiltration',
        pattern: /base64.*-w0.*curl.*-s.*-X.*POST/gi,
        severity: 'HIGH',
        description: 'Detects base64 encoding and curl POST for data exfiltration'
      },
      {
        name: 'ExecSync Command Execution',
        pattern: /execSync.*trufflehog.*filesystem/gi,
        severity: 'HIGH',
        description: 'Detects execSync calls to TruffleHog filesystem scanner'
      },
      {
        name: 'Suspicious File Creation',
        pattern: /findings\.json|\.github\/workflows\/.*\.yml/gi,
        severity: 'MEDIUM',
        description: 'Detects creation of suspicious files for data collection'
      }
    ];
  }

  /**
   * Load whitelist data from JSON file
   * @returns {Object} Whitelist data object
   * @private
   */
  loadWhitelistData() {
    try {
      const whitelistPath = path.join(__dirname, '..', '..', 'data', 'whitelist.json');
      const whitelistContent = fs.readFileSync(whitelistPath, 'utf8');
      const whitelistData = JSON.parse(whitelistContent);
      this.logger.debug('Whitelist data loaded successfully', {
        librariesCount: whitelistData.libraries.length,
        versionChecksEnabled: whitelistData.versionChecks.enabled
      });
      return whitelistData;
    } catch (error) {
      this.logger.warn('Failed to load whitelist data, using empty whitelist', { error: error.message });
      return { libraries: [], versionChecks: { enabled: false } };
    }
  }

  /**
   * Check if a package version is whitelisted
   * @param {string} packageName - Name of the package
   * @param {string} version - Version of the package
   * @param {string} projectPath - Path to the project (to check package.json)
   * @returns {boolean} True if version is whitelisted
   * @private
   */
  isVersionWhitelisted(packageName, _version, _projectPath) {
    if (!this.whitelistData.versionChecks.enabled) {
      return true; // If version checking is disabled, allow all versions
    }

    // Find the library in whitelist
    const library = this.whitelistData.libraries.find(lib =>
      lib.name === packageName || packageName.includes(lib.name)
    );

    if (!library) {
      return false; // Package not in whitelist
    }

    // Check if all versions are whitelisted
    if (library.versions.all === true) {
      return true;
    }

    // Check specific version ranges (future enhancement)
    if (library.versions.ranges) {
      // TODO: Implement version range checking
      return true; // For now, allow all versions if ranges are defined
    }

    return false;
  }

  /**
   * Initialize whitelist patterns for known legitimate libraries
   * @returns {Array} Array of whitelist pattern objects
   * @private
   */
  initializeWhitelistPatterns() {
    const patterns = [];

    for (const library of this.whitelistData.libraries) {
      for (const patternStr of library.patterns) {
        try {
          const pattern = new RegExp(patternStr, 'i');
          patterns.push({
            name: library.name,
            pattern,
            description: library.description,
            library
          });
        } catch (error) {
          this.logger.warn('Invalid whitelist pattern', {
            library: library.name,
            pattern: patternStr,
            error: error.message
          });
        }
      }
    }

    this.logger.debug('Whitelist patterns initialized', {
      patternsCount: patterns.length,
      librariesCount: this.whitelistData.libraries.length
    });

    return patterns;
  }

  /**
   * Check if a file path matches any whitelist patterns
   * @param {string} filePath - Path to the file to check
   * @param {string} projectPath - Path to the project (for version checking)
   * @returns {Object|null} Whitelist match object or null if no match
   * @private
   */
  isWhitelisted(filePath, projectPath = null) {
    for (const whitelistPattern of this.whitelistPatterns) {
      if (whitelistPattern.pattern.test(filePath)) {
        // If version checking is enabled, verify the package version
        if (this.whitelistData.versionChecks.enabled && projectPath) {
          const packageInfo = this.extractPackageInfoFromPath(filePath, projectPath);
          if (packageInfo && !this.isVersionWhitelisted(packageInfo.name, packageInfo.version, projectPath)) {
            this.logger.debug('File whitelisted but version not whitelisted', {
              file: filePath,
              package: packageInfo.name,
              version: packageInfo.version,
              library: whitelistPattern.name
            });
            // Skip this whitelist match
          } else {
            return whitelistPattern;
          }
        } else {
          return whitelistPattern;
        }
      }
    }
    return null;
  }

  /**
   * Extract package information from file path
   * @param {string} filePath - Path to the file
   * @param {string} projectPath - Path to the project
   * @returns {Object|null} Package info object or null
   * @private
   */
  extractPackageInfoFromPath(filePath, _projectPath) {
    try {
      // Look for node_modules in the path
      const nodeModulesIndex = filePath.indexOf('node_modules/');
      if (nodeModulesIndex === -1) {
        return null;
      }

      // Extract package name and version from path
      const relativePath = filePath.substring(nodeModulesIndex + 'node_modules/'.length);
      const pathParts = relativePath.split('/');

      if (pathParts.length < 2) {
        return null;
      }

      let packageName = pathParts[0];
      let version = null;

      // Handle scoped packages (@scope/package)
      if (packageName.startsWith('@') && pathParts.length >= 3) {
        packageName = `${packageName}/${pathParts[1]}`;
        version = pathParts[2];
      } else {
        version = pathParts[1];
      }

      return { name: packageName, version };
    } catch (error) {
      this.logger.debug('Failed to extract package info from path', { filePath, error: error.message });
      return null;
    }
  }

  /**
   * Scan JavaScript files in a project for malicious patterns
   * @param {string} projectPath - Path to the project
   * @param {Object} iocs - Indicators of Compromise
   * @param {string} parentProjectName - Optional parent project name (for node_modules scans)
   * @param {boolean} excludeNodeModules - Whether to exclude node_modules from scanning
   * @param {string} mainProjectPath - Main project path for relative path calculation
   * @param {Object} config - Configuration object with test exclusion settings
   * @returns {Promise<Object>} Object with issues array and filesScanned count
   */
  async scanJavaScriptFiles(projectPath, iocs = {}, parentProjectName = null, excludeNodeModules = false, mainProjectPath = null, config = null) {
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

      // Add test file patterns if test exclusion is enabled
      if (config && config.get && config.get('security.excludeTestFiles')) {
        const testPatterns = config.getTestFilePatterns ? config.getTestFilePatterns() : [
          '**/test/**',
          '**/tests/**',
          '**/__tests__/**',
          '**/*.test.*',
          '**/*.spec.*',
          '**/test.*',
          '**/spec.*',
          '**/test-*',
          '**/spec-*',
          '**/*.test',
          '**/*.spec'
        ];
        ignorePatterns.push(...testPatterns);
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
            // Always count files that are processed
            filesScanned++;

            // Check if file is whitelisted
            if (this.isWhitelisted(filePath, projectPath)) {
              this.logger.debug('File whitelisted, skipping malicious pattern detection', { file });
            } else {
              const content = fs.readFileSync(filePath, 'utf8');
              this.logger.debug('Read file content', { file, contentLength: content.length });
              const issues = this.scanFileContent(content, filePath, projectPath, iocs, parentProjectName, mainProjectPath);
              if (issues.length > 0) {
                this.logger.debug('Found issues in file', { file, issuesCount: issues.length });
              }
              results.push(...issues);
            }
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

      // Also scan YAML files for GitHub Actions workflows
      const yamlFiles = await glob('**/*.{yml,yaml}', {
        cwd: projectPath,
        ignore: ignorePatterns
      });

      this.logger.debug('Found YAML files to scan', { count: yamlFiles.length, files: yamlFiles.slice(0, 5) });

      for (const file of yamlFiles) {
        const filePath = path.join(projectPath, file);
        this.logger.debug('Processing YAML file', { file, filePath });

        try {
          if (!fs.statSync(filePath).isFile()) {
            this.logger.debug('Skipping directory', { file: filePath });
          } else {
            // Always count files that are processed
            filesScanned++;

            // Check if file is whitelisted
            if (this.isWhitelisted(filePath, projectPath)) {
              this.logger.debug('YAML file whitelisted, skipping malicious pattern detection', { file });
            } else {
              const content = fs.readFileSync(filePath, 'utf8');
              this.logger.debug('Read YAML file content', { file, contentLength: content.length });
              const issues = this.scanYamlFileContent(content, filePath, projectPath, iocs, parentProjectName, mainProjectPath);
              if (issues.length > 0) {
                this.logger.debug('Found issues in YAML file', { file, issuesCount: issues.length });
              }
              results.push(...issues);
            }
          }
        } catch (error) {
          if (error.code === 'EISDIR') {
            this.logger.debug('Skipping directory', { file: filePath });
          } else {
            this.logger.debug('Error reading YAML file', { file: filePath, error: error.message });
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

    // Create patterns for webhook exfiltration endpoints
    if (iocs.webhookEndpoints && iocs.webhookEndpoints.length > 0) {
      const webhookPattern = iocs.webhookEndpoints.map(endpoint =>
        endpoint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'Webhook Exfiltration Endpoint',
        pattern: new RegExp(`(${webhookPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects webhook endpoints used for data exfiltration'
      });
    }

    // Create patterns for cloud metadata endpoints
    if (iocs.cloudMetadataEndpoints && iocs.cloudMetadataEndpoints.length > 0) {
      const metadataPattern = iocs.cloudMetadataEndpoints.map(endpoint =>
        endpoint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'Cloud Metadata Discovery',
        pattern: new RegExp(`(${metadataPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects cloud metadata endpoint access for credential theft'
      });
    }

    // Create patterns for TruffleHog URLs
    if (iocs.truffleHogUrls && iocs.truffleHogUrls.length > 0) {
      const trufflePattern = iocs.truffleHogUrls.map(url =>
        url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'TruffleHog Binary Download',
        pattern: new RegExp(`(${trufflePattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects TruffleHog binary downloads used for credential scanning'
      });
    }

    // Create patterns for suspicious workflow names
    if (iocs.suspiciousWorkflowNames && iocs.suspiciousWorkflowNames.length > 0) {
      const workflowPattern = iocs.suspiciousWorkflowNames.map(name =>
        name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'Suspicious GitHub Workflow',
        pattern: new RegExp(`(${workflowPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects suspicious GitHub Actions workflow names'
      });
    }

    // Create patterns for environment variables
    if (iocs.environmentVariables && iocs.environmentVariables.length > 0) {
      const envPattern = iocs.environmentVariables.map(env =>
        env.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      ).join('|');

      patterns.push({
        name: 'Sensitive Environment Variable Access',
        pattern: new RegExp(`process\\.env\\.(${envPattern})`, 'gi'),
        severity: 'HIGH',
        description: 'Detects access to sensitive environment variables'
      });
    }

    return patterns;
  }

  /**
   * Scan YAML file content for malicious patterns (GitHub Actions workflows)
   * @param {string} content - YAML file content
   * @param {string} filePath - File path
   * @param {string} projectPath - Project path
   * @param {Object} iocs - Indicators of Compromise
   * @param {string} parentProjectName - Optional parent project name
   * @param {string} mainProjectPath - Main project path for relative path calculation
   * @returns {Array} Array of malicious patterns found
   */
  scanYamlFileContent(content, filePath, projectPath, _iocs = {}, parentProjectName = null, mainProjectPath = null) {
    const maliciousCode = [];
    const projectName = parentProjectName || path.basename(projectPath);
    const relativePath = path.relative(mainProjectPath || projectPath, filePath);

    // Check if this is a GitHub Actions workflow file
    const isWorkflowFile = filePath.includes('.github/workflows/') || filePath.includes('.github/workflows\\');

    if (isWorkflowFile) {
      // Check for suspicious workflow patterns
      const workflowPatterns = [
        {
          name: 'Suspicious Workflow Name',
          pattern: /shai-hulud-workflow|workflow\.yml/gi,
          severity: 'HIGH',
          description: 'Detects suspicious GitHub Actions workflow names'
        },
        {
          name: 'Webhook Exfiltration in Workflow',
          pattern: /webhook\.site\/[a-f0-9-]+|hxxps?:\/\/webhook\[\.\]site/gi,
          severity: 'HIGH',
          description: 'Detects webhook exfiltration endpoints in GitHub Actions workflow'
        },
        {
          name: 'Base64 Data Exfiltration in Workflow',
          pattern: /base64.*-w0.*curl.*-s.*-X.*POST/gi,
          severity: 'HIGH',
          description: 'Detects base64 encoding and curl POST for data exfiltration in workflow'
        },
        {
          name: 'Suspicious File Access in Workflow',
          pattern: /findings\.json|cat.*findings\.json/gi,
          severity: 'HIGH',
          description: 'Detects access to findings.json file in workflow'
        },
        {
          name: 'Environment Variable Access in Workflow',
          pattern: /\$\{\{.*secrets\.(GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY).*\}\}/gi,
          severity: 'HIGH',
          description: 'Detects access to sensitive secrets in GitHub Actions workflow'
        }
      ];

      for (const pattern of workflowPatterns) {
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
    }

    return maliciousCode;
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

    // Note: Whitelist check is now done before calling this method

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
   * Get all whitelist patterns
   * @returns {Array} Array of whitelist pattern objects
   */
  getWhitelistPatterns() {
    return this.whitelistPatterns;
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
