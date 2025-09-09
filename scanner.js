const fs = require('fs');
const path = require('path');
const { glob } = require('glob');
const chalk = require('chalk').default || require('chalk');
const ora = require('ora');
const { table } = require('table');
const { Command } = require('commander');

class NPMSecurityScanner {
  constructor(options = {}) {
    this.options = {
      directory: options.directory || process.cwd(),
      verbose: options.verbose || false,
      output: options.output || 'console'
    };

    // Load IoCs from JSON file
    this.iocs = this.loadIOCs();
    
    this.results = {
      compromisedPackages: [],
      maliciousCode: [],
      suspiciousFiles: [],
      vulnerableVersions: [],
      npmCacheIssues: [],
      packageLockIssues: [],
      summary: {
        totalFilesScanned: 0,
        totalPackagesChecked: 0,
        issuesFound: 0
      }
    };

    // Compromised packages by qix author (expanded list)
    this.compromisedPackages = [
      'chalk', 'debug-js', 'debug', 'supports-color', 'has-flag', 'is-fullwidth-code-point',
      'strip-ansi', 'ansi-regex', 'wrap-ansi', 'string-width', 'ansi-styles', 
      'color-convert', 'color-name', 'escape-string-regexp', 'ms', 'has-ansi',
      'supports-hyperlinks', 'chalk-template', 'backslash', 'simple-swizzle',
      'color-string', 'error-ex', 'is-arrayish', 'slice-ansi'
    ];

    // Additional packages to check in package-lock.json
    this.packageLockPackages = [
      'backslash', 'chalk-template', 'supports-hyperlinks', 'has-ansi',
      'simple-swizzle', 'color-string', 'error-ex', 'color-name',
      'is-arrayish', 'slice-ansi', 'color-convert', 'wrap-ansi',
      'ansi-regex', 'supports-color', 'strip-ansi', 'chalk', 'debug',
      'ansi-styles'
    ];

    // Vulnerable versions to check
    this.vulnerableVersions = [
      { name: 'backslash', version: '0.2.1' },
      { name: 'chalk', version: '5.6.1' },
      { name: 'chalk-template', version: '1.1.1' },
      { name: 'color-convert', version: '3.1.1' },
      { name: 'color-name', version: '2.0.1' },
      { name: 'color-string', version: '2.1.1' },
      { name: 'wrap-ansi', version: '9.0.1' },
      { name: 'supports-hyperlinks', version: '4.1.1' },
      { name: 'strip-ansi', version: '7.1.1' },
      { name: 'slice-ansi', version: '7.1.1' },
      { name: 'simple-swizzle', version: '0.2.3' },
      { name: 'is-arrayish', version: '0.3.3' },
      { name: 'error-ex', version: '1.3.3' },
      { name: 'ansi-regex', version: '6.2.1' },
      { name: 'ansi-styles', version: '6.2.2' },
      { name: 'supports-color', version: '10.2.1' },
      { name: 'debug', version: '4.4.2' },
      { name: 'color', version: '5.0.1' },
      { name: 'has-ansi', version: '6.0.1' }
    ];

    // Safe versions recommended by JD Stärk
    this.safeVersions = {
      'chalk': '5.3.0',
      'strip-ansi': '7.1.0',
      'color-convert': '2.0.1',
      'color-name': '1.1.4',
      'is-core-module': '2.13.1',
      'error-ex': '1.3.2',
      'has-ansi': '5.0.1'
    };

    // Malicious code patterns to detect (enhanced with JD Stärk analysis)
    this.maliciousPatterns = [
      {
        name: 'Ethereum Wallet Hook',
        pattern: /checkethereumw/gi,
        severity: 'HIGH',
        description: 'Detects the main malicious function that hooks into Ethereum wallets'
      },
      {
        name: 'Obfuscated Code Pattern',
        pattern: /const _0x[a-f0-9]+=_0x[a-f0-9]+;/gi,
        severity: 'HIGH',
        description: 'Detects heavily obfuscated JavaScript code typical of malware'
      },
      {
        name: 'Crypto Address Replacement',
        pattern: /0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976/gi,
        severity: 'HIGH',
        description: 'Detects hardcoded malicious Ethereum address used for fund theft'
      },
      {
        name: 'Solana Address Replacement',
        pattern: /19111111111111111111111111111111/gi,
        severity: 'HIGH',
        description: 'Detects hardcoded malicious Solana address used for fund theft'
      },
      {
        name: 'WebSocket Data Exfiltration',
        pattern: /websocket-api2\.publicvm\.com/gi,
        severity: 'HIGH',
        description: 'Detects malicious WebSocket endpoint for data exfiltration'
      },
      {
        name: 'CDN Malware Hosting',
        pattern: /(static-mw-host|img-data-backup)\.b-cdn\.net/gi,
        severity: 'HIGH',
        description: 'Detects malicious CDN domains used for hosting malware'
      },
      {
        name: 'Fake NPM Domain',
        pattern: /npmjs\.help/gi,
        severity: 'MEDIUM',
        description: 'Detects fake NPM domain used in phishing attacks'
      },
      {
        name: 'Ethereum Function Hooking',
        pattern: /window\.ethereum.*(request|send|sendAsync)/gi,
        severity: 'MEDIUM',
        description: 'Detects potential Ethereum function hooking patterns'
      },
      {
        name: 'Fetch/XMLHttpRequest Override',
        pattern: /(window\.fetch\s*=|XMLHttpRequest\.prototype\.(open|send)\s*=)/gi,
        severity: 'HIGH',
        description: 'Detects malicious override of network request functions'
      },
      {
        name: 'Malicious Network Interception',
        pattern: /(originalFetch|originalOpen|originalSend).*fetch|XMLHttpRequest/gi,
        severity: 'HIGH',
        description: 'Detects malicious network request interception patterns'
      },
      {
        name: 'Levenshtein Distance Calculation',
        pattern: /levenshtein.*distance/gi,
        severity: 'LOW',
        description: 'Detects potential address similarity calculation for replacement'
      },
      {
        name: 'Stealth Proxy Control',
        pattern: /window\.stealthProxyControl/gi,
        severity: 'HIGH',
        description: 'Detects stealth proxy control object used by the malware'
      },
      {
        name: 'Crypto Transaction Interception',
        pattern: /eth_sendTransaction|solana_signTransaction|solana_signAndSendTransaction/gi,
        severity: 'HIGH',
        description: 'Detects crypto transaction interception patterns'
      },
      {
        name: 'Obfuscated Function Calls',
        pattern: /_0x[a-f0-9]+\(/gi,
        severity: 'MEDIUM',
        description: 'Detects obfuscated function calls typical of malware'
      },
      {
        name: 'Wallet Detection Code',
        pattern: /typeof window.*ethereum.*undefined/gi,
        severity: 'MEDIUM',
        description: 'Detects wallet detection logic used by the malware'
      }
    ];

    // Get all suspicious addresses from IoCs
    this.suspiciousAddresses = [
      ...this.iocs.bitcoin,
      ...this.iocs.tron,
      ...this.iocs.ethereum,
      ...this.iocs.solana,
      ...this.iocs.bitcoinCash
    ];
  }

  loadIOCs() {
    try {
      const iocsPath = path.join(__dirname, 'data', 'iocs.json');
      return JSON.parse(fs.readFileSync(iocsPath, 'utf8'));
    } catch (error) {
      console.warn(chalk.yellow(`Warning: Could not load IoCs from data/iocs.json: ${error.message}`));
      return {
        bitcoin: [],
        tron: [],
        ethereum: [],
        solana: [],
        bitcoinCash: [],
        domains: [],
        ipAddresses: [],
        specialAddresses: {}
      };
    }
  }

  async scan() {
    if (!this.options.silent) {
      console.log(chalk.blue.bold('\n🔍 NPM Security Scanner - QIX Supply Chain Attack Detection\n'));
      console.log(chalk.gray(`Scanning directory: ${this.options.directory}`));
      console.log(chalk.gray('Scanning for compromised packages and malicious code patterns...\n'));
    }

    const spinner = ora('Initializing scan...').start();

    try {
      // Step 1: Find all projects recursively
      spinner.text = 'Discovering projects recursively...';
      const projects = await this.discoverProjects();
      console.log(chalk.gray(`Found ${projects.length} projects to scan`));

      // Step 2: Scan each project
      for (let i = 0; i < projects.length; i++) {
        const project = projects[i];
        spinner.text = `Scanning project ${i + 1}/${projects.length}: ${project.name}`;
        
        // Update current project context
        this.currentProject = project;
        
        // Scan this project
        await this.scanProject(project);
      }

      // Step 3: Generate comprehensive report
      spinner.text = 'Generating security report...';
      this.generateReport();
      
      // Step 4: Generate markdown report
      spinner.text = 'Generating markdown report...';
      await this.generateMarkdownReport();

      spinner.succeed('Security scan completed!');
      return this.results;

    } catch (error) {
      spinner.fail('Scan failed!');
      console.error(chalk.red('Error during scan:'), error.message);
      throw error;
    }
  }

  async discoverProjects() {
    const projects = [];
    
    // Find all directories containing package.json files
    const packageJsonFiles = await glob('**/package.json', {
      cwd: this.options.directory,
      ignore: [
        '**/node_modules/**', 
        '**/dist/**', 
        '**/build/**', 
        '**/.git/**',
        '**/security-check/**',  // Ignore the scanner itself
        '**/test-scanner.js'     // Ignore test files
      ]
    });

    for (const packageFile of packageJsonFiles) {
      const projectPath = path.dirname(path.join(this.options.directory, packageFile));
      const projectName = path.basename(projectPath);
      
      // Skip if this is the scanner directory itself
      if (projectName === 'security-check' && path.basename(this.options.directory) === 'security-check') {
        continue;
      }
      
      projects.push({
        name: projectName,
        path: projectPath,
        relativePath: path.relative(this.options.directory, projectPath),
        packageJsonPath: packageFile
      });
    }

    return projects;
  }

  async scanProject(project) {
    const originalDirectory = this.options.directory;
    this.options.directory = project.path;

    try {
      // Scan package.json files
      await this.scanPackageFiles();

      // Scan node_modules for compromised packages
      await this.scanNodeModules();

      // Scan package-lock.json files
      await this.scanPackageLockFiles();

      // Check npm cache for vulnerable packages
      await this.scanNpmCache();

      // Scan JavaScript files for malicious patterns (including node_modules)
      await this.scanJavaScriptFiles();
      
      // Additional focused scan of node_modules for compromised packages
      await this.scanNodeModulesForMaliciousCode();

    } finally {
      this.options.directory = originalDirectory;
    }
  }

  async scanPackageFiles() {
    const packageFiles = await glob('**/package.json', {
      cwd: this.options.directory,
      ignore: ['**/node_modules/**']
    });

    for (const packageFile of packageFiles) {
      this.results.summary.totalPackagesChecked++;
      
      try {
        const packagePath = path.join(this.options.directory, packageFile);
        const packageContent = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        
        const dependencies = {
          ...packageContent.dependencies || {},
          ...packageContent.devDependencies || {},
          ...packageContent.peerDependencies || {}
        };

        for (const [packageName, version] of Object.entries(dependencies)) {
          if (this.isVulnerableVersion(packageName, version)) {
            this.results.compromisedPackages.push({
              project: this.currentProject ? this.currentProject.name : 'Unknown',
              projectPath: this.currentProject ? this.currentProject.relativePath : '.',
              file: packageFile,
              package: packageName,
              version: version,
              severity: 'HIGH',
              description: `Vulnerable version ${version} of '${packageName}' found in dependencies`
            });
            this.results.summary.issuesFound++;
          }
        }
      } catch (error) {
        if (this.options.verbose) {
          console.warn(chalk.yellow(`Warning: Could not parse ${packageFile}: ${error.message}`));
        }
      }
    }
  }

  async scanNodeModules() {
    const nodeModulesPath = path.join(this.options.directory, 'node_modules');
    
    if (!fs.existsSync(nodeModulesPath)) {
      return;
    }

    for (const packageName of this.compromisedPackages) {
      const packagePath = path.join(nodeModulesPath, packageName);
      if (fs.existsSync(packagePath)) {
        try {
          // Read package.json to get the actual installed version
          const packageJsonPath = path.join(packagePath, 'package.json');
          if (fs.existsSync(packageJsonPath)) {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            const installedVersion = packageJson.version;
            
            if (this.isVulnerableVersion(packageName, installedVersion)) {
              this.results.compromisedPackages.push({
                project: this.currentProject ? this.currentProject.name : 'Unknown',
                projectPath: this.currentProject ? this.currentProject.relativePath : '.',
                file: `node_modules/${packageName}`,
                package: packageName,
                version: installedVersion,
                severity: 'HIGH',
                description: `Vulnerable version ${installedVersion} of '${packageName}' found in node_modules`
              });
              this.results.summary.issuesFound++;
            }
          }
        } catch (error) {
          if (this.options.verbose) {
            console.warn(chalk.yellow(`Warning: Could not read package.json for ${packageName}: ${error.message}`));
          }
        }
      }
    }
  }

  async scanPackageLockFiles() {
    const packageLockFiles = await glob('**/package-lock.json', {
      cwd: this.options.directory,
      ignore: ['**/node_modules/**']
    });

    for (const lockFile of packageLockFiles) {
      try {
        const lockPath = path.join(this.options.directory, lockFile);
        const lockContent = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        
        // Check for vulnerable packages in package-lock.json
        for (const vulnPackage of this.vulnerableVersions) {
          if (lockContent.packages) {
            // npm 7+ format
            for (const [packagePath, packageData] of Object.entries(lockContent.packages)) {
              if (packagePath.includes(`node_modules/${vulnPackage.name}`) && 
                  packageData.version === vulnPackage.version) {
                this.results.packageLockIssues.push({
                  file: lockFile,
                  package: vulnPackage.name,
                  version: vulnPackage.version,
                  severity: 'HIGH',
                  description: `Vulnerable version ${vulnPackage.version} of ${vulnPackage.name} found in package-lock.json`
                });
                this.results.summary.issuesFound++;
              }
            }
          } else if (lockContent.dependencies) {
            // npm 6 format
            this.checkDependenciesRecursive(lockContent.dependencies, vulnPackage, lockFile);
          }
        }
      } catch (error) {
        if (this.options.verbose) {
          console.warn(chalk.yellow(`Warning: Could not parse ${lockFile}: ${error.message}`));
        }
      }
    }
  }

  checkDependenciesRecursive(deps, vulnPackage, lockFile) {
    for (const [depName, depData] of Object.entries(deps)) {
      if (depName === vulnPackage.name && depData.version === vulnPackage.version) {
        this.results.packageLockIssues.push({
          file: lockFile,
          package: vulnPackage.name,
          version: vulnPackage.version,
          severity: 'HIGH',
          description: `Vulnerable version ${vulnPackage.version} of ${vulnPackage.name} found in package-lock.json`
        });
        this.results.summary.issuesFound++;
      }
      
      if (depData.dependencies) {
        this.checkDependenciesRecursive(depData.dependencies, vulnPackage, lockFile);
      }
    }
  }

  async scanNpmCache() {
    try {
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);
      
      // Get package names for npm cache check
      const packageNames = this.vulnerableVersions.map(p => p.name).join(' ');
      
      // Run npm cache ls command
      const { stdout } = await execAsync(`npm cache ls ${packageNames} 2>/dev/null || true`, {
        cwd: this.options.directory
      });
      
      // Check each vulnerable version
      for (const vulnPackage of this.vulnerableVersions) {
        if (stdout.includes(`${vulnPackage.name}-${vulnPackage.version}`)) {
          this.results.npmCacheIssues.push({
            package: vulnPackage.name,
            version: vulnPackage.version,
            severity: 'HIGH',
            description: `Vulnerable version ${vulnPackage.version} of ${vulnPackage.name} found in npm cache`
          });
          this.results.summary.issuesFound++;
        }
      }
    } catch (error) {
      if (this.options.verbose) {
        console.warn(chalk.yellow(`Warning: Could not check npm cache: ${error.message}`));
      }
    }
  }

  async scanJavaScriptFiles() {
    // CRITICAL: Scan node_modules for malicious patterns (QIX attack targets packages)
    const jsFiles = await glob('**/*.{js,ts,jsx,tsx,mjs,cjs}', {
      cwd: this.options.directory,
      ignore: ['**/dist/**', '**/build/**', '**/coverage/**', '**/reports/**']
    });

    for (const jsFile of jsFiles) {
      this.results.summary.totalFilesScanned++;
      
      try {
        const filePath = path.join(this.options.directory, jsFile);
        
        // Skip if it's a directory (some packages have .js directories)
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) {
          continue;
        }
        
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Check for malicious patterns
        for (const pattern of this.maliciousPatterns) {
          const matches = content.match(pattern.pattern);
          if (matches) {
            this.results.maliciousCode.push({
              project: this.currentProject ? this.currentProject.name : 'Unknown',
              projectPath: this.currentProject ? this.currentProject.relativePath : '.',
              file: jsFile,
              pattern: pattern.name,
              severity: pattern.severity,
              description: pattern.description,
              matches: matches.length,
              lineNumbers: this.getLineNumbers(content, pattern.pattern)
            });
            this.results.summary.issuesFound++;
          }
        }

        // Check for suspicious addresses
        for (const address of this.suspiciousAddresses) {
          if (content.includes(address)) {
            this.results.suspiciousFiles.push({
              file: jsFile,
              address: address,
              severity: 'HIGH',
              description: `Suspicious crypto address found: ${address}`
            });
            this.results.summary.issuesFound++;
          }
        }

      } catch (error) {
        // Only show warnings for non-directory errors in verbose mode
        if (this.options.verbose && !error.message.includes('EISDIR')) {
          console.warn(chalk.yellow(`Warning: Could not read ${jsFile}: ${error.message}`));
        }
      }
    }
  }

  /**
   * Scan node_modules specifically for malicious code patterns
   * This is critical for detecting QIX attack payloads in installed packages
   */
  async scanNodeModulesForMaliciousCode() {
    const nodeModulesPath = path.join(this.options.directory, 'node_modules');
    
    if (!fs.existsSync(nodeModulesPath)) {
      return;
    }

    // Get all compromised package names
    const compromisedPackageNames = Object.keys(this.compromisedPackages);
    
    for (const packageName of compromisedPackageNames) {
      const packagePath = path.join(nodeModulesPath, packageName);
      
      if (fs.existsSync(packagePath)) {
        try {
          // Scan all JS files in this specific compromised package
          const packageJsFiles = await glob('**/*.{js,mjs,cjs}', {
            cwd: packagePath,
            ignore: ['**/test/**', '**/tests/**', '**/spec/**', '**/docs/**']
          });

          for (const jsFile of packageJsFiles) {
            const filePath = path.join(packagePath, jsFile);
            
            // Skip if it's a directory (some packages have .js directories)
            const stats = fs.statSync(filePath);
            if (!stats.isFile()) {
              continue;
            }
            
            const content = fs.readFileSync(filePath, 'utf8');
            
            // Check for malicious patterns with higher priority
            for (const pattern of this.maliciousPatterns) {
              const matches = content.match(pattern.pattern);
              if (matches) {
                this.results.maliciousCode.push({
                  project: this.currentProject ? this.currentProject.name : 'Unknown',
                  projectPath: this.currentProject ? this.currentProject.relativePath : '.',
                  file: `node_modules/${packageName}/${jsFile}`,
                  pattern: pattern.name,
                  severity: 'CRITICAL', // Higher severity for node_modules
                  description: `MALICIOUS CODE DETECTED in compromised package '${packageName}': ${pattern.description}`,
                  matches: matches.length,
                  lineNumbers: this.getLineNumbers(content, pattern.pattern),
                  package: packageName
                });
                this.results.summary.issuesFound++;
              }
            }

            // Check for crypto addresses in compromised packages
            for (const address of this.suspiciousAddresses) {
              if (content.includes(address)) {
                this.results.maliciousCode.push({
                  project: this.currentProject ? this.currentProject.name : 'Unknown',
                  projectPath: this.currentProject ? this.currentProject.relativePath : '.',
                  file: `node_modules/${packageName}/${jsFile}`,
                  pattern: 'Crypto Address in Compromised Package',
                  severity: 'CRITICAL',
                  description: `Suspicious crypto address found in compromised package '${packageName}': ${address}`,
                  address: address,
                  package: packageName
                });
                this.results.summary.issuesFound++;
              }
            }
          }
        } catch (error) {
          // Only show warnings for non-directory errors in verbose mode
          if (this.options.verbose && !error.message.includes('EISDIR')) {
            console.warn(chalk.yellow(`Warning: Could not scan package ${packageName}: ${error.message}`));
          }
        }
      }
    }
  }

  getLineNumbers(content, pattern) {
    const lines = content.split('\n');
    const lineNumbers = [];
    
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        lineNumbers.push(i + 1);
      }
    }
    
    return lineNumbers;
  }

  generateReport() {
    console.log('\n' + '='.repeat(80));
    console.log(chalk.bold.blue('🔒 SECURITY SCAN REPORT'));
    console.log('='.repeat(80));

    // Summary
    console.log(chalk.bold('\n📊 SUMMARY:'));
    console.log(`Files scanned: ${this.results.summary.totalFilesScanned}`);
    console.log(`Packages checked: ${this.results.summary.totalPackagesChecked}`);
    console.log(`Issues found: ${this.results.summary.issuesFound}`);

    if (this.results.summary.issuesFound === 0) {
      console.log(chalk.green.bold('\n✅ No security issues detected! Your project appears to be clean.'));
      return;
    }

    // Compromised packages
    if (this.results.compromisedPackages.length > 0) {
      console.log(chalk.red.bold('\n🚨 COMPROMISED PACKAGES FOUND:'));
      const tableData = [
        ['Project', 'Relative Path', 'File', 'Package', 'Version', 'Severity']
      ];
      
      this.results.compromisedPackages.forEach(issue => {
        const relativePath = path.relative(process.cwd(), issue.projectPath || '.');
        tableData.push([
          issue.project || 'Unknown',
          relativePath,
          issue.file,
          issue.package,
          issue.version,
          this.getSeverityColor(issue.severity)
        ]);
      });
      
      console.log(table(tableData));
    }

    // Malicious code
    if (this.results.maliciousCode.length > 0) {
      console.log(chalk.red.bold('\n💀 MALICIOUS CODE DETECTED:'));
      const tableData = [
        ['Project', 'Relative Path', 'File', 'Pattern', 'Severity', 'Matches', 'Lines']
      ];
      
      this.results.maliciousCode.forEach(issue => {
        const relativePath = path.relative(process.cwd(), issue.file || '.');
        tableData.push([
          issue.project || 'Unknown',
          relativePath,
          issue.file,
          issue.pattern,
          this.getSeverityColor(issue.severity),
          issue.matches.toString(),
          issue.lineNumbers.join(', ')
        ]);
      });
      
      console.log(table(tableData));
    }

    // Package-lock.json issues
    if (this.results.packageLockIssues.length > 0) {
      console.log(chalk.red.bold('\n📦 PACKAGE-LOCK.JSON VULNERABILITIES:'));
      const tableData = [
        ['File', 'Package', 'Version', 'Severity']
      ];
      
      this.results.packageLockIssues.forEach(issue => {
        tableData.push([
          issue.file,
          issue.package,
          issue.version,
          this.getSeverityColor(issue.severity)
        ]);
      });
      
      console.log(table(tableData));
    }

    // NPM cache issues (deduplicated)
    if (this.results.npmCacheIssues.length > 0) {
      console.log(chalk.red.bold('\n💾 NPM CACHE VULNERABILITIES:'));
      const tableData = [
        ['Package', 'Version', 'Severity']
      ];
      
      // Deduplicate by package+version
      const uniqueIssues = this.results.npmCacheIssues.filter((issue, index, self) => 
        index === self.findIndex(i => i.package === issue.package && i.version === issue.version)
      );
      
      uniqueIssues.forEach(issue => {
        tableData.push([
          issue.package,
          issue.version,
          this.getSeverityColor(issue.severity)
        ]);
      });
      
      console.log(table(tableData));
    }

    // Suspicious files
    if (this.results.suspiciousFiles.length > 0) {
      console.log(chalk.yellow.bold('\n⚠️  SUSPICIOUS FILES:'));
      const tableData = [
        ['Project', 'Relative Path', 'File', 'Address', 'Severity']
      ];
      
      this.results.suspiciousFiles.forEach(issue => {
        const relativePath = path.relative(process.cwd(), issue.file || '.');
        tableData.push([
          issue.project || 'Unknown',
          relativePath,
          issue.file,
          issue.address,
          this.getSeverityColor(issue.severity)
        ]);
      });
      
      console.log(table(tableData));
    }

    // Remediation steps
    this.printRemediationSteps();
  }

  getSeverityColor(severity) {
    switch (severity) {
      case 'HIGH':
        return chalk.red.bold(severity);
      case 'MEDIUM':
        return chalk.yellow.bold(severity);
      case 'LOW':
        return chalk.blue.bold(severity);
      default:
        return severity;
    }
  }

  getGitPath(projectPath) {
    if (!projectPath) return '.';
    
    try {
      // Try to find git root and get relative path from there
      const gitRoot = this.findGitRoot(projectPath);
      if (gitRoot) {
        return path.relative(gitRoot, projectPath) || '.';
      }
      return path.basename(projectPath);
    } catch (error) {
      return path.basename(projectPath);
    }
  }

  findGitRoot(startPath) {
    let currentPath = path.resolve(startPath);
    const root = path.parse(currentPath).root;
    
    while (currentPath !== root) {
      if (fs.existsSync(path.join(currentPath, '.git'))) {
        return currentPath;
      }
      currentPath = path.dirname(currentPath);
    }
    return null;
  }

  isVulnerableVersion(packageName, version) {
    // Check if this package has a vulnerable version
    const vulnerablePackage = this.vulnerableVersions.find(v => v.name === packageName);
    if (!vulnerablePackage) {
      return false;
    }

    // Extract version number from version string (remove ^, ~, etc.)
    const cleanVersion = version.replace(/^[\^~]/, '');
    
    // Check if the version matches the vulnerable version
    return cleanVersion === vulnerablePackage.version;
  }

  printRemediationSteps() {
    console.log(chalk.bold('\n🔧 RECOMMENDED REMEDIATION STEPS:'));
    console.log('='.repeat(80));

    if (this.results.compromisedPackages.length > 0) {
      console.log(chalk.red.bold('\n1. IMMEDIATE ACTION REQUIRED - Compromised Packages:'));
      console.log('   • Remove all compromised packages immediately');
      console.log('   • Use package.json overrides to force safe versions');
      console.log('   • Check package-lock.json for any suspicious entries');
      console.log('   • Run: npm audit --audit-level high');
      console.log('   • Delete node_modules and package-lock.json, then run npm install');
      
      console.log(chalk.yellow('\n   Add these overrides to your package.json:'));
      console.log('   {');
      console.log('     "overrides": {');
      Object.entries(this.safeVersions).forEach(([pkg, version]) => {
        console.log(`       "${pkg}": "${version}",`);
      });
      console.log('     }');
      console.log('   }');
      
      const uniquePackages = [...new Set(this.results.compromisedPackages.map(p => p.package))];
      console.log(chalk.yellow('\n   Compromised packages to remove:'));
      uniquePackages.forEach(pkg => {
        console.log(`   • npm uninstall ${pkg}`);
      });
    }

    if (this.results.npmCacheIssues.length > 0) {
      console.log(chalk.red.bold('\n2. NPM CACHE VULNERABILITIES:'));
      console.log('   • IMMEDIATE ACTION: Clear npm cache to remove vulnerable packages');
      console.log('   • Run: npm cache clean --force');
      console.log('   • Verify: npm cache verify');
      console.log('   • For each project: rm -rf node_modules package-lock.json && npm install');
      console.log('   • Check cache location: npm config get cache');
      console.log('   • If issues persist: rm -rf ~/.npm && npm cache verify');
    }

    if (this.results.maliciousCode.length > 0) {
      console.log(chalk.red.bold('\n3. MALICIOUS CODE DETECTED:'));
      console.log('   • Review all flagged files immediately');
      console.log('   • Remove or quarantine suspicious code');
      console.log('   • Check git history for when malicious code was introduced');
      console.log('   • Consider reverting to a known clean state');
      console.log('   • Scan all dependencies for similar patterns');
    }

    console.log(chalk.blue.bold('\n4. GENERAL SECURITY MEASURES:'));
    console.log('   • Enable 2FA on all npm accounts');
    console.log('   • Use package-lock.json and commit it to version control');
    console.log('   • Regularly update dependencies');
    console.log('   • Use tools like npm audit and snyk');
    console.log('   • Consider using npm ci in CI/CD pipelines');
    console.log('   • Review package.json changes in pull requests');

    console.log(chalk.green.bold('\n5. VERIFICATION STEPS:'));
    console.log('   • Run this scanner again after remediation');
    console.log('   • Test your application thoroughly');
    console.log('   • Monitor for any unusual network activity');
    console.log('   • Check browser developer tools for suspicious requests');

    // Projects that need fixing
    const affectedProjects = this.getAffectedProjects();
    if (affectedProjects.length > 0) {
      console.log(chalk.yellow.bold('\n📋 PROJECTS REQUIRING IMMEDIATE ATTENTION:'));
      console.log('='.repeat(80));
      affectedProjects.forEach(project => {
        console.log(chalk.red(`• ${project.name} (${project.path})`));
        if (project.issues.length > 0) {
          project.issues.forEach(issue => {
            console.log(chalk.gray(`  - ${issue.type}: ${issue.description}`));
          });
        }
      });
    }

    console.log(chalk.gray('\nFor more information, visit:'));
    console.log('   • https://www.securityalliance.org/news/2025-09-npm-supply-chain');
    console.log('   • https://github.com/AndrewMohawk/RandomScripts/blob/main/scan_for_deps_qix-2025-08-09.sh');
  }

  getAffectedProjects() {
    const projectMap = new Map();

    // Collect all issues by project
    [...this.results.compromisedPackages, ...this.results.maliciousCode, ...this.results.suspiciousFiles].forEach(issue => {
      const projectName = issue.project || 'Unknown';
      const projectPath = issue.projectPath || '.';
      
      if (!projectMap.has(projectName)) {
        projectMap.set(projectName, {
          name: projectName,
          path: projectPath,
          issues: []
        });
      }

      const project = projectMap.get(projectName);
      project.issues.push({
        type: issue.pattern || issue.package || 'Suspicious file',
        description: issue.description || `Found in ${issue.file}`
      });
    });

    return Array.from(projectMap.values());
  }

  async generateMarkdownReport() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportsDir = path.join(process.cwd(), 'reports');
    
    // Ensure reports directory exists
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }
    
    const reportPath = path.join(reportsDir, `security-scan-report-${timestamp}.md`);
    
    let markdown = `# Security Scan Report\n\n`;
    markdown += `**Generated:** ${new Date().toLocaleString()}\n`;
    markdown += `**Scanner Version:** 1.0.0\n`;
    markdown += `**Scan Directory:** ${this.options.directory}\n\n`;
    
    // Summary
    markdown += `## 📊 Summary\n\n`;
    markdown += `- **Files scanned:** ${this.results.summary.totalFilesScanned}\n`;
    markdown += `- **Packages checked:** ${this.results.summary.totalPackagesChecked}\n`;
    markdown += `- **Issues found:** ${this.results.summary.issuesFound}\n\n`;
    
    if (this.results.summary.issuesFound === 0) {
      markdown += `## ✅ No Security Issues Detected\n\n`;
      markdown += `Your project appears to be clean!\n\n`;
    } else {
      // Compromised packages
      if (this.results.compromisedPackages.length > 0) {
        markdown += `## 🚨 Compromised Packages Found\n\n`;
        markdown += `| Project | Relative Path | File | Package | Version | Severity |\n`;
        markdown += `|---------|---------------|------|---------|---------|----------|\n`;
        
        this.results.compromisedPackages.forEach(issue => {
          const relativePath = path.relative(process.cwd(), issue.projectPath || '.');
          markdown += `| ${issue.project || 'Unknown'} | ${relativePath} | ${issue.file} | ${issue.package} | ${issue.version} | **${issue.severity}** |\n`;
        });
        markdown += `\n`;
      }
      
      // Malicious code
      if (this.results.maliciousCode.length > 0) {
        markdown += `## 💀 Malicious Code Detected\n\n`;
        markdown += `| Project | Relative Path | File | Pattern | Severity | Matches | Lines |\n`;
        markdown += `|---------|---------------|------|---------|----------|---------|-------|\n`;
        
        this.results.maliciousCode.forEach(issue => {
          const relativePath = path.relative(process.cwd(), issue.file || '.');
          markdown += `| ${issue.project || 'Unknown'} | ${relativePath} | ${issue.file} | ${issue.pattern} | **${issue.severity}** | ${issue.matches} | ${issue.lineNumbers.join(', ')} |\n`;
        });
        markdown += `\n`;
      }
      
      // Package-lock.json issues
      if (this.results.packageLockIssues.length > 0) {
        markdown += `## 📦 Package-lock.json Vulnerabilities\n\n`;
        markdown += `| File | Package | Version | Severity |\n`;
        markdown += `|------|---------|---------|----------|\n`;
        
        this.results.packageLockIssues.forEach(issue => {
          markdown += `| ${issue.file} | ${issue.package} | ${issue.version} | **${issue.severity}** |\n`;
        });
        markdown += `\n`;
      }
      
      // NPM cache issues (deduplicated)
      if (this.results.npmCacheIssues.length > 0) {
        markdown += `## 💾 NPM Cache Vulnerabilities\n\n`;
        markdown += `| Package | Version | Severity |\n`;
        markdown += `|---------|---------|----------|\n`;
        
        // Deduplicate by package+version
        const uniqueIssues = this.results.npmCacheIssues.filter((issue, index, self) => 
          index === self.findIndex(i => i.package === issue.package && i.version === issue.version)
        );
        
        uniqueIssues.forEach(issue => {
          markdown += `| ${issue.package} | ${issue.version} | **${issue.severity}** |\n`;
        });
        markdown += `\n`;
      }
      
      // Suspicious files
      if (this.results.suspiciousFiles.length > 0) {
        markdown += `## ⚠️ Suspicious Files\n\n`;
        markdown += `| Project | Relative Path | File | Address | Severity |\n`;
        markdown += `|---------|---------------|------|---------|----------|\n`;
        
        this.results.suspiciousFiles.forEach(issue => {
          const relativePath = path.relative(process.cwd(), issue.file || '.');
          markdown += `| ${issue.project || 'Unknown'} | ${relativePath} | ${issue.file} | \`${issue.address}\` | **${issue.severity}** |\n`;
        });
        markdown += `\n`;
      }
      
      // Affected projects
      const affectedProjects = this.getAffectedProjects();
      if (affectedProjects.length > 0) {
        markdown += `## 📋 Projects Requiring Immediate Attention\n\n`;
        affectedProjects.forEach(project => {
          markdown += `### ${project.name} (${project.path})\n\n`;
          project.issues.forEach(issue => {
            markdown += `- ${issue.type}: ${issue.description}\n`;
          });
          markdown += `\n`;
        });
      }
      
      // Remediation steps
      markdown += `## 🔧 Recommended Remediation Steps\n\n`;
      markdown += this.getMarkdownRemediationSteps();
    }
    
    // Write the markdown file
    try {
      await fs.promises.writeFile(reportPath, markdown, 'utf8');
      console.log(chalk.green(`\n📄 Markdown report saved: ${reportPath}`));
    } catch (error) {
      console.error(chalk.red('Failed to write markdown report:'), error.message);
    }
  }

  getMarkdownRemediationSteps() {
    let markdown = '';
    
    if (this.results.compromisedPackages.length > 0) {
      markdown += `### 1. IMMEDIATE ACTION REQUIRED - Compromised Packages\n\n`;
      markdown += `- Remove all compromised packages immediately\n`;
      markdown += `- Use package.json overrides to force safe versions\n`;
      markdown += `- Check package-lock.json for any suspicious entries\n`;
      markdown += `- Run: \`npm audit --audit-level high\`\n`;
      markdown += `- Delete node_modules and package-lock.json, then run \`npm install\`\n\n`;
      
      markdown += `Add these overrides to your package.json:\n\n`;
      markdown += `\`\`\`json\n`;
      markdown += `{\n`;
      markdown += `  "overrides": {\n`;
      Object.entries(this.safeVersions).forEach(([pkg, version]) => {
        markdown += `    "${pkg}": "${version}",\n`;
      });
      markdown += `  }\n`;
      markdown += `}\n`;
      markdown += `\`\`\`\n\n`;
    }
    
    if (this.results.npmCacheIssues.length > 0) {
      markdown += `### 2. NPM Cache Vulnerabilities\n\n`;
      markdown += `**IMMEDIATE ACTION REQUIRED:** Clear your npm cache to remove vulnerable packages\n\n`;
      markdown += `#### 🚨 Quick Fix (Recommended)\n\n`;
      markdown += `\`\`\`bash\n`;
      markdown += `# Step 1: Clear npm cache completely\n`;
      markdown += `npm cache clean --force\n\n`;
      markdown += `# Step 2: Verify cache is clean\n`;
      markdown += `npm cache verify\n\n`;
      markdown += `# Step 3: For each affected project, clean and reinstall\n`;
      markdown += `cd /path/to/your/project\n`;
      markdown += `rm -rf node_modules package-lock.json\n`;
      markdown += `npm install\n`;
      markdown += `\`\`\`\n\n`;
      
      markdown += `#### 🔍 Thorough Cleanup (If issues persist)\n\n`;
      markdown += `\`\`\`bash\n`;
      markdown += `# Step 1: Find your npm cache location\n`;
      markdown += `npm config get cache\n\n`;
      markdown += `# Step 2: Stop any running npm processes\n`;
      markdown += `pkill -f npm\n\n`;
      markdown += `# Step 3: Delete the entire cache directory\n`;
      markdown += `rm -rf ~/.npm\n\n`;
      markdown += `# Step 4: Clear npm configuration cache\n`;
      markdown += `npm config delete cache\n`;
      markdown += `npm config set cache ~/.npm\n\n`;
      markdown += `# Step 5: Verify cache is completely clean\n`;
      markdown += `npm cache verify\n`;
      markdown += `\`\`\`\n\n`;
      
      markdown += `#### 🛠️ Advanced Cleanup (Nuclear option)\n\n`;
      markdown += `\`\`\`bash\n`;
      markdown += `# Step 1: Clear all npm-related caches\n`;
      markdown += `npm cache clean --force\n`;
      markdown += `npm config delete cache\n`;
      markdown += `rm -rf ~/.npm\n`;
      markdown += `rm -rf ~/.npmrc\n\n`;
      markdown += `# Step 2: Clear global npm cache (if using global packages)\n`;
      markdown += `npm cache clean --force --global\n\n`;
      markdown += `# Step 3: Reset npm configuration\n`;
      markdown += `npm config set cache ~/.npm\n`;
      markdown += `npm config set registry https://registry.npmjs.org/\n\n`;
      markdown += `# Step 4: Verify everything is clean\n`;
      markdown += `npm cache verify\n`;
      markdown += `npm config list\n`;
      markdown += `\`\`\`\n\n`;
      
      markdown += `#### 📋 Verification Steps\n\n`;
      markdown += `After cleaning, verify the vulnerable packages are gone:\n\n`;
      markdown += `\`\`\`bash\n`;
      markdown += `# Check if vulnerable packages are still in cache\n`;
      markdown += `npm cache ls | grep -E "(strip-ansi|ansi-regex|ansi-styles)"\n\n`;
      markdown += `# Should return empty results\n`;
      markdown += `# If any results appear, repeat the cleanup process\n`;
      markdown += `\`\`\`\n\n`;
      
      markdown += `#### ⚠️ Important Notes\n\n`;
      markdown += `- **Backup first**: Consider backing up your package-lock.json files before cleanup\n`;
      markdown += `- **Team coordination**: If working in a team, ensure everyone cleans their cache\n`;
      markdown += `- **CI/CD**: Update your CI/CD pipelines to use clean npm cache\n`;
      markdown += `- **Docker**: If using Docker, rebuild images to ensure clean cache\n`;
      markdown += `- **Global packages**: Check global packages with \`npm list -g --depth=0\`\n\n`;
    }
    
    if (this.results.maliciousCode.length > 0) {
      markdown += `### 3. Malicious Code Detected\n\n`;
      markdown += `- Review all flagged files immediately\n`;
      markdown += `- Remove or quarantine suspicious code\n`;
      markdown += `- Check git history for when malicious code was introduced\n`;
      markdown += `- Consider reverting to a known clean state\n`;
      markdown += `- Scan all dependencies for similar patterns\n\n`;
    }
    
    markdown += `### 4. General Security Measures\n\n`;
    markdown += `- Enable 2FA on all npm accounts\n`;
    markdown += `- Use package-lock.json and commit it to version control\n`;
    markdown += `- Regularly update dependencies\n`;
    markdown += `- Use tools like npm audit and snyk\n`;
    markdown += `- Consider using npm ci in CI/CD pipelines\n`;
    markdown += `- Review package.json changes in pull requests\n\n`;
    
    markdown += `### 5. Verification Steps\n\n`;
    markdown += `- Run this scanner again after remediation\n`;
    markdown += `- Test your application thoroughly\n`;
    markdown += `- Monitor for any unusual network activity\n`;
    markdown += `- Check browser developer tools for suspicious requests\n\n`;
    
    markdown += `---\n\n`;
    markdown += `For more information, visit:\n`;
    markdown += `- https://www.securityalliance.org/news/2025-09-npm-supply-chain\n`;
    markdown += `- https://github.com/AndrewMohawk/RandomScripts/blob/main/scan_for_deps_qix-2025-08-09.sh\n`;
    
    return markdown;
  }
}

// CLI Interface
const program = new Command();

program
  .name('npm-security-scanner')
  .description('Security scanner for detecting compromised npm packages and malicious code')
  .version('1.0.0')
  .option('-d, --directory <path>', 'Directory to scan', process.cwd())
  .option('-v, --verbose', 'Verbose output')
  .option('-o, --output <format>', 'Output format (console, json)', 'console')
  .action(async (options) => {
    try {
      const scanner = new NPMSecurityScanner(options);
      const results = await scanner.scan();
      
      if (options.output === 'json') {
        console.log(JSON.stringify(results, null, 2));
      }
      
      process.exit(results.summary.issuesFound > 0 ? 1 : 0);
    } catch (error) {
      console.error(chalk.red('Scanner failed:'), error.message);
      process.exit(1);
    }
  });

// Only run CLI when executed directly, not when required as module
if (require.main === module) {
  program.parse();
}

module.exports = NPMSecurityScanner;
