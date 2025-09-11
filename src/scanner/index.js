/**
 * @fileoverview Professional NPM Security Scanner
 * @description Enterprise-grade security scanner for detecting compromised packages and malicious code
 * @author DolaSoft Security Team
 * @version 2.0.0
 * @since 1.0.0
 */

const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

// Import our utilities
const Logger = require('../utils/logger');
const Config = require('../config');
const Validator = require('../utils/validator');
const PerformanceMonitor = require('../utils/performance');
const ParallelScanner = require('../utils/parallelScanner');
const PackageScanner = require('../utils/packageScanner');
const ReportGenerator = require('../utils/reportGenerator');
const PatternMatcher = require('../utils/patternMatcher');

/**
 * Professional NPM Security Scanner Class
 *
 * Provides comprehensive security scanning capabilities including:
 * - Compromised package detection
 * - Malicious code pattern scanning
 * - NPM cache vulnerability detection
 * - Parallel processing with resource management
 * - Professional logging and reporting
 *
 * @class NPMSecurityScanner
 * @example
 * ```javascript
 * const scanner = new NPMSecurityScanner({
 *   directory: '/path/to/projects',
 *   maxConcurrency: 4,
 *   verbose: true
 * });
 *
 * const results = await scanner.scan();
 * console.log(`Found ${results.summary.issuesFound} security issues`);
 * ```
 */
class NPMSecurityScanner {
  /**
   * Creates an instance of NPMSecurityScanner
   *
   * @param {Object} options - Configuration options
   * @param {string} [options.directory=process.cwd()] - Directory to scan
   * @param {number} [options.maxConcurrency] - Maximum parallel workers
   * @param {boolean} [options.verbose=false] - Enable verbose logging
   * @param {boolean} [options.silent=false] - Suppress console output
   * @param {string} [options.logLevel='info'] - Logging level
   * @param {boolean} [options.includeNodeModules=true] - Scan node_modules
   * @param {boolean} [options.scanMaliciousCode=true] - Scan for malicious patterns
   * @param {boolean} [options.scanCompromisedPackages=true] - Scan for vulnerable packages
   * @param {boolean} [options.scanNpmCache=true] - Scan NPM cache
   * @param {Object} [options.output] - Output configuration
   * @param {string} [options.output.format='console'] - Output format (console|json|markdown)
   * @param {boolean} [options.output.report=true] - Generate reports
   * @param {string} [options.output.reportDir='reports'] - Report directory
   * @param {Object} [options.performance] - Performance configuration
   * @param {number} [options.performance.timeout=30000] - Worker timeout in ms
   * @param {number} [options.performance.memoryLimit] - Memory limit per worker
   * @param {boolean} [options.performance.enableCaching=true] - Enable caching
   *
   * @throws {Error} When configuration is invalid
   *
   * @example
   * ```javascript
   * // Basic usage
   * const scanner = new NPMSecurityScanner();
   *
   * // Advanced configuration
   * const scanner = new NPMSecurityScanner({
   *   directory: '/path/to/projects',
   *   maxConcurrency: 4,
   *   verbose: true,
   *   output: {
   *     format: 'markdown',
   *     reportDir: 'security-reports'
   *   }
   * });
   * ```
   */
  constructor(options = {}) {
    // Initialize configuration with validation
    this.config = new Config(options);

    // Initialize logger with configuration
    this.logger = new Logger(this.config.getLoggingConfig());

    // Initialize validator for input sanitization
    this.validator = new Validator(this.logger);

    // Initialize performance monitor
    this.performance = new PerformanceMonitor(this.logger);

    // Initialize parallel scanner for concurrent processing
    this.parallelScanner = new ParallelScanner(this.config, this.logger, this.iocs);

    // Initialize package scanner for vulnerable package detection
    this.packageScanner = new PackageScanner(this.logger, this.performance, this.validator);

    // Initialize report generator
    this.reportGenerator = new ReportGenerator(this.logger);

    // Initialize pattern matcher for malicious code detection
    this.patternMatcher = new PatternMatcher(this.logger);

    // Initialize results structure
    this.results = {
      compromisedPackages: [],
      maliciousCode: [],
      npmCacheIssues: [],
      suspiciousFiles: [],
      packageValidationIssues: [],
      summary: {
        filesScanned: 0,
        packagesChecked: 0,
        issuesFound: 0,
        duration: 0
      }
    };

    // Track total packages checked across all projects
    this.totalPackagesChecked = 0;

    // Load security indicators
    this.loadIoCs();

    // Initialize detection patterns
    this.initializeMaliciousPatterns();

    // Initialize vulnerable package versions
    this.initializeVulnerableVersions();

    this.logger.info('NPM Security Scanner initialized', this.config.getSummary());
  }

  /**
   * Load Indicators of Compromise (IoCs) from JSON file
   *
   * Loads comprehensive IoCs including:
   * - Cryptocurrency addresses (Bitcoin, Ethereum, Solana, etc.)
   * - Malicious domains
   * - Suspicious IP addresses
   * - Known attack patterns
   *
   * @private
   * @returns {void}
   */
  loadIoCs() {
    try {
      const iocPath = path.join(__dirname, '..', '..', 'data', 'iocs.json');
      if (fs.existsSync(iocPath)) {
        this.iocs = JSON.parse(fs.readFileSync(iocPath, 'utf8'));
        this.logger.debug('IoCs loaded successfully', {
          count: Object.keys(this.iocs).length
        });
      } else {
        this.logger.warn('IoCs file not found, using empty IoCs');
        this.iocs = {};
      }
    } catch (error) {
      this.logger.error('Failed to load IoCs', error);
      this.iocs = {};
    }
  }

  /**
   * Initialize malicious code detection patterns
   *
   * Sets up comprehensive pattern matching for:
   * - Ethereum wallet hooks
   * - Crypto address replacement
   * - WebSocket data exfiltration
   * - CDN malware hosting
   * - Network request interception
   * - Address similarity calculations
   *
   * @private
   * @returns {void}
   */
  initializeMaliciousPatterns() {
    this.maliciousPatterns = [
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
        name: 'CDN Malware Hosting',
        pattern: /(static-mw-host\.b-cdn\.net|cdn\.jsdelivr\.net\/npm\/[^/]+\/dist)/gi,
        severity: 'HIGH',
        description: 'Detects malicious CDN domains used for hosting malware'
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

    this.logger.debug('Malicious patterns initialized', {
      count: this.maliciousPatterns.length
    });
  }

  /**
   * Initialize vulnerable package versions database
   *
   * Sets up known vulnerable versions for packages affected by:
   * - QIX supply chain attack
   * - Chalk package compromise
   * - Debug package compromise
   * - Related dependency vulnerabilities
   *
   * @private
   * @returns {void}
   */
  initializeVulnerableVersions() {
    // Use the centralized packageScanner utility instead of duplicating data
    this.vulnerableVersions = this.packageScanner.getVulnerablePackages();
    this.safeVersions = this.packageScanner.getSafeVersions();

    this.logger.debug('Vulnerable versions initialized from packageScanner', {
      vulnerable: Object.keys(this.vulnerableVersions).length,
      safe: Object.keys(this.safeVersions).length
    });
  }

  /**
   * Main scan method - orchestrates the entire security scan
   *
   * Performs comprehensive security scanning including:
   * - Input validation and sanitization
   * - Project discovery
   * - Parallel or sequential scanning
   * - Report generation
   * - Performance monitoring
   *
   * @param {string} [directory=null] - Directory to scan (overrides config)
   * @returns {Promise<Object>} Scan results object
   * @throws {Error} When scan fails or configuration is invalid
   *
   * @example
   * ```javascript
   * // Scan current directory
   * const results = await scanner.scan();
   *
   * // Scan specific directory
   * const results = await scanner.scan('/path/to/projects');
   *
   * // Handle results
   * if (results.summary.issuesFound > 0) {
   *   console.log(`Found ${results.summary.issuesFound} security issues`);
   *   console.log('Compromised packages:', results.compromisedPackages.length);
   *   console.log('Malicious code:', results.maliciousCode.length);
   * }
   * ```
   */
  async scan(directory = null) {
    const scanTimer = this.performance.startTimer('full-scan');
    this.performance.startMonitoring();

    try {
      // Step 1: Validate input directory
      this.logger.progress('initializing', { step: 'Validating input directory...' });
      const targetDir = directory || this.config.get('directory');
      const validation = this.validator.validateDirectory(targetDir);

      if (!validation.isValid) {
        throw new Error(`Invalid directory: ${validation.errors.join(', ')}`);
      }

      if (validation.warnings.length > 0) {
        validation.warnings.forEach(warning => this.logger.warn(warning));
      }

      this.logger.info('🔍 NPM Security Scanner - QIX Supply Chain Attack Detection');
      this.logger.info(`Scanning directory: ${targetDir}`);

      // Step 2: Discover projects
      this.logger.progress('discovering', { step: 'Discovering projects recursively...' });
      const projects = await this.discoverProjects(targetDir);
      this.logger.info(`Found ${projects.length} projects to scan`);

      if (projects.length === 0) {
        this.logger.warn('No projects found to scan');
        return this.results;
      }

      // Step 3: Choose scanning strategy
      this.logger.progress('configuring', {
        step: 'Configuring scan strategy...',
        strategy: this.config.get('performance.maxConcurrency') > 1 && projects.length > 1 ? 'parallel' : 'sequential',
        concurrency: this.config.get('performance.maxConcurrency')
      });

      // Step 4: Execute scanning
      this.logger.progress('scanning', { step: 'Scanning for compromised packages and malicious code patterns...' });
      if (this.config.get('performance.maxConcurrency') > 1 && projects.length > 1) {
        await this.scanProjectsParallel(projects);
      } else {
        await this.scanProjectsSequential(projects);
      }

      // Step 5: Calculate final summary
      this.logger.progress('finalizing', { step: 'Finalizing scan results...' });
      this.calculateSummary();

      // Step 6: Generate reports (markdown only - console output handled by CLI)
      if (this.config.get('output.report')) {
        this.logger.progress('reporting', { step: 'Generating security reports...' });
        // Console output is handled by the CLI layer, not here
      }

      const scanResult = this.performance.endTimer(scanTimer, {
        projectsScanned: projects.length,
        issuesFound: this.results.summary.issuesFound
      });

      this.logger.info('Security scan completed', {
        duration: scanResult.duration,
        issuesFound: this.results.summary.issuesFound
      });

      return this.results;
    } catch (error) {
      this.logger.error('Scan failed', error);
      throw error;
    } finally {
      this.performance.stopMonitoring();
    }
  }

  /**
   * Discover projects in the target directory
   *
   * Recursively searches for projects containing package.json files,
   * respecting include/exclude patterns from configuration.
   *
   * @param {string} directory - Directory to search
   * @returns {Promise<Array<string>>} Array of project directory paths
   * @private
   * @throws {Error} When directory discovery fails
   */
  async discoverProjects(directory) {
    const discoverTimer = this.performance.startTimer('discover-projects');

    try {
      // Use a more specific pattern to avoid node_modules and the scanner project itself
      const packageJsonFiles = await glob('**/package.json', {
        cwd: directory,
        ignore: [
          '**/node_modules/**',
          '**/dist/**',
          '**/build/**',
          '**/coverage/**',
          '**/.git/**',
          '**/security-check/**',
          '**/test-scanner.js',
          '**/test-comprehensive.js'
        ]
      });

      const projects = packageJsonFiles
        .map(file => path.join(directory, path.dirname(file)))
        .filter(projectPath => {
          // Additional filtering to ensure we don't include node_modules
          const relativePath = path.relative(directory, projectPath);
          const pathParts = relativePath.split(path.sep);

          // Reject if any part of the path is node_modules, dist, build, coverage, or .git
          const isExcludedPath = pathParts.some(part =>
            part === 'node_modules' ||
            part === 'dist' ||
            part === 'build' ||
            part === 'coverage' ||
            part === '.git'
          );

          // Reject if this is the scanner project itself (security-check directory)
          const isScannerProject = path.basename(projectPath) === 'security-check' ||
                                 path.basename(projectPath) === 'npm-security-scanner';

          return !isExcludedPath && !isScannerProject;
        });

      this.performance.endTimer(discoverTimer, { projectsFound: projects.length });
      return projects;
    } catch (error) {
      this.performance.endTimer(discoverTimer, { error: error.message });
      throw error;
    }
  }

  /**
   * Scan multiple projects in parallel using worker threads
   *
   * Distributes project scanning across multiple worker threads
   * with proper resource management and error handling.
   *
   * @param {Array<string>} projects - Array of project paths
   * @returns {Promise<void>}
   * @private
   * @throws {Error} When parallel scanning fails
   */
  async scanProjectsParallel(projects) {
    this.logger.info('Scanning projects in parallel', {
      count: projects.length,
      concurrency: this.config.get('performance.maxConcurrency')
    });

    const parallelResults = await this.parallelScanner.scanProjects(projects);

    // Merge results from all workers
    parallelResults.results.forEach(projectResult => {
      this.mergeProjectResults(projectResult);
    });

    // Log any errors from parallel scanning
    if (parallelResults.errors.length > 0) {
      this.logger.warn(`${parallelResults.errors.length} projects failed to scan`, {
        errors: parallelResults.errors.map(e => e.project)
      });
    }
  }

  /**
   * Scan multiple projects sequentially
   *
   * Processes projects one by one with progress reporting.
   * Used when parallel processing is disabled or not available.
   *
   * @param {Array<string>} projects - Array of project paths
   * @returns {Promise<void>}
   * @private
   */
  async scanProjectsSequential(projects) {
    this.logger.info('Scanning projects sequentially', { count: projects.length });

    for (let i = 0; i < projects.length; i++) {
      const project = projects[i];
      const projectName = path.basename(project);

      // Show progress with spinner
      this.logger.progress('scanning-project', {
        current: i + 1,
        total: projects.length,
        project: projectName,
        step: `Scanning project ${i + 1}/${projects.length}: ${projectName}`
      });

      try {
        const projectResult = await this.scanProject(project);
        this.mergeProjectResults(projectResult);

        // Show completion status
        const issuesCount = projectResult.compromisedPackages.length +
                          projectResult.maliciousCode.length +
                          projectResult.npmCacheIssues.length +
                          projectResult.suspiciousFiles.length;

        if (issuesCount > 0) {
          this.logger.warn(`⚠️  ${projectName}: ${issuesCount} issues found`);
        } else {
          this.logger.info(`✅ ${projectName}: Clean`);
        }
      } catch (error) {
        this.logger.error(`❌ Failed to scan project ${projectName}`, error);
      }
    }
  }

  /**
   * Scan a single project for security issues
   *
   * Performs comprehensive security analysis including:
   * - Package.json vulnerability scanning
   * - JavaScript file malicious pattern detection
   * - Node_modules security analysis
   * - NPM cache vulnerability checking
   *
   * @param {string} projectPath - Path to project directory
   * @returns {Promise<Object>} Project scan results
   * @throws {Error} When project scanning fails
   *
   * @example
   * ```javascript
   * const projectResult = await scanner.scanProject('/path/to/project');
   * console.log('Issues found:', projectResult.compromisedPackages.length);
   * ```
   */
  async scanProject(projectPath) {
    const projectTimer = this.performance.startTimer('scan-project');

    try {
      const projectName = path.basename(projectPath);
      const results = {
        project: projectName,
        path: projectPath,
        compromisedPackages: [],
        maliciousCode: [],
        npmCacheIssues: [],
        suspiciousFiles: [],
        packageValidationIssues: [],
        filesScanned: 0
      };

      // Step 1: Scan package.json for vulnerable packages
      if (this.config.get('security.scanCompromisedPackages')) {
        this.logger.debug('  📦 Scanning package.json for vulnerable packages...');
        const packageResults = await this.packageScanner.scanPackageFiles(projectPath);
        results.compromisedPackages.push(...packageResults.compromisedPackages);

        if (packageResults.compromisedPackages.length > 0) {
          this.logger.debug(`  ⚠️  Found ${packageResults.compromisedPackages.length} vulnerable packages`);
        }
      }

      // Step 1.5: Validate package.json format
      this.logger.debug('  📋 Validating package.json format...');
      const validationResults = await this.packageScanner.validatePackageJson(projectPath);
      results.packageValidationIssues.push(...validationResults);

      if (validationResults.length > 0) {
        this.logger.debug(`  ⚠️  Found ${validationResults.length} package validation issues`);
      }

      // Step 2: Scan JavaScript files for malicious patterns (including node_modules)
      if (this.config.get('security.scanMaliciousCode')) {
        this.logger.debug('  🔍 Scanning JavaScript files for malicious patterns...');
        const jsResults = await this.patternMatcher.scanJavaScriptFiles(projectPath, this.iocs, path.basename(projectPath), false, projectPath);
        results.maliciousCode.push(...jsResults.issues);
        results.filesScanned += jsResults.filesScanned;

        if (jsResults.issues.length > 0) {
          this.logger.debug(`  ⚠️  Found ${jsResults.issues.length} malicious code patterns`);
        }
      }

      // Step 3: Scan NPM cache for vulnerabilities
      if (this.config.get('security.scanNpmCache')) {
        this.logger.debug('  💾 Scanning NPM cache for vulnerabilities...');
        const cacheResults = await this.scanNpmCache();
        results.npmCacheIssues.push(...cacheResults);
        if (cacheResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${cacheResults.length} NPM cache issues`);
        }
      }

      // Calculate summary for single project
      results.summary = {
        filesScanned: results.filesScanned,
        packagesChecked: results.compromisedPackages.length,
        issuesFound: results.compromisedPackages.length + results.maliciousCode.length +
                    results.npmCacheIssues.length + results.suspiciousFiles.length +
                    results.packageValidationIssues.length,
        duration: 0
      };

      const projectResult = this.performance.endTimer(projectTimer, {
        project: projectName,
        issuesFound: results.summary.issuesFound
      });

      results.summary.duration = projectResult.duration;

      return results;
    } catch (error) {
      this.performance.endTimer(projectTimer, { error: error.message });
      throw error;
    }
  }

  /**
   * Merge project results into main results collection
   *
   * @param {Object} projectResult - Project scan result
   * @private
   */
  mergeProjectResults(projectResult) {
    this.results.compromisedPackages.push(...(projectResult.compromisedPackages || []));
    this.results.maliciousCode.push(...(projectResult.maliciousCode || []));
    this.results.npmCacheIssues.push(...(projectResult.npmCacheIssues || []));
    this.results.suspiciousFiles.push(...(projectResult.suspiciousFiles || []));
    this.results.packageValidationIssues.push(...(projectResult.packageValidationIssues || []));

    // Track total packages checked from this project
    if (projectResult.summary && projectResult.summary.packagesChecked) {
      this.totalPackagesChecked += projectResult.summary.packagesChecked;
    }
  }

  /**
   * Get current scan resultst
   *
   * @returns {Object} Current scan results
   * @example
   * ```javascript
   * const results = scanner.getResults();
   * console.log('Total issues:', results.summary.issuesFound);
   * ```
   */
  getResults() {
    return this.results;
  }

  /**
   * Get performance monitoring report
   *
   * @returns {Object} Performance report with metrics and suggestions
   * @example
   * ```javascript
   * const perfReport = scanner.getPerformanceReport();
   * console.log('Scan duration:', perfReport.summary.totalDuration);
   * console.log('Memory usage:', perfReport.memory.current);
   * ```
   */
  getPerformanceReport() {
    return this.performance.createReport();
  }

  /**
   * Reset scanner state and clear all results
   *
   * @returns {void}
   * @example
   * ```javascript
   * scanner.reset();
   * // Scanner is now ready for a fresh scan
   * ```
   */
  reset() {
    this.results = {
      compromisedPackages: [],
      maliciousCode: [],
      npmCacheIssues: [],
      suspiciousFiles: [],
      packageValidationIssues: [],
      summary: {
        filesScanned: 0,
        packagesChecked: 0,
        issuesFound: 0,
        duration: 0
      }
    };
    this.performance.reset();
    this.logger.info('Scanner state reset');
  }

  /**
   * Scan NPM cache for vulnerabilities
   * @returns {Promise<Array>} Cache issues found
   * @private
   */
  async scanNpmCache() {
    const results = [];

    try {
      // This is a placeholder - in a real implementation, you'd scan the NPM cache
      // for vulnerable packages or malicious code
      this.logger.debug('NPM cache scan not implemented yet');
    } catch (error) {
      this.logger.error('Error scanning NPM cache', { error: error.message });
    }

    return results;
  }

  /**
   * Calculate final summary statistics
   * @private
   */
  calculateSummary() {
    this.results.summary.filesScanned = this.results.maliciousCode.length + this.results.suspiciousFiles.length;
    this.results.summary.packagesChecked = this.totalPackagesChecked;
    this.results.summary.issuesFound =
      this.results.compromisedPackages.length +
      this.results.maliciousCode.length +
      this.results.npmCacheIssues.length +
      this.results.suspiciousFiles.length +
      this.results.packageValidationIssues.length;
  }
}

module.exports = NPMSecurityScanner;
