#!/usr/bin/env node

/**
 * @fileoverview Professional CLI Interface for NPM Security Scanner
 * @description Command-line interface with comprehensive options and validation
 * @author DolaSoft Security Team
 * @version 2.0.0
 */

const { Command } = require('commander');
const chalk = require('chalk').default || require('chalk');
const path = require('path');
const fs = require('fs');

// Import our modules
const NPMSecurityScanner = require('../scanner');
const Logger = require('../utils/logger');
const Config = require('../config');
const Validator = require('../utils/validator');
const ConcurrencyCalculator = require('../utils/concurrencyCalculator');

/**
 * Professional CLI Interface for NPM Security Scanner
 *
 * Provides comprehensive command-line interface with:
 * - Input validation and sanitization
 * - Smart concurrency calculation
 * - Multiple output formats
 * - Performance monitoring
 * - Professional error handling
 */
class SecurityScannerCLI {
  constructor() {
    this.program = new Command();
    this.logger = null;
    this.scanner = null;
    this.setupCommands();
  }

  /**
   * Setup CLI commands and options
   * @private
   */
  setupCommands() {
    this.program
      .name('npm-security-scanner')
      .description('Professional NPM Security Scanner - Detect compromised packages and malicious code')
      .version('2.0.0')
      .option('-d, --directory <path>', 'Directory to scan (default: current directory)')
      .option('-c, --concurrency <number>', 'Maximum parallel workers (auto-calculated if not specified)')
      .option('-v, --verbose', 'Enable verbose logging')
      .option('-s, --silent', 'Suppress console output')
      .option('--log-level <level>', 'Logging level (error|warn|info|debug|trace)', 'info')
      .option('--log-file <path>', 'Log file path')
      .option('-f, --format <format>', 'Output format (console|json|markdown)', 'console')
      .option('--no-report', 'Disable report generation')
      .option('--report-dir <path>', 'Report directory', 'reports')
      .option('--no-node-modules', 'Skip node_modules scanning')
      .option('--no-malicious-code', 'Skip malicious code scanning')
      .option('--no-compromised-packages', 'Skip compromised package scanning')
      .option('--no-npm-cache', 'Skip NPM cache scanning')
      .option('--timeout <ms>', 'Worker timeout in milliseconds', '30000')
      .option('--memory-limit <mb>', 'Memory limit per worker in MB', '512')
      .option('--strict', 'Enable strict mode (fail on high severity issues)')
      .option('--analyze-system', 'Analyze system and recommend optimal settings')
      .option('--test-concurrency <workers>', 'Test concurrency performance')
      .option('--config <path>', 'Configuration file path')
      .action(async options => {
        try {
          await this.handleCommand(options);
        } catch (error) {
          this.handleError(error);
          process.exit(1);
        }
      });

    // Add system analysis command
    this.program
      .command('analyze')
      .description('Analyze system capabilities and recommend optimal settings')
      .option('-v, --verbose', 'Enable verbose output')
      .action(async options => {
        try {
          await this.analyzeSystem(options);
        } catch (error) {
          this.handleError(error);
          process.exit(1);
        }
      });

    // Add test command
    this.program
      .command('test')
      .description('Test scanner functionality')
      .option('-d, --directory <path>', 'Test directory')
      .action(async options => {
        try {
          await this.testScanner(options);
        } catch (error) {
          this.handleError(error);
          process.exit(1);
        }
      });
  }

  /**
   * Handle main scan command
   * @param {Object} options - CLI options
   * @private
   */
  async handleCommand(options) {
    // Load configuration
    const config = await this.loadConfiguration(options);

    // Initialize logger
    this.logger = new Logger(config.getLoggingConfig());

    // Validate inputs
    this.validateInputs(options, config);

    // Handle special commands
    if (options.analyzeSystem) {
      await this.analyzeSystem({ verbose: options.verbose });
      return;
    }

    if (options.testConcurrency) {
      await this.testConcurrency(parseInt(options.testConcurrency), config);
      return;
    }

    // Initialize scanner
    this.scanner = new NPMSecurityScanner(config.options);

    // Run scan
    const results = await this.scanner.scan(options.directory);

    // Display results
    this.displayResults(results, options);

    // Exit with appropriate code
    if (options.strict && this.hasHighSeverityIssues(results)) {
      this.logger.error('High severity issues found in strict mode');
      process.exit(1);
    }
  }

  /**
   * Load configuration from file or CLI options
   * @param {Object} options - CLI options
   * @returns {Promise<Config>} Configuration object
   * @private
   */
  async loadConfiguration(options) {
    let configOptions = {};

    // Load from config file if specified
    if (options.config) {
      try {
        configOptions = Config.fromFile(options.config);
      } catch (error) {
        throw new Error(`Failed to load config file: ${error.message}`);
      }
    }

    // Override with CLI options
    const cliOverrides = this.buildConfigOverrides(options);
    configOptions = { ...configOptions, ...cliOverrides };

    return new Config(configOptions);
  }

  /**
   * Build configuration overrides from CLI options
   * @param {Object} options - CLI options
   * @returns {Object} Configuration overrides
   * @private
   */
  buildConfigOverrides(options) {
    const overrides = {};

    if (options.directory) {
      overrides.directory = options.directory;
    }

    if (options.concurrency) {
      overrides.performance = {
        ...overrides.performance,
        maxConcurrency: parseInt(options.concurrency)
      };
    }

    if (options.verbose) {
      overrides.logging = {
        ...overrides.logging,
        level: 'debug'
      };
    }

    if (options.silent) {
      overrides.logging = {
        ...overrides.logging,
        console: false
      };
    }

    if (options.logLevel) {
      overrides.logging = {
        ...overrides.logging,
        level: options.logLevel
      };
    }

    if (options.logFile) {
      overrides.logging = {
        ...overrides.logging,
        file: options.logFile
      };
    }

    if (options.format) {
      overrides.output = {
        ...overrides.output,
        format: options.format
      };
    }

    if (options.report === false) {
      overrides.output = {
        ...overrides.output,
        report: false
      };
    }

    if (options.reportDir) {
      overrides.output = {
        ...overrides.output,
        reportDir: options.reportDir
      };
    }

    if (options.nodeModules === false) {
      overrides.security = {
        ...overrides.security,
        scanNodeModules: false
      };
    }

    if (options.maliciousCode === false) {
      overrides.security = {
        ...overrides.security,
        scanMaliciousCode: false
      };
    }

    if (options.compromisedPackages === false) {
      overrides.security = {
        ...overrides.security,
        scanCompromisedPackages: false
      };
    }

    if (options.npmCache === false) {
      overrides.security = {
        ...overrides.security,
        scanNpmCache: false
      };
    }

    if (options.timeout) {
      overrides.performance = {
        ...overrides.performance,
        timeout: parseInt(options.timeout)
      };
    }

    if (options.memoryLimit) {
      overrides.performance = {
        ...overrides.performance,
        memoryLimit: parseInt(options.memoryLimit) * 1024 * 1024
      };
    }

    if (options.strict) {
      overrides.security = {
        ...overrides.security,
        strictMode: true,
        failOnHigh: true
      };
    }

    return overrides;
  }

  /**
   * Validate CLI inputs
   * @param {Object} options - CLI options
   * @param {Config} config - Configuration object
   * @private
   */
  validateInputs(options, config) {
    const validator = new Validator(this.logger);

    // Validate directory
    if (options.directory) {
      const validation = validator.validateDirectory(options.directory);
      if (!validation.isValid) {
        throw new Error(`Invalid directory: ${validation.errors.join(', ')}`);
      }
    }

    // Validate concurrency
    if (options.concurrency) {
      const concurrency = parseInt(options.concurrency);
      if (isNaN(concurrency) || concurrency < 1 || concurrency > 100) {
        throw new Error('Concurrency must be a number between 1 and 100');
      }
    }

    // Validate log level
    const validLogLevels = ['error', 'warn', 'info', 'debug', 'trace'];
    if (options.logLevel && !validLogLevels.includes(options.logLevel)) {
      throw new Error(`Invalid log level: ${options.logLevel}. Must be one of: ${validLogLevels.join(', ')}`);
    }

    // Validate output format
    const validFormats = ['console', 'json', 'markdown'];
    if (options.format && !validFormats.includes(options.format)) {
      throw new Error(`Invalid output format: ${options.format}. Must be one of: ${validFormats.join(', ')}`);
    }
  }

  /**
   * Analyze system capabilities
   * @param {Object} options - Analysis options
   * @private
   */
  async analyzeSystem(options) {
    const logger = new Logger({
      level: options.verbose ? 'debug' : 'info',
      colors: true
    });

    const calculator = new ConcurrencyCalculator(logger);

    console.log(chalk.bold.blue('\n🔍 NPM Security Scanner - System Analysis\n'));

    // Get system status
    const systemStatus = calculator.getSystemStatus();

    console.log(chalk.bold('💻 Hardware Analysis:'));
    console.log(`  CPU Cores: ${systemStatus.cpuCores}`);
    console.log(`  CPU Speed: ${systemStatus.cpuSpeed} MHz`);
    console.log(`  Total Memory: ${systemStatus.totalMemory}`);
    console.log(`  Free Memory: ${systemStatus.freeMemory}`);
    console.log(`  Memory Pressure: ${systemStatus.memoryPressure}%`);
    console.log(`  Platform: ${systemStatus.platform} (${systemStatus.arch})`);
    console.log(`  High Performance: ${systemStatus.isHighPerformance ? '✅' : '❌'}`);
    console.log(`  Memory Constrained: ${systemStatus.isMemoryConstrained ? '⚠️' : '✅'}`);

    // Test different scenarios
    const scenarios = [
      { name: 'Small Projects (1-10)', projectCount: 5, avgProjectSize: 'small', includeNodeModules: false },
      { name: 'Medium Projects (10-50)', projectCount: 25, avgProjectSize: 'medium', includeNodeModules: true },
      { name: 'Large Projects (50+)', projectCount: 100, avgProjectSize: 'large', includeNodeModules: true }
    ];

    console.log(chalk.bold('\n🎯 Concurrency Recommendations:\n'));

    for (const scenario of scenarios) {
      const analysis = calculator.calculateOptimalConcurrency(scenario);

      console.log(chalk.bold(`${scenario.name}:`));
      console.log(`  📈 Optimal: ${chalk.green(analysis.optimal)} workers`);
      console.log(`  🛡️  Safe: ${chalk.yellow(analysis.safe)} workers`);
      console.log(`  ⚡ Aggressive: ${chalk.red(analysis.aggressive)} workers`);
      console.log(`  💾 Memory per worker: ${analysis.memoryPerWorker}`);
      console.log('');
    }

    // Final recommendations
    const generalAnalysis = calculator.calculateOptimalConcurrency({
      projectCount: 20,
      avgProjectSize: 'medium',
      includeNodeModules: true
    });

    console.log(chalk.bold('💡 Final Recommendations:\n'));
    console.log(`For your system (${systemStatus.cpuCores} cores, ${systemStatus.totalMemory} RAM):`);
    console.log(`  🎯 Recommended: ${chalk.green(generalAnalysis.optimal)} parallel workers`);
    console.log(`  🛡️  Conservative: ${chalk.yellow(generalAnalysis.safe)} parallel workers`);
    console.log(`  ⚡ Maximum: ${chalk.red(generalAnalysis.aggressive)} parallel workers`);
  }

  /**
   * Test concurrency performance
   * @param {number} workers - Number of workers to test
   * @param {Config} config - Configuration object
   * @private
   */
  async testConcurrency(workers, config) {
    const logger = new Logger(config.getLoggingConfig());
    const calculator = new ConcurrencyCalculator(logger);

    console.log(chalk.bold(`\n🧪 Testing Concurrency: ${workers} workers\n`));

    try {
      const results = await calculator.testConcurrency(workers, {
        duration: 5000,
        projectCount: 20
      });

      console.log(`  ⏱️  Duration: ${results.duration}ms`);
      console.log(`  💾 Memory Delta: ${calculator.formatBytes(results.memoryDelta)}`);
      console.log(`  📊 Throughput: ${results.throughput.toFixed(2)} projects/sec`);
      console.log(`  ⚡ Efficiency: ${results.efficiency.toFixed(2)} projects/worker/sec`);
    } catch (error) {
      console.log(chalk.red(`  ❌ Test failed: ${error.message}`));
    }
  }

  /**
   * Test scanner functionality
   * @param {Object} options - Test options
   * @private
   */
  async testScanner(options) {
    const testDir = options.directory || path.join(__dirname, '..', '..', 'tests', 'test-projects');

    if (!fs.existsSync(testDir)) {
      throw new Error(`Test directory not found: ${testDir}`);
    }

    console.log(chalk.bold('\n🧪 Testing Scanner Functionality\n'));

    const config = new Config({
      directory: testDir,
      output: { report: false },
      logging: { level: 'info' }
    });

    const scanner = new NPMSecurityScanner(config);
    const results = await scanner.scan();

    console.log('✅ Scanner test completed');
    console.log(`  Projects scanned: ${results.summary.filesScanned}`);
    console.log(`  Issues found: ${results.summary.issuesFound}`);
    console.log(`  Duration: ${results.summary.duration}ms`);
  }

  /**
   * Display scan results
   * @param {Object} results - Scan results
   * @param {Object} options - CLI options
   * @private
   */
  displayResults(results, options) {
    if (options.format === 'json') {
      console.log(JSON.stringify(results, null, 2));
      return;
    }

    if (options.format === 'markdown') {
      this.displayMarkdownResults(results);
      return;
    }

    // Console format (default)
    this.displayConsoleResults(results);
  }

  /**
   * Display results in console format
   * @param {Object} results - Scan results
   * @private
   */
  displayConsoleResults(results) {
    console.log(chalk.bold('\n🔒 SECURITY SCAN REPORT'));
    console.log('='.repeat(80));

    // Summary
    console.log(chalk.bold('\n📊 SUMMARY:'));
    console.log(`Files scanned: ${results.summary.filesScanned}`);
    console.log(`Packages checked: ${results.summary.packagesChecked}`);
    console.log(`Issues found: ${results.summary.issuesFound}`);

    // Compromised packages
    if (results.compromisedPackages.length > 0) {
      console.log(chalk.red.bold('\n🚨 COMPROMISED PACKAGES FOUND:'));
      // Display table of compromised packages
    }

    // Malicious code
    if (results.maliciousCode.length > 0) {
      console.log(chalk.red.bold('\n💀 MALICIOUS CODE DETECTED:'));
      // Display table of malicious code
    }

    // NPM cache issues
    if (results.npmCacheIssues.length > 0) {
      console.log(chalk.yellow.bold('\n⚠️ NPM CACHE VULNERABILITIES:'));
      // Display NPM cache issues
    }
  }

  /**
   * Display results in markdown format
   * @param {Object} results - Scan results
   * @private
   */
  displayMarkdownResults(results) {
    // Implementation for markdown output
    console.log('# Security Scan Report\n');
    console.log(`**Files scanned:** ${results.summary.filesScanned}`);
    console.log(`**Issues found:** ${results.summary.issuesFound}\n`);
  }

  /**
   * Check if results contain high severity issues
   * @param {Object} results - Scan results
   * @returns {boolean} Whether high severity issues exist
   * @private
   */
  hasHighSeverityIssues(results) {
    const highSeverityPatterns = results.maliciousCode.filter(issue =>
      issue.severity === 'HIGH' || issue.severity === 'CRITICAL'
    );

    return highSeverityPatterns.length > 0 || results.compromisedPackages.length > 0;
  }

  /**
   * Handle errors with proper logging
   * @param {Error} error - Error object
   * @private
   */
  handleError(error) {
    if (this.logger) {
      this.logger.error('CLI Error', error);
    } else {
      console.error(chalk.red('Error:'), error.message);
    }
  }

  /**
   * Run the CLI
   * @returns {void}
   */
  run() {
    this.program.parse();
  }
}

// Export for testing
module.exports = SecurityScannerCLI;

// Run CLI if this file is executed directly
if (require.main === module) {
  const cli = new SecurityScannerCLI();
  cli.run();
}
