/**
 * Configuration management for NPM Security Scanner
 * Handles all configuration options, validation, and defaults
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

class Config {
  constructor(options = {}) {
    this.options = this.mergeWithDefaults(options);
    this.validate();
  }

  /**
   * Merge user options with defaults
   * @param {Object} userOptions - User provided options
   * @returns {Object} - Merged configuration
   * @private
   */
  mergeWithDefaults(userOptions) {
    const defaults = {
      // Scan configuration
      directory: process.cwd(),
      recursive: true,
      includeNodeModules: true,
      includeHidden: false,

      // File patterns
      includePatterns: ['**/*.js', '**/*.json', '**/*.ts', '**/*.jsx', '**/*.tsx'],
      excludePatterns: [
        '**/node_modules/**',
        '**/dist/**',
        '**/build/**',
        '**/coverage/**',
        '**/.git/**',
        '**/security-check/**',
        '**/test-scanner.js',
        '**/test-comprehensive.js'
      ],

      // Output configuration
      output: {
        format: 'both', // 'console', 'json', 'markdown', 'both'
        report: true,
        reportDir: 'reports',
        verbose: true,
        silent: false,
        colors: true
      },

      // Logging configuration
      logging: {
        level: 'info', // 'error', 'warn', 'info', 'debug', 'trace'
        file: null,
        console: true
      },

      // Security configuration
      security: {
        scanMaliciousCode: true,
        scanCompromisedPackages: true,
        scanNpmCache: true,
        scanNodeModules: true,
        strictMode: false,
        failOnHigh: false
      },

      // Performance configuration
      performance: {
        maxConcurrency: Math.max(1, Math.floor(os.cpus().length * 0.4)), // 40% of CPU cores for memory-constrained systems
        timeout: 30000, // 30 seconds
        memoryLimit: 512 * 1024 * 1024, // 512MB (reduced for memory-constrained systems)
        enableCaching: true
      },

      // Validation configuration
      validation: {
        strictPackageJson: true,
        validateVersions: true,
        checkIntegrity: true
      }
    };

    return this.deepMerge(defaults, userOptions);
  }

  /**
   * Deep merge two objects
   * @param {Object} target - Target object
   * @param {Object} source - Source object
   * @returns {Object} - Merged object
   * @private
   */
  deepMerge(target, source) {
    const result = { ...target };

    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(target[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }

    return result;
  }

  /**
   * Validate configuration
   * @throws {Error} - If configuration is invalid
   * @private
   */
  validate() {
    // Validate directory
    if (!fs.existsSync(this.options.directory)) {
      throw new Error(`Directory does not exist: ${this.options.directory}`);
    }

    if (!fs.statSync(this.options.directory).isDirectory()) {
      throw new Error(`Path is not a directory: ${this.options.directory}`);
    }

    // Validate logging level
    const validLevels = ['error', 'warn', 'info', 'debug', 'trace'];
    if (!validLevels.includes(this.options.logging.level)) {
      throw new Error(`Invalid logging level: ${this.options.logging.level}`);
    }

    // Validate output format
    const validFormats = ['console', 'json', 'markdown', 'both'];
    if (!validFormats.includes(this.options.output.format)) {
      throw new Error(`Invalid output format: ${this.options.output.format}`);
    }

    // Validate performance settings
    if (this.options.performance.maxConcurrency < 1) {
      throw new Error('Max concurrency must be at least 1');
    }

    if (this.options.performance.timeout < 1000) {
      throw new Error('Timeout must be at least 1000ms');
    }

    // Validate memory limit
    if (this.options.performance.memoryLimit < 100 * 1024 * 1024) {
      throw new Error('Memory limit must be at least 100MB');
    }
  }

  /**
   * Get configuration value by path
   * @param {string} path - Dot notation path (e.g., 'output.verbose')
   * @returns {*} - Configuration value
   */
  get(path) {
    return path.split('.').reduce((obj, key) => obj?.[key], this.options);
  }

  /**
   * Set configuration value by path
   * @param {string} path - Dot notation path
   * @param {*} value - Value to set
   */
  set(path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((obj, key) => {
      if (!obj[key]) obj[key] = {};
      return obj[key];
    }, this.options);
    target[lastKey] = value;
  }

  /**
   * Check if option is enabled
   * @param {string} path - Dot notation path
   * @returns {boolean} - Whether option is enabled
   */
  isEnabled(path) {
    return Boolean(this.get(path));
  }

  /**
   * Get scan patterns
   * @returns {Object} - Include and exclude patterns
   */
  getScanPatterns() {
    return {
      include: this.options.includePatterns,
      exclude: this.options.excludePatterns
    };
  }

  /**
   * Get output configuration
   * @returns {Object} - Output configuration
   */
  getOutputConfig() {
    return this.options.output;
  }

  /**
   * Get logging configuration
   * @returns {Object} - Logging configuration
   */
  getLoggingConfig() {
    return this.options.logging;
  }

  /**
   * Get security configuration
   * @returns {Object} - Security configuration
   */
  getSecurityConfig() {
    return this.options.security;
  }

  /**
   * Get performance configuration
   * @returns {Object} - Performance configuration
   */
  getPerformanceConfig() {
    return this.options.performance;
  }

  /**
   * Get validation configuration
   * @returns {Object} - Validation configuration
   */
  getValidationConfig() {
    return this.options.validation;
  }

  /**
   * Load configuration from file
   * @param {string} configPath - Path to configuration file
   * @returns {Config} - New Config instance
   * @static
   */
  static fromFile(configPath) {
    try {
      const configData = fs.readFileSync(configPath, 'utf8');
      const userOptions = JSON.parse(configData);
      return new Config(userOptions);
    } catch (error) {
      throw new Error(`Failed to load configuration from ${configPath}: ${error.message}`);
    }
  }

  /**
   * Save configuration to file
   * @param {string} configPath - Path to save configuration
   */
  saveToFile(configPath) {
    try {
      const configDir = path.dirname(configPath);
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }

      fs.writeFileSync(configPath, JSON.stringify(this.options, null, 2));
    } catch (error) {
      throw new Error(`Failed to save configuration to ${configPath}: ${error.message}`);
    }
  }

  /**
   * Create default configuration file
   * @param {string} configPath - Path to save default configuration
   * @static
   */
  static createDefaultConfig(configPath) {
    const defaultConfig = new Config();
    defaultConfig.saveToFile(configPath);
  }

  /**
   * Get configuration summary
   * @returns {Object} - Configuration summary
   */
  getSummary() {
    return {
      directory: this.options.directory,
      recursive: this.options.recursive,
      includeNodeModules: this.options.includeNodeModules,
      outputFormat: this.options.output.format,
      logLevel: this.options.logging.level,
      securityScans: {
        maliciousCode: this.options.security.scanMaliciousCode,
        compromisedPackages: this.options.security.scanCompromisedPackages,
        npmCache: this.options.security.scanNpmCache,
        nodeModules: this.options.security.scanNodeModules
      },
      performance: {
        maxConcurrency: this.options.performance.maxConcurrency,
        timeout: this.options.performance.timeout
      }
    };
  }

  /**
   * Clone configuration
   * @returns {Config} - Cloned configuration
   */
  clone() {
    return new Config(JSON.parse(JSON.stringify(this.options)));
  }
}

module.exports = Config;
