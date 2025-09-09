/**
 * Input validation and sanitization utilities for NPM Security Scanner
 * Provides comprehensive validation for all inputs and data
 */

const path = require('path');
const fs = require('fs');
const { URL } = require('url');

class Validator {
  constructor(logger) {
    this.logger = logger;
  }

  /**
   * Validate directory path
   * @param {string} dirPath - Directory path to validate
   * @returns {Object} - Validation result
   */
  validateDirectory(dirPath) {
    const errors = [];
    const warnings = [];

    if (!dirPath || typeof dirPath !== 'string') {
      errors.push('Directory path is required and must be a string');
      return { isValid: false, errors, warnings };
    }

    // Normalize path
    const normalizedPath = path.resolve(dirPath);

    // Check if path exists
    if (!fs.existsSync(normalizedPath)) {
      errors.push(`Directory does not exist: ${normalizedPath}`);
      return { isValid: false, errors, warnings };
    }

    // Check if it's a directory
    const stats = fs.statSync(normalizedPath);
    if (!stats.isDirectory()) {
      errors.push(`Path is not a directory: ${normalizedPath}`);
      return { isValid: false, errors, warnings };
    }

    // Check read permissions
    try {
      fs.accessSync(normalizedPath, fs.constants.R_OK);
    } catch (error) {
      errors.push(`No read permission for directory: ${normalizedPath}`);
      return { isValid: false, errors, warnings };
    }

    // Check for potential security issues
    if (this.isSuspiciousPath(normalizedPath)) {
      warnings.push(`Suspicious directory path detected: ${normalizedPath}`);
    }

    return { isValid: true, errors, warnings, normalizedPath };
  }

  /**
   * Validate file path
   * @param {string} filePath - File path to validate
   * @returns {Object} - Validation result
   */
  validateFile(filePath) {
    const errors = [];
    const warnings = [];

    if (!filePath || typeof filePath !== 'string') {
      errors.push('File path is required and must be a string');
      return { isValid: false, errors, warnings };
    }

    const normalizedPath = path.resolve(filePath);

    if (!fs.existsSync(normalizedPath)) {
      errors.push(`File does not exist: ${normalizedPath}`);
      return { isValid: false, errors, warnings };
    }

    const stats = fs.statSync(normalizedPath);
    if (!stats.isFile()) {
      errors.push(`Path is not a file: ${normalizedPath}`);
      return { isValid: false, errors, warnings };
    }

    // Check file size
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (stats.size > maxSize) {
      warnings.push(`Large file detected: ${normalizedPath} (${this.formatBytes(stats.size)})`);
    }

    // Check for suspicious file extensions
    const ext = path.extname(normalizedPath).toLowerCase();
    const suspiciousExts = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com'];
    if (suspiciousExts.includes(ext)) {
      warnings.push(`Suspicious file extension: ${ext}`);
    }

    return { isValid: true, errors, warnings, normalizedPath };
  }

  /**
   * Validate package.json content
   * @param {Object} packageJson - Package.json object
   * @returns {Object} - Validation result
   */
  validatePackageJson(packageJson) {
    const errors = [];
    const warnings = [];

    if (!packageJson || typeof packageJson !== 'object') {
      errors.push('Package.json must be a valid object');
      return { isValid: false, errors, warnings };
    }

    // Validate required fields
    if (!packageJson.name) {
      errors.push('Package name is required');
    } else if (typeof packageJson.name !== 'string') {
      errors.push('Package name must be a string');
    } else if (!this.isValidPackageName(packageJson.name)) {
      errors.push('Invalid package name format');
    }

    if (!packageJson.version) {
      errors.push('Package version is required');
    } else if (!this.isValidVersion(packageJson.version)) {
      errors.push('Invalid version format');
    }

    // Validate dependencies
    if (packageJson.dependencies) {
      const depValidation = this.validateDependencies(packageJson.dependencies);
      errors.push(...depValidation.errors);
      warnings.push(...depValidation.warnings);
    }

    if (packageJson.devDependencies) {
      const depValidation = this.validateDependencies(packageJson.devDependencies);
      errors.push(...depValidation.errors);
      warnings.push(...depValidation.warnings);
    }

    // Check for suspicious fields
    const suspiciousFields = ['scripts', 'bin', 'preinstall', 'postinstall'];
    for (const field of suspiciousFields) {
      if (packageJson[field]) {
        warnings.push(`Field '${field}' found - review for security implications`);
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate dependencies object
   * @param {Object} dependencies - Dependencies object
   * @returns {Object} - Validation result
   * @private
   */
  validateDependencies(dependencies) {
    const errors = [];
    const warnings = [];

    if (typeof dependencies !== 'object') {
      errors.push('Dependencies must be an object');
      return { errors, warnings };
    }

    for (const [name, version] of Object.entries(dependencies)) {
      // Validate package name
      if (!this.isValidPackageName(name)) {
        errors.push(`Invalid package name: ${name}`);
      }

      // Validate version
      if (!this.isValidVersion(version)) {
        errors.push(`Invalid version for ${name}: ${version}`);
      }

      // Check for suspicious packages
      if (this.isSuspiciousPackage(name)) {
        warnings.push(`Suspicious package detected: ${name}`);
      }

      // Check for version ranges that might be too broad
      if (this.isTooBroadVersion(version)) {
        warnings.push(`Broad version range for ${name}: ${version}`);
      }
    }

    return { errors, warnings };
  }

  /**
   * Validate package name
   * @param {string} name - Package name
   * @returns {boolean} - Whether name is valid
   * @private
   */
  isValidPackageName(name) {
    if (typeof name !== 'string') return false;

    // NPM package name rules
    const npmNameRegex = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
    return npmNameRegex.test(name) && name.length <= 214;
  }

  /**
   * Validate version string
   * @param {string} version - Version string
   * @returns {boolean} - Whether version is valid
   * @private
   */
  isValidVersion(version) {
    if (typeof version !== 'string') return false;

    // Basic semver-like validation
    const versionRegex = /^[\^~]?[\d]+\.[\d]+\.[\d]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;
    return versionRegex.test(version);
  }

  /**
   * Check if package is suspicious
   * @param {string} name - Package name
   * @returns {boolean} - Whether package is suspicious
   * @private
   */
  isSuspiciousPackage(name) {
    const suspiciousPatterns = [
      /typo/i,
      /misspell/i,
      /fake/i,
      /malware/i,
      /virus/i,
      /trojan/i,
      /backdoor/i,
      /keylogger/i,
      /stealer/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(name));
  }

  /**
   * Check if version range is too broad
   * @param {string} version - Version string
   * @returns {boolean} - Whether version is too broad
   * @private
   */
  isTooBroadVersion(version) {
    // Check for very broad ranges
    const broadPatterns = [
      /^\*$/, // *
      /^[\^~]?[\d]+$/, // ^1 or ~1
      /^[\^~]?[\d]+\.[\d]+$/, // ^1.0 or ~1.0
      /^latest$/i, // latest
      /^any$/i // any
    ];

    return broadPatterns.some(pattern => pattern.test(version));
  }

  /**
   * Check if path is suspicious
   * @param {string} path - Path to check
   * @returns {boolean} - Whether path is suspicious
   * @private
   */
  isSuspiciousPath(path) {
    const suspiciousPatterns = [
      /\.\./, // Parent directory traversal
      /\/tmp\//, // Temporary directories
      /\/temp\//, // Temporary directories
      /\/cache\//, // Cache directories
      /node_modules/, // Node modules (might be expected)
      /\.git/, // Git directories
      /\.svn/, // SVN directories
      /\.hg/ // Mercurial directories
    ];

    return suspiciousPatterns.some(pattern => pattern.test(path));
  }

  /**
   * Validate URL
   * @param {string} url - URL to validate
   * @returns {Object} - Validation result
   */
  validateUrl(url) {
    const errors = [];
    const warnings = [];

    if (!url || typeof url !== 'string') {
      errors.push('URL is required and must be a string');
      return { isValid: false, errors, warnings };
    }

    try {
      const parsedUrl = new URL(url);

      // Check protocol
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        errors.push(`Unsupported protocol: ${parsedUrl.protocol}`);
      }

      // Check for suspicious domains
      if (this.isSuspiciousDomain(parsedUrl.hostname)) {
        warnings.push(`Suspicious domain detected: ${parsedUrl.hostname}`);
      }

      // Check for IP addresses
      if (this.isIPAddress(parsedUrl.hostname)) {
        warnings.push(`IP address used instead of domain: ${parsedUrl.hostname}`);
      }
    } catch (error) {
      errors.push(`Invalid URL format: ${error.message}`);
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Check if domain is suspicious
   * @param {string} domain - Domain to check
   * @returns {boolean} - Whether domain is suspicious
   * @private
   */
  isSuspiciousDomain(domain) {
    const suspiciousPatterns = [
      /typo/i,
      /misspell/i,
      /fake/i,
      /phishing/i,
      /malware/i,
      /virus/i,
      /\.tk$/i,
      /\.ml$/i,
      /\.ga$/i,
      /\.cf$/i
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  /**
   * Check if string is an IP address
   * @param {string} str - String to check
   * @returns {boolean} - Whether string is an IP address
   * @private
   */
  isIPAddress(str) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(str) || ipv6Regex.test(str);
  }

  /**
   * Sanitize file path
   * @param {string} filePath - File path to sanitize
   * @returns {string} - Sanitized path
   */
  sanitizePath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      return '';
    }

    // Normalize path separators
    let sanitized = filePath.replace(/[\\\/]+/g, path.sep);

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Resolve relative paths
    sanitized = path.resolve(sanitized);

    return sanitized;
  }

  /**
   * Sanitize string input
   * @param {string} input - Input string
   * @param {Object} options - Sanitization options
   * @returns {string} - Sanitized string
   */
  sanitizeString(input, options = {}) {
    if (typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Trim whitespace
    if (options.trim !== false) {
      sanitized = sanitized.trim();
    }

    // Limit length
    if (options.maxLength && sanitized.length > options.maxLength) {
      sanitized = sanitized.substring(0, options.maxLength);
    }

    // Remove control characters
    if (options.removeControlChars !== false) {
      sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
    }

    return sanitized;
  }

  /**
   * Validate scan options
   * @param {Object} options - Scan options
   * @returns {Object} - Validation result
   */
  validateScanOptions(options) {
    const errors = [];
    const warnings = [];

    if (!options || typeof options !== 'object') {
      errors.push('Options must be an object');
      return { isValid: false, errors, warnings };
    }

    // Validate directory
    if (options.directory) {
      const dirValidation = this.validateDirectory(options.directory);
      if (!dirValidation.isValid) {
        errors.push(...dirValidation.errors);
      }
      warnings.push(...dirValidation.warnings);
    }

    // Validate concurrency
    if (options.maxConcurrency !== undefined) {
      if (typeof options.maxConcurrency !== 'number' || options.maxConcurrency < 1) {
        errors.push('maxConcurrency must be a positive number');
      } else if (options.maxConcurrency > 100) {
        warnings.push('High concurrency may impact system performance');
      }
    }

    // Validate timeout
    if (options.timeout !== undefined) {
      if (typeof options.timeout !== 'number' || options.timeout < 1000) {
        errors.push('timeout must be at least 1000ms');
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Format bytes to human readable string
   * @param {number} bytes - Number of bytes
   * @returns {string} - Formatted string
   * @private
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  }
}

module.exports = Validator;
