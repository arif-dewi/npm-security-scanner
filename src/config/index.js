/**
 * Configuration management for NPM Security Scanner
 * @module config
 */

const path = require('path');
const fs = require('fs');

/**
 * Default configuration values
 */
const DEFAULT_CONFIG = {
  // Scan settings
  scanSettings: {
    recursive: true,
    ignorePatterns: [
      '**/node_modules/**',
      '**/security-check/**',
      '**/test-scanner.js',
      '**/.git/**',
      '**/reports/**',
      '**/coverage/**',
      '**/dist/**',
      '**/build/**'
    ],
    maxConcurrentScans: 5,
    timeout: 30000 // 30 seconds per project
  },
  
  // Output settings
  output: {
    reportsDir: 'reports',
    generateMarkdown: true,
    generateConsole: true,
    verbose: false
  },
  
  // Detection settings
  detection: {
    enablePackageScan: true,
    enableNodeModulesScan: true,
    enableMaliciousCodeScan: true,
    enableNpmCacheScan: true,
    enableSuspiciousFileScan: true
  }
};

/**
 * Configuration manager class
 */
class ConfigManager {
  constructor(options = {}) {
    this.config = this._mergeConfig(DEFAULT_CONFIG, options);
    this._validateConfig();
  }

  /**
   * Get configuration value by path
   * @param {string} path - Dot notation path (e.g., 'scanSettings.recursive')
   * @returns {*} Configuration value
   */
  get(path) {
    return this._getNestedValue(this.config, path);
  }

  /**
   * Set configuration value by path
   * @param {string} path - Dot notation path
   * @param {*} value - Value to set
   */
  set(path, value) {
    this._setNestedValue(this.config, path, value);
  }

  /**
   * Get all configuration
   * @returns {Object} Complete configuration object
   */
  getAll() {
    return JSON.parse(JSON.stringify(this.config));
  }

  /**
   * Merge configuration objects
   * @private
   */
  _mergeConfig(defaultConfig, userConfig) {
    const merged = JSON.parse(JSON.stringify(defaultConfig));
    
    for (const key in userConfig) {
      if (userConfig[key] && typeof userConfig[key] === 'object' && !Array.isArray(userConfig[key])) {
        merged[key] = this._mergeConfig(merged[key] || {}, userConfig[key]);
      } else {
        merged[key] = userConfig[key];
      }
    }
    
    return merged;
  }

  /**
   * Get nested value from object using dot notation
   * @private
   */
  _getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  /**
   * Set nested value in object using dot notation
   * @private
   */
  _setNestedValue(obj, path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);
    target[lastKey] = value;
  }

  /**
   * Validate configuration
   * @private
   */
  _validateConfig() {
    const { scanSettings, output, detection } = this.config;

    // Validate scan settings
    if (typeof scanSettings.recursive !== 'boolean') {
      throw new Error('scanSettings.recursive must be a boolean');
    }
    
    if (!Array.isArray(scanSettings.ignorePatterns)) {
      throw new Error('scanSettings.ignorePatterns must be an array');
    }

    if (typeof scanSettings.maxConcurrentScans !== 'number' || scanSettings.maxConcurrentScans < 1) {
      throw new Error('scanSettings.maxConcurrentScans must be a positive number');
    }

    // Validate output settings
    if (typeof output.reportsDir !== 'string' || !output.reportsDir.trim()) {
      throw new Error('output.reportsDir must be a non-empty string');
    }

    // Validate detection settings
    Object.values(detection).forEach(value => {
      if (typeof value !== 'boolean') {
        throw new Error('All detection settings must be boolean values');
      }
    });
  }
}

module.exports = {
  ConfigManager,
  DEFAULT_CONFIG
};
