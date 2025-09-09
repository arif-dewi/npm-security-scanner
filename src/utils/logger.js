/**
 * Professional logging utility for NPM Security Scanner
 * Provides structured logging with different levels and output formats
 */

const chalk = require('chalk').default || require('chalk');
const fs = require('fs');
const path = require('path');

class Logger {
  constructor(options = {}) {
    this.level = options.level || 'info';
    this.verbose = options.verbose || false;
    this.silent = options.silent || false;
    this.logFile = options.logFile || null;
    this.colors = options.colors !== false;

    // Log levels hierarchy
    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
      trace: 4
    };

    // Initialize log file if specified
    if (this.logFile) {
      this.ensureLogDirectory();
    }
  }

  /**
   * Ensure log directory exists
   * @private
   */
  ensureLogDirectory() {
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  /**
   * Check if message should be logged based on level
   * @param {string} level - Log level
   * @returns {boolean} - Whether to log
   * @private
   */
  shouldLog(level) {
    return this.levels[level] <= this.levels[this.level];
  }

  /**
   * Format timestamp for logs
   * @returns {string} - Formatted timestamp
   * @private
   */
  getTimestamp() {
    return new Date().toISOString();
  }

  /**
   * Format log message with colors
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   * @returns {string} - Formatted message
   * @private
   */
  formatMessage(level, message, meta = {}) {
    const timestamp = this.getTimestamp();
    const levelUpper = level.toUpperCase();

    let formattedMessage = `[${timestamp}] ${levelUpper}: ${message}`;

    if (meta && typeof meta === 'object' && Object.keys(meta).length > 0) {
      formattedMessage += ` ${JSON.stringify(meta)}`;
    }

    return formattedMessage;
  }

  /**
   * Get colored output for console
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @returns {string} - Colored message
   * @private
   */
  getColoredMessage(level, message) {
    if (!this.colors) return message;

    const colors = {
      error: chalk.red,
      warn: chalk.yellow,
      info: chalk.blue,
      debug: chalk.gray,
      trace: chalk.dim
    };

    return colors[level] ? colors[level](message) : message;
  }

  /**
   * Write to log file
   * @param {string} message - Log message
   * @private
   */
  writeToFile(message) {
    if (this.logFile) {
      try {
        fs.appendFileSync(this.logFile, `${message}\n`);
      } catch (error) {
        // Fallback to console if file write fails
        console.error('Failed to write to log file:', error.message);
      }
    }
  }

  /**
   * Core logging method
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   * @private
   */
  log(level, message, meta = {}) {
    if (this.silent || !this.shouldLog(level)) {
      return;
    }

    const formattedMessage = this.formatMessage(level, message, meta);
    const coloredMessage = this.getColoredMessage(level, formattedMessage);

    // Write to console
    if (level === 'error') {
      console.error(coloredMessage);
    } else {
      console.log(coloredMessage);
    }

    // Write to file
    this.writeToFile(formattedMessage);
  }

  /**
   * Log error message
   * @param {string} message - Error message
   * @param {Error|Object} error - Error object or metadata
   */
  error(message, error = null) {
    const meta = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error;

    this.log('error', message, meta);
  }

  /**
   * Log warning message
   * @param {string} message - Warning message
   * @param {Object} meta - Additional metadata
   */
  warn(message, meta = {}) {
    this.log('warn', message, meta);
  }

  /**
   * Log info message
   * @param {string} message - Info message
   * @param {Object} meta - Additional metadata
   */
  info(message, meta = {}) {
    this.log('info', message, meta);
  }

  /**
   * Log debug message
   * @param {string} message - Debug message
   * @param {Object} meta - Additional metadata
   */
  debug(message, meta = {}) {
    this.log('debug', message, meta);
  }

  /**
   * Log trace message
   * @param {string} message - Trace message
   * @param {Object} meta - Additional metadata
   */
  trace(message, meta = {}) {
    this.log('trace', message, meta);
  }

  /**
   * Log security event
   * @param {string} event - Security event type
   * @param {Object} details - Event details
   */
  security(event, details = {}) {
    this.warn(`SECURITY: ${event}`, details);
  }

  /**
   * Log scan progress
   * @param {string} phase - Scan phase
   * @param {Object} progress - Progress details
   */
  progress(phase, progress = {}) {
    this.info(`SCAN: ${phase}`, progress);
  }

  /**
   * Log performance metrics
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in milliseconds
   * @param {Object} meta - Additional metadata
   */
  performance(operation, duration, meta = {}) {
    this.debug(`PERF: ${operation}`, { duration, ...meta });
  }

  /**
   * Create child logger with additional context
   * @param {Object} context - Additional context
   * @returns {Logger} - Child logger
   */
  child(context = {}) {
    const childLogger = new Logger({
      level: this.level,
      verbose: this.verbose,
      silent: this.silent,
      logFile: this.logFile,
      colors: this.colors
    });

    // Override log method to include context
    const originalLog = childLogger.log.bind(childLogger);
    childLogger.log = (level, message, meta = {}) => {
      originalLog(level, message, { ...context, ...meta });
    };

    return childLogger;
  }

  /**
   * Set log level
   * @param {string} level - New log level
   */
  setLevel(level) {
    if (Object.prototype.hasOwnProperty.call(this.levels, level)) {
      this.level = level;
    } else {
      this.warn(`Invalid log level: ${level}. Using 'info' instead.`);
      this.level = 'info';
    }
  }

  /**
   * Enable/disable verbose mode
   * @param {boolean} verbose - Verbose mode
   */
  setVerbose(verbose) {
    this.verbose = verbose;
    if (verbose && this.level === 'info') {
      this.level = 'debug';
    }
  }

  /**
   * Enable/disable silent mode
   * @param {boolean} silent - Silent mode
   */
  setSilent(silent) {
    this.silent = silent;
  }
}

module.exports = Logger;
