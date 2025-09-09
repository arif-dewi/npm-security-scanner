/**
 * Advanced logging utility for NPM Security Scanner
 * @module utils/logger
 */

const chalk = require('chalk').default || require('chalk');
const fs = require('fs');
const path = require('path');

/**
 * Log levels
 */
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  TRACE: 4
};

/**
 * Logger class with multiple output targets and formatting
 */
class Logger {
  constructor(options = {}) {
    this.level = options.level || LOG_LEVELS.INFO;
    this.verbose = options.verbose || false;
    this.logFile = options.logFile;
    this.silent = options.silent || false;
    
    // Initialize log file if specified
    if (this.logFile) {
      this._ensureLogDirectory();
    }
  }

  /**
   * Log error message
   * @param {string} message - Error message
   * @param {Error} [error] - Error object for stack trace
   * @param {Object} [context] - Additional context
   */
  error(message, error = null, context = {}) {
    if (this.level >= LOG_LEVELS.ERROR) {
      this._log('ERROR', message, { error, ...context }, chalk.red);
    }
  }

  /**
   * Log warning message
   * @param {string} message - Warning message
   * @param {Object} [context] - Additional context
   */
  warn(message, context = {}) {
    if (this.level >= LOG_LEVELS.WARN) {
      this._log('WARN', message, context, chalk.yellow);
    }
  }

  /**
   * Log info message
   * @param {string} message - Info message
   * @param {Object} [context] - Additional context
   */
  info(message, context = {}) {
    if (this.level >= LOG_LEVELS.INFO) {
      this._log('INFO', message, context, chalk.blue);
    }
  }

  /**
   * Log debug message
   * @param {string} message - Debug message
   * @param {Object} [context] - Additional context
   */
  debug(message, context = {}) {
    if (this.level >= LOG_LEVELS.DEBUG) {
      this._log('DEBUG', message, context, chalk.gray);
    }
  }

  /**
   * Log trace message
   * @param {string} message - Trace message
   * @param {Object} [context] - Additional context
   */
  trace(message, context = {}) {
    if (this.level >= LOG_LEVELS.TRACE) {
      this._log('TRACE', message, context, chalk.gray.dim);
    }
  }

  /**
   * Create a child logger with additional context
   * @param {Object} context - Context to add to all logs
   * @returns {Logger} Child logger instance
   */
  child(context) {
    return new Logger({
      level: this.level,
      verbose: this.verbose,
      logFile: this.logFile,
      silent: this.silent,
      context: { ...this.context, ...context }
    });
  }

  /**
   * Internal log method
   * @private
   */
  _log(level, message, context, colorFn) {
    if (this.silent) return;

    const timestamp = new Date().toISOString();
    const contextStr = Object.keys(context).length > 0 ? ` ${JSON.stringify(context)}` : '';
    const logMessage = `[${timestamp}] ${level}: ${message}${contextStr}`;
    
    // Console output with colors
    console.log(colorFn(logMessage));
    
    // File output (no colors)
    if (this.logFile) {
      const fileMessage = `[${timestamp}] ${level}: ${message}${contextStr}\n`;
      fs.appendFileSync(this.logFile, fileMessage);
    }
  }

  /**
   * Ensure log directory exists
   * @private
   */
  _ensureLogDirectory() {
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }
}

/**
 * Create a logger instance
 * @param {Object} options - Logger options
 * @returns {Logger} Logger instance
 */
function createLogger(options = {}) {
  return new Logger(options);
}

module.exports = {
  Logger,
  createLogger,
  LOG_LEVELS
};
