/**
 * Performance monitoring and optimization utilities for NPM Security Scanner
 * Provides performance tracking, memory monitoring, and optimization suggestions
 */

const os = require('os');
const process = require('process');
const { performance } = require('perf_hooks');

class PerformanceMonitor {
  constructor(logger) {
    this.logger = logger;
    this.metrics = new Map();
    this.memorySnapshots = [];
    this.startTime = performance.now();
    this.isMonitoring = false;
  }

  /**
   * Start performance monitoring
   */
  startMonitoring() {
    this.isMonitoring = true;
    this.startTime = performance.now();
    this.memorySnapshots = [];

    // Take initial memory snapshot
    this.takeMemorySnapshot('start');

    this.logger.debug('Performance monitoring started');
  }

  /**
   * Stop performance monitoring
   * @returns {Object} - Performance summary
   */
  stopMonitoring() {
    if (!this.isMonitoring) {
      return null;
    }

    this.isMonitoring = false;
    const endTime = performance.now();
    const totalDuration = endTime - this.startTime;

    // Take final memory snapshot
    this.takeMemorySnapshot('end');

    const summary = this.generateSummary(totalDuration);
    this.logger.performance('monitoring-complete', totalDuration, summary);

    return summary;
  }

  /**
   * Start timing an operation
   * @param {string} operation - Operation name
   * @returns {string} - Timer ID
   */
  startTimer(operation) {
    const timerId = `${operation}_${Date.now()}_${Math.random()}`;
    this.metrics.set(timerId, {
      operation,
      startTime: performance.now(),
      startMemory: this.getCurrentMemoryUsage()
    });

    return timerId;
  }

  /**
   * End timing an operation
   * @param {string} timerId - Timer ID
   * @param {Object} metadata - Additional metadata
   * @returns {Object} - Timing result
   */
  endTimer(timerId, metadata = {}) {
    const timer = this.metrics.get(timerId);
    if (!timer) {
      this.logger.warn(`Timer not found: ${timerId}`);
      return null;
    }

    const endTime = performance.now();
    const duration = endTime - timer.startTime;
    const endMemory = this.getCurrentMemoryUsage();
    const memoryDelta = endMemory.heapUsed - timer.startMemory.heapUsed;

    const result = {
      operation: timer.operation,
      duration,
      memoryDelta,
      startMemory: timer.startMemory,
      endMemory,
      metadata
    };

    // Log performance
    this.logger.performance(timer.operation, duration, {
      memoryDelta,
      ...metadata
    });

    // Check for performance issues
    this.checkPerformanceIssues(result);

    // Clean up timer
    this.metrics.delete(timerId);

    return result;
  }

  /**
   * Take memory snapshot
   * @param {string} label - Snapshot label
   */
  takeMemorySnapshot(label) {
    const memory = this.getCurrentMemoryUsage();
    const snapshot = {
      label,
      timestamp: performance.now(),
      ...memory
    };

    this.memorySnapshots.push(snapshot);

    // Keep only last 100 snapshots
    if (this.memorySnapshots.length > 100) {
      this.memorySnapshots.shift();
    }
  }

  /**
   * Get current memory usage
   * @returns {Object} - Memory usage information
   */
  getCurrentMemoryUsage() {
    const usage = process.memoryUsage();
    return {
      rss: usage.rss,
      heapTotal: usage.heapTotal,
      heapUsed: usage.heapUsed,
      external: usage.external,
      arrayBuffers: usage.arrayBuffers,
      systemMemory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem()
      }
    };
  }

  /**
   * Check for performance issues
   * @param {Object} result - Timing result
   * @private
   */
  checkPerformanceIssues(result) {
    const issues = [];

    // Check duration
    if (result.duration > 30000) { // 30 seconds
      issues.push({
        type: 'slow_operation',
        message: `Operation '${result.operation}' took ${this.formatDuration(result.duration)}`,
        severity: 'warning'
      });
    }

    // Check memory usage
    if (result.memoryDelta > 100 * 1024 * 1024) { // 100MB
      issues.push({
        type: 'high_memory_usage',
        message: `Operation '${result.operation}' used ${this.formatBytes(result.memoryDelta)} of memory`,
        severity: 'warning'
      });
    }

    // Check memory leak (only for significant memory growth in short time)
    if (result.memoryDelta > 50 * 1024 * 1024 && result.duration < 100) { // 50MB+ in <100ms
      issues.push({
        type: 'potential_memory_leak',
        message: `Operation '${result.operation}' may have a memory leak`,
        severity: 'error'
      });
    }

    // Log issues
    issues.forEach(issue => {
      if (issue.severity === 'error') {
        this.logger.error(`Performance issue: ${issue.message}`);
      } else {
        this.logger.warn(`Performance issue: ${issue.message}`);
      }
    });
  }

  /**
   * Generate performance summary
   * @param {number} totalDuration - Total duration
   * @returns {Object} - Performance summary
   * @private
   */
  generateSummary(totalDuration) {
    const currentMemory = this.getCurrentMemoryUsage();
    const initialMemory = this.memorySnapshots[0] || currentMemory;
    const memoryGrowth = currentMemory.heapUsed - initialMemory.heapUsed;

    // Calculate memory growth rate
    const memoryGrowthRate = totalDuration > 0 ? memoryGrowth / totalDuration : 0;

    // Find peak memory usage
    const peakMemory = this.memorySnapshots.reduce((peak, snapshot) => snapshot.heapUsed > peak.heapUsed ? snapshot : peak, currentMemory);

    return {
      totalDuration: this.formatDuration(totalDuration),
      memory: {
        initial: this.formatBytes(initialMemory.heapUsed),
        current: this.formatBytes(currentMemory.heapUsed),
        peak: this.formatBytes(peakMemory.heapUsed),
        growth: this.formatBytes(memoryGrowth),
        growthRate: `${this.formatBytes(memoryGrowthRate)}/ms`
      },
      system: {
        cpuCount: os.cpus().length,
        platform: os.platform(),
        arch: os.arch(),
        nodeVersion: process.version
      },
      snapshots: this.memorySnapshots.length
    };
  }

  /**
   * Get optimization suggestions
   * @returns {Array} - Array of optimization suggestions
   */
  getOptimizationSuggestions() {
    const suggestions = [];
    const currentMemory = this.getCurrentMemoryUsage();
    const totalMemory = os.totalmem();
    const memoryUsagePercent = (currentMemory.heapUsed / totalMemory) * 100;

    // Memory usage suggestions
    if (memoryUsagePercent > 80) {
      suggestions.push({
        type: 'memory',
        priority: 'high',
        message: 'High memory usage detected. Consider reducing concurrency or implementing streaming.',
        action: 'Reduce maxConcurrency or enable memory optimization'
      });
    }

    // CPU usage suggestions
    const cpuCount = os.cpus().length;
    const activeTimers = this.metrics.size;

    if (activeTimers > cpuCount * 2) {
      suggestions.push({
        type: 'concurrency',
        priority: 'medium',
        message: 'High concurrency detected. Consider reducing parallel operations.',
        action: 'Reduce maxConcurrency setting'
      });
    }

    // Performance suggestions based on metrics
    const slowOperations = Array.from(this.metrics.values())
      .filter(timer => performance.now() - timer.startTime > 10000);

    if (slowOperations.length > 0) {
      suggestions.push({
        type: 'performance',
        priority: 'medium',
        message: `${slowOperations.length} slow operations detected. Consider optimizing file I/O.`,
        action: 'Review file scanning patterns and consider caching'
      });
    }

    return suggestions;
  }

  /**
   * Create performance report
   * @returns {Object} - Performance report
   */
  createReport() {
    const summary = this.generateSummary(performance.now() - this.startTime);
    const suggestions = this.getOptimizationSuggestions();
    const currentMemory = this.getCurrentMemoryUsage();

    return {
      summary,
      suggestions,
      currentStatus: {
        isMonitoring: this.isMonitoring,
        activeTimers: this.metrics.size,
        memorySnapshots: this.memorySnapshots.length,
        uptime: this.formatDuration(performance.now() - this.startTime)
      },
      memory: {
        current: currentMemory,
        snapshots: this.memorySnapshots
      }
    };
  }

  /**
   * Format duration in milliseconds to human readable string
   * @param {number} ms - Duration in milliseconds
   * @returns {string} - Formatted duration
   * @private
   */
  formatDuration(ms) {
    if (ms < 1000) {
      return `${Math.round(ms)}ms`;
    } else if (ms < 60000) {
      return `${(ms / 1000).toFixed(2)}s`;
    } else {
      const minutes = Math.floor(ms / 60000);
      const seconds = ((ms % 60000) / 1000).toFixed(2);
      return `${minutes}m ${seconds}s`;
    }
  }

  /**
   * Format bytes to human readable string
   * @param {number} bytes - Number of bytes
   * @returns {string} - Formatted string
   * @private
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));

    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }

  /**
   * Reset all metrics
   */
  reset() {
    this.metrics.clear();
    this.memorySnapshots = [];
    this.startTime = performance.now();
    this.logger.debug('Performance metrics reset');
  }

  /**
   * Get current status
   * @returns {Object} - Current status
   */
  getStatus() {
    return {
      isMonitoring: this.isMonitoring,
      activeTimers: this.metrics.size,
      memorySnapshots: this.memorySnapshots.length,
      uptime: this.formatDuration(performance.now() - this.startTime),
      currentMemory: this.getCurrentMemoryUsage()
    };
  }
}

module.exports = PerformanceMonitor;
