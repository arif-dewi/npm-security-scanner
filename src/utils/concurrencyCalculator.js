/**
 * Smart concurrency calculator for NPM Security Scanner
 * Calculates optimal parallel processes based on hardware and workload
 */

const os = require('os');
const process = require('process');

class ConcurrencyCalculator {
  constructor(logger) {
    this.logger = logger;
  }

  /**
   * Calculate optimal concurrency for scanning
   * @param {Object} options - Calculation options
   * @returns {Object} - Concurrency recommendations
   */
  calculateOptimalConcurrency(options = {}) {
    const hardware = this.analyzeHardware();
    const workload = this.analyzeWorkload(options);
    const recommendations = this.generateRecommendations(hardware, workload);

    this.logger.debug('Concurrency calculation', {
      hardware,
      workload,
      recommendations
    });

    return {
      hardware,
      workload,
      recommendations,
      optimal: recommendations.optimal,
      safe: recommendations.safe,
      aggressive: recommendations.aggressive
    };
  }

  /**
   * Analyze hardware capabilities
   * @returns {Object} - Hardware analysis
   * @private
   */
  analyzeHardware() {
    const cpus = os.cpus();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;

    // Calculate memory pressure (0 = no pressure, 1 = max pressure)
    const memoryPressure = usedMemory / totalMemory;

    // Analyze CPU performance
    const avgCpuSpeed = cpus.reduce((sum, cpu) => sum + cpu.speed, 0) / cpus.length;
    const isHighPerformance = avgCpuSpeed > 2000; // 2GHz+

    // Check for memory constraints
    const isMemoryConstrained = memoryPressure > 0.9; // 90%+ memory used
    const isLowMemory = totalMemory < 4 * 1024 * 1024 * 1024; // < 4GB

    return {
      cpuCores: cpus.length,
      cpuSpeed: Math.round(avgCpuSpeed),
      totalMemory: this.formatBytes(totalMemory),
      freeMemory: this.formatBytes(freeMemory),
      usedMemory: this.formatBytes(usedMemory),
      memoryPressure: Math.round(memoryPressure * 100),
      isHighPerformance,
      isMemoryConstrained,
      isLowMemory,
      platform: os.platform(),
      arch: os.arch()
    };
  }

  /**
   * Analyze workload characteristics
   * @param {Object} options - Workload options
   * @returns {Object} - Workload analysis
   * @private
   */
  analyzeWorkload(options) {
    const {
      projectCount = 1,
      avgProjectSize = 'medium', // 'small', 'medium', 'large'
      includeNodeModules = true,
      scanType = 'full' // 'quick', 'full', 'deep'
    } = options;

    // Estimate memory usage per project
    const memoryPerProject = this.estimateMemoryPerProject(avgProjectSize, includeNodeModules);

    // Estimate CPU intensity
    const cpuIntensity = this.estimateCpuIntensity(scanType, includeNodeModules);

    // Calculate total estimated memory usage
    const totalEstimatedMemory = memoryPerProject * projectCount;

    return {
      projectCount,
      avgProjectSize,
      includeNodeModules,
      scanType,
      memoryPerProject: this.formatBytes(memoryPerProject),
      totalEstimatedMemory: this.formatBytes(totalEstimatedMemory),
      cpuIntensity, // 0-1 scale
      isLargeWorkload: projectCount > 50,
      isMemoryIntensive: totalEstimatedMemory > 2 * 1024 * 1024 * 1024 // > 2GB
    };
  }

  /**
   * Estimate memory usage per project
   * @param {string} size - Project size
   * @param {boolean} includeNodeModules - Whether to include node_modules
   * @returns {number} - Estimated memory in bytes
   * @private
   */
  estimateMemoryPerProject(size, includeNodeModules) {
    const baseMemory = {
      small: 10 * 1024 * 1024, // 10MB
      medium: 50 * 1024 * 1024, // 50MB
      large: 200 * 1024 * 1024 // 200MB
    };

    const nodeModulesMultiplier = includeNodeModules ? 3 : 1;
    return baseMemory[size] * nodeModulesMultiplier;
  }

  /**
   * Estimate CPU intensity
   * @param {string} scanType - Type of scan
   * @param {boolean} includeNodeModules - Whether to include node_modules
   * @returns {number} - CPU intensity (0-1)
   * @private
   */
  estimateCpuIntensity(scanType, includeNodeModules) {
    const baseIntensity = {
      quick: 0.2,
      full: 0.6,
      deep: 0.9
    };

    const nodeModulesMultiplier = includeNodeModules ? 1.5 : 1;
    return Math.min(baseIntensity[scanType] * nodeModulesMultiplier, 1);
  }

  /**
   * Generate concurrency recommendations
   * @param {Object} hardware - Hardware analysis
   * @param {Object} workload - Workload analysis
   * @returns {Object} - Concurrency recommendations
   * @private
   */
  generateRecommendations(hardware, workload) {
    const { cpuCores, isMemoryConstrained, isLowMemory, isHighPerformance } = hardware;
    const { projectCount: _projectCount, isLargeWorkload, isMemoryIntensive, cpuIntensity } = workload;

    // Base concurrency (CPU cores)
    let baseConcurrency = cpuCores;

    // Adjust for memory constraints
    if (isMemoryConstrained || isLowMemory) {
      baseConcurrency = Math.max(1, Math.floor(cpuCores * 0.5));
    }

    // Adjust for memory-intensive workloads
    if (isMemoryIntensive) {
      baseConcurrency = Math.max(1, Math.floor(baseConcurrency * 0.7));
    }

    // Adjust for CPU intensity
    if (cpuIntensity > 0.8) {
      baseConcurrency = Math.max(1, Math.floor(baseConcurrency * 0.8));
    }

    // Adjust for large workloads (more projects = more overhead)
    if (isLargeWorkload) {
      baseConcurrency = Math.max(1, Math.floor(baseConcurrency * 0.9));
    }

    // Performance boost for high-performance systems
    if (isHighPerformance && !isMemoryConstrained) {
      baseConcurrency = Math.min(baseConcurrency * 1.2, cpuCores * 2);
    }

    // Calculate different concurrency levels
    const optimal = Math.max(1, Math.floor(baseConcurrency));
    const safe = Math.max(1, Math.floor(baseConcurrency * 0.7));
    const aggressive = Math.min(Math.floor(baseConcurrency * 1.5), cpuCores * 2);

    // Calculate memory per worker
    const memoryPerWorker = Math.floor((os.totalmem() * 0.8) / optimal); // 80% of total memory

    return {
      optimal,
      safe,
      aggressive,
      maxPossible: cpuCores * 2,
      memoryPerWorker: this.formatBytes(memoryPerWorker),
      reasoning: this.generateReasoning(hardware, workload, { optimal, safe, aggressive }) || []
    };
  }

  /**
   * Generate reasoning for recommendations
   * @param {Object} hardware - Hardware analysis
   * @param {Object} workload - Workload analysis
   * @param {Object} concurrency - Concurrency levels
   * @returns {Array} - Reasoning explanations
   * @private
   */
  generateReasoning(hardware, workload, _concurrency) {
    const reasons = [];

    reasons.push(`Base concurrency: ${hardware.cpuCores} CPU cores`);

    if (hardware.isMemoryConstrained) {
      reasons.push(`Reduced due to high memory pressure (${hardware.memoryPressure}% used)`);
    }

    if (hardware.isLowMemory) {
      reasons.push(`Reduced due to low total memory (${hardware.totalMemory})`);
    }

    if (workload.isMemoryIntensive) {
      reasons.push('Reduced due to memory-intensive workload');
    }

    if (workload.cpuIntensity > 0.8) {
      reasons.push('Reduced due to high CPU intensity');
    }

    if (workload.isLargeWorkload) {
      reasons.push(`Reduced due to large workload (${workload.projectCount} projects)`);
    }

    if (hardware.isHighPerformance && !hardware.isMemoryConstrained) {
      reasons.push('Increased due to high-performance system');
    }

    return reasons;
  }

  /**
   * Get real-time system status
   * @returns {Object} - Current system status
   */
  getSystemStatus() {
    const hardware = this.analyzeHardware();
    const processMemory = process.memoryUsage();

    return {
      ...hardware,
      processMemory: {
        rss: this.formatBytes(processMemory.rss),
        heapTotal: this.formatBytes(processMemory.heapTotal),
        heapUsed: this.formatBytes(processMemory.heapUsed),
        external: this.formatBytes(processMemory.external)
      },
      uptime: Math.round(process.uptime()),
      nodeVersion: process.version
    };
  }

  /**
   * Test concurrency with a sample workload
   * @param {number} concurrency - Concurrency level to test
   * @param {Object} options - Test options
   * @returns {Promise<Object>} - Test results
   */
  async testConcurrency(concurrency, options = {}) {
    const { duration = 5000, projectCount = 10 } = options;

    this.logger.info(`Testing concurrency level: ${concurrency}`, {
      duration,
      projectCount
    });

    const startTime = Date.now();
    const startMemory = process.memoryUsage();

    // Simulate workload
    const promises = Array(concurrency).fill().map(async(_, _i) => {
      const projects = Math.ceil(projectCount / concurrency);
      for (let j = 0; j < projects; j++) {
        // Simulate file I/O
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
      }
    });

    await Promise.all(promises);

    const endTime = Date.now();
    const endMemory = process.memoryUsage();

    const results = {
      concurrency,
      duration: endTime - startTime,
      memoryDelta: endMemory.heapUsed - startMemory.heapUsed,
      throughput: projectCount / ((endTime - startTime) / 1000),
      efficiency: (projectCount / concurrency) / ((endTime - startTime) / 1000)
    };

    this.logger.debug('Concurrency test completed', results);
    return results;
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
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }
}

module.exports = ConcurrencyCalculator;
