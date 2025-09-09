/**
 * Parallel project scanner for NPM Security Scanner
 * Handles concurrent scanning of multiple projects with proper resource management
 */

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const path = require('path');
const _os = require('os');
const EventEmitter = require('events');

class ParallelScanner extends EventEmitter {
  constructor(config, logger) {
    super();
    this.config = config;
    this.logger = logger;
    this.maxConcurrency = config.getPerformanceConfig().maxConcurrency;
    this.timeout = config.getPerformanceConfig().timeout;
    this.workerPool = [];
    this.activeWorkers = new Map();
    this.queue = [];
    this.results = [];
    this.errors = [];
    this.isScanning = false;
    this.scanStartTime = null;
  }

  /**
   * Scan multiple projects in parallel
   * @param {Array} projects - Array of project paths
   * @returns {Promise<Object>} - Scan results
   */
  async scanProjects(projects) {
    if (this.isScanning) {
      throw new Error('Scanner is already running');
    }

    this.isScanning = true;
    this.scanStartTime = Date.now();
    this.results = [];
    this.errors = [];
    this.queue = [...projects];

    this.logger.info(`Starting parallel scan of ${projects.length} projects`, {
      maxConcurrency: this.maxConcurrency,
      timeout: this.timeout
    });

    try {
      // Initialize worker pool
      await this.initializeWorkerPool();

      // Process all projects
      await this.processQueue();

      // Cleanup workers
      await this.cleanupWorkers();

      const duration = Date.now() - this.scanStartTime;
      this.logger.performance('parallel-scan', duration, {
        projectsScanned: this.results.length,
        errors: this.errors.length,
        concurrency: this.maxConcurrency
      });

      return {
        results: this.results,
        errors: this.errors,
        summary: {
          totalProjects: projects.length,
          scanned: this.results.length,
          failed: this.errors.length,
          duration,
          concurrency: this.maxConcurrency
        }
      };
    } catch (error) {
      this.logger.error('Parallel scan failed', error);
      throw error;
    } finally {
      this.isScanning = false;
    }
  }

  /**
   * Initialize worker pool
   * @private
   */
  async initializeWorkerPool() {
    const workerCount = Math.min(this.maxConcurrency, this.queue.length);

    for (let i = 0; i < workerCount; i++) {
      const worker = new Worker(__filename, {
        workerData: {
          config: this.config.options,
          workerId: i
        }
      });

      worker.on('message', message => this.handleWorkerMessage(worker, message));
      worker.on('error', error => this.handleWorkerError(worker, error));
      worker.on('exit', code => this.handleWorkerExit(worker, code));

      this.workerPool.push(worker);
      this.activeWorkers.set(worker, { status: 'idle', startTime: null });
    }

    this.logger.debug(`Initialized worker pool with ${workerCount} workers`);
  }

  /**
   * Process the queue of projects
   * @private
   */
  async processQueue() {
    return new Promise((resolve, reject) => {
      this.queueResolve = resolve;
      this.queueReject = reject;
      this.processedCount = 0;
      this.totalProjects = this.queue.length;

      // Start processing
      this.assignWork();
    });
  }

  /**
   * Assign work to available workers
   * @private
   */
  assignWork() {
    if (this.queue.length === 0) {
      // Check if all workers are idle
      const allIdle = Array.from(this.activeWorkers.values()).every(w => w.status === 'idle');
      if (allIdle && this.processedCount === this.totalProjects) {
        this.queueResolve();
        return;
      }
      return;
    }

    // Find idle worker
    const idleWorker = this.findIdleWorker();
    if (!idleWorker) {
      // No idle workers, wait for one to become available
      return;
    }

    const project = this.queue.shift();
    this.assignProjectToWorker(idleWorker, project);
  }

  /**
   * Find an idle worker
   * @returns {Worker|null} - Idle worker or null
   * @private
   */
  findIdleWorker() {
    for (const [worker, info] of this.activeWorkers) {
      if (info.status === 'idle') {
        return worker;
      }
    }
    return null;
  }

  /**
   * Assign project to worker
   * @param {Worker} worker - Worker instance
   * @param {string} project - Project path
   * @private
   */
  assignProjectToWorker(worker, project) {
    const workerInfo = this.activeWorkers.get(worker);
    workerInfo.status = 'working';
    workerInfo.startTime = Date.now();
    workerInfo.project = project;

    this.logger.debug(`Assigning project to worker ${workerInfo.workerId}`, {
      project: path.basename(project),
      workerId: workerInfo.workerId
    });

    // Set timeout for worker
    const timeoutId = setTimeout(() => {
      this.handleWorkerTimeout(worker, project);
    }, this.timeout);

    workerInfo.timeoutId = timeoutId;
    worker.postMessage({ type: 'scan', project, config: this.config.options });
  }

  /**
   * Handle worker message
   * @param {Worker} worker - Worker instance
   * @param {Object} message - Message from worker
   * @private
   */
  handleWorkerMessage(worker, message) {
    const _workerInfo = this.activeWorkers.get(worker);

    switch (message.type) {
      case 'result':
        this.handleWorkerResult(worker, message.data);
        break;
      case 'error':
        this.handleWorkerError(worker, new Error(message.error));
        break;
      case 'progress':
        this.handleWorkerProgress(worker, message.data);
        break;
      default:
        this.logger.warn('Unknown worker message type', { type: message.type });
    }
  }

  /**
   * Handle worker result
   * @param {Worker} worker - Worker instance
   * @param {Object} data - Result data
   * @private
   */
  handleWorkerResult(worker, data) {
    const workerInfo = this.activeWorkers.get(worker);

    // Clear timeout
    if (workerInfo.timeoutId) {
      clearTimeout(workerInfo.timeoutId);
      workerInfo.timeoutId = null;
    }

    // Record performance
    const duration = Date.now() - workerInfo.startTime;
    this.logger.performance('project-scan', duration, {
      project: path.basename(workerInfo.project),
      workerId: workerInfo.workerId,
      issuesFound: data.issues?.length || 0
    });

    // Store result
    this.results.push({
      project: workerInfo.project,
      ...data,
      workerId: workerInfo.workerId,
      duration
    });

    this.processedCount++;
    this.emit('projectComplete', {
      project: workerInfo.project,
      result: data,
      workerId: workerInfo.workerId
    });

    // Reset worker
    workerInfo.status = 'idle';
    workerInfo.startTime = null;
    workerInfo.project = null;

    // Assign next work
    this.assignWork();
  }

  /**
   * Handle worker error
   * @param {Worker} worker - Worker instance
   * @param {Error} error - Error object
   * @private
   */
  handleWorkerError(worker, error) {
    const workerInfo = this.activeWorkers.get(worker);

    // Clear timeout
    if (workerInfo.timeoutId) {
      clearTimeout(workerInfo.timeoutId);
      workerInfo.timeoutId = null;
    }

    const project = workerInfo.project || 'unknown';
    this.errors.push({
      project,
      error: error.message,
      stack: error.stack,
      workerId: workerInfo.workerId
    });

    this.logger.error(`Worker error for project ${project}`, error);

    this.processedCount++;
    this.emit('projectError', {
      project,
      error,
      workerId: workerInfo.workerId
    });

    // Reset worker
    workerInfo.status = 'idle';
    workerInfo.startTime = null;
    workerInfo.project = null;

    // Assign next work
    this.assignWork();
  }

  /**
   * Handle worker progress
   * @param {Worker} worker - Worker instance
   * @param {Object} data - Progress data
   * @private
   */
  handleWorkerProgress(worker, data) {
    const workerInfo = this.activeWorkers.get(worker);
    this.emit('progress', {
      project: workerInfo.project,
      ...data,
      workerId: workerInfo.workerId
    });
  }

  /**
   * Handle worker timeout
   * @param {Worker} worker - Worker instance
   * @param {string} project - Project path
   * @private
   */
  handleWorkerTimeout(worker, project) {
    this.logger.warn(`Worker timeout for project ${project}`, {
      timeout: this.timeout,
      workerId: this.activeWorkers.get(worker)?.workerId
    });

    // Terminate worker
    worker.terminate();

    // Remove from active workers
    this.activeWorkers.delete(worker);

    // Create new worker to replace terminated one
    this.createReplacementWorker();

    // Record error
    this.errors.push({
      project,
      error: 'Worker timeout',
      timeout: this.timeout
    });

    this.processedCount++;
    this.emit('projectError', {
      project,
      error: new Error('Worker timeout'),
      timeout: this.timeout
    });

    // Continue processing
    this.assignWork();
  }

  /**
   * Create replacement worker
   * @private
   */
  createReplacementWorker() {
    const workerId = this.workerPool.length;
    const worker = new Worker(__filename, {
      workerData: {
        config: this.config.options,
        workerId
      }
    });

    worker.on('message', message => this.handleWorkerMessage(worker, message));
    worker.on('error', error => this.handleWorkerError(worker, error));
    worker.on('exit', code => this.handleWorkerExit(worker, code));

    this.workerPool.push(worker);
    this.activeWorkers.set(worker, { status: 'idle', startTime: null, workerId });
  }

  /**
   * Handle worker exit
   * @param {Worker} worker - Worker instance
   * @param {number} code - Exit code
   * @private
   */
  handleWorkerExit(worker, code) {
    if (code !== 0) {
      this.logger.warn(`Worker exited with code ${code}`, {
        workerId: this.activeWorkers.get(worker)?.workerId
      });
    }

    this.activeWorkers.delete(worker);
  }

  /**
   * Cleanup all workers
   * @private
   */
  async cleanupWorkers() {
    const cleanupPromises = this.workerPool.map(worker => new Promise(resolve => {
      worker.terminate();
      worker.on('exit', () => resolve());
    }));

    await Promise.all(cleanupPromises);
    this.workerPool = [];
    this.activeWorkers.clear();

    this.logger.debug('All workers cleaned up');
  }

  /**
   * Get current status
   * @returns {Object} - Current status
   */
  getStatus() {
    const activeWorkers = Array.from(this.activeWorkers.values());
    const working = activeWorkers.filter(w => w.status === 'working').length;
    const idle = activeWorkers.filter(w => w.status === 'idle').length;

    return {
      isScanning: this.isScanning,
      queueLength: this.queue.length,
      processedCount: this.processedCount,
      totalProjects: this.totalProjects,
      activeWorkers: {
        total: activeWorkers.length,
        working,
        idle
      },
      results: this.results.length,
      errors: this.errors.length
    };
  }
}

// Worker thread code
if (!isMainThread) {
  const WorkerScanner = require('./workerScanner');
  const Logger = require('./logger');
  const Config = require('../config');

  const config = new Config(workerData.config);
  const scannerLogger = new Logger(config.getLoggingConfig());
  const scanner = new WorkerScanner(config, scannerLogger);

  // Handle messages from main thread
  parentPort.on('message', async message => {
    try {
      switch (message.type) {
        case 'scan': {
          scannerLogger.info(`Worker ${workerData.workerId} starting scan`, {
            project: message.project
          });

          const result = await scanner.scanProject(message.project);

          parentPort.postMessage({
            type: 'result',
            data: result
          });
          break;
        }

        default:
          scannerLogger.warn('Unknown message type in worker', {
            type: message.type,
            workerId: workerData.workerId
          });
      }
    } catch (error) {
      parentPort.postMessage({
        type: 'error',
        error: error.message
      });
    }
  });

  // Handle worker termination
  process.on('SIGTERM', () => {
    scannerLogger.info(`Worker ${workerData.workerId} terminating`);
    process.exit(0);
  });
}

module.exports = ParallelScanner;
