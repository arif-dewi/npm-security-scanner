/**
 * Worker Scanner for Parallel Processing
 * 
 * This module is used by worker threads to avoid circular dependencies.
 * It contains only the core scanning logic without the parallel processing components.
 */

const fs = require('fs');
const path = require('path');
const PackageScanner = require('./packageScanner');
const PatternMatcher = require('./patternMatcher');
const Logger = require('./logger');
const Config = require('../config');
const PerformanceMonitor = require('./performance');
const Validator = require('./validator');

class WorkerScanner {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.performance = new PerformanceMonitor(logger);
    this.validator = new Validator(logger);
    this.packageScanner = new PackageScanner(logger, this.performance, this.validator);
    this.patternMatcher = new PatternMatcher(logger);
  }

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
        suspiciousFiles: []
      };

      // Step 1: Scan package.json for vulnerable packages
      if (this.config.get('security.scanCompromisedPackages')) {
        this.logger.debug('  📦 Scanning package.json for vulnerable packages...');
        const packageResults = await this.packageScanner.scanPackageFiles(projectPath);
        results.compromisedPackages.push(...packageResults);
        if (packageResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${packageResults.length} vulnerable packages`);
        }
      }

      // Step 2: Scan JavaScript files for malicious patterns
      if (this.config.get('security.scanMaliciousCode')) {
        this.logger.debug('  🔍 Scanning JavaScript files for malicious patterns...');
        const jsResults = await this.patternMatcher.scanJavaScriptFiles(projectPath);
        results.maliciousCode.push(...jsResults);
        if (jsResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${jsResults.length} malicious code patterns`);
        }
      }

      // Step 3: Scan node_modules for malicious code
      if (this.config.get('security.scanNodeModules')) {
        this.logger.debug('  📁 Scanning node_modules for malicious code...');
        const nodeModulesResults = await this.patternMatcher.scanJavaScriptFiles(path.join(projectPath, 'node_modules'));
        results.maliciousCode.push(...nodeModulesResults);
        if (nodeModulesResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${nodeModulesResults.length} malicious patterns in node_modules`);
        }
      }

      // Step 4: Scan NPM cache for vulnerabilities
      if (this.config.get('security.scanNpmCache')) {
        this.logger.debug('  💾 Scanning NPM cache for vulnerabilities...');
        const cacheResults = await this.scanNpmCache();
        results.npmCacheIssues.push(...cacheResults);
        if (cacheResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${cacheResults.length} NPM cache issues`);
        }
      }

      const totalIssues = results.compromisedPackages.length + results.maliciousCode.length + results.npmCacheIssues.length;
      this.performance.endTimer(projectTimer, {
        project: projectName,
        issuesFound: totalIssues
      });

      return results;
    } catch (error) {
      this.performance.endTimer(projectTimer, { error: error.message });
      throw error;
    }
  }

  async scanNpmCache() {
    // Placeholder for NPM cache scanning
    return [];
  }
}

module.exports = WorkerScanner;
