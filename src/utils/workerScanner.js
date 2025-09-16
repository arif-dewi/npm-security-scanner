/**
 * Worker Scanner for Parallel Processing
 *
 * This module is used by worker threads to avoid circular dependencies.
 * It contains only the core scanning logic without the parallel processing components.
 */

const path = require('path');
const PackageScanner = require('./packageScanner');
const PatternMatcher = require('./patternMatcher');
const PerformanceMonitor = require('./performance');
const Validator = require('./validator');

class WorkerScanner {
  constructor(config, logger, iocs = {}) {
    this.config = config;
    this.logger = logger;
    this.iocs = iocs;
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
      let packagesChecked = 0;
      if (this.config.get('security.scanCompromisedPackages')) {
        this.logger.debug('  📦 Scanning package.json for vulnerable packages...');
        const packageResults = await this.packageScanner.scanPackageFiles(projectPath);
        results.compromisedPackages.push(...packageResults.compromisedPackages);
        packagesChecked = packageResults.packagesChecked;
        if (packageResults.compromisedPackages.length > 0) {
          this.logger.debug(`  ⚠️  Found ${packageResults.compromisedPackages.length} vulnerable packages`);
        }
      }

      // Step 2: Scan JavaScript files for malicious patterns (including node_modules)
      if (this.config.get('security.scanMaliciousCode')) {
        this.logger.debug('  🔍 Scanning JavaScript files for malicious patterns...');
        const jsResults = await this.patternMatcher.scanJavaScriptFiles(projectPath, this.iocs, path.basename(projectPath), false, projectPath);
        results.maliciousCode.push(...(jsResults.issues || []));
        results.filesScanned = (results.filesScanned || 0) + (jsResults.filesScanned || 0);
        if (jsResults.issues && jsResults.issues.length > 0) {
          this.logger.debug(`  ⚠️  Found ${jsResults.issues.length} malicious code patterns`);
        }
      }

      // Step 3: Scan NPM cache for vulnerabilities
      if (this.config.get('security.scanNpmCache')) {
        this.logger.debug('  💾 Scanning NPM cache for vulnerabilities...');
        const cacheResults = await this.scanNpmCache();
        results.npmCacheIssues.push(...cacheResults);
        if (cacheResults.length > 0) {
          this.logger.debug(`  ⚠️  Found ${cacheResults.length} NPM cache issues`);
        }
      }

      const totalIssues = results.compromisedPackages.length + results.maliciousCode.length + results.npmCacheIssues.length;

      // Calculate summary for this project
      results.summary = {
        filesScanned: results.filesScanned || 0,
        packagesChecked,
        issuesFound: totalIssues,
        duration: 0
      };

      // End performance timer
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
