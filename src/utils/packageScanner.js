/**
 * Package scanning utilities for NPM Security Scanner
 * Handles package.json analysis and vulnerable package detection
 */

const fs = require('fs');
const path = require('path');

class PackageScanner {
  constructor(logger, performance, validator) {
    this.logger = logger;
    this.performance = performance;
    this.validator = validator;
    this.vulnerableVersions = this.initializeVulnerableVersions();
    this.safeVersions = this.initializeSafeVersions();
  }

  /**
   * Initialize vulnerable package versions
   * @returns {Object} Vulnerable versions database
   * @private
   */
  initializeVulnerableVersions() {
    try {
      // Load QIX attack data
      const qixPath = path.join(__dirname, '..', '..', 'data', 'qix-attack.json');
      const qixData = JSON.parse(fs.readFileSync(qixPath, 'utf8'));

      // Load Tinycolor attack data
      const tinycolorPath = path.join(__dirname, '..', '..', 'data', 'tinycolor-attack.json');
      const tinycolorData = JSON.parse(fs.readFileSync(tinycolorPath, 'utf8'));

      // Load comprehensive attack data (195+ packages)
      const comprehensivePath = path.join(__dirname, '..', '..', 'data', 'comprehensive-attack.json');
      const comprehensiveData = JSON.parse(fs.readFileSync(comprehensivePath, 'utf8'));

      // Merge all attack databases
      const vulnerableVersions = {
        ...qixData.vulnerableVersions,
        ...tinycolorData.vulnerableVersions,
        ...comprehensiveData.vulnerableVersions
      };

      this.logger.debug('Vulnerable versions loaded from data files', {
        qixPackages: Object.keys(qixData.vulnerableVersions).length,
        tinycolorPackages: Object.keys(tinycolorData.vulnerableVersions).length,
        comprehensivePackages: Object.keys(comprehensiveData.vulnerableVersions).length,
        totalPackages: Object.keys(vulnerableVersions).length
      });

      return vulnerableVersions;
    } catch (error) {
      this.logger.error('Failed to load vulnerable versions from data files', error);
      // Fallback to empty object if data files can't be loaded
      return {};
    }
  }

  /**
   * Initialize safe package versions
   * @returns {Object} Safe versions database
   * @private
   */
  initializeSafeVersions() {
    try {
      // Load QIX attack data
      const qixPath = path.join(__dirname, '..', '..', 'data', 'qix-attack.json');
      const qixData = JSON.parse(fs.readFileSync(qixPath, 'utf8'));

      // Load Tinycolor attack data
      const tinycolorPath = path.join(__dirname, '..', '..', 'data', 'tinycolor-attack.json');
      const tinycolorData = JSON.parse(fs.readFileSync(tinycolorPath, 'utf8'));

      // Load comprehensive attack data (195+ packages)
      const comprehensivePath = path.join(__dirname, '..', '..', 'data', 'comprehensive-attack.json');
      const comprehensiveData = JSON.parse(fs.readFileSync(comprehensivePath, 'utf8'));

      // Merge all safe version databases
      const safeVersions = {
        ...qixData.safeVersions,
        ...tinycolorData.safeVersions,
        ...comprehensiveData.safeVersions
      };

      this.logger.debug('Safe versions loaded from data files', {
        qixPackages: Object.keys(qixData.safeVersions).length,
        tinycolorPackages: Object.keys(tinycolorData.safeVersions).length,
        comprehensivePackages: Object.keys(comprehensiveData.safeVersions).length,
        totalPackages: Object.keys(safeVersions).length
      });

      return safeVersions;
    } catch (error) {
      this.logger.error('Failed to load safe versions from data files', error);
      // Fallback to empty object if data files can't be loaded
      return {};
    }
  }

  /**
   * Scan package.json files for compromised packages
   * @param {string} projectPath - Project path
   * @returns {Promise<Array>} Compromised packages found
   */
  async scanPackageFiles(projectPath) {
    const packageTimer = this.performance?.startTimer('scan-packages');

    try {
      const packageJsonPath = path.join(projectPath, 'package.json');

      if (!fs.existsSync(packageJsonPath)) {
        return [];
      }

      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

      // Validate package.json
      const validation = this.validator.validatePackageJson(packageJson);
      if (!validation.isValid) {
        this.logger.warn('Invalid package.json detected', {
          project: path.basename(projectPath),
          errors: validation.errors
        });
      }

      const compromisedPackages = [];
      const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };

      for (const [pkg, version] of Object.entries(allDeps || {})) {
        if (this.isVulnerableVersion(pkg, version)) {
          compromisedPackages.push({
            project: path.basename(projectPath),
            package: pkg,
            version,
            severity: 'HIGH'
          });
        }
      }

      if (packageTimer) {
        this.performance?.endTimer(packageTimer, {
          packagesChecked: Object.keys(allDeps).length,
          compromisedFound: compromisedPackages.length
        });
      }

      return {
        compromisedPackages,
        packagesChecked: Object.keys(allDeps).length
      };
    } catch (error) {
      if (packageTimer) {
        this.performance?.endTimer(packageTimer, { error: error.message });
      }
      this.logger.error('Failed to scan package files', error);
      return [];
    }
  }

  /**
   * Check if package version is vulnerable
   * @param {string} packageName - Package name
   * @param {string} version - Package version
   * @returns {boolean} Whether version is vulnerable
   * @private
   */
  isVulnerableVersion(packageName, version) {
    const vulnerableVersions = this.vulnerableVersions[packageName];
    if (!vulnerableVersions) return false;

    // Remove version prefixes
    const cleanVersion = version.replace(/^[\^~]/, '');
    return vulnerableVersions.includes(cleanVersion);
  }

  /**
   * Get safe version for a package
   * @param {string} packageName - Package name
   * @returns {string|null} Safe version or null
   */
  getSafeVersion(packageName) {
    const versions = this.safeVersions[packageName];
    return versions ? versions[0] : null; // Return the first (latest safe) version
  }

  /**
   * Get all vulnerable packages
   * @returns {Object} Vulnerable packages database
   */
  getVulnerablePackages() {
    return this.vulnerableVersions;
  }

  /**
   * Get all safe versions
   * @returns {Object} Safe versions database
   */
  getSafeVersions() {
    return this.safeVersions;
  }

  /**
   * Validate package.json file
   * @param {string} projectPath - Project path
   * @returns {Promise<Array>} Validation issues found
   */
  async validatePackageJson(projectPath) {
    try {
      const packageJsonPath = path.join(projectPath, 'package.json');

      if (!fs.existsSync(packageJsonPath)) {
        return [];
      }

      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      const validation = this.validator.validatePackageJson(packageJson);

      if (!validation.isValid) {
        this.logger.warn('Invalid package.json detected', {
          project: path.basename(projectPath),
          errors: validation.errors
        });

        return [{
          project: path.basename(projectPath),
          type: 'Invalid package.json',
          severity: 'MEDIUM',
          description: `Package.json validation failed: ${validation.errors.join(', ')}`,
          errors: validation.errors
        }];
      }

      return [];
    } catch (error) {
      this.logger.error('Failed to validate package.json', error);
      return [];
    }
  }

  /**
   * Add vulnerable version
   * @param {string} packageName - Package name
   * @param {string} version - Vulnerable version
   */
  addVulnerableVersion(packageName, version) {
    if (!this.vulnerableVersions[packageName]) {
      this.vulnerableVersions[packageName] = [];
    }
    if (!this.vulnerableVersions[packageName].includes(version)) {
      this.vulnerableVersions[packageName].push(version);
      this.logger.debug('Vulnerable version added', { package: packageName, version });
    }
  }

  /**
   * Add safe version
   * @param {string} packageName - Package name
   * @param {string} version - Safe version
   */
  addSafeVersion(packageName, version) {
    if (!this.safeVersions[packageName]) {
      this.safeVersions[packageName] = [];
    }
    if (!this.safeVersions[packageName].includes(version)) {
      this.safeVersions[packageName].push(version);
    }
    this.logger.debug('Safe version added', { package: packageName, version });
  }

  /**
   * Generate package.json overrides for safe versions
   * @param {Array} compromisedPackages - Array of compromised packages
   * @returns {Object} Package.json overrides object
   */
  generateOverrides(compromisedPackages) {
    const overrides = {};

    for (const pkg of compromisedPackages) {
      const safeVersion = this.getSafeVersion(pkg.package);
      if (safeVersion) {
        overrides[pkg.package] = safeVersion;
      }
    }

    return overrides;
  }

  /**
   * Generate remediation commands
   * @param {Array} compromisedPackages - Array of compromised packages
   * @returns {Array} Array of remediation commands
   */
  generateRemediationCommands(compromisedPackages) {
    const uniquePackages = [...new Set(compromisedPackages.map(p => p.package))];
    return uniquePackages.map(pkg => `npm uninstall ${pkg}`);
  }
}

module.exports = PackageScanner;
