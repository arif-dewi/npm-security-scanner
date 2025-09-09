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
    // QIX supply chain attack (Sept 2025) - confirmed malicious versions
    // Source: https://www.endorlabs.com/learn/major-supply-chain-attack-compromises-popular-npm-packages-including-chalk-and-debug
    // Attack: Account takeover of 'qix' publisher via phishing (support@npmjs[.]help)
    // Malware: checkethereumw function + crypto address replacement to 0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976
    // Impact: 18 packages, hundreds of millions of weekly downloads
    return {
      backslash: ['0.2.1'],
      chalk: ['5.6.1'],
      'chalk-template': ['1.1.1'],
      'color-convert': ['3.1.1'],
      'color-name': ['2.0.1'],
      'color-string': ['2.1.1'],
      'wrap-ansi': ['9.0.1'],
      'supports-hyperlinks': ['4.1.1'],
      'strip-ansi': ['7.1.1'],
      'slice-ansi': ['7.1.1'],
      'simple-swizzle': ['0.2.3'],
      'is-arrayish': ['0.3.3'],
      'error-ex': ['1.3.3'],
      'has-ansi': ['6.0.1'],
      'ansi-regex': ['6.2.1'],
      'ansi-styles': ['6.2.2'],
      'supports-color': ['10.2.1'],
      'proto-tinker-wc': ['1.8.7'],
      debug: ['4.4.2']
    };
  }

  /**
   * Initialize safe package versions
   * @returns {Object} Safe versions database
   * @private
   */
  initializeSafeVersions() {
    // Safe versions published before the QIX compromise (Sept 2025)
    // These are the last known good versions before the attack
    return {
      backslash: ['0.2.0'], // Last safe version before 0.2.1
      chalk: ['5.6.0'], // Last safe version before 5.6.1
      'chalk-template': ['1.1.0'], // Last safe version before 1.1.1
      'color-convert': ['3.1.0'], // Last safe version before 3.1.1
      'color-name': ['2.0.0'], // Last safe version before 2.0.1
      'color-string': ['2.1.0'], // Last safe version before 2.1.1
      'wrap-ansi': ['9.0.0'], // Last safe version before 9.0.1
      'supports-hyperlinks': ['4.1.0'], // Last safe version before 4.1.1
      'strip-ansi': ['7.1.0'], // Last safe version before 7.1.1
      'slice-ansi': ['7.1.0'], // Last safe version before 7.1.1
      'simple-swizzle': ['0.2.2'], // Last safe version before 0.2.3
      'is-arrayish': ['0.3.2'], // Last safe version before 0.3.3
      'error-ex': ['1.3.2'], // Last safe version before 1.3.3
      'has-ansi': ['6.0.0'], // Last safe version before 6.0.1
      'ansi-regex': ['6.2.0'], // Last safe version before 6.2.1
      'ansi-styles': ['6.2.1'], // Last safe version before 6.2.2
      'supports-color': ['10.2.0'], // Last safe version before 10.2.1
      'proto-tinker-wc': ['1.8.6'], // Last safe version before 1.8.7
      debug: ['4.4.1'] // Last safe version before 4.4.2
    };
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

      return compromisedPackages;
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
