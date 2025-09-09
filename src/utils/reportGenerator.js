/**
 * Report generation utilities for NPM Security Scanner
 * Handles console, markdown, and JSON report generation
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk').default || require('chalk');
const { table } = require('table');

class ReportGenerator {
  constructor(logger) {
    this.logger = logger;
  }

  /**
   * Generate console report
   * @param {Object} results - Scan results
   */
  generateConsoleReport(results) {
    console.log(chalk.bold('\n🔒 SECURITY SCAN REPORT'));
    console.log('='.repeat(80));

    // Summary
    this.printSummary(results.summary);

    // Compromised packages
    if (results.compromisedPackages.length > 0) {
      this.printCompromisedPackages(results.compromisedPackages);
    }

    // Malicious code
    if (results.maliciousCode.length > 0) {
      this.printMaliciousCode(results.maliciousCode);
    }

    // NPM cache issues
    if (results.npmCacheIssues.length > 0) {
      this.printNpmCacheIssues(results.npmCacheIssues);
    }

    // Suspicious files
    if (results.suspiciousFiles.length > 0) {
      this.printSuspiciousFiles(results.suspiciousFiles);
    }

    // Package validation issues
    if (results.packageValidationIssues.length > 0) {
      this.printPackageValidationIssues(results.packageValidationIssues);
    }

    // Remediation steps
    this.printRemediationSteps(results);

    // Affected projects
    this.printAffectedProjects(results);
  }

  /**
   * Generate markdown report
   * @param {Object} results - Scan results
   * @param {string} outputPath - Output file path
   */
  async generateMarkdownReport(results, outputPath) {
    try {
      const markdown = this.buildMarkdownReport(results);

      // Ensure directory exists
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(outputPath, markdown);
      this.logger.info('Markdown report generated', { path: outputPath });
    } catch (error) {
      this.logger.error('Failed to generate markdown report', error);
      throw error;
    }
  }

  /**
   * Generate JSON report
   * @param {Object} results - Scan results
   * @param {string} outputPath - Output file path
   */
  async generateJsonReport(results, outputPath) {
    try {
      const jsonReport = {
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        summary: results.summary,
        results: {
          compromisedPackages: results.compromisedPackages,
          maliciousCode: results.maliciousCode,
          npmCacheIssues: results.npmCacheIssues,
          suspiciousFiles: results.suspiciousFiles
        },
        metadata: {
          scanner: 'NPM Security Scanner',
          generatedBy: 'DolaSoft Security Team'
        }
      };

      // Ensure directory exists
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(outputPath, JSON.stringify(jsonReport, null, 2));
      this.logger.info('JSON report generated', { path: outputPath });
    } catch (error) {
      this.logger.error('Failed to generate JSON report', error);
      throw error;
    }
  }

  /**
   * Print summary section
   * @param {Object} summary - Summary data
   * @private
   */
  printSummary(summary) {
    console.log(chalk.bold('\n📊 SUMMARY:'));
    console.log(`Files scanned: ${summary.filesScanned}`);
    console.log(`Packages checked: ${summary.packagesChecked}`);
    console.log(`Issues found: ${summary.issuesFound}`);
    if (summary.duration) {
      console.log(`Duration: ${this.formatDuration(summary.duration)}`);
    }
  }

  /**
   * Print compromised packages section
   * @param {Array} packages - Compromised packages
   * @private
   */
  printCompromisedPackages(packages) {
    console.log(chalk.red.bold('\n🚨 COMPROMISED PACKAGES FOUND:'));

    const tableData = [
      ['Project', 'Package', 'Version', 'Severity']
    ];

    packages.forEach(pkg => {
      tableData.push([
        pkg.project || 'Unknown',
        pkg.package,
        pkg.version,
        pkg.severity
      ]);
    });

    console.log(table(tableData, {
      border: {
        topBody: '─',
        topJoin: '┬',
        topLeft: '┌',
        topRight: '┐',
        bottomBody: '─',
        bottomJoin: '┴',
        bottomLeft: '└',
        bottomRight: '┘',
        bodyLeft: '│',
        bodyRight: '│',
        bodyJoin: '│',
        joinBody: '─',
        joinLeft: '├',
        joinRight: '┤',
        joinJoin: '┼'
      }
    }));
  }

  /**
   * Print malicious code section
   * @param {Array} maliciousCode - Malicious code found
   * @private
   */
  printMaliciousCode(maliciousCode) {
    console.log(chalk.red.bold('\n💀 MALICIOUS CODE DETECTED:'));

    const tableData = [
      ['Project', 'File', 'Pattern', 'Severity', 'Matches', 'Lines']
    ];

    maliciousCode.forEach(code => {
      tableData.push([
        code.project || 'Unknown',
        code.file,
        code.pattern,
        code.severity,
        code.matches,
        code.lines ? code.lines.join(', ') : 'N/A'
      ]);
    });

    console.log(table(tableData, {
      border: {
        topBody: '─',
        topJoin: '┬',
        topLeft: '┌',
        topRight: '┐',
        bottomBody: '─',
        bottomJoin: '┴',
        bottomLeft: '└',
        bottomRight: '┘',
        bodyLeft: '│',
        bodyRight: '│',
        bodyJoin: '│',
        joinBody: '─',
        joinLeft: '├',
        joinRight: '┤',
        joinJoin: '┼'
      }
    }));
  }

  /**
   * Print NPM cache issues section
   * @param {Array} issues - NPM cache issues
   * @private
   */
  printNpmCacheIssues(issues) {
    console.log(chalk.yellow.bold('\n⚠️ NPM CACHE VULNERABILITIES:'));

    issues.forEach(issue => {
      console.log(`  • ${issue.package}: ${issue.description}`);
    });
  }

  /**
   * Print suspicious files section
   * @param {Array} files - Suspicious files
   * @private
   */
  printSuspiciousFiles(files) {
    console.log(chalk.yellow.bold('\n🔍 SUSPICIOUS FILES:'));

    const tableData = [
      ['Project', 'File', 'Address', 'Severity']
    ];

    files.forEach(file => {
      tableData.push([
        file.project || 'Unknown',
        file.file,
        file.address,
        file.severity
      ]);
    });

    console.log(table(tableData, {
      border: {
        topBody: '─',
        topJoin: '┬',
        topLeft: '┌',
        topRight: '┐',
        bottomBody: '─',
        bottomJoin: '┴',
        bottomLeft: '└',
        bottomRight: '┘',
        bodyLeft: '│',
        bodyRight: '│',
        bodyJoin: '│',
        joinBody: '─',
        joinLeft: '├',
        joinRight: '┤',
        joinJoin: '┼'
      }
    }));
  }

  /**
   * Print package validation issues section
   * @param {Array} validationIssues - Array of package validation issues
   * @private
   */
  printPackageValidationIssues(validationIssues) {
    console.log(chalk.yellow.bold('\n⚠️  PACKAGE VALIDATION ISSUES:'));

    const tableData = [
      ['Project', 'Type', 'Description', 'Severity']
    ];

    validationIssues.forEach(issue => {
      tableData.push([
        issue.project || 'Unknown',
        issue.type,
        issue.description,
        issue.severity
      ]);
    });

    console.log(table(tableData, {
      border: {
        topBody: '─',
        topJoin: '┬',
        topLeft: '┌',
        topRight: '┐',
        bottomBody: '─',
        bottomJoin: '┴',
        bottomLeft: '└',
        bottomRight: '┘',
        bodyLeft: '│',
        bodyRight: '│',
        bodyJoin: '│',
        joinBody: '─',
        joinLeft: '├',
        joinRight: '┤',
        joinJoin: '┼'
      }
    }));
  }

  /**
   * Print remediation steps
   * @param {Object} results - Scan results
   * @private
   */
  printRemediationSteps(results) {
    console.log(chalk.bold('\n🔧 RECOMMENDED REMEDIATION STEPS:'));
    console.log('='.repeat(80));

    let stepNumber = 1;

    if (results.compromisedPackages.length > 0) {
      console.log(chalk.red.bold(`\n${stepNumber}. IMMEDIATE ACTION REQUIRED - Compromised Packages:`));
      stepNumber++;
      console.log('   • Remove all compromised packages immediately');
      console.log('   • Use package.json overrides to force safe versions');
      console.log('   • Check package-lock.json for any suspicious entries');
      console.log('   • Run: npm audit --audit-level high');
      console.log('   • Delete node_modules and package-lock.json, then run npm install');
    }

    if (results.npmCacheIssues.length > 0) {
      console.log(chalk.red.bold(`\n${stepNumber}. NPM CACHE VULNERABILITIES:`));
      stepNumber++;
      console.log('   • IMMEDIATE ACTION: Clear npm cache to remove vulnerable packages');
      console.log('   • Run: npm cache clean --force');
      console.log('   • Verify: npm cache verify');
      console.log('   • For each project: rm -rf node_modules package-lock.json && npm install');
    }

    if (results.maliciousCode.length > 0) {
      console.log(chalk.red.bold(`\n${stepNumber}. MALICIOUS CODE DETECTED:`));
      stepNumber++;
      console.log('   • Review all flagged files immediately');
      console.log('   • Remove or quarantine suspicious code');
      console.log('   • Check git history for when malicious code was introduced');
      console.log('   • Consider reverting to a known clean state');
    }

    // Always show these sections
    console.log(chalk.blue.bold(`\n${stepNumber}. GENERAL SECURITY MEASURES:`));
    stepNumber++;
    console.log('   • Enable 2FA on all npm accounts');
    console.log('   • Use package-lock.json and commit it to version control');
    console.log('   • Regularly update dependencies');
    console.log('   • Use tools like npm audit and snyk');

    console.log(chalk.green.bold(`\n${stepNumber}. VERIFICATION STEPS:`));
    console.log('   • Run this scanner again after remediation');
    console.log('   • Test your application thoroughly');
    console.log('   • Monitor for any unusual network activity');
  }

  /**
   * Print affected projects section
   * @param {Object} results - Scan results
   * @private
   */
  printAffectedProjects(results) {
    const affectedProjects = this.getAffectedProjects(results);

    if (affectedProjects.length > 0) {
      console.log(chalk.bold('\n📋 PROJECTS REQUIRING IMMEDIATE ATTENTION:'));
      console.log('='.repeat(80));

      affectedProjects.forEach(project => {
        console.log(`• ${project.name} (${project.path})`);
        project.issues.forEach(issue => {
          console.log(`  - ${issue.type}: ${issue.description}`);
        });
      });
    }
  }

  /**
   * Build markdown report content
   * @param {Object} results - Scan results
   * @returns {string} Markdown content
   * @private
   */
  buildMarkdownReport(results) {
    const now = new Date();
    const generatedDate = now.toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'numeric', 
      day: 'numeric' 
    });
    const generatedTime = now.toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit', 
      second: '2-digit' 
    });

    let markdown = '# Security Scan Report\n\n';
    markdown += `**Generated:** ${generatedDate}, ${generatedTime}\n`;
    markdown += '**Scanner Version:** 2.0.0\n';
    markdown += `**Scan Directory:** ${process.cwd()}\n\n`;

    // Summary
    markdown += '## 📊 Summary\n\n';
    markdown += `- **Files scanned:** ${results.summary.filesScanned}\n`;
    markdown += `- **Packages checked:** ${results.summary.packagesChecked}\n`;
    markdown += `- **Issues found:** ${results.summary.issuesFound}\n\n`;

    // Compromised packages
    if (results.compromisedPackages.length > 0) {
      markdown += '## 🚨 Compromised Packages Found\n\n';
      markdown += '| Project | Package | Version | Severity |\n';
      markdown += '|---------|---------|---------|----------|\n';

      results.compromisedPackages.forEach(pkg => {
        markdown += `| ${pkg.project || 'Unknown'} | ${pkg.package} | ${pkg.version} | **${pkg.severity}** |\n`;
      });
      markdown += '\n';
    }

    // Malicious code
    if (results.maliciousCode.length > 0) {
      markdown += '## 💀 Malicious Code Detected\n\n';
      markdown += '| Project | Relative Path | File | Pattern | Severity | Matches | Lines |\n';
      markdown += '|---------|---------------|------|---------|----------|---------|-------|\n';

      // Group by project for better organization
      const projectGroups = this.groupByProject(results.maliciousCode);
      
      Object.entries(projectGroups).forEach(([project, issues]) => {
        const fileGroups = this.groupByFile(issues);
        
        Object.entries(fileGroups).forEach(([file, fileIssues]) => {
          const patternGroups = this.groupByPattern(fileIssues);
          
          Object.entries(patternGroups).forEach(([pattern, patternIssues]) => {
            const severity = patternIssues[0].severity;
            const matches = patternIssues.length;
            const lines = patternIssues.map(issue => issue.lines).flat().join(', ');
                   const relativePath = patternIssues[0].relativePath || this.getRelativePath(project, file);
            
            markdown += `| ${project} | ${relativePath} | ${file} | ${pattern} (${matches}) | **${severity}** | ${matches} | ${lines} |\n`;
          });
        });
      });
      markdown += '\n';
    }

    // Projects requiring attention
    markdown += this.getMarkdownProjectsRequiringAttention(results);

    // Remediation steps
    markdown += this.getMarkdownRemediationSteps(results);

    return markdown;
  }

  /**
   * Group issues by project
   * @param {Array} issues - Array of issues
   * @returns {Object} Grouped issues by project
   * @private
   */
  groupByProject(issues) {
    return issues.reduce((groups, issue) => {
      const project = issue.project || 'Unknown';
      if (!groups[project]) {
        groups[project] = [];
      }
      groups[project].push(issue);
      return groups;
    }, {});
  }

  /**
   * Group issues by file
   * @param {Array} issues - Array of issues
   * @returns {Object} Grouped issues by file
   * @private
   */
  groupByFile(issues) {
    return issues.reduce((groups, issue) => {
      const file = issue.file || 'Unknown';
      if (!groups[file]) {
        groups[file] = [];
      }
      groups[file].push(issue);
      return groups;
    }, {});
  }

  /**
   * Group issues by pattern
   * @param {Array} issues - Array of issues
   * @returns {Object} Grouped issues by pattern
   * @private
   */
  groupByPattern(issues) {
    return issues.reduce((groups, issue) => {
      const pattern = issue.pattern || 'Unknown';
      if (!groups[pattern]) {
        groups[pattern] = [];
      }
      groups[pattern].push(issue);
      return groups;
    }, {});
  }

  /**
   * Get relative path for project and file
   * @param {string} project - Project name
   * @param {string} file - File name
   * @returns {string} Relative path
   * @private
   */
  getRelativePath(project, file) {
    // This is a simplified version - in a real implementation you'd want to track actual paths
    return `${project}/${file}`;
  }

  /**
   * Get projects requiring immediate attention section
   * @param {Object} results - Scan results
   * @returns {string} Markdown projects section
   * @private
   */
  getMarkdownProjectsRequiringAttention(results) {
    let markdown = '## 📋 Projects Requiring Immediate Attention\n\n';
    
    const projectGroups = this.groupByProject(results.maliciousCode);
    
    Object.entries(projectGroups).forEach(([project, issues]) => {
      const patternGroups = this.groupByPattern(issues);
      
      markdown += `### ${project}\n\n`;
      
      Object.entries(patternGroups).forEach(([pattern, patternIssues]) => {
        markdown += `- ${pattern}: ${patternIssues[0].description || 'Detects malicious patterns'}\n`;
      });
      
      markdown += '\n';
    });

    return markdown;
  }

  /**
   * Get markdown remediation steps
   * @param {Object} results - Scan results
   * @returns {string} Markdown remediation steps
   * @private
   */
  getMarkdownRemediationSteps(results) {
    let markdown = '## Remediation Steps\n\n';
    let stepNumber = 1;

    if (results.compromisedPackages.length > 0) {
      markdown += `### ${stepNumber}. Compromised Packages\n\n`;
      stepNumber++;
      markdown += '- Remove all compromised packages immediately\n';
      markdown += '- Use package.json overrides to force safe versions\n';
      markdown += '- Run: `npm audit --audit-level high`\n\n';
    }

    if (results.maliciousCode.length > 0) {
      markdown += `### ${stepNumber}. Malicious Code\n\n`;
      stepNumber++;
      markdown += '- Review all flagged files immediately\n';
      markdown += '- Remove or quarantine suspicious code\n';
      markdown += '- Check git history for when malicious code was introduced\n\n';
    }

    markdown += `### ${stepNumber}. General Security Measures\n\n`;
    markdown += '- Enable 2FA on all npm accounts\n';
    markdown += '- Use package-lock.json and commit it to version control\n';
    markdown += '- Regularly update dependencies\n\n';

    return markdown;
  }

  /**
   * Get affected projects
   * @param {Object} results - Scan results
   * @returns {Array} Array of affected projects
   * @private
   */
  getAffectedProjects(results) {
    const projectMap = new Map();

    // Process compromised packages
    results.compromisedPackages.forEach(pkg => {
      const projectName = pkg.project || 'Unknown';
      if (!projectMap.has(projectName)) {
        projectMap.set(projectName, {
          name: projectName,
          path: '.',
          issues: []
        });
      }
      projectMap.get(projectName).issues.push({
        type: 'Compromised Package',
        description: `${pkg.package} (${pkg.version})`
      });
    });

    // Process malicious code
    results.maliciousCode.forEach(code => {
      const projectName = code.project || 'Unknown';
      if (!projectMap.has(projectName)) {
        projectMap.set(projectName, {
          name: projectName,
          path: '.',
          issues: []
        });
      }
      projectMap.get(projectName).issues.push({
        type: code.pattern,
        description: code.description
      });
    });

    return Array.from(projectMap.values());
  }

  /**
   * Format duration in milliseconds
   * @param {number} ms - Duration in milliseconds
   * @returns {string} Formatted duration
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
}

module.exports = ReportGenerator;
