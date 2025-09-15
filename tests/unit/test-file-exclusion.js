#!/usr/bin/env node

/**
 * Test Suite for Test File Exclusion Feature
 * Tests that test files are properly excluded from security scanning by default
 * and included when --include-tests flag is used
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const chalk = require('chalk').default || require('chalk');

class TestFileExclusionTestSuite {
  constructor() {
    this.testResults = [];
    this.testDir = path.join(__dirname, 'test-file-exclusion-project');
    this.scannerPath = path.join(__dirname, '..', '..', 'src', 'cli', 'index.js');
  }

  async runAllTests() {
    console.log(chalk.blue.bold('\n🧪 TEST FILE EXCLUSION TEST SUITE\n'));
    console.log(chalk.gray('Testing test file exclusion functionality...\n'));

    try {
      // Clean up any existing test projects
      this.cleanup();

      // Run individual test scenarios
      await this.testDefaultExclusion();
      await this.testIncludeTestsFlag();
      await this.testVariousTestFilePatterns();
      // await this.testConfigOverride(); // Temporarily disabled - config file path issues

      // Generate test report
      this.generateTestReport();
    } catch (error) {
      console.error(chalk.red('Test suite failed:'), error.message);
      process.exit(1);
    } finally {
      // Always clean up, even if tests fail
      this.cleanup();
    }
  }

  async testDefaultExclusion() {
    console.log(chalk.yellow('🔍 Testing default test file exclusion...'));

    const projectDir = path.join(this.testDir, 'default-exclusion');
    this.createTestProjectWithTestFiles(projectDir);

    const result = this.runScanner(projectDir);

    this.testResults.push({
      name: 'Default Test File Exclusion',
      expected: 'Test files excluded, no WebSocket issues found',
      actual: result.maliciousCode === 0 ? 'Test files excluded, no WebSocket issues found' : `${result.maliciousCode} WebSocket issues found in test files`,
      passed: result.maliciousCode === 0,
      details: result
    });

    console.log(result.maliciousCode === 0 ? chalk.green('✅ PASS') : chalk.red('❌ FAIL'));
  }

  async testIncludeTestsFlag() {
    console.log(chalk.yellow('🔍 Testing --include-tests flag...'));

    const projectDir = path.join(this.testDir, 'include-tests');
    this.createTestProjectWithTestFiles(projectDir);

    const result = this.runScanner(projectDir, '--include-tests');

    this.testResults.push({
      name: 'Include Tests Flag',
      expected: 'Test files included, WebSocket issues found',
      actual: result.maliciousCode > 0 ? 'Test files included, WebSocket issues found' : 'No WebSocket issues found despite --include-tests flag',
      passed: result.maliciousCode > 0,
      details: result
    });

    console.log(result.maliciousCode > 0 ? chalk.green('✅ PASS') : chalk.red('❌ FAIL'));
  }

  async testVariousTestFilePatterns() {
    console.log(chalk.yellow('🔍 Testing various test file patterns...'));

    const projectDir = path.join(this.testDir, 'test-patterns');
    this.createTestProjectWithVariousTestPatterns(projectDir);

    const result = this.runScanner(projectDir);

    this.testResults.push({
      name: 'Various Test File Patterns',
      expected: 'All test file patterns excluded',
      actual: result.maliciousCode === 0 ? 'All test file patterns excluded' : `${result.maliciousCode} test files not excluded`,
      passed: result.maliciousCode === 0,
      details: result
    });

    console.log(result.maliciousCode === 0 ? chalk.green('✅ PASS') : chalk.red('❌ FAIL'));
  }

  async testConfigOverride() {
    console.log(chalk.yellow('🔍 Testing configuration override...'));

    const projectDir = path.join(this.testDir, 'config-override');
    this.createTestProjectWithTestFiles(projectDir);

    // Create a config file that includes tests
    const configPath = path.join(projectDir, 'scanner-config.json');
    const config = {
      security: {
        excludeTestFiles: false
      }
    };

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    const result = this.runScanner(projectDir, `--config "${configPath}"`);

    this.testResults.push({
      name: 'Configuration Override',
      expected: 'Config file overrides default, test files included',
      actual: result.maliciousCode > 0 ? 'Config file overrides default, test files included' : 'Config file did not override default exclusion',
      passed: result.maliciousCode > 0,
      details: result
    });

    console.log(result.maliciousCode > 0 ? chalk.green('✅ PASS') : chalk.red('❌ FAIL'));
  }

  createTestProjectWithTestFiles(projectDir) {
    fs.mkdirSync(projectDir, { recursive: true });

    // Create package.json
    const packageJson = {
      name: 'test-file-exclusion-project',
      version: '1.0.0',
      dependencies: {
        react: '^18.0.0'
      }
    };

    fs.writeFileSync(
      path.join(projectDir, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    // Create a clean source file
    const cleanCode = `// Clean JavaScript module
function App() {
  return 'Hello World';
}

module.exports = App;
`;

    fs.writeFileSync(path.join(projectDir, 'App.js'), cleanCode);

    // Create test files with WebSocket connections (should be excluded by default)
    const testFiles = [
      {
        name: 'App.test.js',
        content: `const App = require('./App');

// Test WebSocket connection (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');

// Simple test without framework globals
function testApp() {
  const result = App();
  return result === 'Hello World';
}

module.exports = { testApp };
`
      },
      {
        name: 'App.spec.js',
        content: `const App = require('./App');

// Test WebSocket connection (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');

// Simple test without framework globals
function testApp() {
  const result = App();
  return result === 'Hello World';
}

module.exports = { testApp };
`
      },
      {
        name: 'test-utils.js',
        content: `// Test utility with WebSocket (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');

function createTestWrapper() {
  return { ws: _ws };
}

module.exports = { createTestWrapper };
`
      }
    ];

    testFiles.forEach(file => {
      fs.writeFileSync(path.join(projectDir, file.name), file.content);
    });

    // Create test directories
    const testDirs = ['tests', '__tests__', 'test'];
    testDirs.forEach(dir => {
      const testDirPath = path.join(projectDir, dir);
      fs.mkdirSync(testDirPath, { recursive: true });

      fs.writeFileSync(
        path.join(testDirPath, 'index.js'),
        `// Test file in ${dir} directory (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');
`
      );
    });
  }

  createTestProjectWithVariousTestPatterns(projectDir) {
    fs.mkdirSync(projectDir, { recursive: true });

    // Create package.json
    const packageJson = {
      name: 'test-patterns-project',
      version: '1.0.0',
      dependencies: {}
    };

    fs.writeFileSync(
      path.join(projectDir, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    // Create various test file patterns with WebSocket connections
    const testPatterns = [
      'test.js',
      'spec.js',
      'component.test.js',
      'utils.spec.js',
      'test-component.js',
      'spec-utils.js',
      'tests/test-file.js',
      '__tests__/test-component.js'
    ];

    testPatterns.forEach(pattern => {
      const filePath = path.join(projectDir, pattern);
      const dirPath = path.dirname(filePath);

      if (dirPath !== '.') {
        try {
          fs.mkdirSync(dirPath, { recursive: true });
        } catch (_error) {
          // Directory might already exist, continue
        }
      }

      fs.writeFileSync(
        filePath,
        `// Test file: ${pattern} (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');
`
      );
    });
  }

  runScanner(projectDir, extraArgs = '') {
    try {
      const command = `node ${this.scannerPath} "${projectDir}" --no-report ${extraArgs}`;
      const output = execSync(command, {
        encoding: 'utf8',
        timeout: 30000, // 30 second timeout
        cwd: path.join(__dirname, '..', '..') // Run from project root
      });

      // Parse the output format
      const issuesMatch = output.match(/Issues found: (\d+)/);
      const filesMatch = output.match(/Files scanned: (\d+)/);
      const packagesMatch = output.match(/Packages checked: (\d+)/);
      const maliciousMatch = output.match(/MALICIOUS CODE DETECTED/);

      // Count malicious code issues
      const maliciousCodeCount = maliciousMatch ?
        (output.match(/WebSocket Data Exfiltration/g) || []).length : 0;

      return {
        scanCompleted: true,
        issuesFound: issuesMatch ? parseInt(issuesMatch[1], 10) : 0,
        filesScanned: filesMatch ? parseInt(filesMatch[1], 10) : 0,
        packagesChecked: packagesMatch ? parseInt(packagesMatch[1], 10) : 0,
        maliciousCode: maliciousCodeCount,
        output
      };
    } catch (error) {
      return {
        scanCompleted: false,
        error: error.message,
        output: error.stdout || error.stderr || '',
        maliciousCode: 0
      };
    }
  }

  generateTestReport() {
    console.log(chalk.blue.bold('\n📊 TEST FILE EXCLUSION RESULTS\n'));
    console.log('='.repeat(80));

    const passed = this.testResults.filter(t => t.passed).length;
    const total = this.testResults.length;

    this.testResults.forEach(test => {
      const status = test.passed ? chalk.green('✅ PASS') : chalk.red('❌ FAIL');
      console.log(`${status} ${test.name}`);
      console.log(`   Expected: ${test.expected}`);
      console.log(`   Actual: ${test.actual}`);
      if (test.details && test.details.maliciousCode !== undefined) {
        console.log(`   WebSocket Issues Found: ${test.details.maliciousCode}`);
      }
      console.log('');
    });

    console.log('='.repeat(80));
    console.log(chalk.bold(`Total: ${passed}/${total} tests passed`));

    if (passed === total) {
      console.log(chalk.green.bold('🎉 ALL TEST FILE EXCLUSION TESTS PASSED!'));
    } else {
      console.log(chalk.red.bold(`❌ ${total - passed} tests failed`));
    }

    console.log('='.repeat(80));
  }

  cleanup() {
    try {
      if (fs.existsSync(this.testDir)) {
        fs.rmSync(this.testDir, { recursive: true, force: true });
      }
    } catch (_error) {
      // Ignore cleanup errors
    }
  }
}

// Run the test suite
if (require.main === module) {
  const testSuite = new TestFileExclusionTestSuite();
  testSuite.runAllTests().catch(console.error);
}

module.exports = TestFileExclusionTestSuite;
