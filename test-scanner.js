#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const NPMSecurityScanner = require('./scanner.js');

// Create test directory structure
const testDir = path.join(__dirname, 'test-project');
const testNodeModules = path.join(testDir, 'node_modules');
const testChalkDir = path.join(testNodeModules, 'chalk');

// Create test files with malicious patterns
const maliciousCode = `
// This is a test file with malicious patterns
function checkethereumw() {
  // Malicious function that hooks into Ethereum wallets
  if (window.ethereum) {
    // Hook into Ethereum functions
    const originalRequest = window.ethereum.request;
    const originalSend = window.ethereum.send;
    const originalSendAsync = window.ethereum.sendAsync;
    
    // Override fetch and XMLHttpRequest
    const originalFetch = window.fetch;
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    
    // Malicious address for fund theft
    const maliciousAddress = '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976';
    const solanaAddress = '19111111111111111111111111111111';
    
    // WebSocket for data exfiltration
    const ws = new WebSocket('wss://websocket-api2.publicvm.com');
    
    // CDN domains
    const cdn1 = 'https://static-mw-host.b-cdn.net/malware.js';
    const cdn2 = 'https://img-data-backup.b-cdn.net/stealer.js';
    
    // Fake NPM domain
    const fakeNpm = 'https://npmjs.help/settings/qix/tfa/manageTfa';
    
    // Bitcoin addresses
    const btc1 = '1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx';
    const btc2 = '1Li1CRPwjovnGHGPTtcKzy75j37K6n97Rd';
    
    // Levenshtein distance calculation
    function levenshteinDistance(str1, str2) {
      // Calculate edit distance for address replacement
      return Math.abs(str1.length - str2.length);
    }
  }
}
`;

const packageJson = {
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "chalk": "^4.1.2",
    "debug-js": "^1.0.0",
    "supports-color": "^7.2.0",
    "has-flag": "^4.0.0",
    "is-fullwidth-code-point": "^3.0.0",
    "strip-ansi": "^6.0.1",
    "ansi-regex": "^5.0.1",
    "wrap-ansi": "^7.0.0",
    "string-width": "^4.2.3",
    "ansi-styles": "^4.3.0",
    "color-convert": "^2.0.1",
    "color-name": "^1.1.4",
    "escape-string-regexp": "^4.0.0",
    "ms": "^2.1.3",
    "clean-package": "^1.0.0"
  }
};

async function setupTestEnvironment() {
  console.log('Setting up test environment...');
  
  // Create directories
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  if (!fs.existsSync(testNodeModules)) {
    fs.mkdirSync(testNodeModules, { recursive: true });
  }
  if (!fs.existsSync(testChalkDir)) {
    fs.mkdirSync(testChalkDir, { recursive: true });
  }
  
  // Create test files
  fs.writeFileSync(path.join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));
  fs.writeFileSync(path.join(testDir, 'malicious.js'), maliciousCode);
  fs.writeFileSync(path.join(testDir, 'clean.js'), 'console.log("This is clean code");');
  fs.writeFileSync(path.join(testChalkDir, 'package.json'), JSON.stringify({
    "name": "chalk",
    "version": "4.1.2",
    "author": "qix"
  }, null, 2));
  
  console.log('Test environment created successfully!');
}

async function runTest() {
  console.log('Running security scanner test...\n');
  
  const scanner = new NPMSecurityScanner({
    directory: testDir,
    verbose: true
  });
  
  try {
    const results = await scanner.scan();
    
    console.log('\n' + '='.repeat(50));
    console.log('TEST RESULTS SUMMARY');
    console.log('='.repeat(50));
    console.log(`Total issues found: ${results.summary.issuesFound}`);
    console.log(`Compromised packages: ${results.compromisedPackages.length}`);
    console.log(`Malicious code patterns: ${results.maliciousCode.length}`);
    console.log(`Suspicious files: ${results.suspiciousFiles.length}`);
    
    if (results.summary.issuesFound > 0) {
      console.log('\n✅ Test PASSED - Scanner detected malicious patterns!');
    } else {
      console.log('\n❌ Test FAILED - Scanner did not detect malicious patterns!');
    }
    
  } catch (error) {
    console.error('Test failed with error:', error.message);
  }
}

async function cleanup() {
  console.log('\nCleaning up test environment...');
  
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('Test environment cleaned up!');
  }
}

async function main() {
  try {
    await setupTestEnvironment();
    await runTest();
  } catch (error) {
    console.error('Test setup failed:', error.message);
  } finally {
    await cleanup();
  }
}

if (require.main === module) {
  main();
}

module.exports = { setupTestEnvironment, runTest, cleanup };
