const fs = require('fs');
const path = require('path');

class SimplePatternMatcher {
  constructor() {
    this.patterns = this.initializePatterns();
    this.whitelist = this.loadWhitelist();
  }

  initializePatterns() {
    // Only keep the most obvious malicious patterns
    return [
      {
        name: 'TruffleHog Execution',
        pattern: /execSync.*trufflehog.*filesystem/gi,
        severity: 'HIGH',
        description: 'Detects TruffleHog execution for credential scanning'
      },
      {
        name: 'Webhook Exfiltration',
        pattern: /webhook\.site.*bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/gi,
        severity: 'HIGH',
        description: 'Detects specific webhook exfiltration endpoint from tinycolor attack'
      },
      {
        name: 'Cloud Metadata Discovery',
        pattern: /169\.254\.169\.254.*metadata|metadata\.google\.internal/gi,
        severity: 'HIGH',
        description: 'Detects cloud metadata discovery for credential theft'
      },
      {
        name: 'Malicious Postinstall Script',
        pattern: /postinstall.*bundle\.js|postinstall.*trufflehog/gi,
        severity: 'HIGH',
        description: 'Detects malicious postinstall scripts'
      },
      {
        name: 'Shai-Hulud Workflow',
        pattern: /shai-hulud.*workflow|\.github\/workflows\/.*shai-hulud/gi,
        severity: 'HIGH',
        description: 'Detects Shai-Hulud malicious workflow creation'
      }
    ];
  }

  loadWhitelist() {
    try {
      const whitelistPath = path.join(__dirname, '..', '..', 'data', 'whitelist.json');
      return JSON.parse(fs.readFileSync(whitelistPath, 'utf8'));
    } catch (error) {
      console.warn('Could not load whitelist:', error.message);
      return { libraries: [] };
    }
  }

  isWhitelisted(filePath) {
    for (const library of this.whitelist.libraries) {
      for (const pattern of library.patterns) {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(filePath)) {
          return true;
        }
      }
    }
    return false;
  }

  scanFile(filePath, content) {
    const results = [];
    // Skip whitelisted files
    if (this.isWhitelisted(filePath)) {
      return results;
    }

    for (const pattern of this.patterns) {
      const matches = content.match(pattern.pattern);
      if (matches) {
        results.push({
          pattern: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          matches: matches.length,
          lines: this.getLineNumbers(content, pattern.pattern)
        });
      }
    }

    return results;
  }

  getLineNumbers(content, pattern) {
    const lines = content.split('\n');
    const lineNumbers = [];
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        lineNumbers.push(i + 1);
      }
    }

    return lineNumbers;
  }
}

module.exports = SimplePatternMatcher;
