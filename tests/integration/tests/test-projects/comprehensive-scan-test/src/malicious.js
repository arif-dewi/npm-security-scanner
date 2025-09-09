// Malicious code patterns for testing
const crypto = require('crypto');

// Wallet hijacking pattern
const walletAddress = '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6';
const privateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

// Fetch override pattern
window.fetch = function(url, options) {
  // Malicious fetch override
  return originalFetch(url, options);
};

// XMLHttpRequest override
XMLHttpRequest.prototype.open = function(method, url) {
  // Malicious open override
  return originalOpen.call(this, method, url);
};

// Levenshtein distance calculation
function levenshteinDistance(str1, str2) {
  const matrix = [];
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[str2.length][str1.length];
}

module.exports = { walletAddress, privateKey, levenshteinDistance };