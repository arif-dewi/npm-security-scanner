#!/usr/bin/env node

/**
 * System analysis tool for NPM Security Scanner
 * Analyzes hardware and recommends optimal concurrency settings
 */

const ConcurrencyCalculator = require('./src/utils/concurrencyCalculator');
const Logger = require('./src/utils/logger');
const chalk = require('chalk').default || require('chalk');

async function analyzeSystem() {
  const logger = new Logger({ level: 'info', colors: true });
  const calculator = new ConcurrencyCalculator(logger);

  console.log(chalk.bold.blue('\n🔍 NPM Security Scanner - System Analysis\n'));

  // Get system status
  const systemStatus = calculator.getSystemStatus();

  console.log(chalk.bold('💻 Hardware Analysis:'));
  console.log(`  CPU Cores: ${systemStatus.cpuCores}`);
  console.log(`  CPU Speed: ${systemStatus.cpuSpeed} MHz`);
  console.log(`  Total Memory: ${systemStatus.totalMemory}`);
  console.log(`  Free Memory: ${systemStatus.freeMemory}`);
  console.log(`  Memory Pressure: ${systemStatus.memoryPressure}%`);
  console.log(`  Platform: ${systemStatus.platform} (${systemStatus.arch})`);
  console.log(`  High Performance: ${systemStatus.isHighPerformance ? '✅' : '❌'}`);
  console.log(`  Memory Constrained: ${systemStatus.isMemoryConstrained ? '⚠️' : '✅'}`);
  console.log(`  Low Memory: ${systemStatus.isLowMemory ? '⚠️' : '✅'}`);

  console.log(chalk.bold('\n📊 Process Memory:'));
  console.log(`  RSS: ${systemStatus.processMemory.rss}`);
  console.log(`  Heap Total: ${systemStatus.processMemory.heapTotal}`);
  console.log(`  Heap Used: ${systemStatus.processMemory.heapUsed}`);
  console.log(`  External: ${systemStatus.processMemory.external}`);

  // Test different scenarios
  const scenarios = [
    { name: 'Small Projects (1-10)', projectCount: 5, avgProjectSize: 'small', includeNodeModules: false },
    { name: 'Medium Projects (10-50)', projectCount: 25, avgProjectSize: 'medium', includeNodeModules: true },
    { name: 'Large Projects (50+)', projectCount: 100, avgProjectSize: 'large', includeNodeModules: true },
    { name: 'Quick Scan', projectCount: 20, avgProjectSize: 'medium', includeNodeModules: false, scanType: 'quick' },
    { name: 'Deep Scan', projectCount: 10, avgProjectSize: 'large', includeNodeModules: true, scanType: 'deep' }
  ];

  console.log(chalk.bold('\n🎯 Concurrency Recommendations:\n'));

  for (const scenario of scenarios) {
    const analysis = calculator.calculateOptimalConcurrency(scenario);

    console.log(chalk.bold(`${scenario.name}:`));
    console.log(`  📈 Optimal: ${chalk.green(analysis.optimal)} workers`);
    console.log(`  🛡️  Safe: ${chalk.yellow(analysis.safe)} workers`);
    console.log(`  ⚡ Aggressive: ${chalk.red(analysis.aggressive)} workers`);
    console.log(`  💾 Memory per worker: ${analysis.memoryPerWorker}`);
    console.log(`  📝 Reasoning: ${analysis.reasoning.join(', ')}`);
    console.log('');
  }

  // Test actual concurrency performance
  console.log(chalk.bold('🧪 Performance Testing:\n'));

  const testConcurrency = Math.min(systemStatus.cpuCores, 8); // Test up to 8 workers
  console.log(`Testing with ${testConcurrency} workers...`);

  try {
    const testResults = await calculator.testConcurrency(testConcurrency, {
      duration: 3000,
      projectCount: 20
    });

    console.log(`  ⏱️  Duration: ${testResults.duration}ms`);
    console.log(`  💾 Memory Delta: ${calculator.formatBytes(testResults.memoryDelta)}`);
    console.log(`  📊 Throughput: ${testResults.throughput.toFixed(2)} projects/sec`);
    console.log(`  ⚡ Efficiency: ${testResults.efficiency.toFixed(2)} projects/worker/sec`);
  } catch (error) {
    console.log(chalk.red(`  ❌ Test failed: ${error.message}`));
  }

  // Final recommendations
  console.log(chalk.bold('\n💡 Final Recommendations:\n'));

  const generalAnalysis = calculator.calculateOptimalConcurrency({
    projectCount: 20,
    avgProjectSize: 'medium',
    includeNodeModules: true
  });

  console.log(`For your system (${systemStatus.cpuCores} cores, ${systemStatus.totalMemory} RAM):`);
  console.log(`  🎯 Recommended: ${chalk.green(generalAnalysis.optimal)} parallel workers`);
  console.log(`  🛡️  Conservative: ${chalk.yellow(generalAnalysis.safe)} parallel workers`);
  console.log(`  ⚡ Maximum: ${chalk.red(generalAnalysis.aggressive)} parallel workers`);

  if (systemStatus.isMemoryConstrained) {
    console.log(chalk.yellow('\n⚠️  Warning: High memory pressure detected. Consider:'));
    console.log('  • Closing other applications');
    console.log('  • Using conservative concurrency settings');
    console.log('  • Scanning smaller batches of projects');
  }

  if (systemStatus.isHighPerformance && !systemStatus.isMemoryConstrained) {
    console.log(chalk.green('\n✅ Your system can handle high concurrency well!'));
    console.log('  • You can use aggressive settings for faster scanning');
    console.log('  • Consider increasing maxConcurrency in configuration');
  }

  console.log(chalk.bold('\n🔧 Configuration Example:\n'));
  console.log(chalk.gray('// In your scanner configuration:'));
  console.log(chalk.cyan('performance: {'));
  console.log(chalk.cyan(`  maxConcurrency: ${generalAnalysis.optimal},`));
  console.log(chalk.cyan('  timeout: 30000,'));
  console.log(chalk.cyan('  memoryLimit: 1024 * 1024 * 1024 // 1GB'));
  console.log(chalk.cyan('}'));

  console.log(chalk.bold('\n✨ Analysis complete!\n'));
}

// Run analysis
if (require.main === module) {
  analyzeSystem().catch(error => {
    console.error(chalk.red('Analysis failed:'), error.message);
    process.exit(1);
  });
}

module.exports = analyzeSystem;
