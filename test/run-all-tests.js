/**
 * Master test runner — runs all test suites and reports a combined summary.
 *
 * Usage: npm test  OR  node test/run-all-tests.js
 *
 * Test suites:
 *   1. test-security-fixes.js  — verifies S1/S4/S5 security patches work
 *   2. test-mv3-compliance.js  — verifies no deprecated MV2 APIs remain
 *   3. test-webext-lint.js     — runs Mozilla's official web-ext lint on the build
 */

const { execSync } = require('child_process');
const path = require('path');

const suites = [
    { name: 'Security Fixes', file: 'test-security-fixes.js', icon: '🔒' },
    { name: 'MV3 Compliance', file: 'test-mv3-compliance.js', icon: '🦊' },
    { name: 'web-ext Lint', file: 'test-webext-lint.js', icon: '🔍' },
];

console.log('╔══════════════════════════════════════════════════════╗');
console.log('║   Form History Control II — Automated Test Suite    ║');
console.log('╚══════════════════════════════════════════════════════╝');

let totalPassed = 0;
let totalFailed = 0;
const failedSuites = [];

for (const suite of suites) {
    const suitePath = path.join(__dirname, suite.file);
    try {
        console.log(`\n━━━ ${suite.icon}  ${suite.name} ━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        execSync(`node "${suitePath}"`, { stdio: 'inherit' });

        // Parse the summary line to get counts
        // Can't easily parse inherited output, so re-run capturing
        const output = execSync(`node "${suitePath}"`, { encoding: 'utf-8' });
        const match = output.match(/(\d+) passed, (\d+) failed/);
        if (match) {
            totalPassed += parseInt(match[1]);
            totalFailed += parseInt(match[2]);
            if (parseInt(match[2]) > 0) failedSuites.push(suite.name);
        }
    } catch (e) {
        // Test suite crashed or had failures
        totalFailed++;
        failedSuites.push(suite.name);
        // Try to parse counts from error output
        const output = e.stdout?.toString() || '';
        const match = output.match(/(\d+) passed, (\d+) failed/);
        if (match) {
            totalPassed += parseInt(match[1]);
            totalFailed += parseInt(match[2]) - 1; // already counted the suite failure above
        }
    }
}

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log(`║  TOTAL: ${totalPassed} passed, ${totalFailed} failed`);
if (failedSuites.length > 0) {
    console.log(`║  Failed suites: ${failedSuites.join(', ')}`);
}
console.log('╚══════════════════════════════════════════════════════╝');

process.exit(totalFailed > 0 ? 1 : 0);