/**
 * web-ext lint test — validates the built Firefox extension using Mozilla's
 * official web-ext tool. This is the same lint that AMO (addons.mozilla.org)
 * runs on submission.
 *
 * Prerequisites: the Firefox extension must be built first (npm run build:firefox
 * or: python3 .script/build_extension.py firefox), which creates .dist/dist_firefox/.
 *
 * This test checks that:
 * - 0 errors (errors would block AMO submission)
 * - All UNSAFE_VAR_ASSIGNMENT warnings are in third-party libraries only
 *   (not in our first-party code)
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.join(REPO_ROOT, '.dist', 'dist_firefox');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        passed++;
        console.log(`  ✅ ${name}`);
    } catch (e) {
        failed++;
        console.log(`  ❌ ${name}`);
        console.log(`     ${e.message}`);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

console.log('\n🔍 web-ext Lint Test Suite\n');

// Check if dist directory exists
test('Firefox extension is built (.dist/dist_firefox exists)', () => {
    assert.ok(fs.existsSync(DIST_DIR),
        'dist directory not found. Run: python3 .script/build_extension.py firefox');
    assert.ok(fs.existsSync(path.join(DIST_DIR, 'manifest.json')),
        'manifest.json not found in dist');
});

// Run web-ext lint and parse JSON output
let lintResult = null;
try {
    const output = execSync(
        `npx web-ext lint --source-dir="${DIST_DIR}" --config-discovery=false --output=json`,
        { cwd: REPO_ROOT, encoding: 'utf-8', timeout: 60000, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    lintResult = JSON.parse(output);
} catch (e) {
    // web-ext may exit with non-zero on warnings; capture stdout anyway
    if (e.stdout) {
        try { lintResult = JSON.parse(e.stdout.toString()); } catch (e2) {}
    }
}

test('web-ext lint ran successfully', () => {
    assert.ok(lintResult, 'web-ext lint should produce JSON output');
});

if (lintResult) {
    test('0 errors (errors would block AMO submission)', () => {
        const errorCount = lintResult.errors?.length || 0;
        assert.strictEqual(errorCount, 0,
            `Found ${errorCount} errors:\n` +
            (lintResult.errors || []).map(e => `  ${e.code}: ${e.file}:${e.line} - ${e.description?.slice(0, 100)}`).join('\n'));
    });

    test('no UNSAFE_VAR_ASSIGNMENT warnings in first-party code', () => {
        const warnings = lintResult.warnings || [];
        const unsafeWarnings = warnings.filter(w => w.code === 'UNSAFE_VAR_ASSIGNMENT');
        // Filter to only first-party code (exclude lib/ and purify.js)
        const firstPartyUnsafe = unsafeWarnings.filter(w => {
            const f = w.file || '';
            return !f.includes('/lib/') && !f.endsWith('purify.js') && !f.endsWith('marked.js');
        });
        assert.strictEqual(firstPartyUnsafe.length, 0,
            `Found UNSAFE_VAR_ASSIGNMENT in first-party code:\n` +
            firstPartyUnsafe.map(w => `  ${w.file}:${w.line}`).join('\n'));
    });

    test('warnings count is reasonable (<= 15)', () => {
        const warningCount = lintResult.warnings?.length || 0;
        assert.ok(warningCount <= 15,
            `Too many warnings (${warningCount}); expected <= 15 (3rd-party innerHTML + Android notes)`);
    });

    // Summary
    console.log(`\n  📊 Lint summary: ${lintResult.errors?.length || 0} errors, ${lintResult.warnings?.length || 0} warnings, ${lintResult.notices?.length || 0} notices`);

    // List all warnings for transparency
    if (lintResult.warnings?.length) {
        console.log(`\n  Warning details:`);
        for (const w of lintResult.warnings) {
            const isLib = (w.file || '').includes('/lib/') || (w.file || '').endsWith('purify.js');
            console.log(`    ${isLib ? '📦' : '⚠️ '} ${w.code}: ${w.file}:${w.line || '?'}`);
        }
    }
}

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n─────────────────────────────────────────`);
console.log(`web-ext lint tests: ${passed} passed, ${failed} failed`);
console.log(`─────────────────────────────────────────\n`);

module.exports = { passed, failed };