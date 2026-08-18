/**
 * MV3 Compliance Test Suite — static analysis of source code and manifests.
 *
 * Verifies that no deprecated MV2 APIs or patterns remain in the codebase
 * on the manifest3 branch, and that the Firefox manifest has all required
 * MV3 keys.
 *
 * These tests run with plain Node (no browser needed).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');

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

function readFile(relPath) {
    return fs.readFileSync(path.join(REPO_ROOT, relPath), 'utf-8');
}

function readJSON(relPath) {
    return JSON.parse(readFile(relPath));
}

/**
 * Recursively walk all .js files (excluding third-party libs and node_modules)
 * and return their paths.
 */
function getAllSourceJS() {
    const excludeDirs = ['node_modules', '.git', '.dist', 'popup/tableview/lib', 'popup/entryview/renderjs', 'test'];
    const excludeFiles = ['browser-polyfill.min.js', 'purify.js'];
    const results = [];
    function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                if (!excludeDirs.some(ex => fullPath.includes(ex))) {
                    walk(fullPath);
                }
            } else if (entry.name.endsWith('.js')) {
                if (!excludeFiles.some(ex => entry.name === ex)) {
                    results.push(fullPath);
                }
            }
        }
    }
    walk(REPO_ROOT);
    return results;
}

function grepSource(pattern, flags = '') {
    const regex = new RegExp(pattern, flags);
    const results = [];
    for (const file of getAllSourceJS()) {
        const content = fs.readFileSync(file, 'utf-8');
        const lines = content.split('\n');
        lines.forEach((line, i) => {
            if (regex.test(line) && !line.trim().startsWith('//')) {
                results.push({ file: path.relative(REPO_ROOT, file), line: i + 1, text: line.trim() });
            }
        });
    }
    return results;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

console.log('\n🦊 Firefox MV3 Compliance Test Suite\n');

// Manifest structure tests
console.log('Manifest structure:');

test('manifest.firefox.json is manifest_version 3', () => {
    const m = readJSON('manifest.firefox.json');
    assert.strictEqual(m.manifest_version, 3, 'manifest_version must be 3');
});

test('manifest.json is manifest_version 3', () => {
    const m = readJSON('manifest.json');
    assert.strictEqual(m.manifest_version, 3, 'manifest_version must be 3');
});

test('manifest.chrome.json is manifest_version 3', () => {
    const m = readJSON('manifest.chrome.json');
    assert.strictEqual(m.manifest_version, 3, 'manifest_version must be 3');
});

test('uses browser_specific_settings (not deprecated applications)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.browser_specific_settings, 'must have browser_specific_settings');
    assert.ok(!m.applications, 'must NOT have deprecated applications key');
});

test('browser_specific_settings.gecko.id is set (required for MV3 signing)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.browser_specific_settings.gecko.id, 'gecko.id must be set');
});

test('strict_min_version is at least 128.0', () => {
    const m = readJSON('manifest.firefox.json');
    const minVer = parseInt(m.browser_specific_settings.gecko.strict_min_version);
    assert.ok(minVer >= 128, `strict_min_version should be >= 128, got ${minVer}`);
});

test('gecko_android is present (Firefox for Android support)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.browser_specific_settings.gecko_android !== undefined,
        'gecko_android must be present');
});

test('data_collection_permissions is present (required for AMO post-Nov 2025)', () => {
    const m = readJSON('manifest.firefox.json');
    const dcp = m.browser_specific_settings.gecko.data_collection_permissions;
    assert.ok(dcp, 'data_collection_permissions must be present');
    assert.ok(Array.isArray(dcp.required), 'required must be an array');
});

test('host_permissions is a separate key (MV3 requirement)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.host_permissions, 'must have separate host_permissions key');
    assert.ok(!m.permissions.includes('*://*/*'),
        'host patterns must NOT be in permissions (must be in host_permissions)');
});

test('action key (renamed from browser_action)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.action, 'must have action key');
    assert.ok(!m.browser_action, 'must NOT have deprecated browser_action key');
});

test('commands use _execute_action (not _execute_browser_action)', () => {
    const m = readJSON('manifest.firefox.json');
    const commandKeys = Object.keys(m.commands || {});
    assert.ok(!commandKeys.includes('_execute_browser_action'),
        'must NOT have _execute_browser_action');
    // _execute_action is optional but if present should be correct
});

test('CSP is in object form (MV3 requirement)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(typeof m.content_security_policy === 'object',
        'CSP must be an object, not a string');
    assert.ok(m.content_security_policy.extension_pages,
        'must have extension_pages CSP');
    assert.ok(!m.content_security_policy.extension_pages.includes('unsafe-eval'),
        'CSP must NOT allow unsafe-eval');
});

test('no browser_style: true (removed in MV3)', () => {
    const m = readJSON('manifest.firefox.json');
    const checkKey = (key) => {
        if (m[key] && m[key].browser_style === true) {
            throw new Error(`${key}.browser_style must not be true in MV3`);
        }
    };
    ['action', 'page_action', 'options_ui'].forEach(checkKey);
});

test('background uses scripts (event page) not service_worker (Firefox)', () => {
    const m = readJSON('manifest.firefox.json');
    assert.ok(m.background.scripts, 'Firefox MV3 uses background.scripts (event page)');
    assert.ok(!m.background.service_worker,
        'Firefox MV3 must NOT use background.service_worker');
    assert.ok(m.background.persistent !== true,
        'persistent must NOT be true in MV3');
});

test('background script files exist on disk', () => {
    const m = readJSON('manifest.firefox.json');
    for (const script of m.background.scripts) {
        const scriptPath = path.join(REPO_ROOT, script);
        assert.ok(fs.existsSync(scriptPath), `background script ${script} must exist`);
    }
});

test('manifest.json and manifest.firefox.json are in sync', () => {
    const m1 = readJSON('manifest.json');
    const m2 = readJSON('manifest.firefox.json');
    assert.deepStrictEqual(m1, m2, 'manifest.json must match manifest.firefox.json');
});

// Static analysis: deprecated API usage
console.log('\nDeprecated API usage (static analysis):');

test('no browser.browserAction usage in source JS', () => {
    const hits = grepSource('browser\\.browserAction');
    assert.strictEqual(hits.length, 0,
        `found browser.browserAction: ${hits.map(h => `${h.file}:${h.line}`).join(', ')}`);
});

test('no _execute_browser_action in manifests', () => {
    for (const f of ['manifest.json', 'manifest.firefox.json', 'manifest.chrome.json']) {
        const content = readFile(f);
        assert.ok(!content.includes('_execute_browser_action'),
            `${f} must not contain _execute_browser_action`);
    }
});

test('no applications.gecko in manifests (use browser_specific_settings)', () => {
    for (const f of ['manifest.json', 'manifest.firefox.json', 'manifest.chrome.json']) {
        const m = readJSON(f);
        assert.ok(!m.applications, `${f} must not use deprecated applications key`);
    }
});

test('no tabs.executeScript in source JS (removed in MV3)', () => {
    const hits = grepSource('tabs\\.executeScript');
    assert.strictEqual(hits.length, 0,
        `found tabs.executeScript: ${hits.map(h => `${h.file}:${h.line}`).join(', ')}`);
});

test('no active browser.extension.* usage (deprecated in MV3)', () => {
    // Allow references inside comments and inside the safe _isIncognitoContext wrapper
    const hits = grepSource('browser\\.extension\\.');
    const realHits = hits.filter(h => !h.text.startsWith('//') && !h.text.includes('*'));
    // The _isIncognitoContext wrapper is allowed
    const allowedHits = realHits.filter(h =>
        h.text.includes('inIncognitoContext') &&
        (h.text.includes('try') || h.text.includes('return !!'))
    );
    const badHits = realHits.filter(h => !allowedHits.some(a => a.file === h.file && a.line === h.line));
    assert.strictEqual(badHits.length, 0,
        `found active browser.extension.* usage: ${badHits.map(h => `${h.file}:${h.line} ${h.text}`).join(', ')}`);
});

test('sender.id validation present in all background onMessage listeners', () => {
    for (const f of ['background/receiveFormData.js', 'background/contextmenu.js', 'background/applicationIcon.js']) {
        const content = readFile(f);
        assert.ok(content.includes('sender.id') && content.includes('browser.runtime.id'),
            `${f} must validate sender.id === browser.runtime.id`);
    }
});

test('all JS files pass node --check syntax', () => {
    const errors = [];
    for (const file of getAllSourceJS()) {
        try {
            execSync(`node --check "${file}"`, { stdio: 'pipe', timeout: 5000 });
        } catch (e) {
            errors.push({ file: path.relative(REPO_ROOT, file), error: e.stderr?.toString().trim() });
        }
    }
    assert.strictEqual(errors.length, 0,
        `syntax errors: ${errors.map(e => `${e.file}: ${e.error}`).join('; ')}`);
});

test('all manifests are valid JSON', () => {
    for (const f of ['manifest.json', 'manifest.firefox.json', 'manifest.chrome.json']) {
        assert.doesNotThrow(() => readJSON(f), `${f} must be valid JSON`);
    }
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n─────────────────────────────────────────`);
console.log(`MV3 compliance tests: ${passed} passed, ${failed} failed`);
console.log(`─────────────────────────────────────────\n`);

module.exports = { passed, failed };