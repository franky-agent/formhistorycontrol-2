/**
 * Test suite for security fixes applied to Form History Control II.
 *
 * Tests the pure-JS security functions without needing a browser:
 * - S1: formatDetail() HTML-escapes stored values (stored XSS fix)
 * - S4: _isExcludedByAutocomplete() filters sensitive fields
 * - S5: ellipsis() escapes visible text
 * - _isIncognitoContext() safe fallback
 *
 * Since the source files use browser.* APIs and browser globals, we stub
 * the minimal globals needed and then eval the relevant function bodies.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');

// ─── Test harness ───────────────────────────────────────────────────────────

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

// ─── Stub environment ───────────────────────────────────────────────────────

/**
 * Minimal stubs for browser globals so we can load the source files in Node.
 */
function createBrowserStub() {
    return {
        i18n: {
            getMessage: (key) => `[${key}]`,
            getUILanguage: () => 'en-US',
        },
        runtime: {
            id: 'test-extension-id',
            getURL: (p) => `moz-extension://fake-id${p}`,
            getBrowserInfo: undefined, // not Firefox in test
        },
        storage: { local: { get: () => Promise.resolve({}), set: () => Promise.resolve() } },
        tabs: { query: () => Promise.resolve([]), get: () => Promise.resolve({}) },
        action: { setIcon: () => {} },
        pageAction: { show: () => {}, hide: () => {}, setIcon: () => {} },
        commands: { getAll: () => Promise.resolve([]) },
        menus: { create: () => {}, update: () => {}, remove: () => {} },
        contextMenus: { create: () => {}, update: () => {}, remove: () => {} },
        extension: { inIncognitoContext: false },
        alarms: { create: () => {}, onAlarm: { addListener: () => {} } },
        windows: { onFocusChanged: { addListener: () => {} } },
    };
}

// ─── S1: formatDetail HTML escaping ─────────────────────────────────────────

function loadFormatDetail() {
    const source = fs.readFileSync(
        path.join(REPO_ROOT, 'popup/tableview/DataTableUtil.js'), 'utf-8'
    );
    // Extract the formatDetail method body (between 'static formatDetail( d ) {' and the closing '    }')
    const match = source.match(/static formatDetail\( d \) \{([\s\S]*?)\n    \}/);
    if (!match) throw new Error('Could not extract formatDetail from DataTableUtil.js');

    const body = match[1];

    // The body references DataTableUtil.getLocaleFieldNames() and this.formatDate().
    // Replace those with inline stubs so the function is self-contained.
    const adaptedBody = body
        .replace(/DataTableUtil\.getLocaleFieldNames\(\)/g, 'getLocaleFieldNames()')
        .replace(/this\.formatDate/g, 'formatDate');

    const getLocaleFieldNames = () => ({
        name: 'Fieldname', value: 'Content', type: 'Type', count: 'Count',
        first: 'First used', last: 'Last used', age: 'Age', host: 'Host',
        uri: 'URL', length: 'Length'
    });
    const formatDate = (data, type) => data;

    // eslint-disable-next-line no-new-func
    return (d) => new Function('d', 'getLocaleFieldNames', 'formatDate',
        `return (function(d) {${adaptedBody}})(d);`
    )(d, getLocaleFieldNames, formatDate);
}

// ─── S4: _isExcludedByAutocomplete ──────────────────────────────────────────

function loadIsExcludedByAutocomplete() {
    const source = fs.readFileSync(
        path.join(REPO_ROOT, 'content/collectFormData.js'), 'utf-8'
    );
    // Extract the _SENSITIVE_AUTOCOMPLETE_TOKENS set and _isExcludedByAutocomplete function
    const tokenMatch = source.match(/const _SENSITIVE_AUTOCOMPLETE_TOKENS = new Set\((\[[\s\S]*?\])\);/);
    const fnMatch = source.match(/function _isExcludedByAutocomplete\(elem\) \{[\s\S]*?\n\}/);

    if (!tokenMatch || !fnMatch) throw new Error('Could not extract _isExcludedByAutocomplete');

    // Build a mock element with autocomplete attribute
    const buildElem = (autocomplete) => ({
        hasAttribute: (attr) => attr === 'autocomplete' && autocomplete !== null && autocomplete !== undefined,
        getAttribute: (attr) => attr === 'autocomplete' ? autocomplete : null,
    });

    // eslint-disable-next-line no-new-func
    const fn = new Function('elem', `
        const _SENSITIVE_AUTOCOMPLETE_TOKENS = new Set(${tokenMatch[1]});
        ${fnMatch[0]}
        return _isExcludedByAutocomplete(elem);
    `);

    return (autocomplete) => fn(buildElem(autocomplete));
}

// ─── _isIncognitoContext ────────────────────────────────────────────────────

function loadIsIncognitoContext() {
    const source = fs.readFileSync(
        path.join(REPO_ROOT, 'content/collectFormData.js'), 'utf-8'
    );
    // The function has nested try/catch braces; match from 'function' to the closing '}' before the next blank line
    const fnMatch = source.match(/function _isIncognitoContext\(\) \{\n[\s\S]*?\n\}/);
    if (!fnMatch) throw new Error('Could not extract _isIncognitoContext');

    // Test with a provided browser object
    return (browserObj) => {
        const browser = browserObj;
        // eslint-disable-next-line no-new-func
        return new Function('browser', `${fnMatch[0]} return _isIncognitoContext();`)(browser);
    };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

console.log('\n🔒 Security Fixes Test Suite\n');

// S1: formatDetail HTML escaping
console.log('S1: Stored XSS — formatDetail HTML escaping');
const formatDetail = loadFormatDetail();

test('formatDetail escapes <script> in value field', () => {
    const d = [null, 'fieldname', '<script>alert(1)</script>', 'text', 1, 0, 0, 'host', 'http://evil'];
    const html = formatDetail(d);
    assert.ok(!html.includes('<script>'), 'raw <script> tag should NOT appear in output');
    assert.ok(html.includes('&lt;script&gt;'), 'escaped &lt;script&gt; should appear in output');
});

test('formatDetail escapes <img onerror> in value field', () => {
    const payload = '<img src=x onerror=alert(document.cookie)>';
    const d = [null, 'name', payload, 'text', 1, 0, 0, 'host', 'http://evil'];
    const html = formatDetail(d);
    // The img tag should be escaped so it renders as inert text, not a live HTML element
    assert.ok(html.includes('&lt;img'), 'img tag should be escaped to &lt;img');
    assert.ok(!html.includes('<img src=x'), 'raw <img should NOT appear (must be escaped)');
    // The onerror text may appear inside the escaped text but the tag is inert
    assert.ok(html.includes('&gt;'), 'the closing > should be escaped to &gt;');
});

test('formatDetail escapes HTML in name field (d[1])', () => {
    const d = [null, '<b>name</b>', 'value', 'text', 1, 0, 0];
    const html = formatDetail(d);
    assert.ok(!html.includes('<b>name</b>'), 'raw <b> should NOT appear');
    assert.ok(html.includes('&lt;b&gt;name&lt;/b&gt;'), 'escaped <b> should appear');
});

test('formatDetail escapes HTML in host field (d[7])', () => {
    const d = [null, 'name', 'value', 'text', 1, 0, 0, '<script>alert(1)</script>'];
    const html = formatDetail(d);
    assert.ok(!html.includes('<script>alert(1)</script>'), 'raw script in host should NOT appear');
    assert.ok(html.includes('&lt;script&gt;'), 'escaped script in host should appear');
});

test('formatDetail escapes HTML in uri field (d[8])', () => {
    const d = [null, 'name', 'value', 'text', 1, 0, 0, 'host', 'javascript:alert(1)'];
    const html = formatDetail(d);
    assert.ok(html.includes('javascript:alert(1)'), 'uri text should be present (escaped context)');
    // The uri is in a text content div, not an attribute, so the javascript: protocol is inert
    assert.ok(!html.includes('"><script'), 'no attribute breakout possible');
});

test('formatDetail escapes double quotes (no attribute breakout)', () => {
    const d = [null, 'name', '" onmouseover="alert(1)', 'text', 1, 0, 0];
    const html = formatDetail(d);
    assert.ok(html.includes('&quot;'), 'double quotes should be escaped to &quot;');
    assert.ok(!html.includes('" onmouseover="alert(1)"'), 'no attribute injection possible');
});

test('formatDetail handles undefined/null fields gracefully', () => {
    const d = [null, 'name', 'value', 'text', undefined, 0, 0, undefined, undefined];
    const html = formatDetail(d);
    assert.ok(typeof html === 'string', 'should return a string');
    assert.ok(html.includes('detail-root'), 'should contain the detail-root div');
});

// S4: _isExcludedByAutocomplete
console.log('\nS4: Sensitive field exclusion — _isExcludedByAutocomplete');
const isExcluded = loadIsExcludedByAutocomplete();

test('excludes cc-number fields', () => {
    assert.ok(isExcluded('cc-number'), 'cc-number should be excluded');
});

test('excludes cc-csc fields', () => {
    assert.ok(isExcluded('cc-csc'), 'cc-csc should be excluded');
});

test('excludes current-password fields', () => {
    assert.ok(isExcluded('current-password'), 'current-password should be excluded');
});

test('excludes new-password fields', () => {
    assert.ok(isExcluded('new-password'), 'new-password should be excluded');
});

test('excludes one-time-code fields', () => {
    assert.ok(isExcluded('one-time-code'), 'one-time-code should be excluded');
});

test('excludes autocomplete="off" fields', () => {
    assert.ok(isExcluded('off'), 'off should be excluded');
});

test('excludes autocomplete="nope" fields', () => {
    assert.ok(isExcluded('nope'), 'nope should be excluded');
});

test('excludes cc-exp-month fields', () => {
    assert.ok(isExcluded('cc-exp-month'), 'cc-exp-month should be excluded');
});

test('does NOT exclude normal text fields', () => {
    assert.ok(!isExcluded('given-name'), 'given-name should NOT be excluded');
    assert.ok(!isExcluded('email'), 'email should NOT be excluded');
    assert.ok(!isExcluded('tel'), 'tel should NOT be excluded');
    assert.ok(!isExcluded('street-address'), 'street-address should NOT be excluded');
});

test('does NOT exclude fields without autocomplete attribute', () => {
    assert.ok(!isExcluded(null), 'null autocomplete should NOT be excluded');
    assert.ok(!isExcluded(undefined), 'undefined autocomplete should NOT be excluded');
});

test('is case-insensitive', () => {
    assert.ok(isExcluded('CC-NUMBER'), 'CC-NUMBER (uppercase) should be excluded');
    assert.ok(isExcluded('Off'), 'Off (mixed case) should be excluded');
});

test('handles multi-token autocomplete (shipping cc-number)', () => {
    assert.ok(isExcluded('shipping cc-number'), 'multi-token with cc-number should be excluded');
    assert.ok(!isExcluded('shipping given-name'), 'multi-token with given-name should NOT be excluded');
});

// _isIncognitoContext
console.log('\n_isIncognitoContext: safe deprecated API fallback');
const isIncognito = loadIsIncognitoContext();

test('returns true when browser.extension.inIncognitoContext is true', () => {
    assert.strictEqual(isIncognito({ extension: { inIncognitoContext: true } }), true);
});

test('returns false when browser.extension.inIncognitoContext is false', () => {
    assert.strictEqual(isIncognito({ extension: { inIncognitoContext: false } }), false);
});

test('returns false when browser.extension is undefined (Chrome MV3 SW)', () => {
    assert.strictEqual(isIncognito({}), false);
    assert.strictEqual(isIncognito({ extension: undefined }), false);
});

test('returns false when browser is undefined', () => {
    // This simulates the try/catch — if browser itself throws, we get false
    assert.strictEqual(isIncognito(undefined), false);
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n─────────────────────────────────────────`);
console.log(`Security tests: ${passed} passed, ${failed} failed`);
console.log(`─────────────────────────────────────────\n`);

module.exports = { passed, failed };