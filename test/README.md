# Automated Test Suite

This test suite verifies the security fixes and Firefox MV3 compliance of Form
History Control II **without needing to install the extension in a browser**.

## Quick start

```bash
# Install Node.js (v18+) and npm if not already available

# Build the Firefox extension (needed for the web-ext lint test)
python3 .script/build_extension.py firefox

# Run all tests
npm test
# or: node test/run-all-tests.js
```

## Test suites

### 1. Security Fixes (`test-security-fixes.js`) — 23 tests

Verifies the security patches work correctly by extracting and testing the
pure-JS security functions in a Node environment (with stubbed browser globals):

- **S1 (HIGH) Stored XSS**: `formatDetail()` HTML-escapes all stored form
  values (`<script>`, `<img onerror>`, attribute breakout attempts)
- **S4 (MEDIUM) Sensitive field exclusion**: `_isExcludedByAutocomplete()`
  correctly filters credit-card, password, one-time-code, and opted-out fields
- **`_isIncognitoContext()`**: safe fallback when `browser.extension` is
  unavailable (Chrome MV3 service worker contexts)

### 2. MV3 Compliance (`test-mv3-compliance.js`) — 24 tests

Static analysis verifying no deprecated MV2 patterns remain:

- All manifests are `manifest_version: 3`
- `browser_specific_settings` (not `applications`), with `gecko.id`,
  `gecko_android`, `data_collection_permissions`, `strict_min_version ≥ 115`
- `host_permissions` as a separate key
- `action` (not `browser_action`), `_execute_action` (not `_execute_browser_action`)
- CSP in object form, no `unsafe-eval`, no `browser_style: true`
- `background.scripts` (event page) for Firefox, not `service_worker`
- No `browser.browserAction`, `tabs.executeScript`, or active
  `browser.extension.*` usage in source JS
- `sender.id` validation present in all background `onMessage` listeners
- All JS files pass `node --check` syntax validation
- All manifests are valid JSON

### 3. web-ext Lint (`test-webext-lint.js`) — 5 tests

Runs Mozilla's official [`web-ext`](https://github.com/mozilla/web-ext) lint
tool (the same one AMO uses) on the built extension:

- 0 errors (errors would block AMO submission)
- No `UNSAFE_VAR_ASSIGNMENT` warnings in first-party code (only in 3rd-party
  libraries like jQuery, DataTables, DOMPurify which is expected)
- Warning count within reasonable bounds

## Running individual suites

```bash
npm run test:security   # Security fixes only
npm run test:mv3        # MV3 compliance only
npm run test:lint       # web-ext lint only (requires built extension)
```

## Requirements

- **Node.js** v18+ (for running tests)
- **Python 3** (for the build script)
- **npm** (optional — provides `npm test` convenience; you can also run
  `node test/run-all-tests.js` directly)

No browser installation or manual testing is required.