# Form History Control II — Deep Security Analysis & Firefox MV3 Compliance Audit

**Repository:** https://github.com/stephanmahieu/formhistorycontrol-2
**Fork:** https://github.com/franky-agent/formhistorycontrol-2
**Auditor:** franky-agent
**Date:** 2025-08-18
**Versions audited:** `master` (v2.5.12.0, Manifest V2) and `manifest3` branch (v3.0.4.0, Manifest V3)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Repository & Branch Overview](#2-repository--branch-overview)
3. [Security Audit — Findings Table](#3-security-audit--findings-table)
4. [Security Audit — Detailed Findings](#4-security-audit--detailed-findings)
5. [Third-Party Library Inventory](#5-third-party-library-inventory)
6. [Positive Security Findings](#6-positive-security-findings)
7. [Firefox Manifest V3 Compliance — Checklist](#7-firefox-manifest-v3-compliance--checklist)
8. [MV3 Compliance — Branch-by-Branch Audit](#8-mv3-compliance--branch-by-branch-audit)
9. [Critical: Broken Chrome MV3 Build on `master`](#9-critical-broken-chrome-mv3-build-on-master)
10. [Prioritized Recommendations](#10-prioritized-recommendations)
11. [Methodology & Sources](#11-methodology--sources)

---

## 1. Executive Summary

**Form History Control II** is a browser extension that records form-field history (text inputs,
textareas, contenteditable regions) into local storage (IndexedDB) and provides autocomplete,
import/export (JSON/XML), and a management UI. It runs content scripts on **every page** the user
visits (`*://*/*` + `file:///*`), making the content-script ↔ background boundary the most
security-critical surface.

### Security headline
The codebase is **defensively written in its highest-risk areas**: DOMPurify (v3.2.4) is bundled
and correctly applied before every `innerHTML` insertion of stored data in the content scripts and
the entry viewer; password fields are explicitly excluded from collection; and there is no
`eval` / `new Function` / string-`setTimeout` anywhere in first-party code.

However, one **HIGH-severity stored-XSS** sink was found in the management-table detail renderer
(`DataTableUtil.formatDetail`), which concatenates stored form values into an HTML string **without
escaping** — bypassing the DOMPurify protection used elsewhere. A malicious page (or a crafted
import file) can plant an `onerror`/`<script>` payload in a textarea that executes with extension
privileges when the user expands a row in the popup.

Two **MEDIUM** issues (unvalidated `onMessage` senders; autocomplete data-exfiltration surface) and
three **LOW/INFO** issues round out the findings. No CRITICAL RCE or XXE issues were found.

### MV3 headline
The repository is **mid-migration**:

- The **`master` branch** ships Manifest V2 for Firefox (`manifest.firefox.json`, `manifest_version: 2`,
  `applications.gecko`) but already carries an MV3 `manifest.chrome.json` that is **broken** — it
  references `/background/service-worker.js`, a file that does **not exist** on `master` (it lives
  on the `manifest3` branch as `background/chrome-service-worker.js`). The Chrome build from `master`
  will fail to load.
- The **`manifest3` branch** is a substantially complete MV3 migration with a proper Firefox MV3
  manifest (`manifest_version: 3`, `browser_specific_settings.gecko`, event-page `background.scripts`,
  `host_permissions`, `action`, `_execute_action`). It is **the recommended base going forward** but
  still needs a few finishing touches (CSP tightening, `gecko_android`, `data_collection_permissions`
  for post-Nov-2025 AMO submissions, `marked` upgrade).

Firefox has **not deprecated MV2** (as of Feb 2025 Mozilla reaffirmed MV2 stays "for the foreseeable
future"), so the MV2 `master` build remains submittable to AMO — but migrating to the `manifest3`
branch is strongly recommended for Chrome compatibility (Chrome removed MV2 in 2024–2025) and
forward-proofing.

---

## 2. Repository & Branch Overview

| Branch | Manifest version | Firefox manifest | Chrome manifest | Status |
|---|---|---|---|---|
| `master` (v2.5.12.0) | **MV2** (Firefox) / **MV3** (Chrome, broken) | `manifest.firefox.json` — `applications.gecko`, `strict_min_version: 79.0` | `manifest.chrome.json` — MV3, references missing `service-worker.js` | Firefox MV2 works; **Chrome build broken** |
| `manifest3` (v3.0.4.0) | **MV3** (both) | `manifest.firefox.json` — `browser_specific_settings.gecko`, `strict_min_version: 109.0`, event-page background | `manifest.chrome.json` — MV3, `chrome-service-worker.js` | **Substantially complete; recommended base** |

Other branches: `poc_encryption_password` (encryption POC), `safari_support` (not audited).

---

## 3. Security Audit — Findings Table

| # | Severity | Title | Location |
|---|----------|-------|----------|
| S1 | **HIGH** | Stored XSS via unescaped HTML in `formatDetail` | `popup/tableview/DataTableUtil.js:58-71`; sink `popup/tableview/popup-small.js:81` |
| S2 | MEDIUM | Background `onMessage` handlers do not validate `sender` | `background/receiveFormData.js:12`; `background/contextmenu.js:16`; `background/applicationIcon.js:37` |
| S3 | MEDIUM | Autocomplete returns stored history for page-controlled field names (exfiltration surface) | `content/add-auto-complete.js:67-80`; `background/receiveFormData.js:492-529` |
| S4 | MEDIUM | Credit-card / PII inputs captured (no `autocomplete`-attribute filtering) | `content/collectFormData.js:774-779` |
| S5 | LOW | `ellipsis()` returns unescaped display data (regex tag-strip bypass) | `popup/tableview/DataTableUtil.js:94-126` |
| S6 | LOW | Imported data stored without sanitization/validation | `popup/importexport/import.js:129-175`; `JsonUtil.js:21-67`; `XmlUtil.js:21-92` |
| S7 | INFO | `marked` v3.0.8 has deprecated/removed built-in `sanitize` (mitigated by DOMPurify) | `popup/entryview/renderjs/marked.js` |
| S8 | INFO | No explicit CSP in MV2 manifests (no `web_accessible_resources` — positive) | `manifest.json`, `manifest.firefox.json` (master) |
| S9 | INFO | `clipboardWrite` / `downloads` usage is user-gesture gated (positive) | `common/MiscUtil.js:21-33`; `common/FileUtil.js:18-41` |
| S10 | INFO | `JSON.parse` of imported prefs — no deep merge / no prototype pollution (positive) | `popup/options/options.js:506-516` |

---

## 4. Security Audit — Detailed Findings

### S1 — HIGH: Stored XSS via unescaped HTML in `formatDetail`

**File:** `popup/tableview/DataTableUtil.js:58-71` (sink at `popup/tableview/popup-small.js:81`)

`formatDetail` builds an HTML string by directly concatenating stored database fields with **no
escaping**:

```js
static formatDetail( d ) {
    const i18n = DataTableUtil.getLocaleFieldNames();
    return '<div class="detail-root"><table>'+
        '<tr><td><span class="label">'+i18n.name+':</span></td><td>'+d[1]+'</td></tr>'+
        '<tr><td><span class="label">'+i18n.value+':</span></td><td><div class="detail-info">'+d[2]+'</div></td></tr>'+
        '<tr><td><span class="label">'+i18n.type+':</span></td><td>'+d[3]+'</td></tr>'+
        ...
        (d[8]?('<tr><td><span class="label">'+i18n.uri+':</span></td><td><div class="detail-info">'+d[8]+'</div></td></tr>'):'')+
        '</table></div>';
}
```

This string is passed to DataTables' `row.child()`:

```js
// popup-small.js:81
openChildRow = row.child( DataTableUtil.formatDetail(row.data()), 'no-padding');
```

DataTables' `row.child(html)` inserts the string via jQuery `.html()`, which parses and executes
the HTML. The `value` field (`d[2]`) originates from:
- `content/collectFormData.js:803,807` — `innerHTML` of contenteditable/textarea regions on **any**
  page the user visits (attacker-controlled HTML), and
- imported files (`popup/importexport/import.js` → `_storeTextEntries`/`_storeMultilineEntries`),
  which store `value`/`content` verbatim.

**Impact:** A malicious page (or a crafted import file) can plant `<img src=x onerror=...>` or
`<script>` in a textarea/contenteditable field. When the user later opens the management popup and
expands the row's detail view, the payload executes in the **extension's privileged popup context**
(which has access to `browser.storage`, `browser.tabs`, etc.). This is a stored XSS with extension
privileges.

**Recommended fix:** Escape all interpolated values — reuse the `esc()` helper already present in
`ellipsis()` at `DataTableUtil.js:95-101` — or build the detail DOM with
`document.createElement` / `textContent`. Note the contrast: the entry viewer
(`entryview.js:406,471,494`) **correctly** sanitizes with DOMPurify, but this tableview path does not.

---

### S2 — MEDIUM: Background `onMessage` handlers do not validate `sender`

**Files:** `background/receiveFormData.js:12`; `background/contextmenu.js:16`; `background/applicationIcon.js:37`

All three background listeners accept `(fhcEvent, sender, sendResponse)` but never inspect `sender`:

```js
// receiveFormData.js:12
function receiveEvents(fhcEvent, sender, sendResponse) {
    if (fhcEvent.eventType) {
        switch (fhcEvent.eventType) {
            case 1:  saveOrUpdateTextField(fhcEvent); ...
            case 4:  importIfNotExist(fhcEvent); ...
            case 555: getValuesMatchingSearchtermFromDatabaseAndRespond(..., sendResponse); return true;
```

`eventType 555` returns stored form history via `sendResponse({choices: fieldValues})`
(`receiveFormData.js:527`) to any caller. `eventType 1/2/4/5/6/11` write arbitrary data into the
IndexedDB.

**Impact:** The extension does not set `externally_connectable`, so web pages cannot reach these
listeners directly. However, **any other installed extension** can send messages to this
extension's background page and (a) read stored form history via eventType 555, and (b) inject
arbitrary records via eventType 4/11. There is no `sender.id` allow-list.

**Recommended fix:** Validate `sender.id === browser.runtime.id` (or check `sender.url` starts
with the extension's own `moz-extension://` / `chrome-extension://` origin) at the top of each
listener, and reject otherwise.

---

### S3 — MEDIUM: Autocomplete returns stored history for page-controlled field names

**Files:** `content/add-auto-complete.js:67-80`; `background/receiveFormData.js:492-529`

The content script sends the page's field name and search term to the background, which returns
matching stored values; these are rendered into the page DOM where the page can read them. A
malicious page can enumerate field names it expects the user to have used elsewhere (e.g.
`username`, `email`) and harvest cross-site form history via the autocomplete suggestions.

**Impact:** Cross-site data exfiltration of form history by a malicious page, gated only by the
page knowing/guessing field names. Severity is MEDIUM because exploitation requires the user to
focus a field with a guessable name on the attacker's page.

**Recommended fix:** Consider (a) scoping autocomplete lookups to the **same host** that originally
saved the entry, and/or (b) requiring the field name to match an entry saved for the current page's
origin before returning suggestions. At minimum, document this as accepted behavior.

---

### S4 — MEDIUM: Credit-card / PII inputs captured (no `autocomplete`-attribute filtering)

**File:** `content/collectFormData.js:774-779`

Password fields are correctly excluded (`type !== 'password'`), but there is **no filtering on the
`autocomplete` attribute**. Fields marked `autocomplete="cc-number"`, `cc-csc`, `cc-exp"`,
`"new-password"`, `"off"`, or `"nope"` (a common "don't save this" sentinel) are still captured.

**Impact:** Credit-card numbers, CVVs, and other sensitive autofill values may be stored in the
extension's IndexedDB, increasing the blast radius of S1/S2 and of any local-disk compromise.

**Recommended fix:** Skip collection for fields whose `autocomplete` attribute indicates a
sensitive type (`cc-*`, `current-password`, `new-password`, `off`, `nope`). Add a corresponding
option in the management UI.

---

### S5 — LOW: `ellipsis()` returns unescaped display data

**File:** `popup/tableview/DataTableUtil.js:94-126`

`ellipsis()` strips HTML tags with a regex and then outputs the result into a `<span>` via a
template that is itself concatenated into HTML. The regex tag-strip can be bypassed (e.g. nested
angle brackets, `<scr<script>ipt>`), and the `title` attribute is escaped but the visible text span
content is not consistently escaped before being injected via DataTables. Combined with S1, this is
a secondary XSS vector in the table cells themselves.

**Recommended fix:** Escape the visible text with the existing `esc()` helper before concatenation,
and prefer `textContent` assignment.

---

### S6 — LOW: Imported data stored without sanitization/validation

**Files:** `popup/importexport/import.js:129-175`; `JsonUtil.js:21-67`; `XmlUtil.js:21-92`

Imported JSON/XML entries are parsed and stored verbatim into IndexedDB. There is no schema
validation, length capping, or content sanitization at import time. Because stored `value`/`content`
later flows into the S1 sink, a crafted import file is an alternate injection vector for the stored
XSS.

**Recommended fix:** Validate the imported structure (expected fields/types), cap field lengths,
and run imported `value`/`content` through DOMPurify (or at minimum HTML-escape) before storage
and before display.

---

### S7 — INFO: `marked` v3.0.8 deprecated `sanitize` option (mitigated)

**File:** `popup/entryview/renderjs/marked.js`

`marked` v3 removed the built-in `sanitize` option (the warning at line 369 references the 0.7.0
deprecation; the option is gone in v3). The code **correctly compensates** by piping
`marked.parse()` output through DOMPurify (`entryview.js:470-471`). This is a positive finding, but
`marked` v3.0.8 is old (current is v12+) and should be upgraded for parser bug-fixes.

---

### S8–S10 — INFO (positive / non-issues)

- **S8:** The MV2 manifests declare no explicit CSP and no `web_accessible_resources`, which means
  the extension exposes no web-accessible resources to pages by default — good. (The `manifest3`
  Firefox manifest adds `"content_security_policy": { "extension_pages": "default-src 'self'" }`,
  which is correct and tight.)
- **S9:** `clipboardWrite` (clipboard) and `downloads` (file save) are only invoked behind user
  gestures (button clicks in the import/export UI) — no background-driven silent exfiltration.
- **S10:** Imported preferences are parsed with `JSON.parse` and then shallow-copied via
  `Object.assign({}, res)` onto known keys only (`options.js:214,257`); there is no recursive deep
  merge, so **no prototype-pollution vector** exists.

---

## 5. Third-Party Library Inventory

| Library | Version | Location | Notes |
|---|---|---|---|
| jQuery | 3.7.0 | `popup/tableview/lib/jquery-3.7.0.min.js` | Current; no known critical CVEs for 3.7.0. |
| DataTables core | 2.2.2 | `popup/tableview/lib/dataTables.min.js` | Current. |
| DataTables Responsive | 3.0.4 | (lib) | Current. |
| DataTables Buttons | (bundled) | `popup/tableview/lib/dataTables.buttons.js`, `buttons.colVis.js` | Review version; no known critical CVEs. |
| DOMPurify | **3.2.4** | `common/purify.js` | Current/recent. Correctly used in content scripts + entry viewer. **Not** used in `DataTableUtil.formatDetail` (see S1). |
| marked | **3.0.8** | `popup/entryview/renderjs/marked.js` | **Outdated** (current v12+). Built-in `sanitize` removed in v3; mitigated by DOMPurify post-processing. Upgrade recommended for parser bug-fixes. |
| browser-polyfill | (webextension-polyfill) | `common/browser-polyfill.min.js` | Version not declared in file; check against upstream `webextension-polyfill` (recommend ≥ 0.12.0). |

No known critical CVEs were identified against the bundled versions as of this audit, but **`marked`
3.0.8 should be upgraded** and the **polyfill version should be pinned/documented**.

---

## 6. Positive Security Findings

1. **DOMPurify is bundled and consistently used** in the content scripts (`showFormData.js`,
   `auto-complete.js`) and the entry viewer (`entryview.js`) before every `innerHTML`-equivalent
   insertion of stored, attacker-influenced data.
2. **Password fields are explicitly excluded** from collection (`collectFormData.js:774-779`), and
   custom autocomplete is not attached to password inputs (`add-auto-complete.js:29,34`).
3. **No `eval`, `new Function`, or string-form `setTimeout`** anywhere in first-party code.
4. **No `document.write`** in first-party code.
5. **No `externally_connectable`**, so web pages cannot directly message the background script
   (this narrows S2 to other extensions only).
6. **`downloads` and `clipboardWrite` are user-gesture gated** — no silent background exfiltration.
7. **No prototype-pollution vector** in preference import (shallow copy of known keys).
8. **MV3 `manifest3` Firefox manifest sets a tight CSP** (`default-src 'self'`) and uses
   `browser_specific_settings` (correct MV3 key).
9. **XML import uses `DOMParser`**, which does not resolve external entities (no XXE).

---

## 7. Firefox Manifest V3 Compliance — Checklist

Verified against MDN, Mozilla Blog, and Extension Workshop (2024–2025). See sources in §11.

### Timeline & current status

| Item | Status | Detail |
|---|---|---|
| MV3 stable shipped | **[REQUIRED]** | Firefox **109** (Jan 17, 2023) enabled MV3 by default. |
| MV2 deprecation | **[CHROME-DIFFERENCE]** | Firefox has **no MV2 deprecation timeline** (reaffirmed Feb 2025). MV2 still accepted/signed on AMO. Chrome removed MV2 in 2024–2025. |
| `webRequestBlocking` | **[CHROME-DIFFERENCE]** | Firefox **keeps** `webRequestBlocking` in MV3 (Chrome removed it). Not used by this extension. |

### Firefox-specific MV3 differences from Chrome

| Item | Status | Detail |
|---|---|---|
| `background.service_worker` | **[CHROME-DIFFERENCE]** | **Not supported in Firefox.** Firefox uses event pages via `background.scripts`. |
| `background.scripts` in MV3 | **[REQUIRED]** | Firefox requires `background.scripts` (or `page`). |
| Cross-browser fallback | **[RECOMMENDED]** | Specify **both** `scripts` and `service_worker`; Chrome uses SW, Firefox uses scripts. |
| `persistent` | **[REQUIRED]** | MV3 removes persistent background pages; `"persistent": true` **throws** in MV3. |
| `browser_specific_settings.gecko` | **[REQUIRED]** | Valid MV3 key; `applications` is deprecated. |
| `gecko.id` | **[REQUIRED]** | Mandatory for signing MV3 extensions on AMO. |
| `gecko_android` | **[RECOMMENDED]** | Add `"gecko_android": {}` for Firefox-for-Android support. |
| `browser_action` → `action` | **[REQUIRED]** | Rename manifest key + `browser.browserAction` → `browser.action`. |
| `page_action` | **[CHROME-DIFFERENCE]** | Firefox **retains** `page_action` (key + API + `_execute_page_action`). Chrome merged into `action`. |
| `browser_style` | **[REQUIRED]** | Removed in MV3 (Firefox 118+). Remove from `action`, `page_action`, `options_ui`. |
| `_execute_browser_action` → `_execute_action` | **[REQUIRED]** | MV3 uses `_execute_action`. User shortcuts auto-migrate (Firefox 127+). |
| `host_permissions` (separate key) | **[REQUIRED]** | MV3 puts host permissions in a separate `host_permissions` key, not `permissions`. |
| Install prompt for hosts | **[CHROME-DIFFERENCE]** | Firefox shows `host_permissions` in install prompt from 127+. |
| CSP object form | **[REQUIRED]** | MV3 CSP is an object: `{ "extension_pages": "..." }` (+ optional `sandbox`). No string form. |
| `extension_pages` restrictions | **[REQUIRED]** | `script-src`/`worker-src` may only be `'self'`, `'none'`, `'wasm-unsafe-eval'`. No remote URLs, no `'unsafe-eval'`, no hashes. |
| `content_scripts` CSP sub-key | **[CHROME-DIFFERENCE]** | Chrome MV3 has it; **Firefox does not** (only `extension_pages` + `sandbox`). |
| `web_accessible_resources` MV3 format | **[REQUIRED]** | Array of objects `{ "resources": [...], "matches": [...], "extension_ids": [...] }`, not the MV2 flat array. (This extension declares none — fine.) |
| `optional_host_permissions` | **[RECOMMENDED]** | MV3 optional host permissions (Firefox 128+). Firefox still tolerates hosts in `optional_permissions` but `optional_host_permissions` is recommended. |

### AMO submission requirements (2025)

| Item | Status | Detail |
|---|---|---|
| `gecko.id` | **[REQUIRED]** | Must declare a unique id for MV3 signing. |
| `data_collection_permissions` | **[REQUIRED]** | **New extensions submitted to AMO from Nov 3, 2025** must declare `browser_specific_settings.gecko.data_collection_permissions` (`required: ["none"]` or specific types, + optional `optional`). |
| Remote code / CSP | **[REQUIRED]** | MV3 forbids remote code; `'unsafe-eval'`, remote `script-src`, and CSP hashes disallowed in `extension_pages`. |
| `browser_style` | **[REQUIRED]** | Must be removed. |
| `strict_min_version` | **[RECOMMENDED]** | ≥ 109 (MV3 minimum); ideally 115/128; ≥ 128 if using `optional_host_permissions`. |

---

## 8. MV3 Compliance — Branch-by-Branch Audit

### 8a. `master` branch — Firefox MV2 (`manifest.firefox.json`)

| Check | Status | Detail |
|---|---|---|
| `manifest_version: 2` | OK (MV2) | Still accepted on AMO. |
| `applications.gecko.id` | OK | `formhistory@yahoo.com`. (Deprecated key name but valid in MV2.) |
| `strict_min_version: 79.0` | OK for MV2 | Could raise to 115+. |
| `browser_action` / `page_action` | OK (MV2 keys) | Would need renaming for MV3. |
| `_execute_browser_action` | OK (MV2) | Would need → `_execute_action` for MV3. |
| `permissions` contains host patterns? | N/A | MV2 uses `matches` in content_scripts; no `host_permissions` needed. |
| CSP | Missing (optional in MV2) | OK; consider adding for defense-in-depth. |

### 8b. `master` branch — Chrome MV3 (`manifest.chrome.json`) — **BROKEN**

| Check | Status | Detail |
|---|---|---|
| `manifest_version: 3` | OK | |
| **`background.service_worker` file exists?** | **FAIL** | References `/background/service-worker.js` — **file does not exist on `master`**. The actual service worker lives on the `manifest3` branch as `background/chrome-service-worker.js`. **The Chrome build from `master` will not load.** |
| `host_permissions` | **MISSING** | Content scripts match `*://*/*` and `file:///*`, but there is **no `host_permissions` key**. Chrome MV3 requires host permissions separately; without them content scripts may not inject on all matched hosts. |
| `action` (was `browser_action`) | OK | Renamed correctly. |
| `_execute_action` / `_execute_browser_action` | OK | Neither present (only named commands). |
| `browser_specific_settings` / `applications` | Absent | OK for Chrome (not required). |
| `content_security_policy` | Missing | Chrome MV3 applies a default strict CSP, so not fatal, but should be declared explicitly. |
| `page_action` | Absent | Chrome MV3 merged into `action`; OK that it's absent. |
| `commands` | OK | Named commands only. |

### 8c. `manifest3` branch — Firefox MV3 (`manifest.firefox.json`) — **RECOMMENDED BASE**

| Check | Status | Detail |
|---|---|---|
| `manifest_version: 3` | OK | |
| `browser_specific_settings.gecko.id` | OK | `formhistory@yahoo.com`. Correct MV3 key. |
| `strict_min_version: 109.0` | OK | MV3 minimum. Consider raising to 115/128. |
| `background.scripts` (event page) | OK | Correct for Firefox MV3 (no `service_worker`). |
| `host_permissions: ["*://*/*", "file:///*"]` | OK | Correctly separated from `permissions`. |
| `permissions` (API only) | OK | `menus, activeTab, tabs, storage, alarms, clipboardWrite`. |
| `action` (was `browser_action`) | OK | Renamed. |
| `page_action` retained | OK | Firefox retains `page_action` in MV3. |
| `_execute_action` | OK | Renamed from `_execute_browser_action`. |
| `content_security_policy.extension_pages: "default-src 'self'"` | OK | Tight and MV3-valid. |
| `browser_style` | Absent | OK (removed). |
| `web_accessible_resources` | Absent | OK (none needed). |
| `gecko_android` | **MISSING** | Add `"gecko_android": {}` for Android support. |
| `data_collection_permissions` | **MISSING** | Required for **new** AMO submissions after **Nov 3, 2025**. Add `"data_collection_permissions": { "required": ["none"], "optional": [] }`. |
| Content scripts dropped `browser-polyfill.min.js` | OK | MV3 Firefox doesn't need it in content scripts (native `browser.*` / `chrome.*`). |

### 8d. `manifest3` branch — Chrome MV3 (`manifest.chrome.json`)

| Check | Status | Detail |
|---|---|---|
| `background.service_worker: "/background/chrome-service-worker.js"` | OK | File **does exist** on this branch. |
| `host_permissions` | OK | Declared. |
| `action` | OK | |
| `page_action` | Absent | OK for Chrome MV3. |
| `content_security_policy` | Missing | Should declare `extension_pages` explicitly. |

---

## 9. Critical: Broken Chrome MV3 Build on `master`

**Confirmed by direct inspection:**

```
$ git show master:manifest.chrome.json | grep service_worker
    "service_worker": "/background/service-worker.js"

$ git ls-tree master background/ | grep -c service-worker
0   # ← file does not exist on master

$ git ls-tree remotes/upstream/manifest3 background/ | grep service-worker
background/chrome-service-worker.js   # ← correct filename on manifest3 branch
```

The build script (`.script/build_extension.py`) `post_process_chrome()` does **not** create or
rename the service-worker file — it only removes the `pageaction` directory. Therefore a Chrome
build produced from `master` ships a `manifest.chrome.json` pointing at a non-existent background
script and the extension will fail to load in Chrome.

**Resolution:** Either (a) ship Chrome builds from the `manifest3` branch (which has the correctly
named `chrome-service-worker.js`), or (b) add `background/service-worker.js` to `master` (or fix
the manifest path). Option (a) is recommended since `manifest3` is the intended MV3 migration.

---

## 10. Prioritized Recommendations

### Immediate (security)
1. **Fix S1 (HIGH):** Escape all interpolated values in `DataTableUtil.formatDetail` (lines 58-71)
   with the existing `esc()` helper, or refactor to `document.createElement`/`textContent`. This
   closes the stored-XSS sink in the privileged popup.
2. **Fix S2 (MEDIUM):** Add `sender.id === browser.runtime.id` validation at the top of all three
   background `onMessage` listeners.
3. **Fix S4 (MEDIUM):** Skip collection for fields with sensitive `autocomplete` attribute values
   (`cc-*`, `current-password`, `new-password`, `off`, `nope`).
4. **Fix S6 (LOW):** Validate/sanitize imported entries before storage.

### Immediate (build/MV3)
5. **Stop shipping Chrome MV3 from `master`** — it is broken (missing `service-worker.js` + missing
   `host_permissions`). Use the `manifest3` branch for Chrome builds.
6. **Promote the `manifest3` branch** to the primary Firefox line; it is a correct Firefox MV3
   manifest. The MV2 `master` can remain as a legacy fallback only while Firefox continues to
   accept MV2.

### Short-term (MV3 finishing touches on `manifest3`)
7. Add `"gecko_android": {}` to `browser_specific_settings` for Firefox-for-Android support.
8. Add `"data_collection_permissions": { "required": ["none"], "optional": [] }` to
   `browser_specific_settings.gecko` (required for new AMO submissions after Nov 3, 2025).
9. Raise `strict_min_version` from `109.0` to `115.0` (or `128.0` if adopting
   `optional_host_permissions`).
10. Add an explicit `content_security_policy.extension_pages` to `manifest.chrome.json` (Firefox
    one already has it).
11. Upgrade `marked` from 3.0.8 to current (v12+); keep the DOMPurify post-processing.
12. Pin and document the `webextension-polyfill` version in `dist_3rd-Party-Libs.md`.

### Defense-in-depth
13. Scope autocomplete lookups (S3) to the same host that saved the entry, or document the accepted
    behavior.
14. Escape visible text in `ellipsis()` (S5).
15. Add a Content-Security-Policy to the MV2 `manifest.firefox.json` as defense-in-depth
    (`default-src 'self'; ...`).

---

## 11. Methodology & Sources

### Methodology
- Forked `stephanmahieu/formhistorycontrol-2` to `franky-agent/formhistorycontrol-2` and cloned with
  all branches (`master`, `manifest3`, `poc_encryption_password`, `safari_support`).
- Static analysis of all first-party JS (background, common, content scripts, popup UI, import/
  export) on `master`, excluding third-party libs (`popup/tableview/lib/*`,
  `common/browser-polyfill.min.js`, `common/purify.js`, `popup/entryview/renderjs/marked.js` &
  `wiky.js`).
- Pattern scanning for `eval`, `new Function`, `innerHTML`, `document.write`, `setTimeout(string)`,
  message-handler validation, prototype-pollution vectors, and XML/import safety.
- Manifest comparison across `master` (MV2 Firefox + MV3 Chrome) and `manifest3` (MV3 both).
- Verified each finding against the actual file/line contents.
- MV3 compliance checked against official Mozilla documentation (2024–2025).

### Sources (Firefox MV3)
- MDN — `background`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background
- MDN — `browser_specific_settings`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings
- MDN — `action`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/action
- MDN — `commands`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/commands
- MDN — `host_permissions`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/host_permissions
- MDN — `content_security_policy`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_security_policy
- MDN — `web_accessible_resources`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/web_accessible_resources
- Extension Workshop — MV3 migration guide: https://extensionworkshop.com/documentation/develop/manifest-v3-migration-guide/
- Mozilla Blog — Firefox MV3 approach (Feb 25, 2025): https://blog.mozilla.org/en/firefox/firefox-manifest-v3-adblockers/
- Firefox 109 release notes: https://www.firefox.com/en-US/firefox/109.0/releasenotes/
- mozilla/addons issue #15890 (data_collection_permissions): https://github.com/mozilla/addons/issues/15890

---

*End of report.*