/*
 * Copyright (c) 2023. Stephan Mahieu
 *
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 */

// Chrome MV3 service worker entry point.
// Loads the shared background scripts via importScripts (Chrome SW API).
// Firefox MV3 uses background.scripts (event page) instead and does not
// load this file.
importScripts(
    '/common/browser-polyfill.min.js',
    '/common/DbConst.js',
    '/common/CleanupConst.js',
    '/common/WindowUtil.js',
    '/common/OptionsUtil.js',
    '/common/DateUtil.js',
    '/common/MiscUtil.js',
    '/background/receiveFormData.js',
    '/background/contextmenu.js',
    '/background/applicationIcon.js'
);