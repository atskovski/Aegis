'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'src/ui/index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'src/ui/styles.css'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src/ui/app.js'), 'utf8');

test('settings footer is a dedicated grid row and cannot overlay page controls', () => {
  assert.match(css, /\.settings-content\{[^}]*display:grid;[^}]*grid-template-rows:minmax\(0,1fr\) var\(--settings-footer-h\)/s);
  assert.match(css, /\.settings-footer\{[^}]*grid-row:2;[^}]*position:static/s);
  assert.match(css, /\.settings-page\{[^}]*grid-row:1;[^}]*overflow-y:auto/s);
});

test('settings control center has search, cancel, grouping and unsaved state', () => {
  assert.match(html, /id="settingsSearch"/);
  assert.match(html, /id="settingsSearchResults"/);
  assert.match(html, /id="cancelSettings"/);
  assert.match(html, /settings-group-head/);
  assert.match(js, /function renderSettingsSearch\(/);
  assert.match(js, /setSettingsSaveState\(true\)/);
  assert.match(js, /\$\('#cancelSettings'\)\.addEventListener\('click', hidePanels\)/);
});

test('responsive settings layout supports desktop and compact widths', () => {
  assert.match(css, /--settings-nav-w:220px/);
  assert.match(css, /@media\(max-width:820px\)/);
  assert.match(css, /\.settings-layout\{grid-template-columns:1fr;grid-template-rows:auto minmax\(0,1fr\)\}/);
});
