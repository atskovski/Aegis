'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'src/ui/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src/ui/app.js'), 'utf8');

test('all literal UI id selectors used by app.js exist in index.html', () => {
  const ids = new Set([...js.matchAll(/\$\('#([A-Za-z0-9_-]+)'\)/g)].map((m) => m[1]));
  const missing = [...ids].filter((id) => !new RegExp(`id=["']${id}["']`).test(html));
  assert.deepEqual(missing, []);
});

test('settings pages and nav targets stay paired', () => {
  const targets = [...html.matchAll(/data-settings-target="([^"]+)"/g)].map((m) => m[1]).sort();
  const pages = [...html.matchAll(/data-settings-page="([^"]+)"/g)].map((m) => m[1]).sort();
  assert.deepEqual(targets, pages);
});


test('production UI includes local library and network diagnostics surfaces', () => {
  assert.match(html, /id="libraryPanel"/);
  assert.match(html, /data-settings-page="diagnostics"/);
  assert.match(html, /id="runNetworkTest"/);
  assert.match(html, /id="compatibilityToggle"/);
  assert.match(html, /id="bookmarkBtn"/);
});
