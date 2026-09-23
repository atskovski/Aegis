'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const main = fs.readFileSync(path.join(root, 'src', 'main.js'), 'utf8');
const startHtml = fs.readFileSync(path.join(root, 'src', 'ui', 'start.html'), 'utf8');
const startJs = fs.readFileSync(path.join(root, 'src', 'ui', 'start.js'), 'utf8');
const errorHtml = fs.readFileSync(path.join(root, 'src', 'ui', 'error.html'), 'utf8');
const errorJs = fs.readFileSync(path.join(root, 'src', 'ui', 'error.js'), 'utf8');
const smoke = fs.readFileSync(path.join(root, 'Smoke-Test-Aegis.command'), 'utf8');

test('private start page uses external packaged script instead of a CSP-blocked form action', () => {
  assert.match(startHtml, /id="privateSearch"/);
  assert.match(startHtml, /src="aegis:\/\/app\/start\.js"/);
  assert.doesNotMatch(startHtml, /action="https?:/);
  assert.match(startJs, /event\.preventDefault\(\)/);
  assert.match(startJs, /aegis:\/\/app\/search\?q=/);
  assert.match(main, /u\.pathname === '\/search'/);
});

test('network error page is local-only and offers explicit, never automatic, HTTP recovery', () => {
  assert.match(errorHtml, /Settings → Diagnostics/);
  assert.match(errorJs, /offerHttp/);
  assert.match(errorJs, /aegis:\/\/app\/open-http\?url=/);
  assert.match(main, /u\.pathname === '\/open-http'/);
  assert.match(main, /target\.protocol !== 'http:'/);
});

test('smoke test requires a real external HTTPS navigation', () => {
  assert.match(smoke, /AEGIS_SMOKE_TEST_URL="https:\/\/duckduckgo\.com\/"/);
  assert.match(main, /External website smoke test passed/);
  assert.match(main, /firstTab\.lastNavigationOk !== true/);
});
