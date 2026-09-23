'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main.js'), 'utf8');
const preload = fs.readFileSync(path.join(__dirname, '..', 'src', 'preload.js'), 'utf8');
const ui = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'app.js'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'styles.css'), 'utf8');

test('native page renderer can be occluded by modal browser UI', () => {
  assert.match(main, /uiLayer\.mode === 'hidden'/);
  assert.match(main, /tab\.view\.setVisible\(false\)/);
  assert.match(ui, /payload = \{ mode: 'hidden', reserveRight: 0 \}/);
  assert.match(preload, /'ui:layer'/);
});

test('floating privacy and library panels reserve native viewport space', () => {
  assert.match(ui, /mode: 'reserve-right'/);
  assert.match(ui, /getBoundingClientRect\(\)\.width \+ 32/);
  assert.match(main, /b\.width - reserved/);
});

test('settings are centered above an Aegis-owned modal surface', () => {
  assert.match(css, /\.settings-shell\{[^}]*left:50%/s);
  assert.match(css, /body\[data-ui-layer="modal"\]::before/);
});

test('notification and modal hierarchy keeps confirmations visible above browser UI', () => {
  assert.match(css, /\.toast\{[^}]*z-index:1200/s);
  assert.match(css, /\.permission-overlay\{[^}]*z-index:920/s);
  assert.match(css, /\.command-overlay\{[^}]*z-index:820/s);
  assert.match(css, /\.settings-shell\{[^}]*z-index:620/s);
  assert.match(css, /\.floating-panel\{[^}]*z-index:520/s);
  assert.match(css, /\.toast\{[^}]*top:12px[^}]*bottom:auto/s);
  assert.match(css, /\.toast\{[^}]*min-height:72px/s);
  assert.match(ui, /function hideToast\(\)/);
  assert.match(ui, /duration:12000/);
});

test('settings and permission surfaces use the enlarged modal treatment', () => {
  assert.match(css, /\.settings-shell\{[^}]*width:min\(1280px/s);
  assert.match(css, /\.settings-shell\{[^}]*top:84px/s);
  assert.match(css, /\.permission-dialog\{[^}]*width:min\(660px/s);
  assert.match(css, /\.command-box\{[^}]*width:min\(720px/s);
});
