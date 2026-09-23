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
