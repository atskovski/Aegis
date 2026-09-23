'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('Aegis is configured as a native macOS application bundle', () => {
  assert.equal(pkg.productName, 'Aegis Privacy Browser');
  assert.equal(pkg.build?.appId, 'com.atanasovski.aegis');
  assert.equal(pkg.build?.mac?.icon, 'build/icon.icns');
  assert.equal(pkg.build?.mac?.minimumSystemVersion, '13.0');
  assert.equal(pkg.build?.mac?.hardenedRuntime, true);
  assert.equal(pkg.build?.mac?.notarize, true);
  assert.equal(pkg.build?.mac?.entitlements, 'build/entitlements.mac.plist');
  assert.match(pkg.scripts?.['package:mac:local'] || '', /package-macos-local/);
  assert.match(pkg.scripts?.['install:mac:local'] || '', /install-macos-local/);
  assert.match(pkg.scripts?.['dist:mac'] || '', /electron-builder --mac/);
});

test('macOS app packaging assets and workflows exist', () => {
  for (const rel of [
    'assets/brand/aegis-mark.svg',
    'build/entitlements.mac.plist',
    'scripts/prepare-macos-icon.sh',
    'scripts/package-macos-local.sh',
    'scripts/install-macos-local.sh',
    '.github/workflows/macos-release.yml'
  ]) {
    assert.ok(fs.existsSync(path.join(root, rel)), rel + ' is missing');
  }
  const entitlements = fs.readFileSync(path.join(root, 'build/entitlements.mac.plist'), 'utf8');
  assert.match(entitlements, /com\.apple\.security\.cs\.allow-jit/);
  assert.match(entitlements, /com\.apple\.security\.cs\.allow-unsigned-executable-memory/);
});

test('release workflow requires signing, notarization and Gatekeeper verification', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/macos-release.yml'), 'utf8');
  assert.match(workflow, /MAC_CSC_LINK/);
  assert.match(workflow, /APPLE_APP_SPECIFIC_PASSWORD/);
  assert.match(workflow, /npm run dist:mac/);
  assert.match(workflow, /codesign --verify --deep --strict/);
  assert.match(workflow, /spctl --assess/);
  assert.match(workflow, /stapler validate/);
});
