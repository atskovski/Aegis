'use strict';

const path = require('node:path');

const SUPPORTED_MANIFEST_KEYS = new Set([
  'manifest_version','name','version','description','author','icons','permissions','optional_permissions',
  'host_permissions','optional_host_permissions','content_scripts','web_accessible_resources','browser_specific_settings',
  'applications','action','browser_action','page_action','options_ui','options_page','commands','homepage_url'
]);

const SUPPORTED_PERMISSIONS = new Set([
  'storage','activeTab','tabs','scripting','contextMenus','menus','notifications','clipboardRead','clipboardWrite',
  'unlimitedStorage','webNavigation'
]);

const FIREFOX_ONLY_OR_UNSUPPORTED = new Set([
  'proxy','nativeMessaging','geckoProfiler','pkcs11','experiments','management','privacy','sessions',
  'contextualIdentities','dns','downloads.open','webRequestBlocking','enterprise.deviceAttributes'
]);

function extensionId(manifest = {}) {
  return manifest.browser_specific_settings?.gecko?.id || manifest.applications?.gecko?.id || '';
}

function isSafeRelativeFile(value) {
  if (typeof value !== 'string' || !value || value.length > 500) return false;
  const normalized = path.posix.normalize(value.replace(/\\/g,'/'));
  return !normalized.startsWith('../') && !normalized.startsWith('/') && normalized !== '..';
}

function normalizeContentScripts(manifest = {}) {
  return (Array.isArray(manifest.content_scripts) ? manifest.content_scripts : []).map((entry) => ({
    matches: Array.isArray(entry.matches) ? entry.matches.filter((x) => typeof x === 'string').slice(0,500) : [],
    exclude_matches: Array.isArray(entry.exclude_matches) ? entry.exclude_matches.filter((x) => typeof x === 'string').slice(0,500) : [],
    js: Array.isArray(entry.js) ? entry.js.filter(isSafeRelativeFile).slice(0,100) : [],
    css: Array.isArray(entry.css) ? entry.css.filter(isSafeRelativeFile).slice(0,100) : [],
    run_at: ['document_start','document_end','document_idle'].includes(entry.run_at) ? entry.run_at : 'document_idle',
    all_frames: Boolean(entry.all_frames)
  }));
}

function analyzeManifest(manifest = {}) {
  const errors = [], warnings = [], unsupported = [];
  if (![2,3].includes(Number(manifest.manifest_version))) errors.push('Only WebExtension manifest_version 2 or 3 is accepted.');
  if (!String(manifest.name || '').trim()) errors.push('manifest.name is required.');
  if (!/^\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9.-]+)?$/.test(String(manifest.version || ''))) errors.push('manifest.version is missing or invalid.');

  for (const key of Object.keys(manifest)) {
    if (!SUPPORTED_MANIFEST_KEYS.has(key) && !['background','default_locale','minimum_chrome_version'].includes(key)) warnings.push(`Manifest key "${key}" is not implemented by the Aegis compatibility runtime.`);
  }
  const permissions = [...(Array.isArray(manifest.permissions)?manifest.permissions:[]), ...(Array.isArray(manifest.optional_permissions)?manifest.optional_permissions:[])];
  for (const p of permissions) {
    if (typeof p !== 'string' || p.includes('://') || p === '<all_urls>') continue;
    if (FIREFOX_ONLY_OR_UNSUPPORTED.has(p) || !SUPPORTED_PERMISSIONS.has(p)) unsupported.push(p);
  }
  if (manifest.background) unsupported.push('background');
  if (manifest.experiment_apis) unsupported.push('experiment_apis');

  const scripts = normalizeContentScripts(manifest);
  if (!scripts.length && !manifest.options_ui && !manifest.options_page) warnings.push('No compatible content scripts or options page were found.');

  return {
    valid: errors.length === 0,
    engine: 'aegis-webextensions-compat',
    id: extensionId(manifest),
    name: String(manifest.name || '').slice(0,120),
    version: String(manifest.version || '').slice(0,64),
    manifestVersion: Number(manifest.manifest_version) || 0,
    contentScripts: scripts,
    errors:[...new Set(errors)],
    warnings:[...new Set(warnings)],
    unsupported:[...new Set(unsupported)].sort(),
    fullyCompatible: errors.length === 0 && unsupported.length === 0
  };
}

function installDecision(manifest = {}) {
  const report = analyzeManifest(manifest);
  if (!report.valid) return { allowed:false, mode:'reject', report };
  if (!report.fullyCompatible) return { allowed:false, mode:'requires-gecko', report };
  return { allowed:true, mode:'compat-runtime', report };
}

module.exports = { SUPPORTED_MANIFEST_KEYS, SUPPORTED_PERMISSIONS, FIREFOX_ONLY_OR_UNSUPPORTED, isSafeRelativeFile, normalizeContentScripts, analyzeManifest, installDecision };
