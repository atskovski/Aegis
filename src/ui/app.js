'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let state = { activeId: null, tabs: [], settings: {}, engine: {}, searchEngines: {}, bookmarks: [], downloads: [], network: {}, securitySuite: null, extensions: [], privacyControls: [] };
let draftSettings = null;
let toastTimer;
let commandIndex = 0;
let commandMatches = [];
let permissionQueue = [];
let activePermissionPrompt = null;
let lastUiLayerKey = '';
let currentSettingsPage = 'privacy';
let sentinelMode = 'simple';

const PROFILE_VALUES = {
  standard: { privacyLevel: 'standard', letterbox: false, blockTrackers: true, blockAds: true, blockSocialTrackers: true, heuristicTrackingProtection: false, blockFingerprintingScripts: true, cosmeticFiltering: true, privacyApiGuard: false, blockTrackingBeacons: true, blockThirdPartyCookies: true, stripTrackingParams: true, stripCrossSiteReferrers: true, disableServiceWorkers: false },
  strict: { privacyLevel: 'strict', letterbox: true, blockTrackers: true, blockAds: true, blockSocialTrackers: true, heuristicTrackingProtection: true, blockFingerprintingScripts: true, cosmeticFiltering: true, privacyApiGuard: true, blockTrackingBeacons: true, blockThirdPartyCookies: true, stripTrackingParams: true, stripCrossSiteReferrers: true, disableServiceWorkers: false },
  maximum: { privacyLevel: 'maximum', letterbox: true, blockTrackers: true, blockAds: true, blockSocialTrackers: true, heuristicTrackingProtection: true, blockFingerprintingScripts: true, cosmeticFiltering: true, privacyApiGuard: true, blockTrackingBeacons: true, blockThirdPartyCookies: true, stripTrackingParams: true, stripCrossSiteReferrers: true, disableServiceWorkers: true }
};

const COMMANDS = [
  { name: 'New private tab', hint: '⌘T', run: () => window.aegis.send('tab:new') },
  { name: 'New identity', hint: '⌘⇧N', run: () => window.aegis.send('identity:new') },
  { name: 'Open Site Privacy Inspector', hint: 'Sentinel', run: () => showPanel('privacyPanel') },
  { name: 'Open settings', hint: '⌘,', run: () => openSettings() },
  { name: 'Clear current tab data', hint: 'Storage + cache', run: () => window.aegis.send('data:clear-tab') },
  { name: 'Duplicate tab in a new identity', hint: 'Isolated', run: () => window.aegis.send('tab:duplicate') },
  { name: 'Toggle JavaScript for this tab', hint: 'Scriptless', run: () => { const t = activeTab(); if (t) window.aegis.send('javascript:set', !t.javascriptEnabled); } },
  { name: 'Focus address bar', hint: '⌘L', run: () => { $('#address').focus(); $('#address').select(); } },
  { name: 'Bookmark current page', hint: '⌘D', run: () => window.aegis.send('bookmark:toggle') },
  { name: 'Open local library', hint: 'Bookmarks + downloads', run: () => showPanel('libraryPanel') },
  { name: 'Run connectivity test', hint: 'Diagnostics', run: () => { openSettings('diagnostics'); runNetworkTest(); } },
  { name: 'Run full security verification', hint: 'Security Suite', run: () => { openSettings('diagnostics'); runSecuritySuite(); } },
  { name: 'Toggle compatibility mode', hint: 'Current tab', run: () => { const t = activeTab(); if (t) window.aegis.send('compatibility:set', !t.compatibilityMode); } },
  { name: 'Harden current site', hint: 'Sentinel', run: () => window.aegis.send('site:harden') }
];

function deepClone(value) { return JSON.parse(JSON.stringify(value || {})); }
function activeTab() { return state.tabs.find((t) => t.id === state.activeId); }
function isInternal(url) { return String(url || '').startsWith('aegis://'); }
function displayUrl(url) { return isInternal(url) ? '' : String(url || ''); }
function titleCase(value) { return String(value || '').replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()); }

function currentSitePermission(key) {
  const tab = activeTab();
  if (!tab?.origin) return 'block';
  return state.settings.sitePermissions?.[tab.origin]?.[key] || 'default';
}

function privacyScore(tab) {
  if (!tab) return 100;
  const s = state.settings || {};
  let score = 100;
  if (!tab.shieldsEnabled || !s.blockTrackers) score -= 22;
  if (!s.blockThirdPartyCookies) score -= 14;
  if (!s.stripTrackingParams) score -= 7;
  if (!s.stripCrossSiteReferrers) score -= 7;
  if (tab.allowHttp) score -= 25;
  if (tab.compatibilityMode) score -= 10;
  if (s.privacyLevel === 'standard') score -= 8;
  if (s.privacyLevel !== 'standard' && !s.letterbox) score -= 5;
  if (!s.globalPrivacyControl) score -= 2;
  return Math.max(20, score);
}

function scoreLabel(score) {
  if (score >= 95) return 'Hardened';
  if (score >= 85) return 'Strong';
  if (score >= 70) return 'Reduced';
  return 'Needs attention';
}

function securityScore(tab) {
  if (!tab) return 100;
  let score = 100;
  if (String(tab.url || '').startsWith('http://')) score -= 42;
  if (tab.allowHttp) score -= 20;
  if (tab.lastError) score -= 8;
  score -= Math.min(30, Math.round(Number(tab.safety?.risk || 0) * 0.35));
  if (tab.networkRoute?.ok === false) score -= 12;
  return Math.max(10, Math.min(100, score));
}

function protectionCount(tab) {
  const st = tab?.stats || {};
  return [
    st.blockedTrackers, st.thirdPartyCookiesBlocked, st.blockedPermissions,
    st.trackingParamsRemoved, st.blockedPopups, st.blockedDownloads,
    st.httpsUpgrades, st.etagProtections, st.cdnIsolations, st.sponsorSegmentsSkipped
  ].reduce((sum, value) => sum + Math.max(0, Number(value) || 0), 0);
}

function blockedTotal(tab) {
  const st = tab?.stats || {};
  return [st.blockedTrackers, st.thirdPartyCookiesBlocked, st.blockedPermissions, st.blockedPopups, st.blockedDownloads]
    .reduce((sum, value) => sum + Math.max(0, Number(value) || 0), 0);
}

function exposureScore(tab) {
  if (!tab) return 100;
  const intel = tab.siteIntelligence || {};
  const totals = intel.totals || {};
  const network = intel.network || {};
  let score = 100;
  score -= Math.min(30, Number(totals.allowedSensitiveCategories || 0) * 12);
  score -= Math.min(15, Math.max(0, Number(totals.sensitiveCategories || 0) - Number(totals.allowedSensitiveCategories || 0)) * 3);
  score -= Math.min(18, Number(totals.fingerprintCategories || 0) * 2);
  score -= Math.min(14, Number(network.allowedUnique || 0));
  score -= Math.min(8, Number(totals.formCategories || 0));
  return Math.max(20, Math.round(score));
}

function combinedPosture(tab) {
  const p = privacyScore(tab), s = securityScore(tab), e = exposureScore(tab);
  return Math.round(p * 0.46 + s * 0.34 + e * 0.20);
}

const SIGNAL_ICONS = {
  camera:'●', microphone:'◖', geolocation:'⌖', displayCapture:'▣', clipboardRead:'▤', notifications:'◌', credentials:'◇',
  bluetooth:'⌁', usb:'⌯', serial:'⇄', hid:'⌘', midi:'♪', mediaDevices:'◎', cookies:'◍', localStorage:'▰', indexedDB:'▦',
  hardware:'⌘', screen:'▣', canvas:'◫', webgl:'◇', audio:'◒', fonts:'Aa', highEntropyUA:'≋', speechVoices:'◔',
  webrtc:'⌁', battery:'◑', networkInfo:'⇄', timezone:'◷', languages:'Aa', gamepad:'✣', formEmail:'@', formPassword:'••', formPayment:'$', formAddress:'⌂', formPhone:'☎', fileUpload:'⇧'
};

function signalStatus(signal) {
  if ((signal.blocked || 0) > 0 && (signal.allowed || 0) === 0) return { text: 'Blocked', tone: 'blocked' };
  if ((signal.allowed || 0) > 0) return { text: 'Allowed', tone: 'allowed' };
  if (signal.group === 'fingerprint') return { text: 'Protected', tone: 'protected' };
  if (signal.group === 'storage') return { text: 'Observed', tone: 'observed' };
  if (signal.group === 'form') return { text: 'Detected', tone: 'observed' };
  return { text: 'Requested', tone: 'requested' };
}

function renderSiteIntelligence(tab) {
  const intel = tab?.siteIntelligence || { signals: [], totals: {} };
  const signals = intel.signals || [];
  const total = Number(intel.totals?.categories || signals.length || 0);
  $('#signalCount').textContent = total;
  const list = $('#dataAccessList');
  if (!list) return;
  list.replaceChildren();
  if (!state.settings.siteIntelligence) {
    const empty = document.createElement('div'); empty.className = 'signal-empty';
    const b = document.createElement('b'); b.textContent = 'Site Privacy Intelligence is off';
    const span = document.createElement('span'); span.textContent = 'Enable it in Privacy settings to see what pages try to access.';
    empty.append(b, span); list.append(empty); return;
  }
  if (!signals.length) {
    const empty = document.createElement('div'); empty.className = 'signal-empty';
    const b = document.createElement('b'); b.textContent = 'No sensitive access observed';
    const span = document.createElement('span'); span.textContent = 'Aegis will show permission requests, storage access, and fingerprint surfaces as this page uses them.';
    empty.append(b, span); list.append(empty); return;
  }
  signals.slice(0, 14).forEach((signal) => {
    const row = document.createElement('div'); row.className = `signal-row signal-${signal.group || 'other'}`;
    const icon = document.createElement('span'); icon.className = 'signal-icon'; icon.textContent = SIGNAL_ICONS[signal.category] || '•';
    const copy = document.createElement('span'); copy.className = 'signal-copy';
    const title = document.createElement('b'); title.textContent = signal.label || titleCase(signal.category);
    const detail = document.createElement('small');
    const attempts = Math.max(1, Number(signal.attempts || 0));
    const parts = [`${attempts} ${attempts === 1 ? 'observation' : 'observations'}`];
    if (signal.lastDetail) parts.push(signal.lastDetail);
    detail.textContent = parts.join(' · ');
    copy.append(title, detail);
    const status = signalStatus(signal); const badge = document.createElement('span'); badge.className = `signal-status ${status.tone}`; badge.textContent = status.text;
    row.append(icon, copy, badge); list.append(row);
  });
}

function renderProtectionLayers(tab) {
  const layers = $('#protectionLayers'); if (!layers) return;
  const s = state.settings || {};
  const items = [
    ['HTTPS-first', !tab?.allowHttp && !String(tab?.url || '').startsWith('http://')],
    ['Ephemeral tab', true],
    ['Tracker shield', Boolean(tab?.shieldsEnabled && s.blockTrackers)],
    ['3rd-party cookies', Boolean(s.blockThirdPartyCookies && !tab?.compatibilityMode)],
    ['Fingerprint defense', Boolean(tab?.fingerprintReady && s.privacyLevel !== 'standard')],
    ['WebRTC leak guard', true],
    ['GPC', Boolean(s.globalPrivacyControl)],
    ['Auto-delete', Boolean(s.cookieAutoDelete)]
  ];
  layers.replaceChildren(...items.map(([label, enabled]) => {
    const el = document.createElement('span'); el.className = enabled ? 'layer-chip active' : 'layer-chip reduced';
    const dot = document.createElement('i'); const text = document.createElement('b'); text.textContent = label; el.append(dot, text); return el;
  }));
}

function renderNetworkIntelligence(tab) {
  const net = tab?.siteIntelligence?.network || { uniqueThirdParties: 0, blockedUnique: 0, allowedUnique: 0, hosts: [] };
  $('#thirdPartyUnique').textContent = Number(net.uniqueThirdParties || 0);
  $('#thirdPartyBlockedUnique').textContent = Number(net.blockedUnique || 0);
  $('#thirdPartyAllowedUnique').textContent = Number(net.allowedUnique || 0);
  const list = $('#thirdPartyList'); if (!list) return;
  list.replaceChildren();
  const hosts = net.hosts || [];
  if (!hosts.length) {
    const empty = document.createElement('div'); empty.className = 'signal-empty';
    const b = document.createElement('b'); b.textContent = 'No third-party connections yet';
    const span = document.createElement('span'); span.textContent = 'Domains contacted by this page will appear here.';
    empty.append(b, span); list.append(empty); return;
  }
  hosts.slice(0, 12).forEach((host) => {
    const row = document.createElement('div'); row.className = 'third-party-row';
    const copy = document.createElement('span'); copy.className = 'third-party-copy';
    const name = document.createElement('b'); name.textContent = host.host;
    const detail = document.createElement('small'); detail.textContent = `${titleCase(host.category || 'third-party')} · ${host.requests || 0} request${host.requests === 1 ? '' : 's'} · ${titleCase(host.resourceType || 'other')}`;
    copy.append(name, detail);
    const badge = document.createElement('span');
    const fullyBlocked = (host.blocked || 0) > 0 && (host.allowed || 0) === 0;
    badge.className = `signal-status ${fullyBlocked ? 'blocked' : ((host.blocked || 0) > 0 ? 'protected' : 'observed')}`;
    badge.textContent = fullyBlocked ? 'Blocked' : ((host.blocked || 0) > 0 ? `${host.blocked} blocked` : 'Contacted');
    row.append(copy, badge); list.append(row);
  });
}

function renderIdentitySurfaces(tab) {
  const box = $('#identitySurfaceList'); if (!box) return;
  const s = state.settings || {};
  const surfaces = [
    ['Timezone', s.privacyLevel !== 'standard' ? 'UTC standardized' : 'System timezone', s.privacyLevel !== 'standard'],
    ['Language', s.privacyLevel !== 'standard' ? 'en-US standardized' : 'Reduced locale', true],
    ['Screen size', s.letterbox && s.privacyLevel !== 'standard' ? 'Letterboxed' : 'Native viewport', Boolean(s.letterbox && s.privacyLevel !== 'standard')],
    ['Hardware', s.privacyLevel !== 'standard' ? 'Normalized profile' : 'Reduced profile', s.privacyLevel !== 'standard'],
    ['Canvas / GPU', tab?.fingerprintReady && s.privacyLevel !== 'standard' ? 'Perturbed / normalized' : 'Standard browser behavior', Boolean(tab?.fingerprintReady && s.privacyLevel !== 'standard')],
    ['WebRTC', 'Non-proxied UDP blocked', true],
    ['Storage', 'Ephemeral tab partition', true],
    ['Client hints', s.privacyLevel !== 'standard' ? 'High-entropy hints removed' : 'Reduced', s.privacyLevel !== 'standard']
  ];
  box.replaceChildren(...surfaces.map(([name, detail, protectedState]) => {
    const row = document.createElement('div'); row.className = 'identity-surface-row';
    const copy = document.createElement('span'); const b = document.createElement('b'); b.textContent = name; const small = document.createElement('small'); small.textContent = detail; copy.append(b, small);
    const badge = document.createElement('span'); badge.className = `identity-state ${protectedState ? 'protected' : 'visible'}`; badge.textContent = protectedState ? 'Protected' : 'Visible';
    row.append(copy, badge); return row;
  }));
  $('#exposureScore').textContent = exposureScore(tab);
}

function renderPrivacyTimeline(tab) {
  const timeline = $('#privacyTimeline'); if (!timeline) return;
  const recent = tab?.siteIntelligence?.recent || [];
  $('#timelineCount').textContent = recent.length;
  timeline.replaceChildren();
  if (!recent.length) {
    const empty = document.createElement('div'); empty.className = 'signal-empty';
    const b = document.createElement('b'); b.textContent = 'No privacy events yet';
    const span = document.createElement('span'); span.textContent = 'Recent sensitive API and network events will appear here.';
    empty.append(b, span); timeline.append(empty); return;
  }
  recent.slice(0, 10).forEach((event) => {
    const row = document.createElement('div'); row.className = 'timeline-row';
    const dot = document.createElement('i'); dot.className = `timeline-dot ${event.action || 'observed'}`;
    const copy = document.createElement('span');
    const b = document.createElement('b'); b.textContent = event.kind === 'network' ? event.label : (event.label || titleCase(event.category));
    const small = document.createElement('small');
    const t = event.at ? new Date(event.at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' }) : '';
    small.textContent = [titleCase(event.action || 'observed'), event.detail, t].filter(Boolean).join(' · ');
    copy.append(b, small); row.append(dot, copy); timeline.append(row);
  });
}

function applyAppearance(source = state.settings) {
  const a = source?.appearance || {};
  document.body.dataset.theme = a.theme || 'nebula';
  document.body.dataset.accent = a.accent || 'cyan';
  document.body.dataset.density = a.density || 'comfortable';
  document.body.dataset.reduceMotion = String(Boolean(a.reduceMotion));
  document.body.dataset.textScale = a.textScale || 'large';
}

function renderTabs() {
  const nodes = state.tabs.map((tab) => {
    const el = document.createElement('div');
    el.className = 'tab' + (tab.id === state.activeId ? ' active' : '');
    el.dataset.id = tab.id;
    const dot = document.createElement('span'); dot.className = 'dot';
    const label = document.createElement('span'); label.className = 'label'; label.textContent = tab.title || 'New Private Tab';
    const x = document.createElement('button'); x.className = 'x'; x.textContent = '×'; x.title = 'Close tab'; x.setAttribute('aria-label', 'Close tab');
    x.addEventListener('click', (e) => { e.stopPropagation(); window.aegis.send('tab:close', tab.id); });
    el.addEventListener('click', () => window.aegis.send('tab:activate', tab.id));
    el.append(dot, label, x);
    return el;
  });
  $('#tabs').replaceChildren(...nodes);
}


function applySentinelMode(mode = 'simple') {
  sentinelMode = mode === 'advanced' ? 'advanced' : 'simple';
  const panel = $('#privacyPanel');
  if (panel) panel.dataset.sentinelMode = sentinelMode;
  $('#sentinelSimple')?.classList.toggle('active', sentinelMode === 'simple');
  $('#sentinelAdvanced')?.classList.toggle('active', sentinelMode === 'advanced');
  $('.sentinel-advanced-only').forEach((el) => el.classList.toggle('hidden-by-mode', sentinelMode !== 'advanced'));
}

function renderSentinelSummary(tab) {
  if (!tab) return;
  const stats = tab.stats || {};
  const suite = state.securitySuite || {};
  const ip = suite.publicIp?.ip || 'Not verified';
  $('#sentinelIp').textContent = ip;
  const route = suite.route?.mode || tab.networkRoute?.mode || state.settings.proxy?.mode || 'system';
  const provider = suite.publicIp?.provider ? ' · ' + suite.publicIp.provider : '';
  const routeWarnings = suite.route?.warnings?.length ? ' · warning: ' + suite.route.warnings[0] : '';
  $('#sentinelRoute').textContent = titleCase(route) + ' route' + provider + routeWarnings;
  $('#sentinelTrackers').textContent = stats.blockedTrackers || 0;
  $('#sentinelThirdParty').textContent = tab.siteIntelligence?.network?.uniqueThirdParties || stats.thirdPartyRequests || 0;
  $('#sentinelFingerprint').textContent = tab.siteIntelligence?.totals?.fingerprintCategories || 0;
  $('#sentinelPermissions').textContent = stats.blockedPermissions || 0;

  const degraded = (state.privacyControls || []).filter((x) => x.enabled && x.status === 'degraded').length;
  const allowed = Number(tab.siteIntelligence?.network?.allowedUnique || 0);
  let text = 'Sentinel is watching this tab locally.';
  if (!tab.fingerprintReady && state.settings.privacyLevel !== 'standard') text = 'Fingerprint defenses are not fully confirmed for this tab. Run Security Suite.';
  else if (degraded) text = degraded + ' enabled privacy control' + (degraded === 1 ? ' is' : 's are') + ' not yet confirmed as enforced.';
  else if (allowed) text = allowed + ' third-party domain' + (allowed === 1 ? ' was' : 's were') + ' contacted; open Advanced for details.';
  else if ((stats.blockedTrackers || 0) > 0) text = 'Aegis blocked ' + stats.blockedTrackers + ' tracker request' + (stats.blockedTrackers === 1 ? '' : 's') + ' on this tab.';
  $('#sentinelHeadline').textContent = text;
}

function renderControlAssurance() {
  const box = $('#privacyControlResults');
  if (!box) return;
  const controls = state.privacyControls || [];
  box.replaceChildren();
  if (!controls.length) {
    const empty = document.createElement('div'); empty.className = 'suite-empty';
    empty.innerHTML = '<b>No control evidence available</b><span>Open a web tab to inspect runtime enforcement.</span>';
    box.append(empty); return;
  }
  controls.forEach((item) => {
    const row = document.createElement('div'); row.className = 'assurance-row assurance-' + item.status;
    const badge = document.createElement('span'); badge.className = 'assurance-status ' + item.status;
    badge.textContent = item.status === 'enforced' ? 'ENFORCED' : (item.status === 'degraded' ? 'DEGRADED' : 'DISABLED');
    const copy = document.createElement('span'); copy.className = 'assurance-copy';
    const title = document.createElement('b'); title.textContent = item.label;
    const detail = document.createElement('small'); detail.textContent = item.evidence;
    copy.append(title, detail);
    const layer = document.createElement('em'); layer.textContent = titleCase(item.layer || 'runtime');
    row.append(badge, copy, layer); box.append(row);
  });
}

function renderAddons() {
  const list = $('#addonList');
  if (!list) return;
  const addons = state.extensions || [];
  list.replaceChildren();
  if (!addons.length) {
    const empty = document.createElement('div'); empty.className = 'suite-empty';
    const b = document.createElement('b'); b.textContent = 'No add-ons installed';
    const s = document.createElement('span'); s.textContent = 'Install a Firefox WebExtension .xpi to review its permissions and Aegis compatibility.';
    empty.append(b, s); list.append(empty); return;
  }
  addons.forEach((addon) => {
    const card = document.createElement('div'); card.className = 'addon-card';
    const head = document.createElement('div'); head.className = 'addon-head';
    const copy = document.createElement('span');
    const name = document.createElement('b'); name.textContent = addon.name + ' ' + addon.version;
    const score = document.createElement('small'); score.textContent = 'Aegis compatibility ' + Number(addon.compatibility?.score || 0) + '% · ' + (addon.enabled ? 'Enabled' : 'Disabled');
    copy.append(name, score);
    const toggle = document.createElement('button'); toggle.className = addon.enabled ? 'secondary addon-toggle active' : 'secondary addon-toggle'; toggle.textContent = addon.enabled ? 'Disable' : 'Enable';
    toggle.addEventListener('click', async () => {
      const result = await window.aegis.invoke('extensions:set-enabled', { id:addon.id, enabled:!addon.enabled });
      if (!result?.ok) showToast({message:'Could not update add-on: ' + (result?.error || 'unknown error'),tone:'danger'});
    });
    head.append(copy, toggle); card.append(head);

    const unsupported = addon.compatibility?.unsupported || [];
    const perms = addon.risk || [];
    const details = document.createElement('div'); details.className = 'addon-details';
    const api = document.createElement('span'); api.innerHTML = '<b>Unsupported APIs</b><small></small>';
    api.querySelector('small').textContent = unsupported.length ? unsupported.map((x) => x.api).join(', ') : 'None detected';
    const risk = document.createElement('span'); risk.innerHTML = '<b>Permissions</b><small></small>';
    risk.querySelector('small').textContent = perms.length ? perms.map((x) => x.permission + ' (' + x.level + ')').join(', ') : 'No declared permissions';
    details.append(api, risk); card.append(details);

    const foot = document.createElement('div'); foot.className = 'addon-foot';
    const remove = document.createElement('button'); remove.className = 'text-btn danger-text'; remove.textContent = 'Remove';
    remove.addEventListener('click', async () => {
      if (!confirm('Remove ' + addon.name + ' and its local extension data?')) return;
      const result = await window.aegis.invoke('extensions:remove', addon.id);
      if (!result?.ok) showToast({message:'Could not remove add-on.',tone:'danger'});
    });
    foot.append(remove); card.append(foot); list.append(card);
  });
}

function renderPrivacyPanel(tab) {
  if (!tab) return;
  const score = privacyScore(tab);
  const stats = tab.stats || {};
  $('#blockedCount').textContent = (stats.blockedTrackers || 0) + (stats.thirdPartyCookiesBlocked || 0);
  $('#mTrackers').textContent = stats.blockedTrackers || 0;
  $('#mCookies').textContent = stats.thirdPartyCookiesBlocked || 0;
  $('#mPerms').textContent = stats.blockedPermissions || 0;
  $('#mClean').textContent = stats.trackingParamsRemoved || 0;
  $('#mThirdParty').textContent = stats.thirdPartyRequests || 0;
  $('#mFingerprint').textContent = tab.siteIntelligence?.totals?.fingerprintCategories || 0;
  $('#scoreValue').textContent = score;
  $('#scoreLabel').textContent = scoreLabel(score);
  $('.score-ring').style.setProperty('--score', String(score));
  $('#securityScore').textContent = securityScore(tab);
  $('#privacyPosture').textContent = score;
  $('#protectionCount').textContent = protectionCount(tab);
  $('.score-card').classList.toggle('hidden', state.settings.appearance?.showPrivacyScore === false);
  renderSiteIntelligence(tab);
  renderNetworkIntelligence(tab);
  renderIdentitySurfaces(tab);
  renderPrivacyTimeline(tab);
  renderProtectionLayers(tab);
  renderSentinelSummary(tab);
  applySentinelMode(sentinelMode);
  $('#shieldToggle').checked = Boolean(tab.shieldsEnabled);
  $('#jsToggle').checked = Boolean(tab.javascriptEnabled);
  $('#httpToggle').checked = Boolean(tab.allowHttp);
  $('#compatibilityToggle').checked = Boolean(tab.compatibilityMode);
  $('#fpMode').textContent = titleCase(state.settings.privacyLevel || 'strict');
  $('#safetyMode').textContent = tab.safety?.warnings?.length ? `${tab.safety.warnings.length} warning${tab.safety.warnings.length === 1 ? '' : 's'}` : 'No warnings';
  $('#connectionState').textContent = tab.url?.startsWith('https://') ? 'HTTPS encrypted' : (isInternal(tab.url) ? 'Aegis internal' : (tab.url?.startsWith('http://') ? 'HTTP insecure' : 'Not established'));
  $('#routeState').textContent = titleCase(tab.networkRoute?.mode || state.settings.proxy?.mode || 'system');
  $('#siteLabel').textContent = tab.origin ? new URL(tab.origin).hostname : 'Internal Aegis page';

  const internal = !tab.origin;
  $$('#sitePermissionGrid select').forEach((select) => {
    select.disabled = internal;
    select.value = currentSitePermission(select.dataset.sitePermission);
  });
  $('#resetSitePermissions').disabled = internal;
  $('#sitePermissionHint').textContent = internal
    ? 'Site permissions apply to HTTP and HTTPS origins, not internal Aegis pages.'
    : `Exceptions here apply only to ${new URL(tab.origin).hostname}.`;

  const recent = stats.recentBlocked || [];
  const box = $('#recentBlocked');
  box.replaceChildren();
  if (!recent.length) {
    const chip = document.createElement('span'); chip.className = 'muted'; chip.textContent = 'Nothing blocked yet'; box.append(chip);
  } else {
    recent.forEach((host) => { const chip = document.createElement('span'); chip.textContent = host; box.append(chip); });
  }
}

function renderChrome(tab) {
  if (!tab) return;
  if (document.activeElement !== $('#address')) $('#address').value = displayUrl(tab.url);
  $('#back').disabled = !tab.canGoBack;
  $('#forward').disabled = !tab.canGoForward;
  $('#reload').textContent = tab.loading ? '×' : '↻';
  $('#securityIcon').textContent = tab.url?.startsWith('https://') ? '◆' : (isInternal(tab.url) ? '◈' : '◇');
  $('#securityIcon').style.color = tab.safety?.risk >= 50 || tab.url?.startsWith('http://') ? 'var(--danger)' : '';
  $('#securityIcon').title = tab.safety?.warnings?.length ? tab.safety.warnings.join(' · ') : (tab.url?.startsWith('https://') ? 'Secure connection' : 'Connection status');
  $('#bookmarkBtn').textContent = tab.bookmarked ? '★' : '☆';
  $('#bookmarkBtn').classList.toggle('active', Boolean(tab.bookmarked));
  $('#bookmarkBtn').disabled = !/^https?:\/\//.test(tab.url || '');
  const posture = combinedPosture(tab);
  $('#beaconScore').textContent = posture;
  $('#beaconCount').textContent = blockedTotal(tab);
  $('#privacyBeacon').dataset.posture = posture >= 90 ? 'strong' : (posture >= 75 ? 'medium' : 'weak');
  $('#privacyBeacon').title = `Sentinel ${posture}/100 · ${blockedTotal(tab)} blocked · exposure ${exposureScore(tab)}/100 · ${protectionCount(tab)} privacy actions`;
}

function renderEngineInfo() {
  const e = state.engine || {};
  $('#appVersion').textContent = `v${e.appVersion || '0.9.0'}`;
  $('#electronVersion').textContent = e.electron || '—';
  $('#chromiumVersion').textContent = e.chromium || '—';
  $('#runtimeVersion').textContent = e.node ? `Node ${e.node}` : '—';
  $('#archVersion').textContent = e.platform && e.arch ? `${e.platform} / ${e.arch}` : '—';
}


function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function renderLibrary() {
  const bookmarks = state.bookmarks || [];
  const downloads = state.downloads || [];
  $('#bookmarkCount').textContent = bookmarks.length;
  const bList = $('#bookmarkList'); bList.replaceChildren();
  if (!bookmarks.length) {
    const empty = document.createElement('div'); empty.className = 'library-empty'; empty.textContent = 'No bookmarks yet. Use ⌘D or the star in the address bar.'; bList.append(empty);
  } else bookmarks.forEach((item) => {
    const row = document.createElement('div'); row.className = 'library-row';
    const open = document.createElement('button'); open.className = 'library-open';
    const meta = document.createElement('span'); meta.className = 'library-row-copy';
    const title = document.createElement('b'); title.textContent = item.title || item.url;
    const url = document.createElement('small'); url.textContent = item.url;
    meta.append(title, url); open.append(meta);
    open.addEventListener('click', () => { window.aegis.send('bookmark:open', item.url); hidePanels(); });
    const remove = document.createElement('button'); remove.className = 'library-remove'; remove.textContent = '×'; remove.title = 'Remove bookmark';
    remove.addEventListener('click', () => window.aegis.send('bookmark:remove', item.id));
    row.append(open, remove); bList.append(row);
  });

  const dList = $('#downloadList'); dList.replaceChildren();
  if (!downloads.length) {
    const empty = document.createElement('div'); empty.className = 'library-empty'; empty.textContent = 'No downloads in this Aegis session.'; dList.append(empty);
  } else downloads.forEach((item) => {
    const row = document.createElement('div'); row.className = 'download-row';
    const copy = document.createElement('span'); copy.className = 'library-row-copy';
    const title = document.createElement('b'); title.textContent = item.filename || 'Download';
    const detail = document.createElement('small');
    const progress = item.totalBytes ? `${Math.min(100, Math.round((item.receivedBytes / item.totalBytes) * 100))}% · ` : '';
    detail.textContent = `${progress}${titleCase(item.state || 'starting')} · ${formatBytes(item.receivedBytes || item.totalBytes || 0)}`;
    copy.append(title, detail); row.append(copy);
    if (item.state === 'completed') {
      const reveal = document.createElement('button'); reveal.className = 'text-btn'; reveal.textContent = 'Show';
      reveal.addEventListener('click', () => window.aegis.send('download:reveal', item.id)); row.append(reveal);
    } else if (item.state === 'starting' || item.state === 'progressing') {
      const cancel = document.createElement('button'); cancel.className = 'text-btn'; cancel.textContent = 'Cancel';
      cancel.addEventListener('click', () => window.aegis.send('download:cancel', item.id)); row.append(cancel);
    }
    dList.append(row);
  });
}

function renderNetworkDiagnostics() {
  const r = state.network?.lastTest;
  $('#diagProxy').textContent = r?.proxy || titleCase(state.network?.proxyMode || state.settings?.proxy?.mode || 'system');
  $('#diagDns').textContent = r?.dns || '—';
  $('#diagHttps').textContent = r?.https || '—';
  const t = activeTab();
  $('#diagRenderer').textContent = t?.lastError ? `Error ${t.lastError.code || ''}`.trim() : (t ? (t.loading ? 'Loading' : (t.url ? 'Ready' : 'Starting')) : 'No tab');
  $('#diagElapsed').textContent = r?.elapsedMs ? `${r.elapsedMs} ms` : '—';
  $('#networkStatusTitle').textContent = r ? (r.ok ? 'Connection healthy' : 'Connection problem detected') : 'Not tested';
  $('#networkStatusText').textContent = r ? `Proxy: ${r.proxy || 'unknown'} · DNS: ${r.dns || 'unknown'} · HTTPS: ${r.https || 'unknown'}` : 'Run a connectivity test to verify system proxy routing, DNS and HTTPS.';
  $('#networkOrb').dataset.ok = r ? String(Boolean(r.ok)) : 'unknown';
}

function renderSecuritySuite() {
  const suite = state.securitySuite;
  const ip = $('#publicIpValue');
  const provider = $('#publicIpProvider');
  const summary = $('#suiteSummary');
  const tested = $('#suiteTestedAt');
  const list = $('#securitySuiteResults');
  if (!ip || !provider || !summary || !tested || !list) return;

  ip.textContent = suite?.publicIp?.ip || 'Not tested';
  provider.textContent = suite?.publicIp?.provider ? `Observed through ${suite.publicIp.provider}` : 'Runs only when you request verification';
  const counts = suite?.summary || { pass: 0, warning: 0, info: 0, fail: 0, 'not-tested': 0, total: 0 };
  summary.textContent = suite ? `${counts.pass || 0} pass · ${counts.warning || 0} warning · ${counts.fail || 0} fail · ${counts.info || 0} info · ${counts['not-tested'] || 0} not tested` : 'No verification run yet';
  tested.textContent = suite?.testedAt ? new Date(suite.testedAt).toLocaleString() : '—';

  list.replaceChildren();
  const checks = suite?.checks || [];
  if (!checks.length) {
    const empty = document.createElement('div'); empty.className = 'suite-empty';
    const b = document.createElement('b'); b.textContent = 'Verification has not been run';
    const span = document.createElement('span'); span.textContent = 'Run the Security Suite to test isolation, routed IP, DNS/HTTPS reachability, renderer policy, permission firewall, WebRTC leak guard, tracker defenses, and HTTPS-first posture.';
    empty.append(b, span); list.append(empty); return;
  }
  checks.forEach((check) => {
    const row = document.createElement('div'); row.className = `suite-row suite-${check.status || 'not-tested'}`;
    const badge = document.createElement('span'); badge.className = `suite-status ${check.status || 'not-tested'}`;
    badge.textContent = ({ pass:'PASS', fail:'FAIL', warning:'WARNING', info:'INFO', 'not-tested':'NOT TESTED' })[check.status] || 'NOT TESTED';
    const copy = document.createElement('span'); copy.className = 'suite-copy';
    const title = document.createElement('b'); title.textContent = check.label || check.id || 'Protection check';
    const detail = document.createElement('small'); detail.textContent = check.evidence || 'No evidence returned.';
    copy.append(title, detail);
    const scope = document.createElement('em'); scope.textContent = titleCase(check.scope || 'runtime');
    row.append(badge, copy, scope); list.append(row);
  });
}

async function runSecuritySuite() {
  const button = $('#runSecuritySuite');
  if (!button) return;
  button.disabled = true; button.textContent = 'Verifying…';
  try {
    const result = await window.aegis.invoke('security-suite:run');
    state.securitySuite = result;
    renderSecuritySuite();
    const failed = Number(result?.summary?.fail || 0);
    const warnings = Number(result?.summary?.warning || 0);
    showToast({
      message: failed ? `Security Suite completed with ${failed} failed check${failed === 1 ? '' : 's'}. Review the evidence below.` : (warnings ? `Security Suite passed critical checks with ${warnings} warning${warnings === 1 ? '' : 's'} to review.` : 'Security Suite verification completed with no failed checks.'),
      tone: failed ? 'warning' : (warnings ? 'warning' : 'success')
    });
  } catch (err) {
    showToast({ message: `Security Suite failed to run: ${err.message}`, tone: 'danger' });
  } finally {
    button.disabled = false; button.textContent = 'Run full verification';
  }
}

async function runNetworkTest() {
  const buttons = [$('#runNetworkTest'), $('#networkTestFromNetwork')].filter(Boolean);
  buttons.forEach((b) => { b.disabled = true; b.textContent = 'Testing…'; });
  try {
    const result = await window.aegis.invoke('network:test');
    if (!result?.ok) showToast({ message: `Connectivity test found an issue: ${result?.https || result?.error || 'unknown error'}`, tone: 'warning' });
    else showToast({ message: 'Connectivity test passed through the active private session.', tone: 'success' });
  } catch (err) { showToast({ message: `Connectivity test failed: ${err.message}`, tone: 'danger' }); }
  finally { buttons.forEach((b) => { b.disabled = false; b.textContent = b.id === 'runNetworkTest' ? 'Run connectivity test' : 'Run test'; }); }
}

function render() {
  applyAppearance();
  renderTabs();
  const tab = activeTab();
  renderChrome(tab);
  renderPrivacyPanel(tab);
  renderEngineInfo();
  renderLibrary();
  renderNetworkDiagnostics();
  renderSecuritySuite();
  renderControlAssurance();
  renderAddons();
  if (!$('#settingsPanel').classList.contains('hidden') && !draftSettings) draftSettings = deepClone(state.settings);
  if (!$('#settingsPanel').classList.contains('hidden')) renderSettingsDraft();
}

function openSettings(page) {
  draftSettings = deepClone(state.settings);
  showPanel('settingsPanel');
  switchSettingsPage(page || currentSettingsPage || 'privacy');
  renderSettingsDraft();
  setSettingsSaveState(false);
  clearSettingsSearch();
}

function setSettingsSaveState(dirty) {
  const badge = $('#saveState');
  if (!badge) return;
  badge.textContent = dirty ? 'Unsaved changes' : 'Saved locally';
  badge.classList.toggle('dirty', Boolean(dirty));
}

function clearSettingsSearch() {
  const input = $('#settingsSearch');
  const results = $('#settingsSearchResults');
  if (input) input.value = '';
  if (results) { results.innerHTML = ''; results.classList.add('hidden'); }
}

function renderSettingsSearch(query) {
  const results = $('#settingsSearchResults');
  if (!results) return;
  const q = String(query || '').trim().toLowerCase();
  results.innerHTML = '';
  if (q.length < 2) { results.classList.add('hidden'); return; }

  const selectors = '.setting-row,.select-row,.setting-stack,.text-area-row,.profile-card,.form-card>label,.action-card,.info-callout';
  const matches = [];
  $$('.settings-page').forEach((page) => {
    const pageName = page.dataset.settingsPage;
    page.querySelectorAll(selectors).forEach((el) => {
      const haystack = String(el.textContent || '').replace(/\s+/g, ' ').trim();
      if (!haystack.toLowerCase().includes(q)) return;
      const title = el.querySelector('b')?.textContent?.trim() || haystack.split(/[.!?]/)[0].slice(0, 72) || 'Setting';
      const detail = el.querySelector('small,p,span')?.textContent?.replace(/\s+/g, ' ').trim() || haystack;
      matches.push({ pageName, el, title, detail });
    });
  });

  if (!matches.length) {
    results.innerHTML = '<div class="settings-search-empty">No settings match that search.</div>';
    results.classList.remove('hidden');
    return;
  }

  matches.slice(0, 12).forEach((match) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'settings-search-result';
    const title = document.createElement('b'); title.textContent = match.title;
    const detail = document.createElement('small'); detail.textContent = match.detail;
    const page = document.createElement('em'); page.textContent = match.pageName;
    button.append(title, detail, page);
    button.addEventListener('click', () => {
      switchSettingsPage(match.pageName);
      clearSettingsSearch();
      requestAnimationFrame(() => {
        match.el.scrollIntoView({ behavior: document.body.dataset.reduceMotion === 'true' ? 'auto' : 'smooth', block: 'center' });
        match.el.classList.remove('settings-highlight');
        void match.el.offsetWidth;
        match.el.classList.add('settings-highlight');
        setTimeout(() => match.el.classList.remove('settings-highlight'), 1300);
      });
    });
    results.appendChild(button);
  });
  results.classList.remove('hidden');
}

function renderSettingsDraft() {
  if (!draftSettings) return;
  const s = draftSettings;
  $$('.profile-card').forEach((b) => b.classList.toggle('active', b.dataset.profile === s.privacyLevel));
  $('#blockTrackers').checked = Boolean(s.blockTrackers);
  $('#blockAds').checked = Boolean(s.blockAds);
  $('#blockSocialTrackers').checked = Boolean(s.blockSocialTrackers);
  $('#heuristicTrackingProtection').checked = Boolean(s.heuristicTrackingProtection);
  $('#siteIntelligence').checked = s.siteIntelligence !== false;
  $('#blockFingerprintingScripts').checked = Boolean(s.blockFingerprintingScripts);
  $('#cosmeticFiltering').checked = s.cosmeticFiltering !== false;
  $('#privacyApiGuard').checked = s.privacyApiGuard !== false;
  $('#blockTrackingBeacons').checked = s.blockTrackingBeacons !== false;
  $('#blockThirdPartyCookies').checked = Boolean(s.blockThirdPartyCookies);
  $('#stripTrackingParams').checked = Boolean(s.stripTrackingParams);
  $('#unwrapTrackingLinks').checked = Boolean(s.unwrapTrackingLinks);
  $('#etagProtection').checked = Boolean(s.etagProtection);
  $('#publicCdnIsolation').checked = Boolean(s.publicCdnIsolation);
  $('#stripCrossSiteReferrers').checked = Boolean(s.stripCrossSiteReferrers);
  $('#letterboxToggle').checked = Boolean(s.letterbox);
  $('#disableServiceWorkers').checked = Boolean(s.disableServiceWorkers);
  $('#gpcToggle').checked = Boolean(s.globalPrivacyControl);
  $('#dntToggle').checked = Boolean(s.doNotTrack);
  $('#downloadToggle').checked = Boolean(s.blockRiskyDownloads);
  $('#javascriptDefault').checked = Boolean(s.javascriptDefault);
  $('#clearClipboardIdentity').checked = Boolean(s.clearClipboardOnNewIdentity);
  $('#compatibilityAssistance').checked = s.compatibilityAssistance !== false;
  $('#threatProtection').checked = s.threatProtection !== false;
  $('#cookieAutoDelete').checked = Boolean(s.cookieAutoDelete);
  $('#cookieAutoDeleteDelay').value = String(s.cookieAutoDeleteDelaySec ?? 10);
  $('#sponsorBlockEnabled').checked = Boolean(s.sponsorBlock?.enabled);
  $$('[data-sponsor-category]').forEach((el) => { el.checked = (s.sponsorBlock?.categories || []).includes(el.dataset.sponsorCategory); });
  $('#fireproofSites').value = (s.fireproofSites || []).join('\n');
  $('#proxyMode').value = s.proxy?.mode || 'system';
  $('#proxyServer').value = s.proxy?.server || '';
  $('#proxyBypassLocal').checked = Boolean(s.proxy?.bypassLocal);
  $('#proxyFailClosed').checked = s.proxy?.failClosedFixedProxy !== false;
  $('#homePage').value = s.homePage || 'https://duckduckgo.com/';
  $('#searchEngine').value = s.searchEngine || 'duckduckgo';
  $('#customSearchTemplate').value = s.customSearchTemplate || '';
  $('#customSearchTemplate').disabled = s.searchEngine !== 'custom';
  $('#customFilterRules').value = s.customFilterRules || '';
  $('#themeSelect').value = s.appearance?.theme || 'nebula';
  $('#densitySelect').value = s.appearance?.density || 'comfortable';
  $('#accentSelect').value = s.appearance?.accent || 'cyan';
  $('#textScaleSelect').value = s.appearance?.textScale || 'large';
  $('#showScoreToggle').checked = s.appearance?.showPrivacyScore !== false;
  $('#reduceMotionToggle').checked = Boolean(s.appearance?.reduceMotion);
  $$('[data-permission-default]').forEach((el) => { el.value = s.permissionDefaults?.[el.dataset.permissionDefault] || 'block'; });
  applyAppearance(s);
}

function collectDraftFromControls() {
  if (!draftSettings) draftSettings = deepClone(state.settings);
  draftSettings.blockTrackers = $('#blockTrackers').checked;
  draftSettings.blockAds = $('#blockAds').checked;
  draftSettings.blockSocialTrackers = $('#blockSocialTrackers').checked;
  draftSettings.heuristicTrackingProtection = $('#heuristicTrackingProtection').checked;
  draftSettings.siteIntelligence = $('#siteIntelligence').checked;
  draftSettings.blockFingerprintingScripts = $('#blockFingerprintingScripts').checked;
  draftSettings.cosmeticFiltering = $('#cosmeticFiltering').checked;
  draftSettings.privacyApiGuard = $('#privacyApiGuard').checked;
  draftSettings.blockTrackingBeacons = $('#blockTrackingBeacons').checked;
  draftSettings.blockThirdPartyCookies = $('#blockThirdPartyCookies').checked;
  draftSettings.stripTrackingParams = $('#stripTrackingParams').checked;
  draftSettings.unwrapTrackingLinks = $('#unwrapTrackingLinks').checked;
  draftSettings.etagProtection = $('#etagProtection').checked;
  draftSettings.publicCdnIsolation = $('#publicCdnIsolation').checked;
  draftSettings.stripCrossSiteReferrers = $('#stripCrossSiteReferrers').checked;
  draftSettings.letterbox = $('#letterboxToggle').checked;
  draftSettings.disableServiceWorkers = $('#disableServiceWorkers').checked;
  draftSettings.globalPrivacyControl = $('#gpcToggle').checked;
  draftSettings.doNotTrack = $('#dntToggle').checked;
  draftSettings.blockRiskyDownloads = $('#downloadToggle').checked;
  draftSettings.javascriptDefault = $('#javascriptDefault').checked;
  draftSettings.clearClipboardOnNewIdentity = $('#clearClipboardIdentity').checked;
  draftSettings.compatibilityAssistance = $('#compatibilityAssistance').checked;
  draftSettings.threatProtection = $('#threatProtection').checked;
  draftSettings.cookieAutoDelete = $('#cookieAutoDelete').checked;
  draftSettings.cookieAutoDeleteDelaySec = Number($('#cookieAutoDeleteDelay').value || 10);
  draftSettings.sponsorBlock = { ...(draftSettings.sponsorBlock || {}), enabled: $('#sponsorBlockEnabled').checked, categories: $$('[data-sponsor-category]:checked').map((el) => el.dataset.sponsorCategory) };
  draftSettings.fireproofSites = $('#fireproofSites').value.split(/\r?\n|,/).map((x) => x.trim()).filter(Boolean);
  draftSettings.proxy = { mode: $('#proxyMode').value, server: $('#proxyServer').value.trim(), bypassLocal: $('#proxyBypassLocal').checked, failClosedFixedProxy: $('#proxyFailClosed').checked };
  draftSettings.homePage = $('#homePage').value.trim() || 'https://duckduckgo.com/';
  draftSettings.searchEngine = $('#searchEngine').value;
  draftSettings.customSearchTemplate = $('#customSearchTemplate').value.trim();
  draftSettings.customFilterRules = $('#customFilterRules').value;
  draftSettings.appearance = {
    ...draftSettings.appearance,
    theme: $('#themeSelect').value,
    density: $('#densitySelect').value,
    accent: $('#accentSelect').value,
    textScale: $('#textScaleSelect').value,
    showPrivacyScore: $('#showScoreToggle').checked,
    reduceMotion: $('#reduceMotionToggle').checked
  };
  draftSettings.permissionDefaults = { ...(draftSettings.permissionDefaults || {}) };
  $$('[data-permission-default]').forEach((el) => { draftSettings.permissionDefaults[el.dataset.permissionDefault] = el.value; });
  return draftSettings;
}

function switchSettingsPage(page) {
  currentSettingsPage = page || 'privacy';
  $$('.settings-nav-item').forEach((b) => b.classList.toggle('active', b.dataset.settingsTarget === currentSettingsPage));
  $$('.settings-page').forEach((s) => s.classList.toggle('active', s.dataset.settingsPage === currentSettingsPage));
}

function syncUiLayer() {
  const modalOpen = !$('#settingsPanel').classList.contains('hidden') || !$('#commandPalette').classList.contains('hidden') || !$('#permissionPrompt').classList.contains('hidden');
  let payload = { mode: 'none', reserveRight: 0 };
  if (modalOpen) {
    payload = { mode: 'hidden', reserveRight: 0 };
    document.body.dataset.uiLayer = 'modal';
  } else {
    const floating = !$('#privacyPanel').classList.contains('hidden') ? $('#privacyPanel') : (!$('#libraryPanel').classList.contains('hidden') ? $('#libraryPanel') : null);
    if (floating) {
      const width = Math.ceil(floating.getBoundingClientRect().width + 32);
      payload = { mode: 'reserve-right', reserveRight: width };
      document.body.dataset.uiLayer = 'docked';
    } else {
      document.body.dataset.uiLayer = 'none';
    }
  }
  const key = JSON.stringify(payload);
  if (key !== lastUiLayerKey) {
    lastUiLayerKey = key;
    window.aegis.send('ui:layer', payload);
  }
}

function showPanel(id) {
  ['privacyPanel', 'libraryPanel', 'settingsPanel'].forEach((x) => $('#' + x).classList.toggle('hidden', x !== id));
  if (id !== 'settingsPanel') draftSettings = null;
  requestAnimationFrame(syncUiLayer);
}

function hidePanels() {
  ['privacyPanel', 'libraryPanel', 'settingsPanel'].forEach((x) => $('#' + x).classList.add('hidden'));
  draftSettings = null;
  applyAppearance(state.settings);
  requestAnimationFrame(syncUiLayer);
}

function showToast(payload) {
  const data = typeof payload === 'string' ? { message: payload, tone: 'default' } : (payload || {});
  const el = $('#toast');
  el.textContent = data.message || '';
  el.className = `toast ${data.tone || 'default'}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3800);
}

function permissionNames(keys) {
  const names = { camera:'camera', microphone:'microphone', geolocation:'location', notifications:'notifications', clipboardRead:'clipboard contents', displayCapture:'screen capture', midi:'MIDI access', usb:'USB device access', serial:'serial-device access', hid:'HID-device access' };
  return (keys || []).map((k) => names[k] || k).join(' and ');
}

const PERMISSION_RISKS = {
  camera: { level: 'High', data: 'Live video from your camera', risk: 'Can reveal your face, surroundings, documents, screens, and physical environment.' },
  microphone: { level: 'High', data: 'Live microphone audio', risk: 'Can capture conversations, background speech, and sensitive ambient information.' },
  geolocation: { level: 'High', data: 'Precise device location', risk: 'Can reveal where you are and help correlate your physical movements with browsing activity.' },
  displayCapture: { level: 'Critical', data: 'A selected screen, window, or tab', risk: 'Can expose passwords, messages, work documents, account details, or anything visible in the shared area.' },
  clipboardRead: { level: 'High', data: 'Current clipboard contents', risk: 'May expose copied passwords, wallet addresses, messages, links, or other sensitive text.' },
  notifications: { level: 'Moderate', data: 'Permission to send system notifications', risk: 'Can create persistent prompts, phishing-like messages, and attention tracking outside the active page.' },
  midi: { level: 'Moderate', data: 'Connected MIDI capability', risk: 'Can reveal connected hardware details and interact with supported MIDI devices.' },
  usb: { level: 'Critical', data: 'Connected USB device access', risk: 'Can expose device identifiers or interact with hardware. Aegis keeps WebUSB blocked.' },
  serial: { level: 'Critical', data: 'Connected serial device access', risk: 'Can communicate directly with attached serial hardware. Aegis keeps Web Serial blocked.' },
  hid: { level: 'Critical', data: 'Human-interface device access', risk: 'Can interact with supported keyboards/controllers and other HID hardware. Aegis keeps WebHID blocked.' }
};

function renderPermissionRisks(keys) {
  const box = $('#permissionRiskList');
  if (!box) return;
  box.replaceChildren();
  (keys || []).forEach((key) => {
    const info = PERMISSION_RISKS[key] || { level: 'Elevated', data: titleCase(key), risk: 'This permission exposes additional browser or device capability to the site.' };
    const row = document.createElement('div'); row.className = 'permission-risk-row';
    const badge = document.createElement('span'); badge.className = `permission-risk-badge risk-${String(info.level).toLowerCase()}`; badge.textContent = info.level;
    const copy = document.createElement('span'); const b = document.createElement('b'); b.textContent = info.data; const small = document.createElement('small'); small.textContent = info.risk; copy.append(b, small);
    row.append(badge, copy); box.append(row);
  });
}

function showNextPermissionPrompt() {
  if (activePermissionPrompt || !permissionQueue.length) return;
  activePermissionPrompt = permissionQueue.shift();
  const p = activePermissionPrompt;
  let host = p.origin;
  try { host = new URL(p.origin).hostname; } catch {}
  $('#permissionTitle').textContent = `${host} wants ${permissionNames(p.keys)}`;
  $('#permissionMessage').textContent = `Aegis blocked this by default. Review exactly what ${host} would receive and use the shortest permission duration that works.`;
  renderPermissionRisks(p.keys);
  $('#permissionPrompt').classList.remove('hidden');
  $('#permissionPrompt').setAttribute('aria-hidden', 'false');
  requestAnimationFrame(syncUiLayer);
}

function closePermissionPrompt(id) {
  if (activePermissionPrompt && (!id || activePermissionPrompt.id === id)) activePermissionPrompt = null;
  permissionQueue = permissionQueue.filter((p) => p.id !== id);
  $('#permissionPrompt').classList.add('hidden');
  $('#permissionPrompt').setAttribute('aria-hidden', 'true');
  showNextPermissionPrompt();
  requestAnimationFrame(syncUiLayer);
}

function respondPermission(action) {
  if (!activePermissionPrompt) return;
  window.aegis.send('permission:respond', { id: activePermissionPrompt.id, action });
  closePermissionPrompt(activePermissionPrompt.id);
}

function openCommandPalette() {
  $('#commandPalette').classList.remove('hidden');
  $('#commandPalette').setAttribute('aria-hidden', 'false');
  $('#commandInput').value = '';
  commandIndex = 0;
  renderCommands('');
  requestAnimationFrame(syncUiLayer);
  setTimeout(() => $('#commandInput').focus(), 0);
}

function closeCommandPalette() {
  $('#commandPalette').classList.add('hidden');
  $('#commandPalette').setAttribute('aria-hidden', 'true');
  requestAnimationFrame(syncUiLayer);
}

function renderCommands(query) {
  const q = String(query || '').toLowerCase().trim();
  commandMatches = COMMANDS.filter((c) => !q || c.name.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q));
  commandIndex = Math.min(commandIndex, Math.max(0, commandMatches.length - 1));
  const list = $('#commandList');
  list.replaceChildren(...commandMatches.map((cmd, i) => {
    const b = document.createElement('button');
    b.className = 'command-item' + (i === commandIndex ? ' active' : '');
    const left = document.createElement('b'); left.textContent = cmd.name;
    const right = document.createElement('small'); right.textContent = cmd.hint;
    b.append(left, right);
    b.addEventListener('click', () => { closeCommandPalette(); cmd.run(); });
    return b;
  }));
}

function runSelectedCommand() {
  const cmd = commandMatches[commandIndex];
  if (!cmd) return;
  closeCommandPalette();
  cmd.run();
}

$('#addressForm').addEventListener('submit', (e) => { e.preventDefault(); window.aegis.send('nav', $('#address').value); $('#address').blur(); });
$('#address').addEventListener('focus', (e) => e.target.select());
$('#newTab').addEventListener('click', () => window.aegis.send('tab:new'));
$('#back').addEventListener('click', () => window.aegis.send('tab:command', 'back'));
$('#forward').addEventListener('click', () => window.aegis.send('tab:command', 'forward'));
$('#reload').addEventListener('click', () => window.aegis.send('tab:command', 'reload'));
$('#home').addEventListener('click', () => window.aegis.send('tab:command', 'home'));
$('#identity').addEventListener('click', () => window.aegis.send('identity:new'));
$('#shield').addEventListener('click', () => showPanel('privacyPanel'));
$('#bookmarkBtn').addEventListener('click', () => window.aegis.send('bookmark:toggle'));
$('#libraryBtn').addEventListener('click', () => showPanel('libraryPanel'));
$('#settingsBtn').addEventListener('click', () => openSettings());
$('#commandBtn').addEventListener('click', openCommandPalette);
$('#privacyBeacon').addEventListener('click', () => showPanel('privacyPanel'));
$('#sentinelSimple').addEventListener('click', () => applySentinelMode('simple'));
$('#sentinelAdvanced').addEventListener('click', () => applySentinelMode('advanced'));
$('#openFullSettings').addEventListener('click', () => openSettings('privacy'));
$$('[data-close]').forEach((b) => b.addEventListener('click', hidePanels));

$('#shieldToggle').addEventListener('change', (e) => window.aegis.send('shields:set', e.target.checked));
$('#jsToggle').addEventListener('change', (e) => window.aegis.send('javascript:set', e.target.checked));
$('#httpToggle').addEventListener('change', (e) => window.aegis.send('http:set', e.target.checked));
$('#compatibilityToggle').addEventListener('change', (e) => window.aegis.send('compatibility:set', e.target.checked));
$('#hardenSite').addEventListener('click', () => window.aegis.send('site:harden'));
$('#clearTabData').addEventListener('click', () => window.aegis.send('data:clear-tab'));
$('#resetSitePermissions').addEventListener('click', () => window.aegis.send('site-permission:reset'));
$('#clearDownloads').addEventListener('click', () => window.aegis.send('downloads:clear'));
$('#runNetworkTest').addEventListener('click', runNetworkTest);
$('#runSecuritySuite').addEventListener('click', runSecuritySuite);
$('#installXpi').addEventListener('click', async () => {
  const button = $('#installXpi'); button.disabled = true; button.textContent = 'Reviewing…';
  try {
    const result = await window.aegis.invoke('extensions:install');
    if (result?.ok) showToast({ message:'Installed ' + result.extension.name + '. Matching content scripts will run in isolated extension worlds.', tone:'success' });
    else if (!result?.canceled) showToast({ message:'Extension install failed: ' + (result?.error || 'unknown error'), tone:'danger' });
  } catch (err) { showToast({ message:'Extension install failed: ' + err.message, tone:'danger' }); }
  finally { button.disabled = false; button.textContent = 'Install .xpi'; }
});
$('#networkTestFromNetwork').addEventListener('click', () => { openSettings('diagnostics'); runNetworkTest(); });
$$('[data-site-permission]').forEach((el) => el.addEventListener('change', () => window.aegis.send('site-permission:set', { key: el.dataset.sitePermission, value: el.value })));

$$('.settings-nav-item').forEach((b) => b.addEventListener('click', () => { switchSettingsPage(b.dataset.settingsTarget); clearSettingsSearch(); }));
$$('.profile-card').forEach((b) => b.addEventListener('click', () => {
  if (!draftSettings) draftSettings = deepClone(state.settings);
  Object.assign(draftSettings, PROFILE_VALUES[b.dataset.profile]);
  renderSettingsDraft();
  setSettingsSaveState(true);
}));

const draftControlIds = [
  'blockTrackers','blockAds','blockSocialTrackers','heuristicTrackingProtection','siteIntelligence','blockFingerprintingScripts','cosmeticFiltering','privacyApiGuard','blockTrackingBeacons','blockThirdPartyCookies','stripTrackingParams','unwrapTrackingLinks','etagProtection','publicCdnIsolation','stripCrossSiteReferrers','letterboxToggle',
  'disableServiceWorkers','gpcToggle','dntToggle','downloadToggle','javascriptDefault','clearClipboardIdentity','compatibilityAssistance','threatProtection','cookieAutoDelete','cookieAutoDeleteDelay','sponsorBlockEnabled','fireproofSites',
  'proxyMode','proxyServer','proxyBypassLocal','proxyFailClosed','homePage','searchEngine','customSearchTemplate','customFilterRules','themeSelect','densitySelect','accentSelect','textScaleSelect',
  'showScoreToggle','reduceMotionToggle'
];
draftControlIds.forEach((id) => $('#' + id).addEventListener('input', () => { collectDraftFromControls(); renderSettingsDraft(); setSettingsSaveState(true); }));
$$('[data-permission-default]').forEach((el) => el.addEventListener('change', () => { collectDraftFromControls(); renderSettingsDraft(); setSettingsSaveState(true); }));

$('#torPreset').addEventListener('click', () => {
  $('#proxyMode').value = 'socks5';
  $('#proxyServer').value = '127.0.0.1:9050';
  $('#proxyBypassLocal').checked = true;
  collectDraftFromControls();
  renderSettingsDraft();
  setSettingsSaveState(true);
});

$('#saveSettings').addEventListener('click', () => {
  const draft = collectDraftFromControls();
  if (draft.searchEngine === 'custom' && !draft.customSearchTemplate.includes('%s')) {
    showToast({ message: 'Custom search template must contain %s.', tone: 'warning' });
    switchSettingsPage('search');
    return;
  }
  window.aegis.send('settings:update', draft);
  setSettingsSaveState(false);
});
$('#cancelSettings').addEventListener('click', hidePanels);
$('#settingsSearch').addEventListener('input', (e) => renderSettingsSearch(e.target.value));
$('#settingsSearch').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); clearSettingsSearch(); e.target.blur(); } });
$('#settingsSearch').addEventListener('blur', () => setTimeout(() => $('#settingsSearchResults').classList.add('hidden'), 140));
$('#settingsSearch').addEventListener('focus', (e) => renderSettingsSearch(e.target.value));
$('#resetSettings').addEventListener('click', () => window.aegis.send('settings:reset'));
$('#settingsClearAll').addEventListener('click', () => window.aegis.send('data:clear-all'));
$('#settingsNewIdentity').addEventListener('click', () => { hidePanels(); window.aegis.send('identity:new'); });

$('#permissionBlock').addEventListener('click', () => respondPermission('block-once'));
$('#permissionBlockAlways').addEventListener('click', () => respondPermission('block-always'));
$('#permissionAllowOnce').addEventListener('click', () => respondPermission('allow-once'));
$('#permissionAllow10m').addEventListener('click', () => respondPermission('allow-10m'));
$('#permissionAllowAlways').addEventListener('click', () => respondPermission('allow-always'));

$('#commandInput').addEventListener('input', (e) => { commandIndex = 0; renderCommands(e.target.value); });
$('#commandInput').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown') { e.preventDefault(); commandIndex = Math.min(commandMatches.length - 1, commandIndex + 1); renderCommands(e.target.value); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); commandIndex = Math.max(0, commandIndex - 1); renderCommands(e.target.value); }
  else if (e.key === 'Enter') { e.preventDefault(); runSelectedCommand(); }
  else if (e.key === 'Escape') closeCommandPalette();
});
$('#commandPalette').addEventListener('click', (e) => { if (e.target === $('#commandPalette')) closeCommandPalette(); });

window.addEventListener('keydown', (e) => {
  const mod = e.metaKey || e.ctrlKey;
  if (mod && e.key.toLowerCase() === 'f' && !$('#settingsPanel').classList.contains('hidden')) { e.preventDefault(); $('#settingsSearch').focus(); $('#settingsSearch').select(); }
  else if (mod && e.key.toLowerCase() === 'l') { e.preventDefault(); $('#address').focus(); $('#address').select(); }
  else if (mod && e.key.toLowerCase() === 't') { e.preventDefault(); window.aegis.send('tab:new'); }
  else if (mod && e.key.toLowerCase() === 'w') { e.preventDefault(); const t = activeTab(); if (t) window.aegis.send('tab:close', t.id); }
  else if (mod && e.shiftKey && e.key.toLowerCase() === 'n') { e.preventDefault(); window.aegis.send('identity:new'); }
  else if (mod && e.key === ',') { e.preventDefault(); openSettings(); }
  else if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); openCommandPalette(); }
  else if (mod && e.key.toLowerCase() === 'd') { e.preventDefault(); window.aegis.send('bookmark:toggle'); }
  else if (e.key === 'Escape') { closeCommandPalette(); hidePanels(); }
});

window.aegis.on('state', (s) => { state = s; render(); });
window.aegis.on('toast', showToast);
window.aegis.on('permission:prompt', (p) => { permissionQueue.push(p); showNextPermissionPrompt(); });
window.aegis.on('permission:closed', ({ id }) => closePermissionPrompt(id));
window.aegis.on('ui:open', (payload = {}) => {
  if (payload.panel === 'privacyPanel') showPanel('privacyPanel');
  else if (payload.settingsPage) openSettings(payload.settingsPage);
});
window.aegis.invoke('state:get').then((s) => { if (s) { state = s; render(); } requestAnimationFrame(syncUiLayer); });
