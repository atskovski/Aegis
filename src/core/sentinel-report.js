'use strict';

function safeIp(ip) {
  const value = String(ip || '').trim();
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || (value.includes(':') && /^[0-9a-f:]+$/i.test(value)) ? value : '';
}

function buildSentinelReport({ tab = {}, settings = {}, publicIp = '', route = null, protections = null } = {}) {
  const intel = tab.siteIntelligence || {};
  const network = intel.network || {};
  const signals = Array.isArray(intel.signals) ? intel.signals : Object.values(intel.signals || {});
  const hosts = Array.isArray(network.thirdPartyHosts) ? network.thirdPartyHosts : Object.values(network.thirdPartyHosts || {});
  const blocked = Number(network.blockedThirdParty || tab.stats?.blocked || 0);
  const allowed = Number(network.allowedThirdParty || 0);
  const fingerprint = signals.filter((x) => x.group === 'fingerprint');
  const sensitive = signals.filter((x) => ['sensitive','device','form'].includes(x.group));
  const storage = signals.filter((x) => x.group === 'storage');
  const degraded = protections?.protections?.filter((x) => x.status === 'degraded') || [];

  const simple = {
    site: String(tab.url || '').slice(0, 1000),
    protection: degraded.length ? 'Attention needed' : 'Protected',
    blocked,
    allowedThirdParty: allowed,
    thirdParties: hosts.length,
    fingerprintSurfaces: fingerprint.length,
    sensitiveRequests: sensitive.reduce((n,x) => n + Number(x.attempts || 1), 0),
    storageSurfaces: storage.length,
    route: route?.mode || settings.proxy?.mode || 'system',
    publicIp: safeIp(publicIp),
    ipMeaning: publicIp ? 'Visible to destinations through the configured route. This does not prove anonymity.' : 'Not tested. Aegis does not contact an external IP service until requested.',
    headline: degraded.length ? `${degraded.length} configured protection${degraded.length===1?' is':'s are'} not fully enforced on this tab.` : `${blocked} third-party request${blocked===1?'':'s'} blocked; no configured protection reports degraded.`
  };

  const advanced = {
    generatedAt: new Date().toISOString(),
    route,
    publicIp: safeIp(publicIp),
    network: { ...network, thirdPartyHosts: hosts.slice(0,100) },
    signals: signals.slice(0,200),
    fingerprint,
    sensitive,
    storage,
    stats: tab.stats || {},
    protectionStatus: protections || null,
    fingerprintReady: Boolean(tab.fingerprintReady),
    cosmeticFilteringReady: Boolean(tab.cosmeticFilteringReady),
    sessionPartition: String(tab.partition || '').startsWith('persist:') ? 'persistent' : 'ephemeral'
  };
  return { simple, advanced };
}

module.exports = { buildSentinelReport };
