'use strict';

function timeout(promise, ms, label) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms); })
  ]).finally(() => clearTimeout(timer));
}

async function applyProxyToSession(ses, proxy = {}, options = {}) {
  const mode = proxy.mode || 'system';
  const result = { ok: true, mode, warnings: [], fallback: false, inheritedSystemRoute: false };
  const setMs = options.setTimeoutMs || 3500;
  const closeMs = options.closeTimeoutMs || 2500;

  // A newly-created Chromium session already starts with the platform proxy
  // configuration. Avoid mutating it while the first page is beginning to load;
  // that race can stall or abort the initial navigation on macOS. Existing
  // sessions still receive an explicit System reset when settings are changed.
  if (mode === 'system' && options.freshSession) {
    result.inheritedSystemRoute = true;
    return result;
  }

  try {
    if (mode === 'system') {
      await timeout(ses.setProxy({ mode: 'system' }), setMs, 'System proxy setup');
      if (typeof ses.forceReloadProxyConfig === 'function') {
        try { await timeout(ses.forceReloadProxyConfig(), 2200, 'System proxy reload'); }
        catch (err) { result.warnings.push(err.message); }
      }
    } else if (mode === 'direct') {
      await timeout(ses.setProxy({ mode: 'direct' }), setMs, 'Direct route setup');
    } else {
      if (!proxy.server) throw new Error('A proxy server is required for fixed proxy mode.');
      if (!['socks5', 'http', 'https'].includes(mode)) throw new Error('Unsupported proxy mode.');
      await timeout(ses.setProxy({
        mode: 'fixed_servers',
        proxyRules: `${mode}://${proxy.server}`,
        proxyBypassRules: proxy.bypassLocal ? '<local>' : '<-loopback>'
      }), setMs, 'Fixed proxy setup');
    }
  } catch (err) {
    result.ok = false;
    result.warnings.push(err.message);
    // System mode must fail soft. Chromium already has platform networking and
    // a transient proxy API error should never brick ordinary browsing.
    if (mode === 'system') {
      result.fallback = true;
      result.ok = true;
      result.warnings.push('Using Chromium platform networking fallback.');
    } else if (options.failClosedFixedProxy) {
      throw err;
    }
  }

  if (typeof ses.closeAllConnections === 'function') {
    try { await timeout(ses.closeAllConnections(), closeMs, 'Connection reset'); }
    catch (err) { result.warnings.push(err.message); }
  }
  return result;
}

async function fetchConnectivityTarget(ses, target) {
  try {
    let response;
    try {
      response = await timeout(ses.fetch(target, { method: 'HEAD', redirect: 'follow', cache: 'no-store' }), 9000, 'HTTPS request');
      if ([400, 403, 405].includes(response.status)) {
        response = await timeout(ses.fetch(target, { method: 'GET', redirect: 'follow', cache: 'no-store' }), 9000, 'HTTPS request');
      }
    } catch {
      response = await timeout(ses.fetch(target, { method: 'GET', redirect: 'follow', cache: 'no-store' }), 9000, 'HTTPS request');
    }
    const status = response.status;
    try { await timeout(response.arrayBuffer(), 3000, 'HTTPS response drain'); } catch {}
    return { status, https: `HTTP ${status}`, ok: status >= 200 && status < 500 };
  } catch (err) {
    return { status: null, https: `Error: ${err.message}`, ok: false };
  }
}

async function runConnectivityTest(ses, options = {}) {
  if (!ses) return { ok: false, error: 'No Chromium session available.' };
  const target = options.target || 'https://duckduckgo.com/';
  const host = new URL(target).hostname;
  const startedAt = Date.now();
  const result = {
    ok: false,
    testedAt: new Date().toISOString(),
    target,
    proxyMode: options.proxyMode || 'system',
    proxy: null,
    dns: null,
    https: null,
    status: null,
    elapsedMs: 0
  };

  // These checks are independent and intentionally run in parallel so the
  // Diagnostics button always returns promptly even if one platform resolver
  // path is unhealthy.
  const proxyCheck = (async () => {
    try { return await timeout(ses.resolveProxy(target), 4500, 'Proxy resolution') || 'DIRECT'; }
    catch (err) { return `Error: ${err.message}`; }
  })();
  const skipLocalDns = options.skipLocalDns === true || String(options.proxyMode || '').toLowerCase() === 'socks5';
  const dnsCheck = skipLocalDns
    ? Promise.resolve('Local DNS probe skipped — hostname resolution delegated to the proxied HTTPS request')
    : (async () => {
      try {
        const resolved = await timeout(ses.resolveHost(host), 4500, 'DNS resolution');
        const endpoints = Array.isArray(resolved?.endpoints) ? resolved.endpoints : [];
        return endpoints.length ? `Resolved (${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'})` : 'Resolved';
      } catch (err) { return `Error: ${err.message}`; }
    })();
  const httpsCheck = fetchConnectivityTarget(ses, target);

  const [proxyResult, dnsResult, httpsResult] = await Promise.all([proxyCheck, dnsCheck, httpsCheck]);
  result.proxy = proxyResult;
  result.dns = dnsResult;
  result.https = httpsResult.https;
  result.status = httpsResult.status;
  result.ok = httpsResult.ok;
  result.elapsedMs = Date.now() - startedAt;
  return result;
}


async function verifyTorRoute(ses, options = {}) {
  if (!ses) return { ok:false, verified:false, error:'No Chromium session available.' };
  const startedAt=Date.now();
  const result={ok:false,verified:false,testedAt:new Date().toISOString(),provider:'Tor Project',exitIp:'',elapsedMs:0,error:''};
  const attempts=[
    {url:'https://check.torproject.org/api/ip',json:true},
    {url:'https://check.torproject.org/',json:false}
  ];
  const errors=[];
  for (const attempt of attempts) {
    try {
      const response=await timeout(ses.fetch(attempt.url,{method:'GET',redirect:'follow',cache:'no-store'}), options.timeoutMs || 10000, 'Tor route verification');
      if (!response.ok) throw new Error('HTTP '+response.status);
      const body=await timeout(response.text(),3000,'Tor verification response');
      if (attempt.json) {
        try {
          const data=JSON.parse(body);
          const isTor=data.IsTor === true || data.IsTor === 'true' || data.isTor === true;
          const ip=String(data.IP || data.ip || '').trim();
          if (isTor) {
            result.ok=true; result.verified=true; result.exitIp=ip; result.elapsedMs=Date.now()-startedAt; return result;
          }
          throw new Error('Tor Project reported that this route is not Tor.');
        } catch (err) {
          if (/reported/.test(err.message)) throw err;
          throw new Error('Invalid Tor JSON response');
        }
      }
      const good=/Congratulations\.? This browser is configured to use Tor|This browser is configured to use Tor/i.test(body);
      const bad=/Sorry\.? You are not using Tor/i.test(body);
      if (good && !bad) {
        result.ok=true; result.verified=true;
        const ipMatch=body.match(/(?:Your IP address appears to be|IP Address[^<:]*)[:\s]+(?:<[^>]+>\s*)*([0-9a-f:.]{3,64})/i);
        if (ipMatch) result.exitIp=ipMatch[1];
        result.elapsedMs=Date.now()-startedAt; return result;
      }
      if (bad) throw new Error('Tor Project reported that this route is not Tor.');
      throw new Error('Tor status could not be determined from the response.');
    } catch (err) { errors.push(err.message); }
  }
  result.elapsedMs=Date.now()-startedAt;
  result.error=errors.join(' | ').slice(0,600) || 'Tor verification failed.';
  return result;
}

module.exports = { timeout, applyProxyToSession, runConnectivityTest, verifyTorRoute };
