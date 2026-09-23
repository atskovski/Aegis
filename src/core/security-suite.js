'use strict';

function timeout(promise, ms, label) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms); })
  ]).finally(() => clearTimeout(timer));
}

function isPublicIp(value) {
  const input = String(value || '').trim();
  if (!input || input.length > 64) return false;
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(input) && input.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
  const ipv6 = /^[0-9a-f:]+$/i.test(input) && input.includes(':');
  return ipv4 || ipv6;
}

async function readText(response) {
  const text = await timeout(response.text(), 2500, 'Public IP response');
  return String(text || '').trim();
}

async function fetchPublicIp(ses) {
  if (!ses) return { ok: false, status: 'not-tested', ip: '', provider: '', error: 'No disposable session available.' };
  const endpoints = [
    { url: 'https://api.ipify.org?format=json', provider: 'ipify', parse: (text) => { try { return JSON.parse(text).ip || ''; } catch { return ''; } } },
    { url: 'https://icanhazip.com/', provider: 'icanhazip', parse: (text) => text.split(/\s+/)[0] || '' }
  ];
  const errors = [];
  for (const endpoint of endpoints) {
    try {
      const response = await timeout(ses.fetch(endpoint.url, { method: 'GET', redirect: 'follow', cache: 'no-store' }), 6500, 'Public IP lookup');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const value = endpoint.parse(await readText(response));
      if (!isPublicIp(value)) throw new Error('Provider returned an invalid IP value');
      return { ok: true, status: 'pass', ip: value, provider: endpoint.provider, error: '' };
    } catch (err) { errors.push(`${endpoint.provider}: ${err.message}`); }
  }
  return { ok: false, status: 'fail', ip: '', provider: '', error: errors.join(' | ').slice(0, 500) || 'Public IP lookup failed.' };
}

async function testSessionIsolation(createSession) {
  if (typeof createSession !== 'function') return { ok: false, status: 'not-tested', evidence: 'Session factory unavailable.' };
  const token = `aegis-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const url = 'https://aegis-isolation.test/';
  const a = createSession('proof-a');
  const b = createSession('proof-b');
  try {
    await a.cookies.set({ url, name: 'aegis_proof', value: token, secure: true, sameSite: 'lax' });
    const [cookiesA, cookiesB] = await Promise.all([
      a.cookies.get({ url, name: 'aegis_proof' }),
      b.cookies.get({ url, name: 'aegis_proof' })
    ]);
    const presentA = cookiesA.some((c) => c.value === token);
    const leakedB = cookiesB.some((c) => c.value === token);
    const ok = presentA && !leakedB;
    return {
      ok,
      status: ok ? 'pass' : 'fail',
      evidence: ok ? 'Cookie written to proof session A was absent from isolated session B.' : `Isolation proof failed (presentA=${presentA}, leakedB=${leakedB}).`
    };
  } catch (err) {
    return { ok: false, status: 'fail', evidence: `Isolation test error: ${err.message}` };
  } finally {
    for (const ses of [a, b]) {
      try { await ses.clearData(); } catch {}
      try { await ses.clearCache(); } catch {}
      try { await ses.closeAllConnections(); } catch {}
    }
  }
}

function makeCheck(id, label, status, evidence, scope = 'runtime') {
  return { id, label, status, ok: status === 'pass', evidence: String(evidence || '').slice(0, 600), scope };
}

function summarizeChecks(checks) {
  const list = Array.isArray(checks) ? checks : [];
  const counts = { pass: 0, fail: 0, 'not-tested': 0 };
  for (const check of list) counts[check?.status] = (counts[check?.status] || 0) + 1;
  return { ...counts, total: list.length };
}

module.exports = { isPublicIp, fetchPublicIp, testSessionIsolation, makeCheck, summarizeChecks };
