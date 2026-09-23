'use strict';

function normalizeHost(value) {
  const s = String(value || '').trim().toLowerCase().replace(/^\|\|/, '').replace(/\^.*$/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\.+|\.+$/g, '');
  return /^[a-z0-9.-]+$/.test(s) && s.includes('.') ? s : '';
}

function hostMatches(host, ruleHost) {
  return host === ruleHost || host.endsWith(`.${ruleHost}`);
}

function validCosmeticSelector(selector) {
  const s = String(selector || '').trim();
  return Boolean(s && s.length <= 260 && !/[{}]/.test(s));
}

function parseFilterRules(text) {
  const block = [];
  const allow = [];
  const cosmetic = [];
  const cosmeticAllow = [];
  for (const lineRaw of String(text || '').split(/\r?\n/).slice(0, 10000)) {
    const line = lineRaw.trim();
    if (!line || line.startsWith('!') || line.startsWith('[')) continue;

    const cosmeticException = line.indexOf('#@#');
    if (cosmeticException >= 0) {
      const selector = line.slice(cosmeticException + 3).trim();
      if (validCosmeticSelector(selector)) cosmeticAllow.push(selector);
      continue;
    }
    const cosmeticRule = line.indexOf('##');
    if (cosmeticRule >= 0 && !line.includes('##+js(')) {
      const selector = line.slice(cosmeticRule + 2).trim();
      if (validCosmeticSelector(selector)) cosmetic.push(selector);
      continue;
    }

    const isAllow = line.startsWith('@@');
    const body = isAllow ? line.slice(2) : line;
    const host = normalizeHost(body);
    if (!host) continue;
    (isAllow ? allow : block).push(host);
  }
  const allowedCosmetics = new Set(cosmeticAllow);
  return {
    block: [...new Set(block)].slice(0, 5000),
    allow: [...new Set(allow)].slice(0, 5000),
    cosmetic: [...new Set(cosmetic)].filter((x) => !allowedCosmetics.has(x)).slice(0, 2500),
    cosmeticAllow: [...allowedCosmetics].slice(0, 2500)
  };
}

function matchFilterRules(rawUrl, rules) {
  let host;
  try { host = new URL(rawUrl).hostname.toLowerCase(); } catch { return null; }
  if (rules?.allow?.some((r) => hostMatches(host, r))) return 'allow';
  if (rules?.block?.some((r) => hostMatches(host, r))) return 'block';
  return null;
}

module.exports = { parseFilterRules, matchFilterRules, normalizeHost, hostMatches, validCosmeticSelector };
