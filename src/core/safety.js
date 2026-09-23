'use strict';
const net = require('node:net');

const BRANDS = ['google.com','apple.com','microsoft.com','paypal.com','amazon.com','facebook.com','instagram.com','github.com','duckduckgo.com'];
function levenshtein(a, b) {
  a = String(a); b = String(b);
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0]; row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return row[b.length];
}
function registrableGuess(host) {
  const p = String(host || '').toLowerCase().split('.').filter(Boolean);
  return p.length > 1 ? p.slice(-2).join('.') : host;
}
function analyzeUrl(raw) {
  const warnings = [];
  let u;
  try { u = new URL(raw); } catch { return { risk: 0, warnings }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { risk: 20, warnings: ['Non-web protocol'] };
  if (u.username || u.password) warnings.push('Address contains embedded credentials');
  if (net.isIP(u.hostname)) warnings.push('Destination uses a raw IP address');
  if (u.hostname.includes('xn--')) warnings.push('Destination contains internationalized/punycode labels');
  if (u.port && !['80', '443'].includes(u.port)) warnings.push(`Non-standard port ${u.port}`);
  const reg = registrableGuess(u.hostname);
  for (const brand of BRANDS) {
    if (reg !== brand && levenshtein(reg, brand) === 1) { warnings.push(`Domain resembles ${brand}`); break; }
  }
  return { risk: Math.min(100, warnings.length * 25), warnings };
}
module.exports = { analyzeUrl, levenshtein, registrableGuess };
