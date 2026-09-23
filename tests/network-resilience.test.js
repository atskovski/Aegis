'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { applyProxyToSession, runConnectivityTest } = require('../src/core/network');

test('fresh system sessions inherit platform routing without racing setProxy', async () => {
  let setProxyCalls = 0;
  let closeCalls = 0;
  const ses = {
    setProxy: async () => { setProxyCalls += 1; },
    closeAllConnections: async () => { closeCalls += 1; }
  };
  const result = await applyProxyToSession(ses, { mode: 'system' }, { freshSession: true });
  assert.equal(result.ok, true);
  assert.equal(result.inheritedSystemRoute, true);
  assert.equal(setProxyCalls, 0);
  assert.equal(closeCalls, 0);
});

test('explicit direct routing is applied and stale connections are closed', async () => {
  const calls = [];
  const ses = {
    setProxy: async (config) => { calls.push(['proxy', config]); },
    closeAllConnections: async () => { calls.push(['close']); }
  };
  const result = await applyProxyToSession(ses, { mode: 'direct' });
  assert.equal(result.ok, true);
  assert.deepEqual(calls[0], ['proxy', { mode: 'direct' }]);
  assert.deepEqual(calls[1], ['close']);
});

test('connectivity diagnostics exercise proxy, DNS and HTTPS in one Chromium session', async () => {
  const calls = [];
  const ses = {
    resolveProxy: async (url) => { calls.push(['proxy', url]); return 'DIRECT'; },
    resolveHost: async (host) => { calls.push(['dns', host]); return { endpoints: [{ address: '1.1.1.1', family: 'ipv4' }] }; },
    fetch: async (url, init) => {
      calls.push(['fetch', url, init.method]);
      return { status: 200, arrayBuffer: async () => new ArrayBuffer(0) };
    }
  };
  const result = await runConnectivityTest(ses, { target: 'https://duckduckgo.com/', proxyMode: 'system' });
  assert.equal(result.ok, true);
  assert.equal(result.proxy, 'DIRECT');
  assert.match(result.dns, /Resolved/);
  assert.equal(result.https, 'HTTP 200');
  assert.ok(calls.some((x) => x[0] === 'proxy'));
  assert.ok(calls.some((x) => x[0] === 'dns'));
  assert.ok(calls.some((x) => x[0] === 'fetch'));
});


test('SOCKS diagnostics never issue a local DNS resolution probe', async () => {
  let dnsCalls=0;
  const calls=[];
  const ses={
    resolveProxy: async()=> 'SOCKS5 127.0.0.1:9050',
    resolveHost: async()=> { dnsCalls += 1; throw new Error('must not be called'); },
    fetch: async(url,init)=> {
      calls.push(['fetch',url,init.method]);
      return {status:200,arrayBuffer:async()=>new ArrayBuffer(0)};
    }
  };
  const result=await runConnectivityTest(ses,{target:'https://duckduckgo.com/',proxyMode:'socks5'});
  assert.equal(result.ok,true);
  assert.equal(dnsCalls,0);
  assert.match(result.dns,/skipped/i);
  assert.ok(calls.some((x)=>x[0]==='fetch'));
});
