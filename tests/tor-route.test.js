'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { verifyTorRoute }=require('../src/core/network');

function mockResponse(body,status=200){
  return {ok:status>=200&&status<300,status,text:async()=>body};
}

test('Tor verifier accepts authoritative JSON proof',async()=>{
  const ses={fetch:async(url)=> {
    assert.match(url,/check\.torproject\.org/);
    return mockResponse(JSON.stringify({IsTor:true,IP:'185.220.101.1'}));
  }};
  const r=await verifyTorRoute(ses,{timeoutMs:500});
  assert.equal(r.verified,true);
  assert.equal(r.exitIp,'185.220.101.1');
});

test('Tor verifier rejects explicit non-Tor result',async()=>{
  let calls=0;
  const ses={fetch:async(url)=> {
    calls++;
    if(url.includes('/api/ip')) return mockResponse(JSON.stringify({IsTor:false,IP:'203.0.113.3'}));
    return mockResponse('<html><body>Sorry. You are not using Tor.</body></html>');
  }};
  const r=await verifyTorRoute(ses,{timeoutMs:500});
  assert.equal(r.verified,false);
  assert.match(r.error,/not Tor/i);
  assert.equal(calls,2);
});
