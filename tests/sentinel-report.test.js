'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { buildSentinelReport }=require('../src/core/sentinel-report');

test('Sentinel exposes a simple and advanced report without claiming anonymity',()=>{
  const report=buildSentinelReport({
    tab:{url:'https://example.com/',partition:'aegis-tab-1',fingerprintReady:true,cosmeticFilteringReady:true,stats:{blocked:7},siteIntelligence:{
      network:{blockedThirdParty:7,allowedThirdParty:2,thirdPartyHosts:{a:{host:'tracker.test',requests:5,blocked:5}}},
      signals:{canvas:{group:'fingerprint',attempts:2},cookies:{group:'storage',attempts:1}}
    }},
    settings:{proxy:{mode:'system'}},
    publicIp:'203.0.113.10',
    route:{mode:'system'},
    protections:{protections:[]}
  });
  assert.equal(report.simple.blocked,7);
  assert.equal(report.simple.thirdParties,1);
  assert.match(report.simple.ipMeaning,/does not prove anonymity/i);
  assert.equal(report.advanced.sessionPartition,'ephemeral');
});

test('Sentinel calls out degraded configured protections',()=>{
  const report=buildSentinelReport({protections:{protections:[{status:'degraded'},{status:'enforced'}]}});
  assert.equal(report.simple.protection,'Attention needed');
  assert.match(report.simple.headline,/1 configured protection/);
});
