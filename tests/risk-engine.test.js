'use strict';const test=require('node:test');const assert=require('node:assert/strict');const {createRiskEngine}=require('../src/core/risk-engine');
test('risk engine escalates correlated hostile behavior',()=>{const r=createRiskEngine();r.add('phishing',{severity:1});r.add('tls-error',{severity:1});assert.ok(['high','critical'].includes(r.score().level))});
test('blocked activity contributes less residual risk',()=>{const a=createRiskEngine(),b=createRiskEngine();a.add('private-network',{blocked:false});b.add('private-network',{blocked:true});assert.ok(a.score().score>b.score().score)});
