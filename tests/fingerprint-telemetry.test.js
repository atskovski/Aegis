'use strict';const test=require('node:test');const assert=require('node:assert/strict');const {createFingerprintTelemetry}=require('../src/core/fingerprint-telemetry');
test('multiple high entropy probes classify aggressive activity',()=>{const t=createFingerprintTelemetry();for(const s of ['canvas','webgl','webgpu','audio','fonts','webrtc','mediaDevices'])t.record(s);assert.equal(t.snapshot().level,'aggressive')});
test('unknown surfaces are ignored',()=>{const t=createFingerprintTelemetry();t.record('unknown');assert.equal(t.snapshot().probes,0)});
