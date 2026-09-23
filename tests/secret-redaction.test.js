'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {redact,redactString,maskProxyServer}=require('../src/core/secret-redaction');
test('redacts credential-shaped object fields',()=>{const v=redact({token:'abc',nested:{apiKey:'xyz',ok:'safe'}});assert.equal(v.token,'[REDACTED]');assert.equal(v.nested.apiKey,'[REDACTED]');assert.equal(v.nested.ok,'safe');});
test('redacts bearer and URL query secrets',()=>{const v=redactString('Bearer abc.def https://x.test/?token=secret');assert.doesNotMatch(v,/abc\.def|token=secret/);});
test('masks proxy credentials',()=>assert.equal(maskProxyServer('socks5://u:p@127.0.0.1:9050'),'socks5://u:[REDACTED]@127.0.0.1:9050'));
