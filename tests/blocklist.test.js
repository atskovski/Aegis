'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isKnownTracker } = require('../src/core/blocklist');

test('blocks common tracker hosts', () => assert.equal(isKnownTracker('https://www.google-analytics.com/g/collect?v=2'), true));
test('blocks analytics host heuristic', () => assert.equal(isKnownTracker('https://analytics.example.net/event'), true));
test('does not block ordinary site asset by default', () => assert.equal(isKnownTracker('https://cdn.example.com/app.js'), false));
