import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { assertAdapterOperation, resolveExperimentalMemoryPolicy } = require('../scripts/ai_runtime_policy.js');

test('recall remains opt-in with bounded immutable defaults', () => {
  assert.equal(resolveExperimentalMemoryPolicy(undefined), null);
  assert.equal(resolveExperimentalMemoryPolicy({ enabled: false }), null);
  const policy = resolveExperimentalMemoryPolicy(true);
  assert.equal(policy.antiHits.limit, 3);
  assert.equal(policy.structuralRecall.limit, 4);
  assert.equal(policy.structuralRecall.maxHops, 1);
  assert.equal(Object.isFrozen(policy.antiHits), true);
});

test('recall rejects excessive or fractional limits and permits explicit lane disabling', () => {
  for (const request of [{ antiHitLimit: 6 }, { structuralLimit: 9 }, { maxCandidateScan: 81 }, { antiHitLimit: 1.5 }]) {
    assert.throws(() => resolveExperimentalMemoryPolicy({ enabled: true, ...request }),
      error => error.code === 'invalid_experimental_limit');
  }
  const policy = resolveExperimentalMemoryPolicy({ enabled: true, antiHits: false, structuralRecall: false });
  assert.equal(policy.antiHits.limit, 0);
  assert.equal(policy.structuralRecall.limit, 0);
});

test('standalone policy grants only the documented local objective operations', () => {
  assert.equal(assertAdapterOperation('memory-objectives', 'observe'), true);
  assert.equal(assertAdapterOperation('memory-objectives', 'local_write'), true);
  assert.throws(() => assertAdapterOperation('memory-objectives', 'remote_write'), /denies/);
  assert.throws(() => assertAdapterOperation('unknown-adapter', 'observe'), /denies/);
});
